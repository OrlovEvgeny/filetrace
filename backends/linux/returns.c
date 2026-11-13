#include "backends/linux/linux.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * On x86-64 a probed function returns through a system call of its own, uretprobe, since 6.11;
 * a seccomp filter that refuses it kills the process unless the kernel lets the call past the
 * filter (6.12.14, 6.13.3, 6.14 and the distributions' backports).
 */
#if defined(__x86_64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_X86_64
#define RETURN_SYSCALL true
#elif defined(__aarch64__)
#define NATIVE_AUDIT_ARCH AUDIT_ARCH_AARCH64
#define RETURN_SYSCALL false
#endif
#define URETPROBE_NR 335 /* x86-64's; unassigned on arm64, where the test only runs on request */

#define TEST_EXIT 42
#define TEST_KILLED 43
#define TEST_WAIT_MS 5000

/* Hidden: "unsafe" takes the test as failed, "run" runs it where the architecture needs none. */
static const char *test_hook(void)
{
    const char *hook = getenv("FILETRACE_TEST_RETURN_PROBES");
    return hook ? hook : "";
}

/* The PHP probes follow a request's script to its end with a return probe. */
static bool probes_wanted(const struct ft_backend_config *cfg)
{
    return cfg->mode >= FT_MODE_STANDARD && cfg->php_scripts;
}

bool ft_linux_returns_tested(const struct ft_backend_config *cfg)
{
    return probes_wanted(cfg) && (RETURN_SYSCALL || strcmp(test_hook(), "run") == 0);
}

/* What the test process calls, with a return probe on it. */
[[gnu::noinline, gnu::used]] static int returns_target(int value)
{
    __asm__ volatile("" : "+r"(value));
    return value + 1;
}

/* The offset in this process's program file of the code at addr. */
static bool file_offset(uintptr_t addr, uint64_t *offset)
{
    char line[512];
    bool found = false;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f)
        return false;
    while (!found && fgets(line, sizeof(line), f)) {
        unsigned long long start, end, off;
        if (sscanf(line, "%llx-%llx %*s %llx", &start, &end, &off) == 3 && addr >= start &&
            addr < end) {
            *offset = addr - start + off;
            found = true;
        }
    }
    fclose(f);
    return found;
}

/* Refuses the uretprobe system call as a container runtime's default profile does. */
static bool refuse_return_syscall(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_AUDIT_ARCH, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, URETPROBE_NR, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {.len = FT_ARRAY_LEN(filter), .filter = filter};
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
           prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) == 0;
}

static void killed(int)
{
    _exit(TEST_KILLED);
}

/* A killed test process would leave a line in the kernel log and a core at every start. */
static void die_quietly(void)
{
    struct sigaction quiet = {.sa_handler = killed};
    sigaction(SIGSEGV, &quiet, nullptr);
    sigaction(SIGBUS, &quiet, nullptr);
    sigaction(SIGILL, &quiet, nullptr);
    setrlimit(RLIMIT_CORE, &(struct rlimit){0});
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

[[noreturn]] static void test_process(int go)
{
    char c;
    if (read(go, &c, 1) != 1)
        _exit(1);
    die_quietly();
    if (!refuse_return_syscall())
        _exit(1);
    int (*volatile call)(int) = returns_target;
    _exit(call(TEST_EXIT - 1));
}

/* Waits for the test process, killing it after a while; its wait status, or -1. */
static int reap(pid_t child)
{
    int status;
    for (int ms = 0; ms < TEST_WAIT_MS; ms++) {
        pid_t done = waitpid(child, &status, WNOHANG);
        if (done == child)
            return status;
        if (done < 0)
            return -1;
        nanosleep(&(struct timespec){.tv_nsec = 1000000}, nullptr);
    }
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    return -1;
}

/*
 * A process of its own, under a seccomp filter that refuses the uretprobe system call, calls a
 * function of this program with a return probe on it, for it alone.
 */
static enum ft_linux_returns run_test(struct bpf_object *obj, int *error)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "ft_return_check");
    struct bpf_map *checks = bpf_object__find_map_by_name(obj, "return_checks");
    uint64_t offset = 0;
    int go[2];

    if (!prog || !checks || bpf_program__fd(prog) < 0 || bpf_map__fd(checks) < 0) {
        *error = ENOENT;
        return FT_RETURNS_UNKNOWN;
    }
    if (!file_offset((uintptr_t)returns_target, &offset) || pipe2(go, O_CLOEXEC) != 0) {
        *error = errno ? errno : ENOENT;
        return FT_RETURNS_UNKNOWN;
    }
    pid_t child = fork();
    if (child == 0) {
        close(go[1]);
        test_process(go[0]);
    }
    close(go[0]);
    if (child < 0) {
        *error = errno;
        close(go[1]);
        return FT_RETURNS_UNKNOWN;
    }

    /* libbpf refuses options whose padding is not zero, which an initializer leaves open. */
    struct bpf_uprobe_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.retprobe = true;
    struct bpf_link *link =
        bpf_program__attach_uprobe_opts(prog, child, "/proc/self/exe", offset, &opts);
    if (libbpf_get_error(link)) {
        *error = -(int)libbpf_get_error(link);
        link = nullptr;
    } else if (write(go[1], "x", 1) != 1) {
        *error = errno;
    }
    close(go[1]);
    int status = reap(child);
    bpf_link__destroy(link);

    uint32_t zero = 0;
    uint64_t returns = 0;
    bpf_map_lookup_elem(bpf_map__fd(checks), &zero, &returns);
    bool died = status != -1 &&
                (WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status) == TEST_KILLED));
    if (died)
        return FT_RETURNS_UNSAFE;
    if (link && status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == TEST_EXIT && returns)
        return FT_RETURNS_SAFE;
    if (!*error)
        *error = EPROTO;
    return FT_RETURNS_UNKNOWN;
}

void ft_linux_returns_test(struct ft_linux_probes *p, const struct ft_backend_config *cfg)
{
    p->returns_error = 0;
    if (!probes_wanted(cfg))
        p->returns = FT_RETURNS_NOT_TESTED;
    else if (strcmp(test_hook(), "unsafe") == 0)
        p->returns = FT_RETURNS_UNSAFE;
    else if (!ft_linux_returns_tested(cfg))
        p->returns = FT_RETURNS_NO_SYSCALL;
    else
        p->returns = run_test(p->obj, &p->returns_error);
}

bool ft_linux_returns_allowed(const struct ft_linux_probes *p, const struct ft_backend_config *cfg)
{
    return p->returns == FT_RETURNS_NO_SYSCALL || p->returns == FT_RETURNS_SAFE ||
           cfg->force_return_probes;
}

bool ft_linux_returns_refused(const struct ft_linux_probes *p)
{
    return p->returns == FT_RETURNS_UNSAFE || p->returns == FT_RETURNS_UNKNOWN;
}

static const char *finding(const struct ft_linux_probes *p, char *buf, size_t size)
{
    if (p->returns == FT_RETURNS_UNSAFE)
        return "return probes kill processes under seccomp on this kernel, as on x86-64 6.11 to "
               "6.12.13 and 6.13 to 6.13.2";
    snprintf(buf, size, "return probes could not be tested against seccomp (%s)",
             strerror(p->returns_error));
    return buf;
}

const char *ft_linux_returns_refusal(const struct ft_linux_probes *p, char *buf, size_t size)
{
    char found[128];
    snprintf(buf, size, "%s: %s[process] force_return_probes%s", finding(p, found, sizeof(found)),
             p->returns == FT_RETURNS_UNSAFE ? "update the kernel, or see " : "",
             p->returns == FT_RETURNS_UNSAFE ? "" : " attaches them anyway");
    return buf;
}

const char *ft_linux_returns_forced(const struct ft_linux_probes *p, char *buf, size_t size)
{
    char found[128];
    snprintf(buf, size, "%s; [process] force_return_probes attaches the PHP probes all the same%s",
             finding(p, found, sizeof(found)),
             p->returns == FT_RETURNS_UNSAFE
                 ? ", so a PHP process under a seccomp filter is killed where its request ends"
                 : "");
    return buf;
}

const char *ft_linux_returns_row(const struct ft_linux_probes *p, char *buf, size_t size)
{
    char found[128];
    snprintf(buf, size,
             "%s%s; the agent attaches the PHP probes here only with [process] "
             "force_return_probes",
             finding(p, found, sizeof(found)),
             p->returns == FT_RETURNS_UNSAFE ? ": update the kernel" : "");
    return buf;
}
