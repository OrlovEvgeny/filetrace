#include "filetrace/sysinfo.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif
#if defined(__APPLE__)
#include <mach/mach.h>
#endif

static uint64_t timeval_ns(struct timeval tv)
{
    return (uint64_t)tv.tv_sec * FT_NS_PER_SEC + (uint64_t)tv.tv_usec * 1000;
}

static uint64_t resident_bytes(void)
{
#if defined(__linux__)
    unsigned long long total = 0;
    unsigned long long resident = 0;
    FILE *f = fopen("/proc/self/statm", "re");
    if (!f)
        return 0;
    int n = fscanf(f, "%llu %llu", &total, &resident);
    fclose(f);
    return n == 2 ? (uint64_t)resident * (uint64_t)sysconf(_SC_PAGESIZE) : 0;
#elif defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) !=
        KERN_SUCCESS)
        return 0;
    return info.resident_size;
#else
    return 0;
#endif
}

static bool count_entries(const char *dir, uint32_t *count)
{
    DIR *d = opendir(dir);
    if (!d)
        return false;

    uint32_t n = 0;
    for (struct dirent *e = readdir(d); e; e = readdir(d)) {
        if (e->d_name[0] != '.')
            n++;
    }
    closedir(d);
    *count = n;
    return true;
}

static uint32_t count_open_fds(void)
{
#if defined(__linux__)
    const char *dir = "/proc/self/fd";
#else
    const char *dir = "/dev/fd";
#endif
    uint32_t n = 0;
    count_entries(dir, &n);
    /* The directory stream itself holds one descriptor. */
    return n ? n - 1 : 0;
}

bool ft_sysinfo_host_pid_namespace(void)
{
#if defined(__linux__)
    /* PROC_PID_INIT_INO: the inode number of the initial PID namespace on every kernel. */
    constexpr ino_t INIT_PID_NAMESPACE = 0xEFFFFFFCu;
    static int host = -1;
    struct stat st;

    if (host < 0)
        host = stat("/proc/self/ns/pid", &st) != 0 || st.st_ino == INIT_PID_NAMESPACE;
    return host;
#else
    return true;
#endif
}

bool ft_sysinfo_process_open_files(uint32_t pid, uint32_t *count)
{
#if defined(__linux__)
    char dir[64];
    snprintf(dir, sizeof(dir), "/proc/%u/fd", pid);
    return count_entries(dir, count);
#else
    (void)pid;
    (void)count;
    return false;
#endif
}

bool ft_sysinfo_process_cgroup(uint32_t pid, char *buf, size_t size)
{
#if defined(__linux__)
    char path[64];
    char line[4352];
    bool found = false;

    snprintf(path, sizeof(path), "/proc/%u/cgroup", pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return false;
    /* The unified hierarchy is the line "0::<path>". */
    while (!found && fgets(line, sizeof(line), f)) {
        if (strncmp(line, "0::", 3) != 0)
            continue;
        line[strcspn(line, "\n")] = '\0';
        ft_strlcpy(buf, line + 3, size);
        found = true;
    }
    fclose(f);
    return found;
#else
    (void)pid;
    (void)buf;
    (void)size;
    return false;
#endif
}

void ft_sysinfo_self(struct ft_self_usage *out)
{
    struct rusage ru;

    memset(out, 0, sizeof(*out));
    if (getrusage(RUSAGE_SELF, &ru) == 0)
        out->cpu_ns = timeval_ns(ru.ru_utime) + timeval_ns(ru.ru_stime);
    out->rss_bytes = resident_bytes();
    out->open_fds = count_open_fds();
}

void ft_sysinfo_host(struct ft_host_info *out)
{
    struct utsname u;

    memset(out, 0, sizeof(*out));
    if (uname(&u) == 0) {
        ft_strlcpy(out->hostname, u.nodename, sizeof(out->hostname));
        ft_strlcpy(out->system, u.sysname, sizeof(out->system));
        ft_strlcpy(out->release, u.release, sizeof(out->release));
        ft_strlcpy(out->arch, u.machine, sizeof(out->arch));
    }
}

const char *ft_platform_name(void)
{
#if defined(__linux__)
    return "linux";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__FreeBSD__)
    return "freebsd";
#else
    return "unknown";
#endif
}

void ft_sysinfo_small_pages(void)
{
#if defined(__linux__) && defined(PR_SET_THP_DISABLE)
    prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
#endif
}
