#include "backends/linux/linux.h"

#include <bpf/libbpf.h>
#include <elf.h>
#include <inttypes.h>
#include <string.h>

#if defined(__x86_64__)
#define NATIVE_MACHINE EM_X86_64
#elif defined(__aarch64__)
#define NATIVE_MACHINE EM_AARCH64
#else
#error "unsupported architecture"
#endif

static bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool ends_with(const char *s, const char *suffix)
{
    size_t n = strlen(s);
    size_t m = strlen(suffix);
    return n >= m && strcmp(s + n - m, suffix) == 0;
}

/*
 * glibc, which glibc before 2.34 installs as libc-2.N.so; musl, by the name of its loader, which
 * is also its C library, and where Debian installs it behind that name.
 */
static bool libc_mapped(const char *path, const char *name)
{
    return strcmp(name, "libc.so.6") == 0 ||
           (starts_with(name, "libc-2.") && ends_with(name, ".so")) ||
           (starts_with(name, "ld-musl-") && ends_with(name, ".so.1")) ||
           ends_with(path, "-linux-musl/libc.so");
}

/* struct addrinfo, which the probes read, is laid out alike only for this machine's programs. */
static uint64_t libc_cookie(int fd)
{
    static const char *const names[] = {"getaddrinfo"};
    bool found[FT_ARRAY_LEN(names)];
    uint16_t machine = 0;

    return ft_linux_elf_exports(fd, names, FT_ARRAY_LEN(names), found, &machine) && found[0] &&
           machine == NATIVE_MACHINE;
}

static void libc_probed(const char *name, uint32_t pid, uint64_t cookie)
{
    (void)cookie;
    ft_log(FT_LOG_INFO, "probing name lookups in %s, as process %" PRIu32 " maps it", name, pid);
}

int ft_linux_lookups_open(struct bpf_object *obj, struct ft_linux_prober *prober, size_t capacity)
{
    struct bpf_program *call = bpf_object__find_program_by_name(obj, "ft_getaddrinfo");
    struct bpf_program *ret = bpf_object__find_program_by_name(obj, "ft_getaddrinfo_return");
    if (!call || !ret || bpf_program__fd(call) < 0 || bpf_program__fd(ret) < 0)
        return -1;
    struct ft_linux_probe_kind kind = {
        .one = "the C library",
        .many = "C libraries",
        .capacity = capacity,
        .probes = {{call, "getaddrinfo", false}, {ret, "getaddrinfo", true}},
        .every_process = true,
        .every_program = true,
        .place_cookie = true,
        .mapped = libc_mapped,
        .cookie = libc_cookie,
        .probed = libc_probed,
    };
    return ft_linux_prober_add(prober, &kind);
}
