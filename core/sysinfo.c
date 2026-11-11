#include "filetrace/sysinfo.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>

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

static uint32_t count_open_fds(void)
{
#if defined(__linux__)
    const char *dir = "/proc/self/fd";
#else
    const char *dir = "/dev/fd";
#endif
    DIR *d = opendir(dir);
    if (!d)
        return 0;

    uint32_t n = 0;
    for (struct dirent *e = readdir(d); e; e = readdir(d)) {
        if (e->d_name[0] != '.')
            n++;
    }
    closedir(d);
    /* The directory stream itself holds one descriptor. */
    return n ? n - 1 : 0;
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
