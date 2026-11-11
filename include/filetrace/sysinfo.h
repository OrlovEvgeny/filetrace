#ifndef FILETRACE_SYSINFO_H
#define FILETRACE_SYSINFO_H

#include "filetrace/base.h"

struct ft_self_usage {
    uint64_t rss_bytes; /* 0 when the platform does not report it */
    uint64_t cpu_ns;    /* user and system time consumed so far */
    uint32_t open_fds;
};

void ft_sysinfo_self(struct ft_self_usage *out);

struct ft_host_info {
    char hostname[64];
    char system[32];  /* "Linux", "Darwin", "FreeBSD" */
    char release[96]; /* kernel release */
    char arch[32];
};

void ft_sysinfo_host(struct ft_host_info *out);

/* Facts about a running process that only the system holds; false when it cannot tell. */
bool ft_sysinfo_process_cgroup(uint32_t pid, char *buf, size_t size);
bool ft_sysinfo_process_open_files(uint32_t pid, uint32_t *count);

/* "linux", "macos", "freebsd" or the lowercase system name. */
const char *ft_platform_name(void);

#endif
