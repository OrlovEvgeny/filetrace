#ifndef FILETRACE_CONFIG_H
#define FILETRACE_CONFIG_H

#include "agent/agent.h"

#include <stdio.h>

#define FT_CONFIG_MAX_PATTERNS 32
#define FT_CONFIG_MAX_WARNINGS 16

/* Never copied: agent points into the structure itself. */
struct ft_config {
    struct ft_agent_config agent;
    bool enabled;
    enum ft_log_level log_level;
    char socket_path[104];
    bool queue_size_set;
    bool event_log_size_set;

    bool correlation_enabled;
    bool track_read;
    bool track_sendfile;

    char format[8]; /* default output format of the commands that list records */
    bool timestamps;

    char *exclude_processes[FT_CONFIG_MAX_PATTERNS];
    size_t exclude_process_count;
    char *exclude_paths[FT_CONFIG_MAX_PATTERNS];
    size_t exclude_path_count;
    char *no_minimum_paths[FT_CONFIG_MAX_PATTERNS];
    size_t no_minimum_path_count;

    /* Accepted and kept, though this build cannot honour them. */
    bool tc_egress;
    bool track_open;
    bool track_mmap;
    bool track_splice;
    bool track_fd_lifecycle;
    bool track_io_uring;
    bool track_process_lifecycle;
    bool storage_enabled;
    char storage_path[256];
    uint64_t storage_retention_ns;

    char source[256]; /* the file that was read; empty when only built-in defaults apply */
    char warnings[FT_CONFIG_MAX_WARNINGS][200];
    size_t warning_count;
};

/* $FILETRACE_CONFIG, or the system-wide file. */
const char *ft_config_default_path(void);

/* Built-in defaults; nullptr when memory runs out. */
struct ft_config *ft_config_new(void);
void ft_config_free(struct ft_config *cfg);

/* A nullptr path means the default file, which alone may be absent. */
int ft_config_load(struct ft_config *cfg, const char *path, struct ft_error *err);

/* Settings that depend on others, applied once the file and the command line are read. */
void ft_config_finish(struct ft_config *cfg);

/* Every setting with its effective value, in the format ft_config_load reads. */
void ft_config_print(const struct ft_config *cfg, FILE *out);

#endif
