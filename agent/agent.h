#ifndef FILETRACE_AGENT_H
#define FILETRACE_AGENT_H

#include "backends/backend.h"
#include "filetrace/state.h"

struct ft_prometheus_config {
    bool enabled;
    char listen[64];
};

struct ft_otlp_config {
    bool enabled;
    char endpoint[108];
    bool logs;
    bool metrics;
    bool file_paths;      /* false: files leave as device and inode only */
    uint32_t event_types; /* bit per enum ft_record_type exported as a log record */
    uint32_t batch_size;
    uint64_t flush_interval_ns;
    uint64_t metrics_interval_ns;
    uint64_t timeout_ns;
};

struct ft_api_config {
    bool enabled;
    char listen[108];
};

struct ft_agent_config {
    const struct ft_backend_ops *backend;
    struct ft_backend_config backend_cfg;
    struct ft_state_config state_cfg;

    /* Where to accept clients; nullptr serves only session_fd. */
    const char *socket_path;

    /* A connected client, or -1; the collector stops when it disconnects. */
    int session_fd;

    uint32_t flush_interval_ms;

    struct ft_prometheus_config prometheus;
    struct ft_otlp_config otlp;
    struct ft_api_config api;
};

void ft_agent_config_defaults(struct ft_agent_config *cfg);

int ft_agent_run(const struct ft_agent_config *cfg, struct ft_error *err);

/* Safe to call from a signal handler. */
void ft_agent_stop(void);

int ft_agent_main(int argc, char **argv, const char *program);

#endif
