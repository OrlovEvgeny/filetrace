#ifndef FILETRACE_TELEMETRY_H
#define FILETRACE_TELEMETRY_H

#include "agent/agent.h"
#include "filetrace/poller.h"

/* What the agent shows the parts that export from it. */
struct ft_telemetry_source {
    struct ft_state *state;
    void *agent;
    void (*stats)(void *agent, uint64_t now_ns, struct ft_row_stats *row);
    char host[64];
};

#define FT_RESOURCE_ATTRS 4

/* service.name, service.version, host.name and os.type. */
void ft_telemetry_resource(const struct ft_telemetry_source *src,
                           struct ft_metric_attr attrs[static FT_RESOURCE_ATTRS]);

void ft_telemetry_collect(const struct ft_telemetry_source *src, uint64_t now_ns,
                          ft_metric_fn *emit, void *ctx);

/* The page a Prometheus server scrapes. A nullptr scrape is accepted and does nothing. */
struct ft_scrape;

struct ft_scrape *ft_scrape_open(const struct ft_prometheus_config *cfg,
                                 const struct ft_telemetry_source *src, struct ft_error *err);
void ft_scrape_close(struct ft_scrape *s);
void ft_scrape_poll(struct ft_scrape *s, struct ft_poller *p);
void ft_scrape_dispatch(struct ft_scrape *s, const struct ft_poller *p, uint64_t now_ns);

#endif
