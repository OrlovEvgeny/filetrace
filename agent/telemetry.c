#include "agent/telemetry.h"

#include "filetrace/schema.h"
#include "filetrace/sysinfo.h"

#include <string.h>

void ft_telemetry_resource(const struct ft_telemetry_source *src,
                           struct ft_metric_attr attrs[static FT_RESOURCE_ATTRS])
{
    const char *platform = ft_platform_name();

    attrs[0] = (struct ft_metric_attr){FT_ATTR_SERVICE_NAME, "filetrace"};
    attrs[1] = (struct ft_metric_attr){FT_ATTR_SERVICE_VERSION, FT_VERSION};
    attrs[2] = (struct ft_metric_attr){FT_ATTR_HOST_NAME, src->host};
    attrs[3] = (struct ft_metric_attr){FT_ATTR_OS_TYPE,
                                       strcmp(platform, "macos") == 0 ? "darwin" : platform};
}

void ft_telemetry_collect(const struct ft_telemetry_source *src, uint64_t now_ns,
                          ft_metric_fn *emit, void *ctx)
{
    struct ft_row_stats stats = {0};
    struct ft_self_usage usage;

    src->stats(src->agent, now_ns, &stats);
    ft_sysinfo_self(&usage);

    struct ft_metrics_input in = {
        .series = src->state->series,
        .stats = &stats,
        .cpu_ns = usage.cpu_ns,
    };
    ft_metrics_collect(&in, emit, ctx);
}
