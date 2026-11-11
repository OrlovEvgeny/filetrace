#ifndef FILETRACE_EXPORTERS_H
#define FILETRACE_EXPORTERS_H

#include "filetrace/metrics.h"

#include <stdio.h>

/* Writes s as a JSON string literal, including the quotes. */
void ft_json_string(FILE *out, const char *s);

/* Writes s as one CSV field, quoting it when RFC 4180 requires. */
void ft_csv_field(FILE *out, const char *s);

/*
 * The Prometheus text exposition format. Names are those an OpenTelemetry Collector gives the
 * same metrics: dots become underscores, then the unit and "_total" for a counter.
 */
struct ft_prometheus {
    FILE *out;
    const struct ft_metric *metric; /* the family being written */
};

/* Writes target_info with the resource attributes as labels. */
void ft_prometheus_begin(struct ft_prometheus *w, FILE *out, const struct ft_metric_attr *resource,
                         size_t count);

/* An ft_metric_fn whose ctx is the struct ft_prometheus. */
void ft_prometheus_point(void *ctx, const struct ft_metric_point *point);

#endif
