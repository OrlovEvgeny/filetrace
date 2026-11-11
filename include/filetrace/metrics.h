#ifndef FILETRACE_METRICS_H
#define FILETRACE_METRICS_H

#include "filetrace/wire.h"

/*
 * Counters per label set. They are kept apart from the state's tables, which forget their
 * oldest entries: a counter must never go backwards.
 */
enum ft_series_kind : uint8_t {
    FT_SERIES_NETWORK_IO,        /* a: protocol number, b: enum ft_direction */
    FT_SERIES_FILE_SENT,         /* a: enum ft_method, b: enum ft_confidence */
    FT_SERIES_TRANSFERS_STARTED, /* a: enum ft_method, b: enum ft_confidence */
    FT_SERIES_KIND_COUNT,
};

enum ft_direction : uint8_t {
    FT_DIR_TRANSMIT,
    FT_DIR_RECEIVE,
};

struct ft_series;

/* Label sets beyond limit are summed into one overflow series per kind. */
struct ft_series *ft_series_create(size_t limit);
void ft_series_destroy(struct ft_series *s);

void ft_series_add(struct ft_series *s, enum ft_series_kind kind, const char *process, uint8_t a,
                   uint8_t b, uint64_t amount);

struct ft_metric {
    const char *name; /* OpenTelemetry instrument name */
    const char *unit; /* UCUM; braces annotate a count */
    const char *description;
    bool monotonic; /* a cumulative counter; otherwise a gauge */
    bool real;      /* the value is a double */
};

#define FT_METRIC_MAX_ATTRS 3

struct ft_metric_attr {
    const char *key;
    const char *value;
};

struct ft_metric_point {
    const struct ft_metric *metric;
    struct ft_metric_attr attrs[FT_METRIC_MAX_ATTRS];
    size_t attr_count;
    uint64_t value;
    double real;
};

/* Strings in a point are valid only during the call. */
typedef void ft_metric_fn(void *ctx, const struct ft_metric_point *point);

struct ft_metrics_input {
    const struct ft_series *series;
    const struct ft_row_stats *stats;
    uint64_t cpu_ns; /* processor time the agent has consumed */
};

/* Emits every point; the points of one metric follow each other. */
void ft_metrics_collect(const struct ft_metrics_input *in, ft_metric_fn *emit, void *ctx);

#endif
