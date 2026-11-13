#ifndef FILETRACE_OTLP_H
#define FILETRACE_OTLP_H

#include "filetrace/metrics.h"

#define FT_OTLP_LOGS_PATH "/opentelemetry.proto.collector.logs.v1.LogsService/Export"
#define FT_OTLP_METRICS_PATH "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export"

/*
 * Records waiting to leave as OpenTelemetry log records. Bytes of one transfer or of one flow
 * that arrive while a batch fills are summed into a single record.
 */
struct ft_otlp_logs;

/*
 * Without file_paths a file is described by device and inode only, and a process by no path
 * either. Without command_line a process's arguments are left out, and without names the names
 * of remote ends.
 */
struct ft_otlp_logs *ft_otlp_logs_new(size_t max_records, bool file_paths, bool command_line,
                                      bool names);
void ft_otlp_logs_free(struct ft_otlp_logs *b);

/*
 * row carries wall-clock time; names are those of a transfer record's remote end, or nullptr.
 * False when the batch is full: the record was not taken.
 */
bool ft_otlp_logs_add(struct ft_otlp_logs *b, const struct ft_row_event *row,
                      const struct ft_remote_names *names);

size_t ft_otlp_logs_count(const struct ft_otlp_logs *b);

/*
 * The batch as an ExportLogsServiceRequest, which the caller frees, or nullptr when memory runs
 * out. Either way the batch is empty afterwards.
 */
uint8_t *ft_otlp_logs_encode(struct ft_otlp_logs *b, const struct ft_metric_attr *resource,
                             size_t resource_count, uint64_t now_wall_ns, size_t *size);

/* Metric points on their way into one ExportMetricsServiceRequest. */
struct ft_otlp_metrics;

struct ft_otlp_metrics *ft_otlp_metrics_new(uint64_t start_wall_ns, uint64_t now_wall_ns);

/* An ft_metric_fn whose ctx is the struct ft_otlp_metrics. */
void ft_otlp_metrics_point(void *ctx, const struct ft_metric_point *point);

/* Frees m; the caller frees the request. nullptr when memory ran out along the way. */
uint8_t *ft_otlp_metrics_encode(struct ft_otlp_metrics *m, const struct ft_metric_attr *resource,
                                size_t resource_count, size_t *size);

/* How many records an ExportLogsServiceResponse says were refused; why receives the reason. */
uint64_t ft_otlp_logs_rejected(const uint8_t *reply, size_t size, char *why, size_t why_size);
uint64_t ft_otlp_metrics_rejected(const uint8_t *reply, size_t size, char *why, size_t why_size);

#endif
