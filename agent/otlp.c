#include "agent/telemetry.h"

#include "exporters/otlp.h"
#include "filetrace/clock.h"
#include "rpc/grpc.h"

#include <stdlib.h>
#include <string.h>

constexpr size_t MAX_WAITING = 16;
constexpr size_t MAX_WAITING_BYTES = 8 * 1024 * 1024;
constexpr uint64_t MIN_PAUSE_NS = FT_NS_PER_SEC;
constexpr uint64_t MAX_PAUSE_NS = 30 * FT_NS_PER_SEC;
constexpr uint64_t DROP_REPORT_NS = 60 * FT_NS_PER_SEC;
constexpr uint64_t DRAIN_NS = FT_NS_PER_SEC;

struct request {
    uint8_t *bytes;
    size_t size;
    size_t records;
};

enum reach : uint8_t {
    REACH_UNKNOWN,
    REACH_YES,
    REACH_NO,
};

struct ft_otlp {
    struct ft_otlp_config cfg;
    struct ft_telemetry_source src;
    struct ft_metric_attr resource[FT_RESOURCE_ATTRS];
    struct ft_grpc_client *client;
    struct ft_otlp_logs *batch;
    struct ft_row_event *row; /* a record with its time turned to wall clock */

    uint64_t next_flush_ns;
    uint64_t next_metrics_ns;
    uint64_t retry_ns; /* nothing is sent before this */
    uint64_t pause_ns;

    struct request waiting[MAX_WAITING]; /* log requests, oldest first */
    size_t waiting_count;
    size_t waiting_bytes;
    struct request logs; /* the log request being sent or sent again */
    bool logs_in_flight;
    struct request metrics;
    bool metrics_in_flight;

    enum reach reach;
    uint64_t dropped; /* records given up since the last report */
    uint64_t drop_report_ns;
};

static void release(struct request *r)
{
    free(r->bytes);
    *r = (struct request){0};
}

static void drop(struct ft_otlp *o, struct request *r)
{
    o->dropped += r->records;
    release(r);
}

static void report_drops(struct ft_otlp *o, uint64_t now_ns)
{
    if (!o->dropped || now_ns < o->drop_report_ns)
        return;
    ft_log(FT_LOG_WARN, "gave up exporting %llu records to %s", (unsigned long long)o->dropped,
           o->cfg.endpoint);
    o->dropped = 0;
    o->drop_report_ns = now_ns + DROP_REPORT_NS;
}

static bool worth_retrying(enum ft_grpc_status status)
{
    switch (status) {
    case FT_GRPC_CANCELLED:
    case FT_GRPC_DEADLINE_EXCEEDED:
    case FT_GRPC_RESOURCE_EXHAUSTED:
    case FT_GRPC_ABORTED:
    case FT_GRPC_OUT_OF_RANGE:
    case FT_GRPC_UNAVAILABLE:
    case FT_GRPC_DATA_LOSS:
        return true;
    default:
        return false;
    }
}

/* Returns whether the request is to be sent again. */
static bool settle(struct ft_otlp *o, const char *what, enum ft_grpc_status status,
                   const char *message, uint64_t rejected, const char *why)
{
    if (status == FT_GRPC_OK) {
        if (o->reach == REACH_NO)
            ft_log(FT_LOG_INFO, "exporting to %s again", o->cfg.endpoint);
        o->reach = REACH_YES;
        o->pause_ns = MIN_PAUSE_NS;
        if (rejected)
            ft_log(FT_LOG_WARN, "%s refused %llu %s: %s", o->cfg.endpoint,
                   (unsigned long long)rejected, what, why);
        return false;
    }
    if (!worth_retrying(status)) {
        ft_log(FT_LOG_WARN, "%s refused a batch of %s (gRPC status %d): %s", o->cfg.endpoint, what,
               (int)status, message);
        return false;
    }
    if (o->reach != REACH_NO)
        ft_log(FT_LOG_WARN, "cannot export to %s: %s; trying again", o->cfg.endpoint, message);
    o->reach = REACH_NO;
    o->retry_ns = ft_clock_mono_ns() + o->pause_ns;
    o->pause_ns = o->pause_ns * 2 > MAX_PAUSE_NS ? MAX_PAUSE_NS : o->pause_ns * 2;
    return true;
}

static void logs_done(void *ctx, enum ft_grpc_status status, const char *message,
                      const uint8_t *reply, size_t size)
{
    struct ft_otlp *o = ctx;
    char why[160] = "";
    uint64_t rejected =
        status == FT_GRPC_OK ? ft_otlp_logs_rejected(reply, size, why, sizeof(why)) : 0;

    o->logs_in_flight = false;
    if (settle(o, "log records", status, message, rejected, why))
        return;
    if (status == FT_GRPC_OK)
        release(&o->logs);
    else
        drop(o, &o->logs);
}

static void metrics_done(void *ctx, enum ft_grpc_status status, const char *message,
                         const uint8_t *reply, size_t size)
{
    struct ft_otlp *o = ctx;
    char why[160] = "";
    uint64_t rejected =
        status == FT_GRPC_OK ? ft_otlp_metrics_rejected(reply, size, why, sizeof(why)) : 0;

    /* Counters are cumulative: the next collection makes up for one that did not arrive. */
    o->metrics_in_flight = false;
    settle(o, "metric points", status, message, rejected, why);
    release(&o->metrics);
}

static void send_waiting(struct ft_otlp *o, uint64_t now_ns)
{
    if (now_ns < o->retry_ns)
        return;
    if (!o->logs_in_flight && !o->logs.bytes && o->waiting_count) {
        o->logs = o->waiting[0];
        o->waiting_bytes -= o->logs.size;
        o->waiting_count--;
        memmove(&o->waiting[0], &o->waiting[1], o->waiting_count * sizeof(o->waiting[0]));
    }
    if (!o->logs_in_flight && o->logs.bytes) {
        o->logs_in_flight = true;
        ft_grpc_client_call(o->client, FT_OTLP_LOGS_PATH, o->logs.bytes, o->logs.size,
                            now_ns + o->cfg.timeout_ns, logs_done, o);
    }
    if (!o->metrics_in_flight && o->metrics.bytes && now_ns >= o->retry_ns) {
        o->metrics_in_flight = true;
        ft_grpc_client_call(o->client, FT_OTLP_METRICS_PATH, o->metrics.bytes, o->metrics.size,
                            now_ns + o->cfg.timeout_ns, metrics_done, o);
    }
}

/* Moves the batch to the requests that wait; the oldest of those makes room if it must. */
static void flush_batch(struct ft_otlp *o)
{
    struct request r = {.records = ft_otlp_logs_count(o->batch)};

    if (r.records == 0)
        return;
    r.bytes =
        ft_otlp_logs_encode(o->batch, o->resource, FT_RESOURCE_ATTRS, ft_clock_wall_ns(), &r.size);
    if (!r.bytes) {
        o->dropped += r.records;
        return;
    }
    while (o->waiting_count &&
           (o->waiting_count == MAX_WAITING || o->waiting_bytes + r.size > MAX_WAITING_BYTES)) {
        o->waiting_bytes -= o->waiting[0].size;
        drop(o, &o->waiting[0]);
        o->waiting_count--;
        memmove(&o->waiting[0], &o->waiting[1], o->waiting_count * sizeof(o->waiting[0]));
    }
    o->waiting[o->waiting_count++] = r;
    o->waiting_bytes += r.size;
}

static void collect_metrics(struct ft_otlp *o, uint64_t now_ns)
{
    struct ft_row_stats stats = {0};

    if (o->metrics_in_flight)
        return;
    o->src.stats(o->src.agent, now_ns, &stats);
    struct ft_otlp_metrics *m = ft_otlp_metrics_new(stats.start_wall_ns, stats.now_wall_ns);
    if (!m)
        return;
    ft_telemetry_collect(&o->src, now_ns, ft_otlp_metrics_point, m);
    release(&o->metrics);
    o->metrics.bytes = ft_otlp_metrics_encode(m, o->resource, FT_RESOURCE_ATTRS, &o->metrics.size);
}

struct ft_otlp *ft_otlp_open(const struct ft_otlp_config *cfg,
                             const struct ft_telemetry_source *src, struct ft_error *err)
{
    struct ft_net_addr addr;
    uint64_t now_ns = ft_clock_mono_ns();

    if (!ft_net_addr_parse(cfg->endpoint, &addr)) {
        ft_error_set(err, FT_EXIT_CONFIG,
                     "[otlp] endpoint = \"%s\" is not a numeric address and port, such as "
                     "\"127.0.0.1:4317\", nor \"unix:\" and a socket path.",
                     cfg->endpoint);
        return nullptr;
    }
    struct ft_otlp *o = calloc(1, sizeof(*o));
    if (o) {
        o->cfg = *cfg;
        o->src = *src;
        o->client =
            ft_grpc_client_new(&addr, ft_net_addr_is_unix(&addr) ? "localhost" : cfg->endpoint);
        o->batch = ft_otlp_logs_new(cfg->batch_size, cfg->file_paths);
        o->row = malloc(sizeof(*o->row));
    }
    if (!o || !o->client || !o->batch || !o->row) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        if (o) {
            ft_grpc_client_free(o->client);
            ft_otlp_logs_free(o->batch);
            free(o->row);
            free(o);
        }
        return nullptr;
    }
    /* The resource names the host through the copy this exporter owns. */
    ft_telemetry_resource(&o->src, o->resource);
    o->pause_ns = MIN_PAUSE_NS;
    o->next_flush_ns = now_ns + cfg->flush_interval_ns;
    o->next_metrics_ns = now_ns + cfg->metrics_interval_ns;
    ft_log(FT_LOG_INFO, "exporting%s%s%s to %s over OTLP/gRPC", cfg->logs ? " events" : "",
           cfg->logs && cfg->metrics ? " and" : "", cfg->metrics ? " metrics" : "", cfg->endpoint);
    return o;
}

void ft_otlp_record(struct ft_otlp *o, const struct ft_row_event *row)
{
    if (!o || !o->cfg.logs || !(o->cfg.event_types & (1u << row->type)))
        return;
    memcpy(o->row, row, ft_row_event_size(row));
    o->row->time_ns = ft_clock_mono_to_wall(row->time_ns);
    if (ft_otlp_logs_add(o->batch, o->row))
        return;
    flush_batch(o);
    if (!ft_otlp_logs_add(o->batch, o->row))
        o->dropped++;
}

void ft_otlp_poll(struct ft_otlp *o, struct ft_poller *p)
{
    if (!o)
        return;
    if (o->cfg.logs)
        ft_poller_wake_by(p, o->next_flush_ns);
    if (o->cfg.metrics)
        ft_poller_wake_by(p, o->next_metrics_ns);
    bool unsent = (!o->logs_in_flight && (o->logs.bytes || o->waiting_count)) ||
                  (!o->metrics_in_flight && o->metrics.bytes);
    if (unsent)
        ft_poller_wake_by(p, o->retry_ns);
    ft_grpc_client_poll(o->client, p);
}

void ft_otlp_dispatch(struct ft_otlp *o, const struct ft_poller *p, uint64_t now_ns)
{
    if (!o)
        return;
    ft_grpc_client_dispatch(o->client, p, now_ns);
    if (o->cfg.logs && now_ns >= o->next_flush_ns) {
        flush_batch(o);
        o->next_flush_ns = now_ns + o->cfg.flush_interval_ns;
    }
    if (o->cfg.metrics && now_ns >= o->next_metrics_ns) {
        collect_metrics(o, now_ns);
        o->next_metrics_ns = now_ns + o->cfg.metrics_interval_ns;
    }
    send_waiting(o, now_ns);
    report_drops(o, now_ns);
}

void ft_otlp_close(struct ft_otlp *o)
{
    static struct ft_poller poller;

    if (!o)
        return;
    uint64_t now_ns = ft_clock_mono_ns();
    uint64_t give_up_ns = now_ns + DRAIN_NS;

    flush_batch(o);
    if (o->cfg.metrics)
        collect_metrics(o, now_ns);
    while (o->reach != REACH_NO && now_ns < give_up_ns) {
        send_waiting(o, now_ns);
        if (!o->logs_in_flight && !o->metrics_in_flight)
            break;
        ft_poller_begin(&poller, give_up_ns);
        ft_grpc_client_poll(o->client, &poller);
        ft_poller_wait(&poller, now_ns);
        now_ns = ft_clock_mono_ns();
        ft_grpc_client_dispatch(o->client, &poller, now_ns);
    }

    ft_grpc_client_free(o->client);
    ft_otlp_logs_free(o->batch);
    for (size_t i = 0; i < o->waiting_count; i++)
        free(o->waiting[i].bytes);
    free(o->logs.bytes);
    free(o->metrics.bytes);
    free(o->row);
    free(o);
}
