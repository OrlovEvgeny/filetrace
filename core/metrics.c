#include "filetrace/metrics.h"

#include "filetrace/event.h"
#include "filetrace/schema.h"
#include "filetrace/table.h"

#include <stdlib.h>
#include <string.h>

struct series_key {
    uint8_t kind;
    uint8_t a;
    uint8_t b;
    uint8_t overflow;
    char process[FT_COMM_MAX];
};

struct ft_series {
    struct ft_table *table; /* value: uint64_t */
    size_t limit;
    size_t labelled; /* series other than the overflow ones */
};

struct ft_series *ft_series_create(size_t limit)
{
    struct ft_series *s = calloc(1, sizeof(*s));
    if (!s)
        return nullptr;

    s->limit = limit;
    /* Room beyond the limit for the overflow series, so that nothing is ever evicted. */
    s->table =
        ft_table_create(limit + FT_SERIES_KIND_COUNT, sizeof(struct series_key), sizeof(uint64_t));
    if (!s->table) {
        free(s);
        return nullptr;
    }
    return s;
}

void ft_series_destroy(struct ft_series *s)
{
    if (!s)
        return;
    ft_table_destroy(s->table);
    free(s);
}

void ft_series_add(struct ft_series *s, enum ft_series_kind kind, const char *process, uint8_t a,
                   uint8_t b, uint64_t amount)
{
    struct series_key key;

    memset(&key, 0, sizeof(key));
    key.kind = kind;
    key.a = a;
    key.b = b;
    ft_strlcpy(key.process, process, sizeof(key.process));

    uint64_t *value = ft_table_find(s->table, &key);
    if (!value) {
        bool created;

        if (s->labelled == s->limit)
            key = (struct series_key){.kind = kind, .overflow = 1};
        value = ft_table_insert(s->table, &key, &created);
        if (created && !key.overflow)
            s->labelled++;
    }
    *value += amount;
}

static const struct ft_metric network_io = {
    .name = "filetrace.network.io",
    .unit = "By",
    .description = "Bytes that local sockets accepted from processes and delivered to them.",
    .monotonic = true,
};
static const struct ft_metric file_sent = {
    .name = "filetrace.file.sent",
    .unit = "By",
    .description = "File bytes sent over the network.",
    .monotonic = true,
};
static const struct ft_metric transfers_started = {
    .name = "filetrace.transfers.started",
    .unit = "{transfer}",
    .description = "File transfers observed.",
    .monotonic = true,
};
static const struct ft_metric transfers_active = {
    .name = "filetrace.transfers.active",
    .unit = "{transfer}",
    .description = "File transfers in progress.",
};
static const struct ft_metric connections_active = {
    .name = "filetrace.connections.active",
    .unit = "{connection}",
    .description = "Sockets that are open or have recent traffic.",
};
static const struct ft_metric processes_active = {
    .name = "filetrace.processes.active",
    .unit = "{process}",
    .description = "Processes with network traffic in the last few seconds.",
};
static const struct ft_metric events_processed = {
    .name = "filetrace.events.processed",
    .unit = "{event}",
    .description = "Events the agent took from the kernel.",
    .monotonic = true,
};
static const struct ft_metric events_dropped = {
    .name = "filetrace.events.dropped",
    .unit = "{event}",
    .description = "Events lost before the agent could record them.",
    .monotonic = true,
};
static const struct ft_metric cpu_time = {
    .name = "process.cpu.time",
    .unit = "s",
    .description = "Processor time the agent has consumed.",
    .monotonic = true,
    .real = true,
};
static const struct ft_metric memory_usage = {
    .name = "process.memory.usage",
    .unit = "By",
    .description = "Resident memory of the agent.",
};

static const char *loss_label(enum ft_loss_kind kind)
{
    switch (kind) {
    case FT_LOSS_EVENT_QUEUE:
        return "event_queue";
    case FT_LOSS_AGGREGATION:
        return "counter_table";
    case FT_LOSS_SOCKET_IDENT:
        return "socket_identity";
    default:
        return "unknown";
    }
}

static void emit_series(const struct ft_series *s, enum ft_series_kind kind,
                        const struct ft_metric *metric, ft_metric_fn *emit, void *ctx)
{
    for (const uint64_t *value = ft_table_first(s->table); value;
         value = ft_table_next(s->table, value)) {
        const struct series_key *key = ft_table_key(s->table, value);
        struct ft_metric_point pt = {.metric = metric, .value = *value};
        char proto[8];

        if (key->kind != kind)
            continue;
        if (key->overflow) {
            pt.attrs[pt.attr_count++] = (struct ft_metric_attr){FT_ATTR_OVERFLOW, "true"};
        } else if (kind == FT_SERIES_NETWORK_IO) {
            pt.attrs[pt.attr_count++] = (struct ft_metric_attr){FT_ATTR_PROCESS_NAME, key->process};
            pt.attrs[pt.attr_count++] =
                (struct ft_metric_attr){FT_ATTR_NETWORK_TRANSPORT, ft_proto_name(key->a, proto)};
            pt.attrs[pt.attr_count++] = (struct ft_metric_attr){
                FT_ATTR_NETWORK_DIRECTION, key->b == FT_DIR_RECEIVE ? "receive" : "transmit"};
        } else {
            pt.attrs[pt.attr_count++] = (struct ft_metric_attr){FT_ATTR_PROCESS_NAME, key->process};
            pt.attrs[pt.attr_count++] = (struct ft_metric_attr){
                FT_ATTR_TRANSFER_METHOD, ft_method_name((enum ft_method)key->a)};
            pt.attrs[pt.attr_count++] = (struct ft_metric_attr){
                FT_ATTR_TRANSFER_CONFIDENCE, ft_confidence_name((enum ft_confidence)key->b)};
        }
        emit(ctx, &pt);
    }
}

static void emit_value(const struct ft_metric *metric, uint64_t value, ft_metric_fn *emit,
                       void *ctx)
{
    struct ft_metric_point pt = {.metric = metric, .value = value};
    emit(ctx, &pt);
}

void ft_metrics_collect(const struct ft_metrics_input *in, ft_metric_fn *emit, void *ctx)
{
    const struct ft_row_stats *stats = in->stats;

    emit_series(in->series, FT_SERIES_NETWORK_IO, &network_io, emit, ctx);
    emit_series(in->series, FT_SERIES_FILE_SENT, &file_sent, emit, ctx);
    emit_series(in->series, FT_SERIES_TRANSFERS_STARTED, &transfers_started, emit, ctx);

    for (size_t c = FT_CONF_INFERRED; c < FT_ARRAY_LEN(stats->active_by_confidence); c++) {
        struct ft_metric_point pt = {
            .metric = &transfers_active,
            .value = stats->active_by_confidence[c],
            .attrs = {{FT_ATTR_TRANSFER_CONFIDENCE, ft_confidence_name((enum ft_confidence)c)}},
            .attr_count = 1,
        };
        emit(ctx, &pt);
    }
    emit_value(&connections_active, stats->open_sockets, emit, ctx);
    emit_value(&processes_active, stats->active_processes, emit, ctx);
    emit_value(&events_processed, stats->events_processed, emit, ctx);

    for (size_t k = 0; k < FT_LOSS_KIND_COUNT; k++) {
        struct ft_metric_point pt = {
            .metric = &events_dropped,
            .value = stats->loss[k],
            .attrs = {{FT_ATTR_LOSS_KIND, loss_label((enum ft_loss_kind)k)}},
            .attr_count = 1,
        };
        emit(ctx, &pt);
    }

    struct ft_metric_point cpu = {
        .metric = &cpu_time,
        .real = (double)in->cpu_ns / (double)FT_NS_PER_SEC,
    };
    emit(ctx, &cpu);
    emit_value(&memory_usage, stats->rss_bytes, emit, ctx);
}
