#include "exporters/otlp.h"

#include "filetrace/arena.h"
#include "filetrace/event.h"
#include "filetrace/schema.h"
#include "filetrace/table.h"

#include "opentelemetry/proto/collector/logs/v1/logs_service.pb-c.h"
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb-c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

typedef Opentelemetry__Proto__Common__V1__AnyValue AnyValue;
typedef Opentelemetry__Proto__Common__V1__KeyValue KeyValue;
typedef Opentelemetry__Proto__Common__V1__InstrumentationScope Scope;
typedef Opentelemetry__Proto__Resource__V1__Resource Resource;
typedef Opentelemetry__Proto__Logs__V1__LogRecord LogRecord;
typedef Opentelemetry__Proto__Logs__V1__ScopeLogs ScopeLogs;
typedef Opentelemetry__Proto__Logs__V1__ResourceLogs ResourceLogs;
typedef Opentelemetry__Proto__Metrics__V1__Metric Metric;
typedef Opentelemetry__Proto__Metrics__V1__Sum Sum;
typedef Opentelemetry__Proto__Metrics__V1__Gauge Gauge;
typedef Opentelemetry__Proto__Metrics__V1__NumberDataPoint NumberDataPoint;
typedef Opentelemetry__Proto__Metrics__V1__ScopeMetrics ScopeMetrics;
typedef Opentelemetry__Proto__Metrics__V1__ResourceMetrics ResourceMetrics;
typedef Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest LogsRequest;
typedef Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceResponse LogsResponse;
typedef Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest MetricsRequest;
typedef Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceResponse MetricsResponse;

/* A request stays well under the 4 MB that a collector accepts by default. */
constexpr size_t MAX_BATCH_BYTES = 3 * 1024 * 1024;
constexpr size_t RECORD_OVERHEAD = 1024; /* attribute keys and framing of one log record */
constexpr size_t MAX_ATTRS = 32;

/* protobuf-c reads strings through pointers that are not const. */
static char *text_of(const char *s)
{
    return (char *)(uintptr_t)s;
}

struct attrs {
    struct ft_arena *arena;
    KeyValue **items;
    size_t count;
    size_t capacity;
};

static struct attrs attrs_begin(struct ft_arena *a, size_t capacity)
{
    struct attrs l = {.arena = a, .items = ft_arena_alloc(a, capacity * sizeof(KeyValue *))};

    l.capacity = l.items ? capacity : 0;
    return l;
}

static AnyValue *attr_add(struct attrs *l, const char *key)
{
    if (l->count == l->capacity)
        return nullptr;
    KeyValue *kv = ft_arena_alloc(l->arena, sizeof(*kv));
    AnyValue *value = ft_arena_alloc(l->arena, sizeof(*value));
    if (!kv || !value)
        return nullptr;
    opentelemetry__proto__common__v1__key_value__init(kv);
    opentelemetry__proto__common__v1__any_value__init(value);
    kv->key = text_of(key);
    kv->value = value;
    l->items[l->count++] = kv;
    return value;
}

static void attr_string(struct attrs *l, const char *key, const char *value)
{
    AnyValue *v = attr_add(l, key);
    if (!v)
        return;
    v->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    v->string_value = ft_arena_text(l->arena, value);
}

static void attr_int(struct attrs *l, const char *key, uint64_t value)
{
    AnyValue *v = attr_add(l, key);
    if (!v)
        return;
    v->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    v->int_value = (int64_t)value;
}

static void attr_bool(struct attrs *l, const char *key, bool value)
{
    AnyValue *v = attr_add(l, key);
    if (!v)
        return;
    v->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_BOOL_VALUE;
    v->bool_value = value;
}

static Resource *make_resource(struct ft_arena *a, const struct ft_metric_attr *attrs, size_t count)
{
    Resource *resource = ft_arena_alloc(a, sizeof(*resource));
    struct attrs l = attrs_begin(a, count);

    if (!resource)
        return nullptr;
    opentelemetry__proto__resource__v1__resource__init(resource);
    for (size_t i = 0; i < count; i++)
        attr_string(&l, attrs[i].key, attrs[i].value);
    resource->attributes = l.items;
    resource->n_attributes = l.count;
    return resource;
}

static Scope *make_scope(struct ft_arena *a)
{
    Scope *scope = ft_arena_alloc(a, sizeof(*scope));

    if (!scope)
        return nullptr;
    opentelemetry__proto__common__v1__instrumentation_scope__init(scope);
    scope->name = text_of("filetrace");
    scope->version = text_of(FT_VERSION);
    return scope;
}

/* What makes two byte-carrying records parts of the same transfer or flow. */
struct merge_key {
    uint64_t sock_id;
    uint64_t dev;
    uint64_t ino;
    uint32_t pid;
    uint8_t type;
    uint8_t method;
    uint8_t pad[2];
    struct ft_endpoint remote;
};

struct ft_otlp_logs {
    size_t max_records;
    bool file_paths;
    bool command_line;
    bool names;
    unsigned char *rows; /* struct ft_row_event up to its text's end, each aligned */
    size_t rows_len;
    size_t rows_cap;
    size_t count;
    size_t estimate;         /* of the encoded request */
    struct ft_table *merged; /* key: struct merge_key, value: size_t offset into rows */
};

struct ft_otlp_logs *ft_otlp_logs_new(size_t max_records, bool file_paths, bool command_line,
                                      bool names)
{
    struct ft_otlp_logs *b = calloc(1, sizeof(*b));
    if (!b)
        return nullptr;
    b->max_records = max_records;
    b->file_paths = file_paths;
    b->command_line = command_line;
    b->names = names;
    b->merged = ft_table_create(max_records, sizeof(struct merge_key), sizeof(size_t));
    if (!b->merged) {
        free(b);
        return nullptr;
    }
    return b;
}

void ft_otlp_logs_free(struct ft_otlp_logs *b)
{
    if (!b)
        return;
    ft_table_destroy(b->merged);
    free(b->rows);
    free(b);
}

size_t ft_otlp_logs_count(const struct ft_otlp_logs *b)
{
    return b->count;
}

static bool about_file(const struct ft_row_event *e)
{
    return e->type == FT_REC_FILE_SEEN || e->type == FT_REC_FILE_TRANSFER;
}

static bool about_process(const struct ft_row_event *e)
{
    return e->type >= FT_REC_PROCESS_EXEC && e->type <= FT_REC_PROCESS_EXIT;
}

static bool carries_bytes(const struct ft_row_event *e)
{
    return e->type == FT_REC_NETWORK_SEND || e->type == FT_REC_NETWORK_RECEIVE ||
           e->type == FT_REC_FILE_TRANSFER;
}

static size_t stored_size(size_t text_bytes)
{
    return (offsetof(struct ft_row_event, text) + text_bytes + alignof(struct ft_row_event) - 1) &
           ~(alignof(struct ft_row_event) - 1);
}

/* The process strings of the record that the batch's settings let leave. */
static bool exported_strings(const struct ft_otlp_logs *b, const struct ft_row_event *row,
                             struct ft_process_strings *out)
{
    if (!(row->flags & FT_EVENT_PROCESS_TEXT))
        return false;
    ft_row_event_strings(row, out);
    if (!b->command_line)
        out->command_line = "";
    if (!b->file_paths) {
        out->cwd = "";
        if (out->script[0] == '/')
            out->script = "";
    }
    return out->command_line[0] || out->cwd[0] || out->script[0];
}

static struct ft_row_event *row_at(const struct ft_otlp_logs *b, size_t offset)
{
    return (struct ft_row_event *)(void *)(b->rows + offset);
}

/* Whether a record in the batch has the name that a record taken now would keep. */
static bool same_name(const struct ft_row_event *kept, const char *name, uint8_t source)
{
    if (!name[0])
        return kept->name_source == FT_NAME_SOURCE_NONE;
    return kept->name_source == source && strcmp(ft_row_event_name(kept), name) == 0;
}

bool ft_otlp_logs_add(struct ft_otlp_logs *b, const struct ft_row_event *row)
{
    bool keep_text = b->file_paths || !about_file(row);
    size_t text_len = keep_text ? strnlen(row->text, FT_PATH_MAX - 1) : 0;
    struct ft_process_strings strings;
    bool with_strings = exported_strings(b, row, &strings);
    size_t strings_size = with_strings ? strlen(strings.command_line) + strlen(strings.cwd) +
                                             strlen(strings.script) + 3
                                       : 0;
    const char *name = b->names ? ft_row_event_name(row) : "";
    size_t name_size = name[0] ? strlen(name) + 1 : 0;
    size_t size = stored_size(text_len + 1 + strings_size + name_size);
    struct merge_key key;

    if (carries_bytes(row)) {
        memset(&key, 0, sizeof(key));
        key.sock_id = row->sock_id;
        key.dev = row->dev;
        key.ino = row->ino;
        key.pid = row->pid;
        key.type = row->type;
        key.method = row->method;
        key.remote = row->remote;

        const size_t *offset = ft_table_find(b->merged, &key);
        /* Bytes sent under another name of the remote end are a record of their own. */
        if (offset && same_name(row_at(b, *offset), name, row->name_source)) {
            struct ft_row_event *sum = row_at(b, *offset);
            sum->bytes += row->bytes;
            sum->read_bytes += row->read_bytes;
            sum->time_ns = row->time_ns;
            /* The latest record knows best how sure the association is. */
            sum->confidence = row->confidence;
            sum->flags = (uint8_t)((row->flags & ~FT_EVENT_PROCESS_TEXT) |
                                   (sum->flags & FT_EVENT_PROCESS_TEXT));
            return true;
        }
    }
    if (b->count == b->max_records || b->estimate + RECORD_OVERHEAD + size > MAX_BATCH_BYTES)
        return false;

    if (b->rows_len + size > b->rows_cap) {
        size_t cap = b->rows_cap ? b->rows_cap : 16384;
        while (cap < b->rows_len + size)
            cap *= 2;
        unsigned char *grown = realloc(b->rows, cap);
        if (!grown)
            return false;
        b->rows = grown;
        b->rows_cap = cap;
    }
    struct ft_row_event *stored = row_at(b, b->rows_len);
    memset(stored, 0, size);
    memcpy(stored, row, offsetof(struct ft_row_event, text) + text_len);
    stored->flags &= (uint8_t)~FT_EVENT_PROCESS_TEXT;
    if (with_strings) {
        ft_process_strings_pack(stored->text + text_len + 1, strings_size, &strings);
        stored->flags |= FT_EVENT_PROCESS_TEXT;
    }
    ft_row_event_set_name(stored, (enum ft_name_source)row->name_source, name);

    if (carries_bytes(row)) {
        size_t *offset = ft_table_insert(b->merged, &key, nullptr);
        *offset = b->rows_len;
    }
    b->rows_len += size;
    b->estimate += RECORD_OVERHEAD + size;
    b->count++;
    return true;
}

static void attr_endpoint(struct attrs *l, const char *address_key, const char *port_key,
                          const struct ft_endpoint *ep)
{
    char address[64];

    if (ep->family) {
        ft_addr_format(ep, address, sizeof(address));
        attr_string(l, address_key, address);
    }
    if (ep->port)
        attr_int(l, port_key, ep->port);
}

static void describe(struct attrs *l, const struct ft_row_event *e)
{
    const char *type = ft_record_type_name((enum ft_record_type)e->type);
    char text[32];

    attr_string(l, FT_ATTR_EVENT_TYPE, type);

    if (e->pid) {
        attr_int(l, FT_ATTR_PROCESS_PID, e->pid);
        if (e->ppid)
            attr_int(l, FT_ATTR_PROCESS_PARENT_PID, e->ppid);
        if (e->comm[0]) {
            attr_string(l, FT_ATTR_PROCESS_NAME, e->comm);
            attr_int(l, FT_ATTR_PROCESS_USER_ID, e->uid);
        }
    }
    if (about_process(e) && e->text[0])
        attr_string(l, FT_ATTR_PROCESS_PATH, e->text);
    if (e->flags & FT_EVENT_PROCESS_TEXT) {
        struct ft_process_strings s;
        ft_row_event_strings(e, &s);
        if (s.command_line[0])
            attr_string(l, FT_ATTR_PROCESS_COMMAND_LINE, s.command_line);
        if (s.cwd[0])
            attr_string(l, FT_ATTR_PROCESS_WORKING_DIRECTORY, s.cwd);
        if (s.script[0])
            attr_string(l, FT_ATTR_PROCESS_SCRIPT, s.script);
    }
    if (e->type == FT_REC_PROCESS_EXIT) {
        if (WIFSIGNALED(e->exit_status))
            attr_int(l, FT_ATTR_PROCESS_EXIT_SIGNAL, (uint64_t)WTERMSIG(e->exit_status));
        else
            attr_int(l, FT_ATTR_PROCESS_EXIT_CODE, (uint64_t)WEXITSTATUS(e->exit_status));
    }

    if (about_file(e)) {
        if (e->text[0])
            attr_string(l, FT_ATTR_FILE_PATH, e->text);
        snprintf(text, sizeof(text), "%llu", (unsigned long long)e->ino);
        attr_string(l, FT_ATTR_FILE_INODE, text);
        attr_int(l, FT_ATTR_FILE_DEVICE, e->dev);
        attr_int(l, FT_ATTR_FILE_SIZE, e->file_size);
        if (e->flags & FT_EVENT_FILE_DELETED)
            attr_bool(l, FT_ATTR_FILE_DELETED, true);
    }

    if (e->sock_id) {
        uint8_t family = e->remote.family ? e->remote.family : e->local.family;

        attr_int(l, FT_ATTR_SOCKET_ID, e->sock_id);
        attr_string(l, FT_ATTR_NETWORK_TRANSPORT, ft_proto_name(e->proto, text));
        if (family)
            attr_string(l, FT_ATTR_NETWORK_TYPE, family == 6 ? "ipv6" : "ipv4");
        attr_endpoint(l, FT_ATTR_NETWORK_LOCAL_ADDRESS, FT_ATTR_NETWORK_LOCAL_PORT, &e->local);
        attr_endpoint(l, FT_ATTR_NETWORK_PEER_ADDRESS, FT_ATTR_NETWORK_PEER_PORT, &e->remote);

        const char *name = ft_row_event_name(e);
        if (name[0]) {
            attr_string(l, FT_ATTR_SERVER_ADDRESS, name);
            attr_string(l, FT_ATTR_SERVER_ADDRESS_SOURCE,
                        ft_name_source_name((enum ft_name_source)e->name_source));
        }
    }

    switch (e->type) {
    case FT_REC_NETWORK_SEND:
    case FT_REC_NETWORK_RECEIVE:
        attr_string(l, FT_ATTR_NETWORK_DIRECTION,
                    e->type == FT_REC_NETWORK_SEND ? "transmit" : "receive");
        attr_int(l, FT_ATTR_NETWORK_BYTES, e->bytes);
        break;
    case FT_REC_FILE_TRANSFER:
        attr_string(l, FT_ATTR_TRANSFER_METHOD, ft_method_name((enum ft_method)e->method));
        attr_int(l, FT_ATTR_TRANSFER_BYTES, e->bytes);
        if (e->method == FT_METHOD_READ_SEND)
            attr_int(l, FT_ATTR_TRANSFER_BYTES_READ, e->read_bytes);
        if (e->flags & FT_EVENT_HAS_CONFIDENCE)
            attr_string(l, FT_ATTR_TRANSFER_CONFIDENCE,
                        ft_confidence_name((enum ft_confidence)e->confidence));
        break;
    case FT_REC_EVENT_LOSS:
        attr_int(l, FT_ATTR_LOSS_EVENTS, e->bytes);
        attr_string(l, FT_ATTR_LOSS_KIND, ft_loss_kind_label((enum ft_loss_kind)e->loss_kind));
        break;
    default:
        break;
    }
}

static LogRecord *make_record(struct ft_arena *a, const struct ft_row_event *e,
                              uint64_t now_wall_ns)
{
    const char *type = ft_record_type_name((enum ft_record_type)e->type);
    LogRecord *record = ft_arena_alloc(a, sizeof(*record));
    AnyValue *body = ft_arena_alloc(a, sizeof(*body));
    char name[48];

    if (!record || !body)
        return nullptr;
    opentelemetry__proto__logs__v1__log_record__init(record);
    opentelemetry__proto__common__v1__any_value__init(body);

    bool loss = e->type == FT_REC_EVENT_LOSS;
    record->time_unix_nano = e->time_ns;
    record->observed_time_unix_nano = now_wall_ns;
    record->severity_number =
        loss ? OPENTELEMETRY__PROTO__LOGS__V1__SEVERITY_NUMBER__SEVERITY_NUMBER_WARN
             : OPENTELEMETRY__PROTO__LOGS__V1__SEVERITY_NUMBER__SEVERITY_NUMBER_INFO;
    record->severity_text = text_of(loss ? "WARN" : "INFO");
    snprintf(name, sizeof(name), "filetrace.%s", type);
    record->event_name = ft_arena_text(a, name);
    body->value_case = OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    body->string_value = text_of(type);
    record->body = body;

    struct attrs l = attrs_begin(a, MAX_ATTRS);
    describe(&l, e);
    record->attributes = l.items;
    record->n_attributes = l.count;
    return record;
}

uint8_t *ft_otlp_logs_encode(struct ft_otlp_logs *b, const struct ft_metric_attr *resource,
                             size_t resource_count, uint64_t now_wall_ns, size_t *size)
{
    struct ft_arena a = {0};
    LogsRequest request;
    ResourceLogs resource_logs;
    ResourceLogs *resource_list[1] = {&resource_logs};
    ScopeLogs scope_logs;
    ScopeLogs *scope_list[1] = {&scope_logs};
    uint8_t *out = nullptr;

    opentelemetry__proto__collector__logs__v1__export_logs_service_request__init(&request);
    opentelemetry__proto__logs__v1__resource_logs__init(&resource_logs);
    opentelemetry__proto__logs__v1__scope_logs__init(&scope_logs);
    request.resource_logs = resource_list;
    request.n_resource_logs = 1;
    resource_logs.resource = make_resource(&a, resource, resource_count);
    resource_logs.scope_logs = scope_list;
    resource_logs.n_scope_logs = 1;
    scope_logs.scope = make_scope(&a);
    scope_logs.log_records = ft_arena_alloc(&a, (b->count ? b->count : 1) * sizeof(LogRecord *));

    for (size_t offset = 0; offset < b->rows_len && scope_logs.log_records;) {
        const struct ft_row_event *row = row_at(b, offset);
        LogRecord *record = make_record(&a, row, now_wall_ns);

        if (record)
            scope_logs.log_records[scope_logs.n_log_records++] = record;
        offset += stored_size(ft_row_event_size(row) - offsetof(struct ft_row_event, text));
    }

    if (!a.failed) {
        *size =
            opentelemetry__proto__collector__logs__v1__export_logs_service_request__get_packed_size(
                &request);
        out = malloc(*size ? *size : 1);
        if (out)
            opentelemetry__proto__collector__logs__v1__export_logs_service_request__pack(&request,
                                                                                         out);
    }
    ft_arena_release(&a);
    ft_table_clear(b->merged);
    b->rows_len = 0;
    b->count = 0;
    b->estimate = 0;
    return out;
}

struct ft_otlp_metrics {
    struct ft_arena arena;
    uint64_t start_wall_ns;
    uint64_t now_wall_ns;
    Metric **metrics;
    size_t metric_count;
    size_t metric_cap;
    const struct ft_metric *current;
    NumberDataPoint **points; /* of the metric being filled */
    size_t point_count;
    size_t point_cap;
};

struct ft_otlp_metrics *ft_otlp_metrics_new(uint64_t start_wall_ns, uint64_t now_wall_ns)
{
    struct ft_otlp_metrics *m = calloc(1, sizeof(*m));
    if (!m)
        return nullptr;
    m->start_wall_ns = start_wall_ns;
    m->now_wall_ns = now_wall_ns;
    return m;
}

/* Appends to an array of pointers that doubles when full. */
static bool push(void ***items, size_t *count, size_t *cap, void *item)
{
    if (*count == *cap) {
        size_t grown_cap = *cap ? *cap * 2 : 16;
        void **grown = realloc(*items, grown_cap * sizeof(void *));
        if (!grown)
            return false;
        *items = grown;
        *cap = grown_cap;
    }
    (*items)[(*count)++] = item;
    return true;
}

/* Hands the collected points to the metric they belong to. */
static void close_metric(struct ft_otlp_metrics *m)
{
    if (!m->current || m->metric_count == 0)
        return;
    Metric *metric = m->metrics[m->metric_count - 1];
    NumberDataPoint **points = ft_arena_alloc(&m->arena, (m->point_count + 1) * sizeof(*points));

    if (!points)
        return;
    if (m->point_count)
        memcpy(points, m->points, m->point_count * sizeof(*points));
    if (metric->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
        metric->sum->data_points = points;
        metric->sum->n_data_points = m->point_count;
    } else {
        metric->gauge->data_points = points;
        metric->gauge->n_data_points = m->point_count;
    }
    m->point_count = 0;
}

static void open_metric(struct ft_otlp_metrics *m, const struct ft_metric *def)
{
    Metric *metric = ft_arena_alloc(&m->arena, sizeof(*metric));
    Sum *sum = ft_arena_alloc(&m->arena, sizeof(*sum));
    Gauge *gauge = ft_arena_alloc(&m->arena, sizeof(*gauge));

    m->current = nullptr;
    if (!metric || !sum || !gauge)
        return;
    opentelemetry__proto__metrics__v1__metric__init(metric);
    metric->name = text_of(def->name);
    metric->unit = text_of(def->unit);
    metric->description = text_of(def->description);
    if (def->monotonic) {
        opentelemetry__proto__metrics__v1__sum__init(sum);
        sum->is_monotonic = true;
        sum->aggregation_temporality =
            OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE;
        metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM;
        metric->sum = sum;
    } else {
        opentelemetry__proto__metrics__v1__gauge__init(gauge);
        metric->data_case = OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE;
        metric->gauge = gauge;
    }
    if (!push((void ***)&m->metrics, &m->metric_count, &m->metric_cap, metric)) {
        m->arena.failed = true;
        return;
    }
    m->current = def;
}

void ft_otlp_metrics_point(void *ctx, const struct ft_metric_point *pt)
{
    struct ft_otlp_metrics *m = ctx;

    if (pt->metric != m->current) {
        close_metric(m);
        open_metric(m, pt->metric);
        if (!m->current)
            return;
    }
    NumberDataPoint *point = ft_arena_alloc(&m->arena, sizeof(*point));
    if (!point)
        return;
    opentelemetry__proto__metrics__v1__number_data_point__init(point);
    point->time_unix_nano = m->now_wall_ns;
    if (pt->metric->monotonic)
        point->start_time_unix_nano = m->start_wall_ns;
    if (pt->metric->real) {
        point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_DOUBLE;
        point->as_double = pt->real;
    } else {
        point->value_case = OPENTELEMETRY__PROTO__METRICS__V1__NUMBER_DATA_POINT__VALUE_AS_INT;
        point->as_int = (int64_t)pt->value;
    }

    struct attrs l = attrs_begin(&m->arena, pt->attr_count);
    for (size_t i = 0; i < pt->attr_count; i++)
        attr_string(&l, pt->attrs[i].key, pt->attrs[i].value);
    point->attributes = l.items;
    point->n_attributes = l.count;

    if (!push((void ***)&m->points, &m->point_count, &m->point_cap, point))
        m->arena.failed = true;
}

uint8_t *ft_otlp_metrics_encode(struct ft_otlp_metrics *m, const struct ft_metric_attr *resource,
                                size_t resource_count, size_t *size)
{
    MetricsRequest request;
    ResourceMetrics resource_metrics;
    ResourceMetrics *resource_list[1] = {&resource_metrics};
    ScopeMetrics scope_metrics;
    ScopeMetrics *scope_list[1] = {&scope_metrics};
    uint8_t *out = nullptr;

    close_metric(m);
    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__init(&request);
    opentelemetry__proto__metrics__v1__resource_metrics__init(&resource_metrics);
    opentelemetry__proto__metrics__v1__scope_metrics__init(&scope_metrics);
    request.resource_metrics = resource_list;
    request.n_resource_metrics = 1;
    resource_metrics.resource = make_resource(&m->arena, resource, resource_count);
    resource_metrics.scope_metrics = scope_list;
    resource_metrics.n_scope_metrics = 1;
    scope_metrics.scope = make_scope(&m->arena);
    scope_metrics.metrics = m->metrics;
    scope_metrics.n_metrics = m->metric_count;

    if (!m->arena.failed) {
        *size =
            opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__get_packed_size(
                &request);
        out = malloc(*size ? *size : 1);
        if (out)
            opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__pack(
                &request, out);
    }
    ft_arena_release(&m->arena);
    free(m->metrics);
    free(m->points);
    free(m);
    return out;
}

uint64_t ft_otlp_logs_rejected(const uint8_t *reply, size_t size, char *why, size_t why_size)
{
    LogsResponse *response =
        opentelemetry__proto__collector__logs__v1__export_logs_service_response__unpack(
            nullptr, size, reply);
    uint64_t rejected = 0;

    why[0] = '\0';
    if (response && response->partial_success) {
        int64_t n = response->partial_success->rejected_log_records;
        rejected = n > 0 ? (uint64_t)n : 0;
        ft_strlcpy(why, response->partial_success->error_message, why_size);
    }
    if (response)
        opentelemetry__proto__collector__logs__v1__export_logs_service_response__free_unpacked(
            response, nullptr);
    return rejected;
}

uint64_t ft_otlp_metrics_rejected(const uint8_t *reply, size_t size, char *why, size_t why_size)
{
    MetricsResponse *response =
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_response__unpack(
            nullptr, size, reply);
    uint64_t rejected = 0;

    why[0] = '\0';
    if (response && response->partial_success) {
        int64_t n = response->partial_success->rejected_data_points;
        rejected = n > 0 ? (uint64_t)n : 0;
        ft_strlcpy(why, response->partial_success->error_message, why_size);
    }
    if (response)
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_response__free_unpacked(
            response, nullptr);
    return rejected;
}
