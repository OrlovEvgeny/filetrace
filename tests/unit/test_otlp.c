#include "unit/test.h"

#include "exporters/otlp.h"
#include "filetrace/schema.h"
#include "filetrace/state.h"

#include "opentelemetry/proto/collector/logs/v1/logs_service.pb-c.h"
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb-c.h"

#include <stdlib.h>

typedef Opentelemetry__Proto__Common__V1__KeyValue KeyValue;
typedef Opentelemetry__Proto__Logs__V1__LogRecord LogRecord;
typedef Opentelemetry__Proto__Metrics__V1__Metric Metric;
typedef Opentelemetry__Proto__Metrics__V1__NumberDataPoint NumberDataPoint;
typedef Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest LogsRequest;
typedef Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest MetricsRequest;

static const struct ft_metric_attr resource[] = {
    {FT_ATTR_SERVICE_NAME, "filetrace"},
    {FT_ATTR_HOST_NAME, "web-01"},
};

static const KeyValue *find(KeyValue *const *attrs, size_t count, const char *key)
{
    for (size_t i = 0; i < count; i++) {
        if (strcmp(attrs[i]->key, key) == 0)
            return attrs[i];
    }
    return nullptr;
}

static const char *text(const LogRecord *r, const char *key)
{
    const KeyValue *kv = find(r->attributes, r->n_attributes, key);
    bool is_text = kv && kv->value->value_case ==
                             OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_STRING_VALUE;
    return is_text ? kv->value->string_value : "(absent)";
}

static int64_t number(const LogRecord *r, const char *key)
{
    const KeyValue *kv = find(r->attributes, r->n_attributes, key);
    bool is_number =
        kv && kv->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_INT_VALUE;
    return is_number ? kv->value->int_value : -1;
}

static struct ft_row_event *transfer_row(uint64_t bytes, uint64_t time_ns)
{
    static const uint8_t remote[16] = {203, 0, 113, 25};
    static const uint8_t local[16] = {10, 0, 0, 10};
    struct ft_row_event *row = calloc(1, sizeof(*row));

    row->type = FT_REC_FILE_TRANSFER;
    row->time_ns = time_ns;
    row->sock_id = 421;
    row->pid = 1245;
    row->ppid = 1;
    row->uid = 33;
    row->dev = 2049;
    row->ino = 182934;
    row->file_size = 50000000;
    row->bytes = bytes;
    row->proto = FT_PROTO_TCP;
    row->method = FT_METHOD_SENDFILE;
    row->confidence = FT_CONF_EXACT;
    row->flags = FT_EVENT_HAS_CONFIDENCE;
    ft_endpoint_set(&row->local, false, local, 443);
    ft_endpoint_set(&row->remote, false, remote, 51822);
    ft_strlcpy(row->comm, "nginx", sizeof(row->comm));
    ft_strlcpy(row->text, "/data/report.pdf", sizeof(row->text));
    return row;
}

static LogsRequest *encode(struct ft_otlp_logs *batch)
{
    size_t size = 0;
    uint8_t *bytes = ft_otlp_logs_encode(batch, resource, FT_ARRAY_LEN(resource), 9000, &size);
    CHECK(bytes != nullptr);
    LogsRequest *request =
        opentelemetry__proto__collector__logs__v1__export_logs_service_request__unpack(nullptr,
                                                                                       size, bytes);
    free(bytes);
    CHECK(request != nullptr);
    return request;
}

static void release(LogsRequest *request)
{
    opentelemetry__proto__collector__logs__v1__export_logs_service_request__free_unpacked(request,
                                                                                          nullptr);
}

static void describes_a_transfer_with_standard_names(void)
{
    struct ft_otlp_logs *batch = ft_otlp_logs_new(16, true, false, true);
    struct ft_row_event *row = transfer_row(8192, 1000);

    CHECK(ft_otlp_logs_add(batch, row));
    LogsRequest *request = encode(batch);
    CHECK_U64(ft_otlp_logs_count(batch), 0);
    CHECK_U64(request->n_resource_logs, 1);

    const Opentelemetry__Proto__Logs__V1__ResourceLogs *logs = request->resource_logs[0];
    CHECK_U64(logs->resource->n_attributes, 2);
    CHECK_STR(logs->resource->attributes[1]->key, "host.name");
    CHECK_STR(logs->resource->attributes[1]->value->string_value, "web-01");
    CHECK_STR(logs->scope_logs[0]->scope->name, "filetrace");
    CHECK_STR(logs->scope_logs[0]->scope->version, FT_VERSION);
    CHECK_U64(logs->scope_logs[0]->n_log_records, 1);

    const LogRecord *r = logs->scope_logs[0]->log_records[0];
    CHECK_U64(r->time_unix_nano, 1000);
    CHECK_U64(r->observed_time_unix_nano, 9000);
    CHECK_STR(r->event_name, "filetrace.file_transfer");
    CHECK_STR(r->severity_text, "INFO");
    CHECK_STR(r->body->string_value, "file_transfer");
    CHECK_STR(text(r, "filetrace.event.type"), "file_transfer");
    CHECK_U64(number(r, "process.pid"), 1245);
    CHECK_U64(number(r, "process.parent_pid"), 1);
    CHECK_U64(number(r, "process.user.id"), 33);
    CHECK_STR(text(r, "process.executable.name"), "nginx");
    CHECK_STR(text(r, "file.path"), "/data/report.pdf");
    CHECK_STR(text(r, "file.inode"), "182934");
    CHECK_U64(number(r, "file.size"), 50000000);
    CHECK_U64(number(r, "filetrace.file.device"), 2049);
    CHECK_U64(number(r, "filetrace.socket.id"), 421);
    CHECK_STR(text(r, "network.transport"), "tcp");
    CHECK_STR(text(r, "network.type"), "ipv4");
    CHECK_STR(text(r, "network.peer.address"), "203.0.113.25");
    CHECK_U64(number(r, "network.peer.port"), 51822);
    CHECK_STR(text(r, "network.local.address"), "10.0.0.10");
    CHECK_U64(number(r, "network.local.port"), 443);
    CHECK_STR(text(r, "filetrace.transfer.method"), "sendfile");
    CHECK_STR(text(r, "filetrace.transfer.confidence"), "exact");
    CHECK_U64(number(r, "filetrace.transfer.bytes"), 8192);
    CHECK_STR(text(r, "filetrace.transfer.bytes_read"), "(absent)");

    release(request);
    ft_otlp_logs_free(batch);
    free(row);
}

static void sums_the_parts_of_one_transfer(void)
{
    struct ft_otlp_logs *batch = ft_otlp_logs_new(16, true, false, true);
    struct ft_row_event *row = transfer_row(1000, 100);

    row->method = FT_METHOD_READ_SEND;
    row->read_bytes = 1500;
    row->flags = 0;
    CHECK(ft_otlp_logs_add(batch, row));

    row->bytes = 2000;
    row->read_bytes = 2500;
    row->time_ns = 200;
    row->confidence = FT_CONF_INFERRED;
    row->flags = FT_EVENT_HAS_CONFIDENCE;
    CHECK(ft_otlp_logs_add(batch, row));

    /* The same file on another socket is another transfer. */
    row->sock_id = 422;
    row->bytes = 7;
    CHECK(ft_otlp_logs_add(batch, row));

    /* Events that carry no bytes are never joined. */
    struct ft_row_event *loss = calloc(1, sizeof(*loss));
    loss->type = FT_REC_EVENT_LOSS;
    loss->bytes = 12;
    loss->loss_kind = FT_LOSS_EVENT_QUEUE;
    CHECK(ft_otlp_logs_add(batch, loss));
    CHECK(ft_otlp_logs_add(batch, loss));
    CHECK_U64(ft_otlp_logs_count(batch), 4);

    LogsRequest *request = encode(batch);
    const Opentelemetry__Proto__Logs__V1__ScopeLogs *scope =
        request->resource_logs[0]->scope_logs[0];
    CHECK_U64(scope->n_log_records, 4);

    const LogRecord *r = scope->log_records[0];
    CHECK_U64(r->time_unix_nano, 200);
    CHECK_U64(number(r, "filetrace.transfer.bytes"), 3000);
    CHECK_U64(number(r, "filetrace.transfer.bytes_read"), 4000);
    CHECK_STR(text(r, "filetrace.transfer.method"), "read-write");
    CHECK_STR(text(r, "filetrace.transfer.confidence"), "inferred");
    CHECK_U64(number(scope->log_records[1], "filetrace.transfer.bytes"), 7);

    r = scope->log_records[2];
    CHECK_STR(r->event_name, "filetrace.event_loss");
    CHECK_STR(r->severity_text, "WARN");
    CHECK_U64(number(r, "filetrace.loss.events"), 12);
    CHECK_STR(text(r, "filetrace.loss.kind"), "event_queue");

    release(request);
    ft_otlp_logs_free(batch);
    free(row);
    free(loss);
}

static void leaves_paths_out_on_request_and_keeps_text_valid(void)
{
    struct ft_otlp_logs *hidden = ft_otlp_logs_new(16, false, false, true);
    struct ft_otlp_logs *shown = ft_otlp_logs_new(16, true, false, true);
    struct ft_row_event *row = transfer_row(10, 1);

    ft_strlcpy(row->text, "/data/caf\xe9.pdf", sizeof(row->text));
    CHECK(ft_otlp_logs_add(hidden, row));
    CHECK(ft_otlp_logs_add(shown, row));

    LogsRequest *request = encode(hidden);
    const LogRecord *r = request->resource_logs[0]->scope_logs[0]->log_records[0];
    CHECK_STR(text(r, "file.path"), "(absent)");
    CHECK_STR(text(r, "file.inode"), "182934");
    release(request);

    /* A byte that is not UTF-8 would make a collector refuse the whole request. */
    request = encode(shown);
    r = request->resource_logs[0]->scope_logs[0]->log_records[0];
    CHECK_STR(text(r, "file.path"), "/data/caf?.pdf");
    release(request);

    ft_otlp_logs_free(hidden);
    ft_otlp_logs_free(shown);
    free(row);
}

static void refuses_more_than_a_batch_holds(void)
{
    struct ft_otlp_logs *batch = ft_otlp_logs_new(2, true, false, true);
    struct ft_row_event *row = transfer_row(10, 1);

    CHECK(ft_otlp_logs_add(batch, row));
    row->sock_id++;
    CHECK(ft_otlp_logs_add(batch, row));
    row->sock_id++;
    CHECK(!ft_otlp_logs_add(batch, row));
    /* What is already in the batch still takes its bytes. */
    row->sock_id--;
    CHECK(ft_otlp_logs_add(batch, row));
    CHECK_U64(ft_otlp_logs_count(batch), 2);

    ft_otlp_logs_free(batch);
    free(row);
}

static const Metric *metric_named(const MetricsRequest *request, const char *name)
{
    const Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope =
        request->resource_metrics[0]->scope_metrics[0];

    for (size_t i = 0; i < scope->n_metrics; i++) {
        if (strcmp(scope->metrics[i]->name, name) == 0)
            return scope->metrics[i];
    }
    return nullptr;
}

static void encodes_counters_as_cumulative_sums(void)
{
    struct ft_state_config cfg;
    struct ft_row_stats stats = {.rss_bytes = 4096, .open_sockets = 3};

    ft_state_config_defaults(&cfg);
    struct ft_state *st = ft_state_create(&cfg);
    ft_series_add(st->series, FT_SERIES_NETWORK_IO, "nginx", FT_PROTO_TCP, FT_DIR_TRANSMIT, 700);
    ft_series_add(st->series, FT_SERIES_NETWORK_IO, "nginx", FT_PROTO_TCP, FT_DIR_RECEIVE, 50);

    struct ft_metrics_input in = {.series = st->series, .stats = &stats, .cpu_ns = 250'000'000};
    struct ft_otlp_metrics *m = ft_otlp_metrics_new(1000, 2000);
    ft_metrics_collect(&in, ft_otlp_metrics_point, m);
    size_t size = 0;
    uint8_t *bytes = ft_otlp_metrics_encode(m, resource, FT_ARRAY_LEN(resource), &size);
    CHECK(bytes != nullptr);
    MetricsRequest *request =
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
            nullptr, size, bytes);
    free(bytes);
    CHECK(request != nullptr);
    CHECK_STR(request->resource_metrics[0]->resource->attributes[0]->key, "service.name");

    const Metric *io = metric_named(request, "filetrace.network.io");
    CHECK(io && io->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM);
    if (io && io->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_SUM) {
        CHECK_STR(io->unit, "By");
        CHECK(io->sum->is_monotonic);
        CHECK_U64(
            io->sum->aggregation_temporality,
            OPENTELEMETRY__PROTO__METRICS__V1__AGGREGATION_TEMPORALITY__AGGREGATION_TEMPORALITY_CUMULATIVE);
        CHECK_U64(io->sum->n_data_points, 2);
        uint64_t total = 0;
        for (size_t i = 0; i < io->sum->n_data_points; i++) {
            const NumberDataPoint *pt = io->sum->data_points[i];
            const KeyValue *process =
                find(pt->attributes, pt->n_attributes, "process.executable.name");
            CHECK_U64(pt->start_time_unix_nano, 1000);
            CHECK_U64(pt->time_unix_nano, 2000);
            CHECK_U64(pt->n_attributes, 3);
            CHECK(process && strcmp(process->value->string_value, "nginx") == 0);
            total += (uint64_t)pt->as_int;
        }
        CHECK_U64(total, 750);
    }

    const Metric *connections = metric_named(request, "filetrace.connections.active");
    CHECK(connections &&
          connections->data_case == OPENTELEMETRY__PROTO__METRICS__V1__METRIC__DATA_GAUGE);
    if (connections) {
        CHECK_U64(connections->gauge->n_data_points, 1);
        CHECK_U64(connections->gauge->data_points[0]->as_int, 3);
        CHECK_U64(connections->gauge->data_points[0]->start_time_unix_nano, 0);
    }

    const Metric *cpu = metric_named(request, "process.cpu.time");
    CHECK(cpu && cpu->sum->data_points[0]->as_double == 0.25);
    CHECK(metric_named(request, "filetrace.file.sent") == nullptr);
    CHECK(metric_named(request, "filetrace.events.dropped") != nullptr);

    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(
        request, nullptr);
    ft_state_destroy(st);
}

static void set_strings(struct ft_row_event *row, const char *command_line, const char *cwd,
                        const char *script)
{
    struct ft_process_strings text = {command_line, cwd, script};
    size_t lead = strlen(row->text) + 1;
    ft_process_strings_pack(row->text + lead, sizeof(row->text) - lead, &text);
    row->flags |= FT_EVENT_PROCESS_TEXT;
}

static const LogRecord *only_record(LogsRequest *request)
{
    const Opentelemetry__Proto__Logs__V1__ScopeLogs *scope =
        request->resource_logs[0]->scope_logs[0];
    CHECK_U64(scope->n_log_records, 1);
    return scope->log_records[0];
}

/* Arguments leave only when asked for; the directory and script stay with the paths. */
static void says_what_a_process_runs(void)
{
    struct ft_otlp_logs *quiet = ft_otlp_logs_new(16, true, false, true);
    struct ft_otlp_logs *full = ft_otlp_logs_new(16, true, true, true);
    struct ft_otlp_logs *pathless = ft_otlp_logs_new(16, false, true, true);
    struct ft_row_event *row = transfer_row(10, 1);

    set_strings(row, "python3 export.py --token=abc", "/srv/app", "/srv/app/export.py");
    CHECK(ft_otlp_logs_add(quiet, row));
    CHECK(ft_otlp_logs_add(full, row));
    CHECK(ft_otlp_logs_add(pathless, row));

    LogsRequest *request = encode(quiet);
    const LogRecord *r = only_record(request);
    CHECK_STR(text(r, "process.command_line"), "(absent)");
    CHECK_STR(text(r, "process.working_directory"), "/srv/app");
    CHECK_STR(text(r, "filetrace.process.script"), "/srv/app/export.py");
    CHECK_STR(text(r, "file.path"), "/data/report.pdf");
    release(request);

    request = encode(full);
    r = only_record(request);
    CHECK_STR(text(r, "process.command_line"), "python3 export.py --token=abc");
    release(request);

    request = encode(pathless);
    r = only_record(request);
    CHECK_STR(text(r, "process.command_line"), "python3 export.py --token=abc");
    CHECK_STR(text(r, "process.working_directory"), "(absent)");
    CHECK_STR(text(r, "filetrace.process.script"), "(absent)");
    CHECK_STR(text(r, "file.path"), "(absent)");
    release(request);

    /* A pool is no path. */
    free(row);
    row = transfer_row(10, 1);
    set_strings(row, "php-fpm: pool site1", "/", "pool:site1");
    CHECK(ft_otlp_logs_add(pathless, row));
    request = encode(pathless);
    CHECK_STR(text(only_record(request), "filetrace.process.script"), "pool:site1");
    release(request);

    ft_otlp_logs_free(quiet);
    ft_otlp_logs_free(full);
    ft_otlp_logs_free(pathless);
    free(row);
}

/* The parts of a transfer are summed into the record that came first, strings and all. */
static void sums_keep_the_first_strings(void)
{
    struct ft_otlp_logs *batch = ft_otlp_logs_new(16, true, true, true);
    struct ft_row_event *bare = transfer_row(10, 1);
    struct ft_row_event *described = transfer_row(20, 2);

    set_strings(described, "python3 export.py", "/srv/app", "/srv/app/export.py");
    CHECK(ft_otlp_logs_add(batch, bare));
    CHECK(ft_otlp_logs_add(batch, described));
    described->sock_id++;
    CHECK(ft_otlp_logs_add(batch, described));
    bare->sock_id = described->sock_id;
    CHECK(ft_otlp_logs_add(batch, bare));
    described->sock_id++;
    CHECK(ft_otlp_logs_add(batch, described));

    LogsRequest *request = encode(batch);
    const Opentelemetry__Proto__Logs__V1__ScopeLogs *scope =
        request->resource_logs[0]->scope_logs[0];
    CHECK_U64(scope->n_log_records, 3);
    if (scope->n_log_records == 3) {
        CHECK_U64(number(scope->log_records[0], "filetrace.transfer.bytes"), 30);
        CHECK_STR(text(scope->log_records[0], "process.command_line"), "(absent)");
        CHECK_U64(number(scope->log_records[1], "filetrace.transfer.bytes"), 30);
        CHECK_STR(text(scope->log_records[1], "process.command_line"), "python3 export.py");
        CHECK_STR(text(scope->log_records[2], "filetrace.process.script"), "/srv/app/export.py");
    }
    release(request);
    ft_otlp_logs_free(batch);
    free(bare);
    free(described);
}

/* Whatever the length of the strings before it, a record's name does not run into the next. */
static void keeps_named_records_apart(void)
{
    for (size_t at = 0; at < 32; at++) {
        bool names = at >= 16;
        size_t len = at % 16 + 1;
        struct ft_otlp_logs *batch = ft_otlp_logs_new(16, true, false, names);
        struct ft_row_event *row = transfer_row(10, 1);

        row->seq = 0x4141414141414141;
        memset(row->text, 'a', len);
        row->text[len] = '\0';
        ft_row_event_set_name(row, FT_NAME_SOURCE_LOOKUP, "files.example.com");
        for (uint64_t sock = 1; sock <= 3; sock++) {
            row->sock_id = sock;
            CHECK(ft_otlp_logs_add(batch, row));
        }
        LogsRequest *request = encode(batch);
        const Opentelemetry__Proto__Logs__V1__ScopeLogs *scope =
            request->resource_logs[0]->scope_logs[0];
        CHECK_U64(scope->n_log_records, 3);
        for (size_t i = 0; i < scope->n_log_records; i++) {
            const LogRecord *r = scope->log_records[i];
            CHECK_STR(r->event_name, "filetrace.file_transfer");
            CHECK_U64(number(r, "filetrace.socket.id"), i + 1);
            CHECK_STR(text(r, "server.address"), names ? "files.example.com" : "(absent)");
        }
        release(request);
        ft_otlp_logs_free(batch);
        free(row);
    }
}

/* The name the process used goes with its socket, network and transfer records. */
static void names_the_remote_end(void)
{
    static const enum ft_record_type types[] = {FT_REC_SOCKET_CONNECT, FT_REC_NETWORK_SEND,
                                                FT_REC_FILE_TRANSFER};
    struct ft_otlp_logs *batch = ft_otlp_logs_new(16, true, false, true);
    struct ft_row_event *row = transfer_row(10, 1);

    ft_row_event_set_name(row, FT_NAME_SOURCE_LOOKUP_TLS, "files.example.com");
    for (size_t i = 0; i < FT_ARRAY_LEN(types); i++) {
        row->type = (uint8_t)types[i];
        CHECK(ft_otlp_logs_add(batch, row));
    }
    LogsRequest *request = encode(batch);
    const Opentelemetry__Proto__Logs__V1__ScopeLogs *scope =
        request->resource_logs[0]->scope_logs[0];
    CHECK_U64(scope->n_log_records, FT_ARRAY_LEN(types));
    for (size_t i = 0; i < scope->n_log_records; i++) {
        const LogRecord *r = scope->log_records[i];
        CHECK_STR(text(r, "server.address"), "files.example.com");
        CHECK_STR(text(r, "filetrace.server.address.source"), "lookup+tls");
        CHECK_STR(text(r, "network.peer.address"), "203.0.113.25");
        CHECK_U64(number(r, "server.port"), -1);
    }
    release(request);

    /* Each source by its name; without a name, no attribute. */
    ft_row_event_set_name(row, FT_NAME_SOURCE_LOOKUP, "files.example.com");
    CHECK(ft_otlp_logs_add(batch, row));
    request = encode(batch);
    CHECK_STR(text(only_record(request), "filetrace.server.address.source"), "lookup");
    release(request);
    ft_row_event_set_name(row, FT_NAME_SOURCE_TLS, "files.example.com");
    CHECK(ft_otlp_logs_add(batch, row));
    request = encode(batch);
    CHECK_STR(text(only_record(request), "filetrace.server.address.source"), "tls");
    release(request);
    ft_row_event_set_name(row, FT_NAME_SOURCE_NONE, "");
    CHECK(ft_otlp_logs_add(batch, row));
    request = encode(batch);
    CHECK_STR(text(only_record(request), "server.address"), "(absent)");
    CHECK_STR(text(only_record(request), "filetrace.server.address.source"), "(absent)");
    release(request);

    ft_otlp_logs_free(batch);
    free(row);
}

static uint8_t *encode_one(struct ft_otlp_logs *batch, const struct ft_row_event *row, size_t *size)
{
    CHECK(ft_otlp_logs_add(batch, row));
    uint8_t *bytes = ft_otlp_logs_encode(batch, resource, FT_ARRAY_LEN(resource), 9000, size);
    CHECK(bytes != nullptr);
    return bytes;
}

/* Without names a record is encoded as one whose remote end has none. */
static void leaves_names_out_on_request(void)
{
    struct ft_otlp_logs *off = ft_otlp_logs_new(16, true, false, false);
    struct ft_otlp_logs *on = ft_otlp_logs_new(16, true, false, true);
    struct ft_row_event *named = transfer_row(10, 1);
    struct ft_row_event *bare = transfer_row(10, 1);
    size_t named_size = 0;
    size_t bare_size = 0;

    ft_row_event_set_name(named, FT_NAME_SOURCE_LOOKUP, "files.example.com");
    uint8_t *left_out = encode_one(off, named, &named_size);
    uint8_t *nameless = encode_one(on, bare, &bare_size);
    CHECK(named_size == bare_size && memcmp(left_out, nameless, bare_size) == 0);
    CHECK(memmem(left_out, named_size, "files.example.com", 17) == nullptr);
    free(left_out);
    free(nameless);

    ft_otlp_logs_free(off);
    ft_otlp_logs_free(on);
    free(named);
    free(bare);
}

/* Bytes sent once the remote end has another name are a record of their own. */
static void sums_under_one_name(void)
{
    struct ft_otlp_logs *batch = ft_otlp_logs_new(16, true, false, true);
    struct ft_otlp_logs *off = ft_otlp_logs_new(16, true, false, false);
    struct ft_row_event *row = transfer_row(10, 1);

    ft_row_event_set_name(row, FT_NAME_SOURCE_LOOKUP, "files.example.com");
    for (int i = 0; i < 4; i++) {
        if (i == 2)
            ft_row_event_set_name(row, FT_NAME_SOURCE_LOOKUP_TLS, "files.example.com");
        CHECK(ft_otlp_logs_add(batch, row));
        CHECK(ft_otlp_logs_add(off, row));
    }
    CHECK_U64(ft_otlp_logs_count(batch), 2);
    CHECK_U64(ft_otlp_logs_count(off), 1);

    LogsRequest *request = encode(batch);
    const Opentelemetry__Proto__Logs__V1__ScopeLogs *scope =
        request->resource_logs[0]->scope_logs[0];
    CHECK_U64(scope->n_log_records, 2);
    if (scope->n_log_records == 2) {
        CHECK_U64(number(scope->log_records[0], "filetrace.transfer.bytes"), 20);
        CHECK_STR(text(scope->log_records[0], "filetrace.server.address.source"), "lookup");
        CHECK_U64(number(scope->log_records[1], "filetrace.transfer.bytes"), 20);
        CHECK_STR(text(scope->log_records[1], "filetrace.server.address.source"), "lookup+tls");
    }
    release(request);
    request = encode(off);
    CHECK_U64(number(only_record(request), "filetrace.transfer.bytes"), 40);
    release(request);

    ft_otlp_logs_free(batch);
    ft_otlp_logs_free(off);
    free(row);
}

void test_otlp(void)
{
    describes_a_transfer_with_standard_names();
    sums_the_parts_of_one_transfer();
    leaves_paths_out_on_request_and_keeps_text_valid();
    refuses_more_than_a_batch_holds();
    encodes_counters_as_cumulative_sums();
    says_what_a_process_runs();
    sums_keep_the_first_strings();
    keeps_named_records_apart();
    names_the_remote_end();
    leaves_names_out_on_request();
    sums_under_one_name();
}
