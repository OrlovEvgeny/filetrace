#include "unit/test.h"

#include "agent/telemetry.h"
#include "exporters/otlp.h"
#include "filetrace/clock.h"
#include "filetrace/schema.h"
#include "filetrace/state.h"
#include "rpc/grpc.h"

#include "opentelemetry/proto/collector/logs/v1/logs_service.pb-c.h"
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb-c.h"

#include <stdlib.h>
#include <unistd.h>

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

    CHECK(ft_otlp_logs_add(batch, row, nullptr));
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
    CHECK(ft_otlp_logs_add(batch, row, nullptr));

    row->bytes = 2000;
    row->read_bytes = 2500;
    row->time_ns = 200;
    row->confidence = FT_CONF_INFERRED;
    row->flags = FT_EVENT_HAS_CONFIDENCE;
    CHECK(ft_otlp_logs_add(batch, row, nullptr));

    /* The same file on another socket is another transfer. */
    row->sock_id = 422;
    row->bytes = 7;
    CHECK(ft_otlp_logs_add(batch, row, nullptr));

    /* Events that carry no bytes are never joined. */
    struct ft_row_event *loss = calloc(1, sizeof(*loss));
    loss->type = FT_REC_EVENT_LOSS;
    loss->bytes = 12;
    loss->loss_kind = FT_LOSS_EVENT_QUEUE;
    CHECK(ft_otlp_logs_add(batch, loss, nullptr));
    CHECK(ft_otlp_logs_add(batch, loss, nullptr));
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
    CHECK(ft_otlp_logs_add(hidden, row, nullptr));
    CHECK(ft_otlp_logs_add(shown, row, nullptr));

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

    CHECK(ft_otlp_logs_add(batch, row, nullptr));
    row->sock_id++;
    CHECK(ft_otlp_logs_add(batch, row, nullptr));
    row->sock_id++;
    CHECK(!ft_otlp_logs_add(batch, row, nullptr));
    /* What is already in the batch still takes its bytes. */
    row->sock_id--;
    CHECK(ft_otlp_logs_add(batch, row, nullptr));
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
    CHECK(ft_otlp_logs_add(quiet, row, nullptr));
    CHECK(ft_otlp_logs_add(full, row, nullptr));
    CHECK(ft_otlp_logs_add(pathless, row, nullptr));

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
    CHECK(ft_otlp_logs_add(pathless, row, nullptr));
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
    CHECK(ft_otlp_logs_add(batch, bare, nullptr));
    CHECK(ft_otlp_logs_add(batch, described, nullptr));
    described->sock_id++;
    CHECK(ft_otlp_logs_add(batch, described, nullptr));
    bare->sock_id = described->sock_id;
    CHECK(ft_otlp_logs_add(batch, bare, nullptr));
    described->sock_id++;
    CHECK(ft_otlp_logs_add(batch, described, nullptr));

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
            CHECK(ft_otlp_logs_add(batch, row, nullptr));
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
        CHECK(ft_otlp_logs_add(batch, row, nullptr));
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
    CHECK(ft_otlp_logs_add(batch, row, nullptr));
    request = encode(batch);
    CHECK_STR(text(only_record(request), "filetrace.server.address.source"), "lookup");
    release(request);
    ft_row_event_set_name(row, FT_NAME_SOURCE_TLS, "files.example.com");
    CHECK(ft_otlp_logs_add(batch, row, nullptr));
    request = encode(batch);
    CHECK_STR(text(only_record(request), "filetrace.server.address.source"), "tls");
    release(request);
    ft_row_event_set_name(row, FT_NAME_SOURCE_NONE, "");
    CHECK(ft_otlp_logs_add(batch, row, nullptr));
    request = encode(batch);
    CHECK_STR(text(only_record(request), "server.address"), "(absent)");
    CHECK_STR(text(only_record(request), "filetrace.server.address.source"), "(absent)");
    release(request);

    ft_otlp_logs_free(batch);
    free(row);
}

static uint8_t *encode_one(struct ft_otlp_logs *batch, const struct ft_row_event *row, size_t *size)
{
    CHECK(ft_otlp_logs_add(batch, row, nullptr));
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
        CHECK(ft_otlp_logs_add(batch, row, nullptr));
        CHECK(ft_otlp_logs_add(off, row, nullptr));
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

static const KeyValue *attribute(const LogRecord *r, const char *key)
{
    return find(r->attributes, r->n_attributes, key);
}

/* The looked-up names go with the record of a transfer, as a list of strings. */
static void lists_the_names_looked_up(void)
{
    /* AnyValue{array_value: {values: [{string_value: ...}, {string_value: ...}]}} */
    static const char list[] = "\x2a\x29"
                               "\x0a\x11\x0a\x0f"
                               "cdn.example.com"
                               "\x0a\x14\x0a\x12"
                               "static.example.com";
    struct ft_remote_names names = {
        .tls = "",
        .resolved = {"cdn.example.com", "static.example.com"},
        .listed = 2,
        .count = 3,
    };
    struct ft_otlp_logs *batch = ft_otlp_logs_new(16, true, false, true);
    struct ft_otlp_logs *off = ft_otlp_logs_new(16, true, false, false);
    struct ft_row_event *row = transfer_row(10, 1);

    ft_row_event_set_name(row, FT_NAME_SOURCE_LOOKUP, "cdn.example.com");
    CHECK(ft_otlp_logs_add(batch, row, &names));
    CHECK(ft_otlp_logs_add(off, row, &names));
    row->type = FT_REC_NETWORK_SEND;
    CHECK(ft_otlp_logs_add(batch, row, &names));
    LogsRequest *request = encode(batch);
    const Opentelemetry__Proto__Logs__V1__ScopeLogs *scope =
        request->resource_logs[0]->scope_logs[0];
    CHECK_U64(scope->n_log_records, 2);
    const KeyValue *kv = attribute(scope->log_records[0], "filetrace.server.resolved_names");
    CHECK(kv &&
          kv->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE);
    if (kv &&
        kv->value->value_case == OPENTELEMETRY__PROTO__COMMON__V1__ANY_VALUE__VALUE_ARRAY_VALUE) {
        uint8_t packed[sizeof(list)];
        size_t size = opentelemetry__proto__common__v1__any_value__get_packed_size(kv->value);
        CHECK_U64(size, sizeof(list) - 1);
        if (size < sizeof(packed)) {
            opentelemetry__proto__common__v1__any_value__pack(kv->value, packed);
            CHECK(memcmp(packed, list, size) == 0);
        }
    }
    CHECK_STR(text(scope->log_records[1], "server.address"), "cdn.example.com");
    CHECK(attribute(scope->log_records[1], "filetrace.server.resolved_names") == nullptr);
    release(request);

    request = encode(off);
    CHECK(attribute(only_record(request), "server.address") == nullptr);
    CHECK(attribute(only_record(request), "filetrace.server.resolved_names") == nullptr);
    release(request);

    /* A name only from TLS has nothing looked up to list. */
    struct ft_remote_names tls_only = {.tls = "files.example.com"};
    row->type = FT_REC_FILE_TRANSFER;
    ft_row_event_set_name(row, FT_NAME_SOURCE_TLS, "files.example.com");
    CHECK(ft_otlp_logs_add(batch, row, &tls_only));
    request = encode(batch);
    CHECK_STR(text(only_record(request), "server.address"), "files.example.com");
    CHECK(attribute(only_record(request), "filetrace.server.resolved_names") == nullptr);
    release(request);

    /* Parts with the same names are summed, and those with others are not. */
    struct ft_remote_names fewer = {.tls = "", .resolved = {"cdn.example.com"}, .listed = 1};
    ft_row_event_set_name(row, FT_NAME_SOURCE_LOOKUP, "cdn.example.com");
    CHECK(ft_otlp_logs_add(batch, row, &names));
    CHECK(ft_otlp_logs_add(batch, row, &names));
    CHECK(ft_otlp_logs_add(batch, row, &fewer));
    CHECK_U64(ft_otlp_logs_count(batch), 2);
    request = encode(batch);
    scope = request->resource_logs[0]->scope_logs[0];
    CHECK_U64(scope->n_log_records, 2);
    if (scope->n_log_records == 2) {
        CHECK_U64(number(scope->log_records[0], "filetrace.transfer.bytes"), 20);
        kv = attribute(scope->log_records[1], "filetrace.server.resolved_names");
        CHECK(kv && kv->value->array_value && kv->value->array_value->n_values == 1);
    }
    release(request);

    ft_otlp_logs_free(batch);
    ft_otlp_logs_free(off);
    free(row);
}

/* Stands in for an OpenTelemetry collector and keeps the first log request it is sent. */
static void collect(void *ctx, struct ft_grpc_call *call, const char *path, const uint8_t *request,
                    size_t size)
{
    LogsRequest **logs = ctx;

    if (strcmp(path, FT_OTLP_LOGS_PATH) == 0 && !*logs)
        *logs = opentelemetry__proto__collector__logs__v1__export_logs_service_request__unpack(
            nullptr, size, request);
    ft_grpc_send(call, nullptr, 0);
    ft_grpc_finish(call, FT_GRPC_OK, nullptr);
}

static void collect_end(void *ctx, struct ft_grpc_call *call)
{
    (void)ctx;
    (void)call;
}

static void no_stats(void *agent, uint64_t now_ns, struct ft_row_stats *row)
{
    (void)agent;
    (void)now_ns;
    (void)row;
}

static void to_otlp(void *ctx, const struct ft_row_event *row)
{
    ft_otlp_record(ctx, row);
}

static void ingest(struct ft_state *st, struct ft_event *ev)
{
    static uint64_t now;

    now = now ? now + FT_NS_PER_MS : ft_clock_mono_ns();
    ev->ts_ns = now;
    ft_state_ingest(st, ev);
}

/* A process looks up two names for an address, connects to it and sends a file. */
static void send_to_two_names(struct ft_state *st)
{
    static const char *const looked_up[] = {"static.example.com", "cdn.example.com"};
    static const uint8_t remote[16] = {203, 0, 113, 25};
    static const enum ft_sock_state states[] = {FT_SOCK_CONNECTING, FT_SOCK_ESTABLISHED};
    struct ft_event ev = {.type = FT_EVENT_PROCESS_EXEC};

    ev.process.pid = 3312;
    ev.process.ppid = 1;
    ev.process.start_ns = 1;
    ft_strlcpy(ev.process.comm, "curl", sizeof(ev.process.comm));
    ingest(st, &ev);
    for (size_t i = 0; i < FT_ARRAY_LEN(looked_up); i++) {
        ev = (struct ft_event){.type = FT_EVENT_NAME_LOOKUP};
        ev.lookup.pid = 3312;
        ev.lookup.tid = 3312;
        ev.lookup.name = looked_up[i];
        ev.lookup.addr_count = 1;
        ft_endpoint_set(&ev.lookup.addrs[0], false, remote, 0);
        ingest(st, &ev);
    }
    for (size_t i = 0; i < FT_ARRAY_LEN(states); i++) {
        ev = (struct ft_event){.type = FT_EVENT_SOCKET_STATE};
        ev.socket.sock_id = 41;
        ev.socket.pid = 3312;
        ev.socket.tid = 3312;
        ev.socket.proto = FT_PROTO_TCP;
        ev.socket.state = states[i];
        ft_endpoint_set(&ev.socket.remote, false, remote, 443);
        ingest(st, &ev);
    }
    ev = (struct ft_event){.type = FT_EVENT_FILE_SEEN};
    ev.file.id = (struct ft_file_id){.dev = 2049, .ino = 77};
    ev.file.path = "/data/invoice.pdf";
    ev.file.size = 65536;
    ingest(st, &ev);
    ev = (struct ft_event){.type = FT_EVENT_TRANSFER};
    ev.transfer.sock_id = 41;
    ev.transfer.pid = 3312;
    ev.transfer.method = FT_METHOD_SENDFILE;
    ev.transfer.file = (struct ft_file_id){.dev = 2049, .ino = 77};
    ev.transfer.first_ns = ft_clock_mono_ns();
    ev.transfer.bytes = 65536;
    ev.transfer.ops = 1;
    ingest(st, &ev);
}

/* What the agent's exporter sends a collector for that transfer, with names on or off. */
static LogsRequest *exported(bool names)
{
    static struct ft_poller poller;
    char dir[] = "/tmp/filetrace-otlp-XXXXXX";
    struct ft_agent_config agent;
    struct ft_state_config state_cfg;
    struct ft_net_addr addr;
    struct ft_error err = {0};
    LogsRequest *logs = nullptr;
    struct ft_grpc_service service = {.ctx = &logs, .on_call = collect, .on_end = collect_end};

    CHECK(mkdtemp(dir) != nullptr);
    ft_agent_config_defaults(&agent);
    struct ft_otlp_config cfg = agent.otlp;
    cfg.enabled = true;
    cfg.metrics = false;
    cfg.names = names;
    cfg.flush_interval_ns = 10 * FT_NS_PER_MS;
    snprintf(cfg.endpoint, sizeof(cfg.endpoint), "unix:%s/collector.sock", dir);
    CHECK(ft_net_addr_parse(cfg.endpoint, &addr));
    struct ft_grpc_server *collector =
        ft_grpc_server_new(ft_net_listen(&addr, &err), true, &service);

    ft_state_config_defaults(&state_cfg);
    struct ft_state *st = ft_state_create(&state_cfg);
    struct ft_telemetry_source src = {.state = st, .stats = no_stats, .host = "web-01"};
    struct ft_otlp *o = ft_otlp_open(&cfg, &src, &err);
    CHECK(o != nullptr);
    st->on_record = to_otlp;
    st->on_record_ctx = o;
    send_to_two_names(st);

    uint64_t give_up_ns = ft_clock_mono_ns() + 2 * FT_NS_PER_SEC;
    while (!logs && ft_clock_mono_ns() < give_up_ns) {
        uint64_t now_ns = ft_clock_mono_ns();
        ft_poller_begin(&poller, now_ns + 10 * FT_NS_PER_MS);
        ft_otlp_poll(o, &poller);
        ft_grpc_server_poll(collector, &poller);
        ft_poller_wait(&poller, now_ns);
        ft_grpc_server_dispatch(collector, &poller);
        ft_otlp_dispatch(o, &poller, ft_clock_mono_ns());
    }
    CHECK(logs != nullptr);

    ft_otlp_close(o);
    ft_grpc_server_free(collector);
    ft_state_destroy(st);
    unlink(cfg.endpoint + 5);
    rmdir(dir);
    return logs;
}

/* The exporter takes the looked-up names from the socket while the record is made. */
static void exports_the_names_of_a_transfer(void)
{
    LogsRequest *on = exported(true);
    LogsRequest *off = exported(false);

    if (on) {
        const LogRecord *r = only_record(on);
        CHECK_STR(text(r, "file.path"), "/data/invoice.pdf");
        CHECK_STR(text(r, "server.address"), "cdn.example.com");
        CHECK_STR(text(r, "filetrace.server.address.source"), "lookup");
        const KeyValue *kv = attribute(r, "filetrace.server.resolved_names");
        CHECK(kv && kv->value->array_value && kv->value->array_value->n_values == 2);
        if (kv && kv->value->array_value && kv->value->array_value->n_values == 2) {
            CHECK_STR(kv->value->array_value->values[0]->string_value, "cdn.example.com");
            CHECK_STR(kv->value->array_value->values[1]->string_value, "static.example.com");
        }
        release(on);
    }
    if (off) {
        const LogRecord *r = only_record(off);
        CHECK_STR(text(r, "file.path"), "/data/invoice.pdf");
        CHECK(attribute(r, "server.address") == nullptr);
        CHECK(attribute(r, "filetrace.server.address.source") == nullptr);
        CHECK(attribute(r, "filetrace.server.resolved_names") == nullptr);
        release(off);
    }
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
    lists_the_names_looked_up();
    exports_the_names_of_a_transfer();
}
