#include "unit/test.h"

#include "agent/agent.h"
#include "exporters/otlp.h"
#include "filetrace/client.h"
#include "filetrace/clock.h"
#include "rpc/grpc.h"

#include "filetrace/v1/filetrace.pb-c.h"
#include "opentelemetry/proto/collector/logs/v1/logs_service.pb-c.h"
#include "opentelemetry/proto/collector/metrics/v1/metrics_service.pb-c.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* A backend that reports one fixed transfer the first time it is flushed. */
struct ft_backend {
    struct ft_sink sink;
    bool emitted;
    uint64_t events;
};

static struct ft_backend scripted;

static void scripted_emit(struct ft_backend *b, const struct ft_event *ev)
{
    b->events++;
    b->sink.emit(b->sink.ctx, ev);
}

static struct ft_backend *scripted_open(const struct ft_backend_config *cfg,
                                        const struct ft_sink *sink, struct ft_error *err)
{
    (void)cfg;
    (void)err;
    scripted = (struct ft_backend){.sink = *sink};
    return &scripted;
}

static struct ft_backend *refusing_open(const struct ft_backend_config *cfg,
                                        const struct ft_sink *sink, struct ft_error *err)
{
    (void)cfg;
    (void)sink;
    ft_error_set(err, FT_EXIT_PERMISSION, "Permission denied.");
    return nullptr;
}

static void scripted_flush(struct ft_backend *b)
{
    static const uint8_t remote[16] = {203, 0, 113, 42};
    static const uint8_t local[16] = {10, 0, 0, 10};
    uint64_t now = ft_clock_mono_ns();

    if (b->emitted)
        return;
    b->emitted = true;

    struct ft_event ev = {.type = FT_EVENT_PROCESS_EXEC, .ts_ns = now};
    ev.process.pid = 1842;
    ev.process.ppid = 1;
    ev.process.start_ns = now;
    ft_strlcpy(ev.process.comm, "nginx", sizeof(ev.process.comm));
    ft_strlcpy(ev.process.exe, "/usr/sbin/nginx", sizeof(ev.process.exe));
    scripted_emit(b, &ev);

    ev = (struct ft_event){.type = FT_EVENT_FILE_SEEN, .ts_ns = now};
    ev.file.id = (struct ft_file_id){.dev = 2049, .ino = 928371};
    ev.file.path = "/data/export/report, \"final\".csv";
    ev.file.size = 148293012;
    ev.file.uid = 33;
    scripted_emit(b, &ev);

    ev = (struct ft_event){.type = FT_EVENT_FLOW, .ts_ns = now};
    ev.flow.sock_id = 127;
    ev.flow.pid = 1842;
    ev.flow.proto = FT_PROTO_TCP;
    ev.flow.first_ns = now;
    ev.flow.tx_bytes = 148293012;
    ft_endpoint_set(&ev.flow.local, false, local, 443);
    ft_endpoint_set(&ev.flow.remote, false, remote, 52144);
    scripted_emit(b, &ev);

    ev = (struct ft_event){.type = FT_EVENT_TRANSFER, .ts_ns = now};
    ev.transfer.sock_id = 127;
    ev.transfer.pid = 1842;
    ev.transfer.method = FT_METHOD_SENDFILE;
    ev.transfer.file = (struct ft_file_id){.dev = 2049, .ino = 928371};
    ev.transfer.first_ns = now;
    ev.transfer.bytes = 148293012;
    ev.transfer.ops = 1248;
    scripted_emit(b, &ev);
}

/* Reports ten more bytes sent on one socket at every flush. */
static void ticking_flush(struct ft_backend *b)
{
    struct ft_event ev = {.type = FT_EVENT_FLOW, .ts_ns = ft_clock_mono_ns()};
    ev.flow.sock_id = 500;
    ev.flow.pid = 77;
    ev.flow.proto = FT_PROTO_UDP;
    ev.flow.first_ns = ev.ts_ns;
    ev.flow.tx_bytes = 10;
    scripted_emit(b, &ev);
}

/* Describes one file once, then reports a hundred more of its bytes sent at every flush. */
static void sending_flush(struct ft_backend *b)
{
    static const uint8_t remote[16] = {203, 0, 113, 42};
    uint64_t now = ft_clock_mono_ns();
    struct ft_event ev;

    if (!b->emitted) {
        b->emitted = true;
        ev = (struct ft_event){.type = FT_EVENT_PROCESS_EXEC, .ts_ns = now};
        ev.process.pid = 1842;
        ev.process.ppid = 1;
        ev.process.start_ns = now;
        ft_strlcpy(ev.process.comm, "nginx", sizeof(ev.process.comm));
        ft_strlcpy(ev.process.exe, "/usr/sbin/nginx", sizeof(ev.process.exe));
        scripted_emit(b, &ev);

        ev = (struct ft_event){.type = FT_EVENT_FILE_SEEN, .ts_ns = now};
        ev.file.id = (struct ft_file_id){.dev = 2049, .ino = 77};
        ev.file.path = "/var/www/stream.bin";
        ev.file.size = 4096;
        scripted_emit(b, &ev);
    }

    ev = (struct ft_event){.type = FT_EVENT_FLOW, .ts_ns = now};
    ev.flow.sock_id = 127;
    ev.flow.pid = 1842;
    ev.flow.proto = FT_PROTO_TCP;
    ev.flow.first_ns = now;
    ev.flow.tx_bytes = 100;
    ft_endpoint_set(&ev.flow.remote, false, remote, 52144);
    scripted_emit(b, &ev);

    ev = (struct ft_event){.type = FT_EVENT_TRANSFER, .ts_ns = now};
    ev.transfer.sock_id = 127;
    ev.transfer.pid = 1842;
    ev.transfer.method = FT_METHOD_SENDFILE;
    ev.transfer.file = (struct ft_file_id){.dev = 2049, .ino = 77};
    ev.transfer.first_ns = now;
    ev.transfer.bytes = 100;
    ev.transfer.ops = 1;
    scripted_emit(b, &ev);
}

static void scripted_stats(struct ft_backend *b, struct ft_backend_stats *out)
{
    out->events = b->events;
    out->queue_bytes = 65536;
}

static void scripted_capabilities(struct ft_backend *b, struct ft_capabilities *out)
{
    (void)b;
    ft_capability_set_all(out, FT_CAP_FULL, "");
    ft_capability_set(out, FT_FEAT_SPLICE, FT_CAP_UNAVAILABLE, "%s", "not followed");
}

static void scripted_close(struct ft_backend *b)
{
    (void)b;
}

static const struct ft_backend_ops scripted_ops = {
    .name = "scripted",
    .open = scripted_open,
    .flush = scripted_flush,
    .stats = scripted_stats,
    .capabilities = scripted_capabilities,
    .close = scripted_close,
};

static const struct ft_backend_ops ticking_ops = {
    .name = "ticking",
    .open = scripted_open,
    .flush = ticking_flush,
    .stats = scripted_stats,
    .capabilities = scripted_capabilities,
    .close = scripted_close,
};

/* What /proc would say of the one process the sending backend reports. */
static bool sending_process_text(uint32_t pid, struct ft_process_text *out)
{
    static const char args[] = "/usr/sbin/nginx\0-g\0daemon off;";
    if (pid != 1842)
        return false;
    memcpy(out->args, args, sizeof(args));
    out->args_len = sizeof(args);
    ft_strlcpy(out->cwd, "/srv/www", sizeof(out->cwd));
    return true;
}

static const struct ft_backend_ops sending_ops = {
    .name = "sending",
    .open = scripted_open,
    .flush = sending_flush,
    .stats = scripted_stats,
    .capabilities = scripted_capabilities,
    .read_process_text = sending_process_text,
    .close = scripted_close,
};

static const struct ft_backend_ops refusing_ops = {
    .name = "refusing",
    .open = refusing_open,
};

static void pause_ms(long ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1'000'000};
    nanosleep(&ts, nullptr);
}

/* peer_fd is the client's end of a session socket, which the agent must not hold. */
static pid_t start_agent_with(const struct ft_backend_ops *ops, const char *socket_path,
                              int session_fd, int peer_fd,
                              void (*adjust)(struct ft_agent_config *cfg, void *arg), void *arg)
{
    pid_t pid = fork();
    if (pid == 0) {
        struct ft_agent_config cfg;
        struct ft_error err = {0};

        if (peer_fd >= 0)
            close(peer_fd);

        ft_agent_config_defaults(&cfg);
        cfg.backend = ops;
        cfg.socket_path = socket_path;
        cfg.session_fd = session_fd;
        cfg.flush_interval_ms = 20;
        if (adjust)
            adjust(&cfg, arg);
        ft_log_set_level(FT_LOG_ERROR);
        _exit(ft_agent_run(&cfg, &err));
    }
    return pid;
}

static pid_t start_agent(const struct ft_backend_ops *ops, const char *socket_path, int session_fd,
                         int peer_fd)
{
    return start_agent_with(ops, socket_path, session_fd, peer_fd, nullptr, nullptr);
}

static int wait_exit(pid_t pid)
{
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return -1;
    return WEXITSTATUS(status);
}

struct reply {
    struct ft_row_stats stats;
    struct ft_row_transfer *transfer;
    struct ft_row_capability capabilities[FT_FEAT_COUNT];
    size_t rows;
};

static void on_row(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct reply *r = ctx;

    if (type == FT_MSG_ROW_STATS) {
        memcpy(&r->stats, payload, size < sizeof(r->stats) ? size : sizeof(r->stats));
    } else if (type == FT_MSG_ROW_TRANSFER) {
        memset(r->transfer, 0, sizeof(*r->transfer));
        memcpy(r->transfer, payload, size < sizeof(*r->transfer) ? size : sizeof(*r->transfer));
    } else if (type == FT_MSG_ROW_CAPABILITY && r->rows < FT_FEAT_COUNT) {
        memcpy(&r->capabilities[r->rows], payload, size);
    }
    r->rows++;
}

/* Repeats the transfer query until the scripted record has been ingested. */
static bool wait_for_transfer(struct ft_client *c, struct reply *r, struct ft_msg_end *end)
{
    struct ft_query q;
    struct ft_error err = {0};

    ft_query_init(&q, FT_Q_TRANSFERS);
    for (int attempt = 0; attempt < 200; attempt++) {
        r->rows = 0;
        if (ft_client_query(c, &q, on_row, r, end, &err) != FT_EXIT_OK)
            return false;
        if (r->rows == 1)
            return true;
        pause_ms(10);
    }
    return false;
}

static void serves_queries_over_a_socket(void)
{
    char dir[] = "/tmp/filetrace-test-XXXXXX";
    char path[64];
    struct ft_error err = {0};
    struct ft_client *c = nullptr;
    struct reply r = {.transfer = malloc(sizeof(struct ft_row_transfer))};
    struct ft_msg_end end = {0};
    struct ft_query q;

    CHECK(mkdtemp(dir) != nullptr);
    snprintf(path, sizeof(path), "%s/agent.sock", dir);

    pid_t pid = start_agent(&scripted_ops, path, -1, -1);
    for (int attempt = 0; attempt < 200 && !c; attempt++) {
        c = ft_client_connect(path, &err);
        if (!c)
            pause_ms(10);
    }
    CHECK(c != nullptr);
    if (!c) {
        free(r.transfer);
        return;
    }

    CHECK(wait_for_transfer(c, &r, &end));
    CHECK_U64(r.transfer->bytes, 148293012);
    CHECK_U64(r.transfer->confidence, FT_CONF_EXACT);
    CHECK_U64(r.transfer->ops, 1248);
    CHECK_U64(r.transfer->remote.port, 52144);
    CHECK_STR(r.transfer->comm, "nginx");
    CHECK_STR(r.transfer->path, "/data/export/report, \"final\".csv");
    CHECK_U64(r.transfer->file_size, 148293012);
    CHECK_U64(r.transfer->file_uid, 33);
    CHECK(end.observed_since_wall_ns != 0);
    CHECK_U64(end.lost_events, 0);

    /* A path filter travels with the query and is applied by the agent. */
    ft_query_init(&q, FT_Q_TRANSFERS);
    ft_strlcpy(q.path, "/nowhere/*", sizeof(q.path));
    r.rows = 0;
    CHECK_U64(ft_client_query(c, &q, on_row, &r, &end, &err), FT_EXIT_OK);
    CHECK_U64(r.rows, 0);

    /* A query the agent cannot evaluate is an error, not an empty result. */
    q.flags = FT_QF_PATH_REGEX;
    ft_strlcpy(q.path, "(unclosed", sizeof(q.path));
    CHECK_U64(ft_client_query(c, &q, on_row, &r, &end, &err), FT_EXIT_USAGE);
    CHECK(strstr(err.msg, "Invalid path expression") != nullptr);

    ft_query_init(&q, FT_Q_STATS);
    r.rows = 0;
    CHECK_U64(ft_client_query(c, &q, on_row, &r, &end, &err), FT_EXIT_OK);
    CHECK_U64(r.rows, 1);
    CHECK_STR(r.stats.backend, "scripted");
    CHECK_STR(r.stats.mode, "standard");
    CHECK_STR(r.stats.version, FT_VERSION);
    CHECK_U64(r.stats.events_received, 4);
    CHECK_U64(r.stats.events_processed, 4);
    CHECK_U64(r.stats.tx_bytes, 148293012);
    CHECK_U64(r.stats.transfers.count, 1);
    CHECK_U64(r.stats.health, FT_HEALTH_OK);
    CHECK_U64(r.stats.pid, (uint64_t)pid);

    ft_query_init(&q, FT_Q_CAPABILITIES);
    r.rows = 0;
    CHECK_U64(ft_client_query(c, &q, on_row, &r, &end, &err), FT_EXIT_OK);
    CHECK_U64(r.rows, FT_FEAT_COUNT);
    CHECK_U64(r.capabilities[FT_FEAT_SENDFILE].status, FT_CAP_FULL);
    CHECK_U64(r.capabilities[FT_FEAT_SPLICE].status, FT_CAP_UNAVAILABLE);
    CHECK_STR(r.capabilities[FT_FEAT_SPLICE].reason, "not followed");

    /* An invalid request is answered with an error, not a dropped connection. */
    ft_query_init(&q, (enum ft_query_kind)999);
    CHECK_U64(ft_client_query(c, &q, on_row, &r, &end, &err), FT_EXIT_USAGE);
    ft_query_init(&q, FT_Q_STATS);
    CHECK_U64(ft_client_query(c, &q, on_row, &r, &end, &err), FT_EXIT_OK);

    /* A second agent refuses to take over a socket that is being served. */
    pid_t second = start_agent(&scripted_ops, path, -1, -1);
    CHECK_U64(wait_exit(second), FT_EXIT_ERROR);

    CHECK_U64(ft_client_shutdown(c, &err), FT_EXIT_OK);
    ft_client_close(c);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);

    CHECK(access(path, F_OK) != 0);
    CHECK(ft_client_connect(path, &err) == nullptr);
    CHECK_U64(err.code, FT_EXIT_NO_AGENT);

    rmdir(dir);
    free(r.transfer);
}

static void serves_a_single_session(void)
{
    struct reply r = {.transfer = malloc(sizeof(struct ft_row_transfer))};
    struct ft_msg_end end = {0};
    int pair[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_agent(&scripted_ops, nullptr, pair[1], pair[0]);
    close(pair[1]);

    struct ft_client *c = ft_client_adopt(pair[0]);
    CHECK(c != nullptr);
    CHECK(wait_for_transfer(c, &r, &end));
    CHECK_U64(r.transfer->bytes, 148293012);

    /* The collector ends with the session that started it. */
    ft_client_close(c);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);
    free(r.transfer);
}

static void minimal_mode(struct ft_agent_config *cfg, void *arg)
{
    (void)arg;
    cfg->backend_cfg.mode = FT_MODE_MINIMAL;
}

static void no_source_of_names(struct ft_agent_config *cfg, void *arg)
{
    (void)arg;
    cfg->backend_cfg.lookup_names = false;
    cfg->backend_cfg.tls_names = false;
}

/* How many names an agent started this way has room for. */
static uint64_t room_for_names(void (*adjust)(struct ft_agent_config *cfg, void *arg))
{
    struct reply r = {0};
    struct ft_error err = {0};
    struct ft_query q;
    int pair[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_agent_with(&scripted_ops, nullptr, pair[1], pair[0], adjust, nullptr);
    close(pair[1]);

    struct ft_client *c = ft_client_adopt(pair[0]);
    ft_query_init(&q, FT_Q_STATS);
    CHECK_U64(ft_client_query(c, &q, on_row, &r, nullptr, &err), FT_EXIT_OK);
    ft_client_close(c);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);
    return r.stats.names.capacity + r.stats.name_lookups.capacity;
}

static void keeps_names_where_they_can_come_from(void)
{
    CHECK_U64(room_for_names(nullptr), 4096 + 16384);
    CHECK_U64(room_for_names(minimal_mode), 0);
    CHECK_U64(room_for_names(no_source_of_names), 0);
}

/* Where the kernel says whether a process may get huge pages, the agent has asked for none. */
static void runs_on_small_pages(void)
{
#if defined(__linux__)
    struct reply r = {0};
    struct ft_error err = {0};
    struct ft_query q;
    char path[64];
    char line[128];
    int allowed = -1;
    int pair[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_agent(&scripted_ops, nullptr, pair[1], pair[0]);
    close(pair[1]);

    struct ft_client *c = ft_client_adopt(pair[0]);
    ft_query_init(&q, FT_Q_STATS);
    CHECK_U64(ft_client_query(c, &q, on_row, &r, nullptr, &err), FT_EXIT_OK);

    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *status = fopen(path, "r");
    while (status && fgets(line, sizeof(line), status)) {
        if (sscanf(line, "THP_enabled: %d", &allowed) == 1)
            break;
    }
    if (status)
        fclose(status);
    CHECK(allowed != 1);

    ft_client_close(c);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);
#endif
}

static void reports_a_backend_that_cannot_start(void)
{
    struct ft_error err = {0};
    struct ft_query q;
    int pair[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_agent(&refusing_ops, nullptr, pair[1], pair[0]);
    close(pair[1]);

    struct ft_client *c = ft_client_adopt(pair[0]);
    ft_query_init(&q, FT_Q_STATS);
    CHECK_U64(ft_client_query(c, &q, nullptr, nullptr, nullptr, &err), FT_EXIT_PERMISSION);
    CHECK_STR(err.msg, "Permission denied.");
    ft_client_close(c);
    CHECK_U64(wait_exit(pid), FT_EXIT_PERMISSION);
}

struct followed {
    uint64_t rows;
    uint64_t last_seq;
    bool in_order;
    bool all_sends;
    volatile sig_atomic_t stop;
};

static void on_followed(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct followed *f = ctx;
    struct ft_row_event head;

    if (type != FT_MSG_ROW_EVENT || size < offsetof(struct ft_row_event, text))
        return;
    memcpy(&head, payload, offsetof(struct ft_row_event, text));
    f->in_order = f->in_order && head.seq > f->last_seq;
    f->all_sends = f->all_sends && head.type == FT_REC_NETWORK_SEND && head.bytes == 10;
    f->last_seq = head.seq;
    if (++f->rows == 3)
        f->stop = 1;
}

static void streams_events_to_a_follower(void)
{
    struct followed f = {.in_order = true, .all_sends = true};
    struct ft_error err = {0};
    struct ft_query q;
    int pair[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_agent(&ticking_ops, nullptr, pair[1], pair[0]);
    close(pair[1]);

    struct ft_client *c = ft_client_adopt(pair[0]);
    CHECK(c != nullptr);
    ft_client_stop_on(c, &f.stop);

    /* No end is sent while following; the query returns because the follower stops. */
    ft_query_init(&q, FT_Q_EVENTS);
    q.flags = FT_QF_FOLLOW;
    q.event_types = 1u << FT_REC_NETWORK_SEND;
    CHECK_U64(ft_client_query(c, &q, on_followed, &f, nullptr, &err), FT_EXIT_OK);
    CHECK(f.rows >= 3);
    CHECK(f.in_order);
    CHECK(f.all_sends);

    ft_client_close(c);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);
}

/* A port that was free a moment ago. */
static uint16_t free_port(void)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    getsockname(fd, (struct sockaddr *)&addr, &len);
    close(fd);
    return ntohs(addr.sin_port);
}

/* The whole response to one GET, or an empty string while nothing listens on the port. */
static void http_get(uint16_t port, const char *target, char *out, size_t size)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(port),
    };
    char request[128];
    size_t len = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    out[0] = '\0';
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        int n = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: test\r\n\r\n", target);
        if (write(fd, request, (size_t)n) == n) {
            ssize_t got;
            while (len + 1 < size && (got = read(fd, out + len, size - 1 - len)) > 0)
                len += (size_t)got;
            out[len] = '\0';
        }
    }
    close(fd);
}

static void serve_metrics(struct ft_agent_config *cfg, void *arg)
{
    cfg->prometheus.enabled = true;
    snprintf(cfg->prometheus.listen, sizeof(cfg->prometheus.listen), "127.0.0.1:%u",
             *(uint16_t *)arg);
}

static void serves_metrics_to_a_scraper(void)
{
    static const char sent[] =
        "filetrace_file_sent_bytes_total{process_executable_name=\"nginx\","
        "filetrace_transfer_method=\"sendfile\",filetrace_transfer_confidence=\"exact\"} "
        "148293012\n";
    uint16_t port = free_port();
    char *page = malloc(65536);
    int pair[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_agent_with(&scripted_ops, nullptr, pair[1], pair[0], serve_metrics, &port);
    close(pair[1]);

    for (int attempt = 0; attempt < 200; attempt++) {
        http_get(port, "/metrics", page, 65536);
        if (strstr(page, sent))
            break;
        pause_ms(10);
    }
    CHECK(strncmp(page, "HTTP/1.1 200 OK\r\n", 17) == 0);
    CHECK(strstr(page, "Content-Type: text/plain; version=0.0.4"));
    CHECK(
        strstr(page, "target_info{service_name=\"filetrace\",service_version=\"" FT_VERSION "\""));
    CHECK(strstr(page, sent));
    CHECK(strstr(page, "filetrace_network_io_bytes_total{process_executable_name=\"nginx\","
                       "network_transport=\"tcp\",network_io_direction=\"transmit\"} 148293012\n"));
    CHECK(strstr(page, "filetrace_transfers_active{filetrace_transfer_confidence=\"exact\"} 1\n"));
    CHECK(strstr(page, "filetrace_events_processed_total 4\n"));

    http_get(port, "/metrics?x=1", page, 65536);
    CHECK(strncmp(page, "HTTP/1.1 200 OK\r\n", 17) == 0);
    http_get(port, "/", page, 65536);
    CHECK(strncmp(page, "HTTP/1.1 404 ", 13) == 0);

    close(pair[0]);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);
    free(page);
}

/* Stands in for an OpenTelemetry collector and adds up what it is sent. */
struct collector {
    uint64_t transfer_bytes;
    uint64_t sent_bytes;
    char path[64];
};

static void collect_logs(struct collector *c, const uint8_t *request, size_t size)
{
    Opentelemetry__Proto__Collector__Logs__V1__ExportLogsServiceRequest *logs =
        opentelemetry__proto__collector__logs__v1__export_logs_service_request__unpack(
            nullptr, size, request);

    CHECK(logs != nullptr && logs->n_resource_logs == 1);
    if (!logs)
        return;
    const Opentelemetry__Proto__Logs__V1__ScopeLogs *scope = logs->resource_logs[0]->scope_logs[0];
    for (size_t i = 0; i < scope->n_log_records; i++) {
        const Opentelemetry__Proto__Logs__V1__LogRecord *r = scope->log_records[i];
        for (size_t k = 0; k < r->n_attributes; k++) {
            if (strcmp(r->attributes[k]->key, "filetrace.transfer.bytes") == 0)
                c->transfer_bytes += (uint64_t)r->attributes[k]->value->int_value;
            if (strcmp(r->attributes[k]->key, "file.path") == 0)
                ft_strlcpy(c->path, r->attributes[k]->value->string_value, sizeof(c->path));
        }
    }
    opentelemetry__proto__collector__logs__v1__export_logs_service_request__free_unpacked(logs,
                                                                                          nullptr);
}

static void collect_metrics(struct collector *c, const uint8_t *request, size_t size)
{
    Opentelemetry__Proto__Collector__Metrics__V1__ExportMetricsServiceRequest *metrics =
        opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__unpack(
            nullptr, size, request);

    CHECK(metrics != nullptr && metrics->n_resource_metrics == 1);
    if (!metrics)
        return;
    const Opentelemetry__Proto__Metrics__V1__ScopeMetrics *scope =
        metrics->resource_metrics[0]->scope_metrics[0];
    for (size_t i = 0; i < scope->n_metrics; i++) {
        const Opentelemetry__Proto__Metrics__V1__Metric *m = scope->metrics[i];
        /* Cumulative: the latest value stands for all before it. */
        if (strcmp(m->name, "filetrace.file.sent") == 0 && m->sum->n_data_points == 1)
            c->sent_bytes = (uint64_t)m->sum->data_points[0]->as_int;
    }
    opentelemetry__proto__collector__metrics__v1__export_metrics_service_request__free_unpacked(
        metrics, nullptr);
}

static void collector_call(void *ctx, struct ft_grpc_call *call, const char *path,
                           const uint8_t *request, size_t size)
{
    if (strcmp(path, FT_OTLP_LOGS_PATH) == 0) {
        collect_logs(ctx, request, size);
    } else if (strcmp(path, FT_OTLP_METRICS_PATH) == 0) {
        collect_metrics(ctx, request, size);
    } else {
        ft_grpc_finish(call, FT_GRPC_UNIMPLEMENTED, path);
        return;
    }
    /* An empty response message: nothing was refused. */
    ft_grpc_send(call, nullptr, 0);
    ft_grpc_finish(call, FT_GRPC_OK, nullptr);
}

static void collector_end(void *ctx, struct ft_grpc_call *call)
{
    (void)ctx;
    (void)call;
}

static void export_to(struct ft_agent_config *cfg, void *arg)
{
    cfg->otlp.enabled = true;
    ft_strlcpy(cfg->otlp.endpoint, arg, sizeof(cfg->otlp.endpoint));
    cfg->otlp.flush_interval_ns = 50 * FT_NS_PER_MS;
    cfg->otlp.metrics_interval_ns = 50 * FT_NS_PER_MS;
}

/* The collector starts after the agent has already failed to reach it once. */
static void exports_to_a_collector_that_appears_later(void)
{
    static struct ft_poller poller;
    char dir[] = "/tmp/filetrace-otlp-XXXXXX";
    char endpoint[96];
    struct collector seen = {0};
    struct ft_grpc_service service = {
        .ctx = &seen,
        .on_call = collector_call,
        .on_end = collector_end,
    };
    struct ft_net_addr addr;
    struct ft_error err = {0};
    int pair[2];

    CHECK(mkdtemp(dir) != nullptr);
    snprintf(endpoint, sizeof(endpoint), "unix:%s/collector.sock", dir);
    CHECK(ft_net_addr_parse(endpoint, &addr));
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_agent_with(&scripted_ops, nullptr, pair[1], pair[0], export_to, endpoint);
    close(pair[1]);
    pause_ms(200);

    int listen_fd = ft_net_listen(&addr, &err);
    CHECK(listen_fd >= 0);
    struct ft_grpc_server *server = ft_grpc_server_new(listen_fd, true, &service);
    uint64_t give_up_ns = ft_clock_mono_ns() + 10 * FT_NS_PER_SEC;
    while ((seen.transfer_bytes == 0 || seen.sent_bytes == 0) && ft_clock_mono_ns() < give_up_ns) {
        uint64_t now_ns = ft_clock_mono_ns();
        ft_poller_begin(&poller, now_ns + 20 * FT_NS_PER_MS);
        ft_grpc_server_poll(server, &poller);
        ft_poller_wait(&poller, now_ns);
        ft_grpc_server_dispatch(server, &poller);
    }
    CHECK_U64(seen.transfer_bytes, 148293012);
    CHECK_U64(seen.sent_bytes, 148293012);
    CHECK_STR(seen.path, "/data/export/report, \"final\".csv");

    close(pair[0]);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);
    ft_grpc_server_free(server);
    unlink(endpoint + 5);
    rmdir(dir);
}

struct api_reply {
    bool done;
    enum ft_grpc_status status;
    char message[160];
    uint8_t *bytes;
    size_t size;
    int events;
    uint64_t last_sequence;
    bool events_as_expected;
};

static void api_done(void *ctx, enum ft_grpc_status status, const char *message,
                     const uint8_t *reply, size_t size)
{
    struct api_reply *r = ctx;

    r->done = true;
    r->status = status;
    ft_strlcpy(r->message, message, sizeof(r->message));
    r->bytes = malloc(size ? size : 1);
    r->size = size;
    if (size)
        memcpy(r->bytes, reply, size);
}

static void api_event(void *ctx, const uint8_t *message, size_t size)
{
    struct api_reply *r = ctx;
    Filetrace__V1__WatchTransfersResponse *w =
        filetrace__v1__watch_transfers_response__unpack(nullptr, size, message);

    if (!w || !w->event) {
        r->events_as_expected = false;
        return;
    }
    const Filetrace__V1__TransferEvent *e = w->event;
    r->events_as_expected =
        r->events_as_expected && e->sequence > r->last_sequence && e->bytes_sent == 100 &&
        e->method == FILETRACE__V1__METHOD__METHOD_SENDFILE &&
        e->confidence == FILETRACE__V1__CONFIDENCE__CONFIDENCE_EXACT && w->missed == 0 &&
        strcmp(e->process->name, "nginx") == 0 &&
        strcmp(e->file->path, "/var/www/stream.bin") == 0 &&
        strcmp(e->process->command_line, "/usr/sbin/nginx -g daemon off;") == 0 &&
        strcmp(e->process->working_directory, "/srv/www") == 0 &&
        strcmp(e->connection->remote->address, "203.0.113.42") == 0;
    r->last_sequence = e->sequence;
    r->events++;
    filetrace__v1__watch_transfers_response__free_unpacked(w, nullptr);
}

static bool enough_events(const struct api_reply *r)
{
    return r->events >= 3;
}

static bool answered(const struct api_reply *r)
{
    return r->done;
}

static void api_pump(struct ft_grpc_client *client, const struct api_reply *r,
                     bool (*until)(const struct api_reply *r))
{
    static struct ft_poller poller;
    uint64_t give_up_ns = ft_clock_mono_ns() + 5 * FT_NS_PER_SEC;

    while (!until(r) && ft_clock_mono_ns() < give_up_ns) {
        uint64_t now_ns = ft_clock_mono_ns();
        ft_poller_begin(&poller, now_ns + 20 * FT_NS_PER_MS);
        ft_grpc_client_poll(client, &poller);
        ft_poller_wait(&poller, now_ns);
        ft_grpc_client_dispatch(client, &poller, ft_clock_mono_ns());
    }
}

/* One unary call of the API with an already packed request. */
static struct api_reply api_call(struct ft_grpc_client *client, const char *method,
                                 const ProtobufCMessage *request)
{
    struct api_reply r = {0};
    char path[96];
    uint8_t packed[512];
    size_t size = protobuf_c_message_pack(request, packed);

    snprintf(path, sizeof(path), "/filetrace.v1.FiletraceService/%s", method);
    ft_grpc_client_call(client, path, packed, size, ft_clock_mono_ns() + 5 * FT_NS_PER_SEC,
                        api_done, &r);
    api_pump(client, &r, answered);
    return r;
}

static Filetrace__V1__ListTransfersResponse *
api_list(struct ft_grpc_client *client, Filetrace__V1__TransferFilter *filter, struct api_reply *r)
{
    Filetrace__V1__ListTransfersRequest request = FILETRACE__V1__LIST_TRANSFERS_REQUEST__INIT;

    request.filter = filter;
    *r = api_call(client, "ListTransfers", &request.base);
    Filetrace__V1__ListTransfersResponse *list =
        r->status == FT_GRPC_OK
            ? filetrace__v1__list_transfers_response__unpack(nullptr, r->size, r->bytes)
            : nullptr;
    free(r->bytes);
    return list;
}

static void serve_api(struct ft_agent_config *cfg, void *arg)
{
    cfg->api.enabled = true;
    ft_strlcpy(cfg->api.listen, arg, sizeof(cfg->api.listen));
}

static void answers_grpc_calls(void)
{
    char dir[] = "/tmp/filetrace-api-XXXXXX";
    char listen[96];
    struct ft_net_addr addr;
    struct api_reply r;
    int pair[2];

    CHECK(mkdtemp(dir) != nullptr);
    snprintf(listen, sizeof(listen), "unix:%s/api.sock", dir);
    CHECK(ft_net_addr_parse(listen, &addr));
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_agent_with(&sending_ops, nullptr, pair[1], pair[0], serve_api, listen);
    close(pair[1]);
    for (int attempt = 0; attempt < 200 && access(listen + 5, F_OK) != 0; attempt++)
        pause_ms(10);

    struct ft_grpc_client *client = ft_grpc_client_new(&addr, "localhost");
    Filetrace__V1__GetStatusRequest status_request = FILETRACE__V1__GET_STATUS_REQUEST__INIT;
    r = api_call(client, "GetStatus", &status_request.base);
    CHECK_U64(r.status, FT_GRPC_OK);
    Filetrace__V1__GetStatusResponse *status =
        filetrace__v1__get_status_response__unpack(nullptr, r.size, r.bytes);
    CHECK(status != nullptr);
    if (status) {
        CHECK_STR(status->version, FT_VERSION);
        CHECK_STR(status->backend, "sending");
        CHECK_STR(status->mode, "standard");
        CHECK(status->start_time_unix_nano != 0);
        CHECK(!status->degraded);
        filetrace__v1__get_status_response__free_unpacked(status, nullptr);
    }
    free(r.bytes);

    Filetrace__V1__ListTransfersResponse *list = nullptr;
    for (int attempt = 0; attempt < 200; attempt++) {
        list = api_list(client, nullptr, &r);
        if (!list || list->n_transfers == 1)
            break;
        filetrace__v1__list_transfers_response__free_unpacked(list, nullptr);
        list = nullptr;
        pause_ms(10);
    }
    CHECK(list != nullptr && list->n_transfers == 1);
    if (list && list->n_transfers == 1) {
        const Filetrace__V1__Transfer *t = list->transfers[0];
        CHECK(t->bytes_sent >= 100 && t->bytes_sent % 100 == 0);
        CHECK_U64(t->method, FILETRACE__V1__METHOD__METHOD_SENDFILE);
        CHECK_U64(t->confidence, FILETRACE__V1__CONFIDENCE__CONFIDENCE_EXACT);
        CHECK(t->n_evidence >= 1);
        if (t->n_evidence)
            CHECK_STR(t->evidence[0], "direct_file_to_socket_transfer");
        CHECK(t->active);
        CHECK_U64(t->process->pid, 1842);
        CHECK_STR(t->process->name, "nginx");
        CHECK_STR(t->process->executable, "/usr/sbin/nginx");
        CHECK_STR(t->process->command_line, "/usr/sbin/nginx -g daemon off;");
        CHECK_STR(t->process->working_directory, "/srv/www");
        CHECK_STR(t->process->script, "");
        CHECK_STR(t->file->path, "/var/www/stream.bin");
        CHECK_U64(t->file->inode, 77);
        CHECK_U64(t->file->size, 4096);
        CHECK_U64(t->connection->socket_id, 127);
        CHECK_U64(t->connection->transport, FILETRACE__V1__TRANSPORT__TRANSPORT_TCP);
        CHECK_STR(t->connection->remote->address, "203.0.113.42");
        CHECK_U64(t->connection->remote->port, 52144);
        CHECK(list->observed_since_unix_nano != 0);
    }
    if (list)
        filetrace__v1__list_transfers_response__free_unpacked(list, nullptr);

    /* The filters are the ones the command line has. */
    Filetrace__V1__TransferFilter filter = FILETRACE__V1__TRANSFER_FILTER__INIT;
    filter.remote = "203.0.113.0/24";
    filter.path = "/var/www/*";
    filter.confidence = FILETRACE__V1__CONFIDENCE__CONFIDENCE_EXACT;
    list = api_list(client, &filter, &r);
    CHECK(list != nullptr && list->n_transfers == 1);
    if (list)
        filetrace__v1__list_transfers_response__free_unpacked(list, nullptr);

    filter.remote = "198.51.100.0/24";
    list = api_list(client, &filter, &r);
    CHECK(list != nullptr && list->n_transfers == 0);
    if (list)
        filetrace__v1__list_transfers_response__free_unpacked(list, nullptr);

    /* nginx runs no script. */
    filter.remote = "203.0.113.0/24";
    filter.script = "*";
    list = api_list(client, &filter, &r);
    CHECK(list != nullptr && list->n_transfers == 0);
    if (list)
        filetrace__v1__list_transfers_response__free_unpacked(list, nullptr);
    filter.script = "";

    filter.remote = "the internet";
    list = api_list(client, &filter, &r);
    CHECK(list == nullptr);
    CHECK_U64(r.status, FT_GRPC_INVALID_ARGUMENT);
    CHECK_STR(r.message, "remote is neither an IP address nor a CIDR network.");

    r = api_call(client, "DeleteEverything", &status_request.base);
    CHECK_U64(r.status, FT_GRPC_UNIMPLEMENTED);
    free(r.bytes);

    /* A watcher receives each record as the agent makes it. */
    Filetrace__V1__WatchTransfersRequest watch_request =
        FILETRACE__V1__WATCH_TRANSFERS_REQUEST__INIT;
    Filetrace__V1__TransferFilter by_process = FILETRACE__V1__TRANSFER_FILTER__INIT;
    uint8_t packed[128];
    struct api_reply watched = {.events_as_expected = true};

    by_process.process = "ngin*";
    watch_request.filter = &by_process;
    size_t size = filetrace__v1__watch_transfers_request__pack(&watch_request, packed);
    ft_grpc_client_stream(client, "/filetrace.v1.FiletraceService/WatchTransfers", packed, size,
                          ft_clock_mono_ns() + 5 * FT_NS_PER_SEC, api_event, api_done, &watched);
    api_pump(client, &watched, enough_events);
    CHECK(watched.events >= 3);
    CHECK(watched.events_as_expected);
    CHECK(!watched.done);

    ft_grpc_client_free(client);
    close(pair[0]);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);
    CHECK(access(listen + 5, F_OK) != 0);
    rmdir(dir);
}

void test_agent(void)
{
    serves_queries_over_a_socket();
    serves_a_single_session();
    streams_events_to_a_follower();
    keeps_names_where_they_can_come_from();
    runs_on_small_pages();
    reports_a_backend_that_cannot_start();
    serves_metrics_to_a_scraper();
    exports_to_a_collector_that_appears_later();
    answers_grpc_calls();
}
