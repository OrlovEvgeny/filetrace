#include "unit/test.h"

#include "daemon/daemon.h"
#include "filetrace/client.h"
#include "filetrace/clock.h"

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

static const struct ft_backend_ops refusing_ops = {
    .name = "refusing",
    .open = refusing_open,
};

static void pause_ms(long ms)
{
    struct timespec ts = {ms / 1000, (ms % 1000) * 1'000'000};
    nanosleep(&ts, nullptr);
}

/* peer_fd is the client's end of a session socket, which the daemon must not hold. */
static pid_t start_daemon(const struct ft_backend_ops *ops, const char *socket_path, int session_fd,
                          int peer_fd)
{
    pid_t pid = fork();
    if (pid == 0) {
        struct ft_daemon_config cfg;
        struct ft_error err = {0};

        if (peer_fd >= 0)
            close(peer_fd);

        ft_daemon_config_defaults(&cfg);
        cfg.backend = ops;
        cfg.socket_path = socket_path;
        cfg.session_fd = session_fd;
        cfg.flush_interval_ms = 20;
        ft_log_set_level(FT_LOG_ERROR);
        _exit(ft_daemon_run(&cfg, &err));
    }
    return pid;
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
    snprintf(path, sizeof(path), "%s/daemon.sock", dir);

    pid_t pid = start_daemon(&scripted_ops, path, -1, -1);
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

    /* A path filter travels with the query and is applied by the daemon. */
    ft_query_init(&q, FT_Q_TRANSFERS);
    ft_strlcpy(q.path, "/nowhere/*", sizeof(q.path));
    r.rows = 0;
    CHECK_U64(ft_client_query(c, &q, on_row, &r, &end, &err), FT_EXIT_OK);
    CHECK_U64(r.rows, 0);

    /* A query the daemon cannot evaluate is an error, not an empty result. */
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

    /* A second daemon refuses to take over a socket that is being served. */
    pid_t second = start_daemon(&scripted_ops, path, -1, -1);
    CHECK_U64(wait_exit(second), FT_EXIT_ERROR);

    CHECK_U64(ft_client_shutdown(c, &err), FT_EXIT_OK);
    ft_client_close(c);
    CHECK_U64(wait_exit(pid), FT_EXIT_OK);

    CHECK(access(path, F_OK) != 0);
    CHECK(ft_client_connect(path, &err) == nullptr);
    CHECK_U64(err.code, FT_EXIT_NO_DAEMON);

    rmdir(dir);
    free(r.transfer);
}

static void serves_a_single_session(void)
{
    struct reply r = {.transfer = malloc(sizeof(struct ft_row_transfer))};
    struct ft_msg_end end = {0};
    int pair[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_daemon(&scripted_ops, nullptr, pair[1], pair[0]);
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

static void reports_a_backend_that_cannot_start(void)
{
    struct ft_error err = {0};
    struct ft_query q;
    int pair[2];

    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    pid_t pid = start_daemon(&refusing_ops, nullptr, pair[1], pair[0]);
    close(pair[1]);

    struct ft_client *c = ft_client_adopt(pair[0]);
    ft_query_init(&q, FT_Q_STATS);
    CHECK_U64(ft_client_query(c, &q, nullptr, nullptr, nullptr, &err), FT_EXIT_PERMISSION);
    CHECK_STR(err.msg, "Permission denied.");
    ft_client_close(c);
    CHECK_U64(wait_exit(pid), FT_EXIT_PERMISSION);
}

void test_daemon(void)
{
    serves_queries_over_a_socket();
    serves_a_single_session();
    reports_a_backend_that_cannot_start();
}
