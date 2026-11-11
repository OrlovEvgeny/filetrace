#include "unit/test.h"

#include "filetrace/clock.h"
#include "filetrace/state.h"

#include <stdlib.h>

constexpr uint64_t SOCK_A = 0x1001;
constexpr uint64_t SOCK_B = 0x1002;
constexpr uint32_t PID_A = 1842;
constexpr uint32_t PID_B = 2910;

struct collected {
    struct ft_row_process processes[16];
    struct ft_row_connection connections[16];
    struct ft_row_flow flows[16];
    struct ft_row_transfer *transfers;
    size_t count;
};

static void collect(void *ctx, uint16_t type, const void *row, size_t size)
{
    struct collected *c = ctx;
    if (c->count >= 16)
        return;
    switch (type) {
    case FT_MSG_ROW_PROCESS:
        memcpy(&c->processes[c->count], row, size);
        break;
    case FT_MSG_ROW_CONNECTION:
        memcpy(&c->connections[c->count], row, size);
        break;
    case FT_MSG_ROW_FLOW:
        memcpy(&c->flows[c->count], row, size);
        break;
    case FT_MSG_ROW_TRANSFER:
        memset(&c->transfers[c->count], 0, sizeof(c->transfers[0]));
        memcpy(&c->transfers[c->count], row, size);
        break;
    default:
        return;
    }
    c->count++;
}

struct fixture {
    struct ft_state *st;
    struct collected rows;
    struct ft_msg_end end;
    uint64_t now;
};

static void fixture_open(struct fixture *f)
{
    struct ft_state_config cfg;

    ft_state_config_defaults(&cfg);
    memset(f, 0, sizeof(*f));
    f->st = ft_state_create(&cfg);
    f->rows.transfers = calloc(16, sizeof(struct ft_row_transfer));
    f->now = ft_clock_mono_ns();
    f->st->start_ns = f->now;
}

static void fixture_close(struct fixture *f)
{
    ft_state_destroy(f->st);
    free(f->rows.transfers);
}

static void run_query(struct fixture *f, const struct ft_query *q)
{
    f->rows.count = 0;
    ft_state_query(f->st, q, f->now, collect, &f->rows, &f->end);
}

static struct ft_endpoint endpoint(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    uint8_t raw[16] = {a, b, c, d};
    struct ft_endpoint ep;
    ft_endpoint_set(&ep, false, raw, port);
    return ep;
}

static struct ft_file_id file_id(uint64_t ino)
{
    return (struct ft_file_id){.dev = 2049, .ino = ino};
}

static void emit_exec(struct fixture *f, uint32_t pid, uint32_t ppid, const char *comm,
                      uint64_t start_s)
{
    struct ft_event ev = {.type = FT_EVENT_PROCESS_EXEC, .ts_ns = f->now};
    ev.process.pid = pid;
    ev.process.ppid = ppid;
    ev.process.uid = 33;
    ev.process.start_ns = start_s * FT_NS_PER_SEC;
    ft_strlcpy(ev.process.comm, comm, sizeof(ev.process.comm));
    snprintf(ev.process.exe, sizeof(ev.process.exe), "/usr/sbin/%s", comm);
    ft_state_ingest(f->st, &ev);
}

static void emit_exit(struct fixture *f, uint32_t pid, uint64_t start_s)
{
    struct ft_event ev = {.type = FT_EVENT_PROCESS_EXIT, .ts_ns = f->now};
    ev.process.pid = pid;
    ev.process.start_ns = start_s * FT_NS_PER_SEC;
    ft_state_ingest(f->st, &ev);
}

static void emit_socket(struct fixture *f, uint64_t sock, uint32_t pid, enum ft_sock_state state,
                        struct ft_endpoint local, struct ft_endpoint remote)
{
    struct ft_event ev = {.type = FT_EVENT_SOCKET_STATE, .ts_ns = f->now};
    ev.socket.sock_id = sock;
    ev.socket.pid = pid;
    ev.socket.proto = FT_PROTO_TCP;
    ev.socket.state = state;
    ev.socket.local = local;
    ev.socket.remote = remote;
    ft_state_ingest(f->st, &ev);
}

static void emit_flow(struct fixture *f, uint64_t sock, uint32_t pid, uint16_t proto,
                      struct ft_endpoint remote, uint64_t tx, uint64_t rx)
{
    struct ft_event ev = {.type = FT_EVENT_FLOW, .ts_ns = f->now};
    ev.flow.sock_id = sock;
    ev.flow.pid = pid;
    ev.flow.proto = proto;
    ev.flow.local = endpoint(10, 0, 0, 10, 443);
    ev.flow.remote = remote;
    ev.flow.first_ns = f->now;
    ev.flow.tx_bytes = tx;
    ev.flow.rx_bytes = rx;
    ev.flow.tx_ops = tx ? 1 : 0;
    ev.flow.rx_ops = rx ? 1 : 0;
    ft_state_ingest(f->st, &ev);
}

static void emit_file(struct fixture *f, uint64_t ino, const char *path, bool deleted)
{
    struct ft_event ev = {.type = FT_EVENT_FILE_SEEN, .ts_ns = f->now};
    ev.file.id = file_id(ino);
    ev.file.path = path;
    ev.file.deleted = deleted;
    ft_strlcpy(ev.file.fs_type, "ext4", sizeof(ev.file.fs_type));
    ft_state_ingest(f->st, &ev);
}

static void emit_transfer(struct fixture *f, uint64_t sock, uint32_t pid, uint64_t ino,
                          enum ft_method method, uint64_t bytes, uint64_t read_bytes,
                          uint32_t alternations)
{
    struct ft_event ev = {.type = FT_EVENT_TRANSFER, .ts_ns = f->now};
    ev.transfer.sock_id = sock;
    ev.transfer.pid = pid;
    ev.transfer.method = method;
    ev.transfer.file = file_id(ino);
    ev.transfer.first_ns = f->now;
    ev.transfer.bytes = bytes;
    ev.transfer.read_bytes = read_bytes;
    ev.transfer.ops = 1;
    ev.transfer.alternations = alternations;
    ft_state_ingest(f->st, &ev);
}

static void sendfile_is_exact(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_endpoint remote = endpoint(203, 0, 113, 42, 52144);

    fixture_open(&f);
    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_file(&f, 928371, "/data/export/report.csv", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 148293012, 512);
    emit_transfer(&f, SOCK_A, PID_A, 928371, FT_METHOD_SENDFILE, 148293012, 0, 0);

    ft_query_init(&q, FT_Q_TRANSFERS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);

    const struct ft_row_transfer *t = &f.rows.transfers[0];
    CHECK_U64(t->confidence, FT_CONF_EXACT);
    CHECK_U64(t->method, FT_METHOD_SENDFILE);
    CHECK_U64(t->bytes, 148293012);
    CHECK_U64(t->pid, PID_A);
    CHECK_U64(t->ino, 928371);
    CHECK_U64(t->dev, 2049);
    CHECK_U64(t->remote.port, 52144);
    CHECK_STR(t->path, "/data/export/report.csv");
    CHECK_STR(t->comm, "nginx");
    CHECK_STR(t->exe, "/usr/sbin/nginx");
    CHECK_STR(t->fs_type, "ext4");
    CHECK(t->evidence & FT_EVD_DIRECT_TRANSFER);
    CHECK(t->evidence & FT_EVD_REMOTE_ENDPOINT);
    CHECK(!(t->evidence & FT_EVD_THREAD_SEQUENCE));
    CHECK(t->flags & FT_XFER_ACTIVE);
    CHECK(t->flags & FT_XFER_PATH_KNOWN);
    CHECK(!(t->flags & FT_XFER_INCOMPLETE));
    CHECK_U64(f.end.lost_events, 0);
    fixture_close(&f);
}

static void inference_needs_evidence(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_endpoint remote = endpoint(192, 0, 2, 10, 443);

    fixture_open(&f);
    emit_exec(&f, PID_B, 1, "python", 2000);
    emit_file(&f, 11, "/etc/ssl/certs/ca-certificates.crt", false);
    emit_file(&f, 12, "/data/export/customers.csv", false);
    emit_file(&f, 13, "/etc/hosts", false);
    emit_flow(&f, SOCK_A, PID_B, FT_PROTO_TCP, remote, 90000000, 4096);

    /* 517 bytes sent after reading a 200 KB file: not a transfer of it. */
    emit_transfer(&f, SOCK_A, PID_B, 11, FT_METHOD_READ_SEND, 517, 200000, 1);
    /* A handful of bytes after a tiny read: below the size threshold. */
    emit_transfer(&f, SOCK_A, PID_B, 13, FT_METHOD_READ_SEND, 40, 120, 1);
    /* Every read was followed by a send of the same size, many times over. */
    emit_transfer(&f, SOCK_A, PID_B, 12, FT_METHOD_READ_SEND, 89128960, 89128960, 1360);

    ft_query_init(&q, FT_Q_TRANSFERS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_STR(f.rows.transfers[0].path, "/data/export/customers.csv");
    CHECK_U64(f.rows.transfers[0].confidence, FT_CONF_INFERRED);
    CHECK(f.rows.transfers[0].evidence & FT_EVD_THREAD_SEQUENCE);
    CHECK(f.rows.transfers[0].evidence & FT_EVD_REPEATED);
    CHECK(f.rows.transfers[0].evidence & FT_EVD_BYTE_BALANCE);
    CHECK(!(f.rows.transfers[0].evidence & FT_EVD_DIRECT_TRANSFER));

    /* The rejected candidates are counted, and never upgraded by a filter. */
    struct ft_row_stats stats = {0};
    ft_state_fill_stats(f.st, f.now, &stats);
    CHECK_U64(stats.candidates_rejected, 2);
    q.confidence = FT_CONF_EXACT;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);

    /* A candidate is reported once enough of the file has followed. */
    emit_transfer(&f, SOCK_A, PID_B, 11, FT_METHOD_READ_SEND, 150000, 0, 3);
    ft_query_init(&q, FT_Q_TRANSFERS);
    ft_strlcpy(q.path, "/etc/ssl/*", sizeof(q.path));
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.transfers[0].bytes, 150517);
    CHECK(!(f.rows.transfers[0].evidence & FT_EVD_BYTE_BALANCE));
    fixture_close(&f);
}

static void unattributed_bytes(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_endpoint remote = endpoint(198, 51, 100, 5, 22);

    fixture_open(&f);
    emit_exec(&f, PID_A, 1, "backup-agent", 1000);
    emit_file(&f, 21, "/backups/db.tar.gz", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 1000000, 0);
    emit_flow(&f, SOCK_B, PID_A, FT_PROTO_TCP, endpoint(198, 51, 100, 6, 22), 5000, 0);
    emit_transfer(&f, SOCK_A, PID_A, 21, FT_METHOD_SENDFILE, 600000, 0, 0);

    ft_query_init(&q, FT_Q_TRANSFERS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);

    q.flags |= FT_QF_INCLUDE_UNKNOWN;
    q.sort = FT_SORT_BYTES;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 3);
    CHECK_U64(f.rows.transfers[0].bytes, 600000);
    CHECK_U64(f.rows.transfers[0].confidence, FT_CONF_EXACT);
    /* What the file does not account for stays visible, without a file. */
    CHECK_U64(f.rows.transfers[1].bytes, 400000);
    CHECK_U64(f.rows.transfers[1].confidence, FT_CONF_UNKNOWN);
    CHECK(!(f.rows.transfers[1].flags & FT_XFER_FILE_KNOWN));
    CHECK_U64(f.rows.transfers[1].remote.port, 22);
    CHECK_U64(f.rows.transfers[2].bytes, 5000);

    q.confidence = FT_CONF_UNKNOWN;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);

    /* A file filter never matches bytes that have no file. */
    q.confidence = FT_CONF_ANY;
    ft_strlcpy(q.path, "/backups/*", sizeof(q.path));
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    fixture_close(&f);
}

static void filters(void)
{
    struct fixture f;
    struct ft_query q;

    fixture_open(&f);
    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_exec(&f, PID_B, 1, "python", 2000);
    emit_file(&f, 31, "/var/www/video.mp4", false);
    emit_file(&f, 32, "/tmp/cache.bin", true);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(198, 51, 100, 4, 443), 1288490188, 0);
    emit_flow(&f, SOCK_B, PID_B, FT_PROTO_TCP, endpoint(192, 0, 2, 12, 8443), 12582912, 0);
    emit_transfer(&f, SOCK_A, PID_A, 31, FT_METHOD_SENDFILE, 1288490188, 0, 0);
    emit_transfer(&f, SOCK_B, PID_B, 32, FT_METHOD_READ_SEND, 12582912, 12582912, 192);

    ft_query_init(&q, FT_Q_TRANSFERS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.pid = PID_B;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_STR(f.rows.transfers[0].path, "/tmp/cache.bin");
    CHECK(f.rows.transfers[0].flags & FT_XFER_FILE_DELETED);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.min_bytes = 100 * 1024 * 1024;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_STR(f.rows.transfers[0].path, "/var/www/video.mp4");

    ft_query_init(&q, FT_Q_TRANSFERS);
    CHECK(ft_addr_parse("192.0.2.12", &q.remote));
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.transfers[0].pid, PID_B);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.flags = FT_QF_DELETED;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.method = FT_METHOD_SENDFILE;
    q.port = 443;
    ft_strlcpy(q.process, "ngin*", sizeof(q.process));
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.flags = FT_QF_COMPLETED;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);

    /* Nothing was active before observation began. */
    ft_query_init(&q, FT_Q_TRANSFERS);
    q.until_wall_ns = ft_clock_mono_to_wall(f.now) - 60 * FT_NS_PER_SEC;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.limit = 1;
    q.sort = FT_SORT_BYTES;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.transfers[0].bytes, 1288490188);
    fixture_close(&f);
}

static void process_lifecycle(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_endpoint remote = endpoint(203, 0, 113, 8, 443);

    fixture_open(&f);
    emit_exec(&f, 1, 0, "systemd", 10);
    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_exec(&f, PID_B, PID_A, "worker", 2000);
    emit_exec(&f, 4000, 1, "true", 3000);

    /* A short-lived process is reported as exited before its bytes arrive. */
    emit_exit(&f, PID_B, 2000);
    emit_exit(&f, 4000, 3000);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 1000, 50);
    emit_flow(&f, SOCK_B, PID_B, FT_PROTO_TCP, remote, 320, 4);

    f.now += 10 * FT_NS_PER_SEC;
    ft_state_sweep(f.st, f.now);
    uint32_t idle_pid = 4000;
    CHECK(ft_table_find(f.st->processes, &idle_pid) == nullptr);

    ft_query_init(&q, FT_Q_PROCESSES);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    CHECK_U64(f.rows.processes[0].pid, PID_A);
    CHECK_U64(f.rows.processes[0].tx_bytes, 1000);
    CHECK_U64(f.rows.processes[1].pid, PID_B);
    CHECK_STR(f.rows.processes[1].comm, "worker");
    CHECK_U64(f.rows.processes[1].ppid, PID_A);
    CHECK(f.rows.processes[1].flags & FT_PROC_EXITED);

    q.flags = FT_QF_INCLUDE_CHILDREN;
    run_query(&f, &q);
    CHECK_U64(f.rows.processes[0].tx_bytes, 1320);
    CHECK_U64(f.rows.processes[0].rx_bytes, 54);

    q.flags = FT_QF_ACTIVE;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.processes[0].pid, PID_A);

    /* The same PID with a different start time is a different process. */
    emit_exec(&f, PID_B, 1, "curl", 9000);
    uint32_t reused = PID_B;
    const struct ft_process *p = ft_table_find(f.st->processes, &reused);
    CHECK(p != nullptr);
    CHECK_STR(p->comm, "curl");
    CHECK_U64(p->tx_bytes, 0);
    CHECK(!p->exited);

    /* A start time rounded by the system still names the same process. */
    struct ft_event rounded = {.type = FT_EVENT_PROCESS_EXEC, .ts_ns = f.now};
    rounded.process.pid = PID_A;
    rounded.process.start_ns = 1000 * FT_NS_PER_SEC + 5 * FT_NS_PER_MS;
    ft_strlcpy(rounded.process.comm, "nginx", sizeof(rounded.process.comm));
    ft_state_ingest(f.st, &rounded);
    uint32_t same = PID_A;
    p = ft_table_find(f.st->processes, &same);
    CHECK_U64(p->tx_bytes, 1000);
    fixture_close(&f);
}

static void sockets_and_flows(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_endpoint local = endpoint(10, 0, 0, 10, 443);
    struct ft_endpoint remote = endpoint(203, 0, 113, 42, 52144);
    struct ft_endpoint gone = endpoint(10, 0, 0, 10, 0);

    fixture_open(&f);
    emit_exec(&f, PID_A, 1, "curl", 1000);
    emit_socket(&f, SOCK_A, PID_A, FT_SOCK_CONNECTING, local, remote);
    emit_socket(&f, SOCK_A, 0, FT_SOCK_ESTABLISHED, local, remote);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 700, 9000);

    ft_query_init(&q, FT_Q_CONNECTIONS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.connections[0].state, FT_SOCK_ESTABLISHED);
    CHECK_U64(f.rows.connections[0].pid, PID_A);
    CHECK_STR(f.rows.connections[0].comm, "curl");

    /* Closing keeps the endpoints that were observed while it was open. */
    emit_socket(&f, SOCK_A, 0, FT_SOCK_CLOSED, gone, remote);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.connections[0].state, FT_SOCK_CLOSED);
    CHECK_U64(f.rows.connections[0].local.port, 443);
    CHECK_U64(f.rows.connections[0].tx_bytes, 700);

    q.flags = FT_QF_ACTIVE;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);

    /* A socket first seen closing was never observed and is not listed. */
    emit_socket(&f, 0x2222, 0, FT_SOCK_CLOSED, local, remote);
    q.flags = 0;
    q.state = FT_SOCK_CLOSED;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);

    /* A datagram socket with several peers has no single remote endpoint. */
    emit_flow(&f, SOCK_B, PID_A, FT_PROTO_UDP, endpoint(192, 0, 2, 1, 53), 40, 0);
    emit_flow(&f, SOCK_B, PID_A, FT_PROTO_UDP, endpoint(192, 0, 2, 2, 53), 40, 0);
    ft_query_init(&q, FT_Q_CONNECTIONS);
    q.proto = FT_PROTO_UDP;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.connections[0].state, FT_SOCK_ACTIVE);
    CHECK_U64(f.rows.connections[0].remote.family, 0);
    CHECK_U64(f.rows.connections[0].tx_bytes, 80);

    ft_query_init(&q, FT_Q_FLOWS);
    q.proto = FT_PROTO_UDP;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);

    /* Without traffic a datagram socket turns idle. */
    f.now += 120 * FT_NS_PER_SEC;
    ft_query_init(&q, FT_Q_CONNECTIONS);
    q.proto = FT_PROTO_UDP;
    run_query(&f, &q);
    CHECK_U64(f.rows.connections[0].state, FT_SOCK_IDLE);
    fixture_close(&f);
}

static void loss_is_reported(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_endpoint remote = endpoint(203, 0, 113, 42, 443);

    fixture_open(&f);
    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_file(&f, 41, "/data/a.bin", false);
    emit_file(&f, 42, "/data/b.bin", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 5000, 0);
    emit_transfer(&f, SOCK_A, PID_A, 41, FT_METHOD_SENDFILE, 5000, 0, 0);

    uint64_t before_loss = f.now;
    f.now += 30 * FT_NS_PER_SEC;
    struct ft_event loss = {.type = FT_EVENT_LOSS, .ts_ns = f.now + FT_NS_PER_SEC};
    loss.loss.kind = FT_LOSS_EVENT_QUEUE;
    loss.loss.count = 124;
    loss.loss.since_ns = f.now;
    emit_flow(&f, SOCK_B, PID_A, FT_PROTO_TCP, remote, 7000, 0);
    emit_transfer(&f, SOCK_B, PID_A, 42, FT_METHOD_SENDFILE, 7000, 0, 0);
    f.now += FT_NS_PER_SEC;
    ft_state_ingest(f.st, &loss);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.sort = FT_SORT_BYTES;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    CHECK_U64(f.end.lost_events, 124);
    CHECK_U64(f.end.health, FT_HEALTH_DEGRADED);
    /* Only the transfer that overlaps the loss is marked. */
    CHECK(f.rows.transfers[0].flags & FT_XFER_INCOMPLETE);
    CHECK(!(f.rows.transfers[1].flags & FT_XFER_INCOMPLETE));

    /* A query confined to the clean period is complete. */
    q.until_wall_ns = ft_clock_mono_to_wall(before_loss + FT_NS_PER_SEC);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.end.lost_events, 0);
    CHECK_U64(f.end.health, FT_HEALTH_OK);

    struct ft_row_stats stats = {0};
    ft_state_fill_stats(f.st, f.now, &stats);
    CHECK_U64(stats.events_dropped, 124);
    CHECK_U64(stats.loss[FT_LOSS_EVENT_QUEUE], 124);
    CHECK_U64(stats.health, FT_HEALTH_DEGRADED);
    fixture_close(&f);
}

static void tables_stay_bounded(void)
{
    struct ft_state_config cfg;
    struct fixture f = {0};

    ft_state_config_defaults(&cfg);
    cfg.max_flows = 32;
    cfg.max_sockets = 32;
    cfg.max_transfers = 32;
    cfg.max_files = 32;
    f.st = ft_state_create(&cfg);
    f.now = ft_clock_mono_ns();
    f.rows.transfers = calloc(16, sizeof(struct ft_row_transfer));

    char path[64];
    for (uint64_t i = 0; i < 1000; i++) {
        snprintf(path, sizeof(path), "/data/file-%" PRIu64, i);
        emit_file(&f, 100 + i, path, false);
        emit_flow(&f, 5000 + i, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 1, 443), 2048, 0);
        emit_transfer(&f, 5000 + i, PID_A, 100 + i, FT_METHOD_SENDFILE, 2048, 0, 0);
    }

    struct ft_row_stats stats = {0};
    ft_state_fill_stats(f.st, f.now, &stats);
    CHECK_U64(stats.flows.count, 32);
    CHECK_U64(stats.transfers.count, 32);
    CHECK_U64(stats.files.count, 32);
    CHECK_U64(stats.transfers.evictions, 968);
    /* Totals survive the forgetting of individual records. */
    CHECK_U64(stats.tx_bytes, 2048 * 1000);
    fixture_close(&f);
}

void test_state(void)
{
    sendfile_is_exact();
    inference_needs_evidence();
    unattributed_bytes();
    filters();
    process_lifecycle();
    sockets_and_flows();
    loss_is_reported();
    tables_stay_bounded();
}
