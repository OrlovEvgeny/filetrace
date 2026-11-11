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
    struct ft_row_event *events;
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
    case FT_MSG_ROW_EVENT:
        memset(&c->events[c->count], 0, sizeof(c->events[0]));
        memcpy(&c->events[c->count], row, size);
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
    struct ft_error err;
    bool ok;
    uint64_t now;
};

static void fixture_open(struct fixture *f)
{
    struct ft_state_config cfg;

    ft_state_config_defaults(&cfg);
    memset(f, 0, sizeof(*f));
    f->st = ft_state_create(&cfg);
    f->rows.transfers = calloc(16, sizeof(struct ft_row_transfer));
    f->rows.events = calloc(16, sizeof(struct ft_row_event));
    f->now = ft_clock_mono_ns();
    f->st->start_ns = f->now;
}

static void fixture_close(struct fixture *f)
{
    ft_state_destroy(f->st);
    free(f->rows.transfers);
    free(f->rows.events);
}

static void run_query(struct fixture *f, const struct ft_query *q)
{
    f->rows.count = 0;
    f->ok = ft_state_query(f->st, q, f->now, collect, &f->rows, &f->end, &f->err);
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
    ev.file.size = ino * 1024 * 1024;
    ev.file.deleted = deleted;
    ft_strlcpy(ev.file.fs_type, "ext4", sizeof(ev.file.fs_type));
    ft_state_ingest(f->st, &ev);
}

static void emit_transfer_of(struct fixture *f, uint64_t sock, uint32_t pid, uint64_t ino,
                             enum ft_method method, uint64_t bytes, uint64_t read_bytes,
                             uint32_t alternations, bool background)
{
    struct ft_event ev = {.type = FT_EVENT_TRANSFER, .ts_ns = f->now};
    ev.transfer.background = background;
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

static void emit_transfer(struct fixture *f, uint64_t sock, uint32_t pid, uint64_t ino,
                          enum ft_method method, uint64_t bytes, uint64_t read_bytes,
                          uint32_t alternations)
{
    emit_transfer_of(f, sock, pid, ino, method, bytes, read_bytes, alternations, false);
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
    q.flags = FT_QF_PATH_REGEX;
    ft_strlcpy(q.path, "^/var/www/.*\\.(mp4|mkv)$", sizeof(q.path));
    run_query(&f, &q);
    CHECK(f.ok);
    CHECK_U64(f.rows.count, 1);
    CHECK_STR(f.rows.transfers[0].path, "/var/www/video.mp4");

    ft_strlcpy(q.path, "(unclosed", sizeof(q.path));
    run_query(&f, &q);
    CHECK(!f.ok);
    CHECK_U64(f.err.code, FT_EXIT_USAGE);
    CHECK(strstr(f.err.msg, "(unclosed") != nullptr);

    /* File 32 is 32 MB, file 31 one megabyte less. */
    ft_query_init(&q, FT_Q_TRANSFERS);
    q.min_size = 32 * 1024 * 1024;
    q.flags = FT_QF_INCLUDE_UNKNOWN;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_STR(f.rows.transfers[0].path, "/tmp/cache.bin");
    CHECK_U64(f.rows.transfers[0].file_size, 32 * 1024 * 1024);

    /* A transfer and a flow belong to the user of the process behind them. */
    ft_query_init(&q, FT_Q_TRANSFERS);
    q.flags = FT_QF_HAS_UID;
    q.uid = 33;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    q.uid = 1000;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);
    ft_query_init(&q, FT_Q_FLOWS);
    q.flags = FT_QF_HAS_UID;
    q.uid = 1000;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);

    /* The host bits of a network are left out of the comparison. */
    ft_query_init(&q, FT_Q_TRANSFERS);
    CHECK(ft_addr_parse("198.51.100.0", &q.remote));
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);
    q.remote_host_bits = 8;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.transfers[0].pid, PID_A);

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

    /* Every flow keeps the id it was given, and a query can name a flow or a socket. */
    uint64_t flow_id = f.rows.flows[0].id;
    struct ft_endpoint flow_remote = f.rows.flows[0].remote;
    CHECK(flow_id != 0 && flow_id != f.rows.flows[1].id);
    ft_query_init(&q, FT_Q_FLOWS);
    q.flow_id = flow_id;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK(ft_addr_equal(&f.rows.flows[0].remote, &flow_remote));
    ft_query_init(&q, FT_Q_FLOWS);
    q.sock_id = SOCK_A;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.flows[0].tx_bytes, 700);
    ft_query_init(&q, FT_Q_CONNECTIONS);
    q.sock_id = SOCK_B;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.connections[0].proto, FT_PROTO_UDP);

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

static void reused_inode_is_another_file(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_endpoint remote = endpoint(203, 0, 113, 42, 443);

    fixture_open(&f);
    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 9000, 0);

    /* The same device and inode number, first for one file and then for its successor. */
    struct ft_event ev = {.type = FT_EVENT_FILE_SEEN, .ts_ns = f.now};
    ev.file.id = (struct ft_file_id){.dev = 2049, .ino = 77, .instance = 1};
    ev.file.path = "/data/old.bin";
    ev.file.deleted = true;
    ft_state_ingest(f.st, &ev);
    ev.file.id.instance = 2;
    ev.file.path = "/data/new.bin";
    ev.file.deleted = false;
    ft_state_ingest(f.st, &ev);

    for (uint32_t instance = 1; instance <= 2; instance++) {
        struct ft_event xfer = {.type = FT_EVENT_TRANSFER, .ts_ns = f.now};
        xfer.transfer.sock_id = SOCK_A;
        xfer.transfer.pid = PID_A;
        xfer.transfer.method = FT_METHOD_SENDFILE;
        xfer.transfer.file = (struct ft_file_id){.dev = 2049, .ino = 77, .instance = instance};
        xfer.transfer.first_ns = f.now;
        xfer.transfer.bytes = 1000 * instance;
        ft_state_ingest(f.st, &xfer);
    }

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.sort = FT_SORT_BYTES;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    CHECK_STR(f.rows.transfers[0].path, "/data/new.bin");
    CHECK_U64(f.rows.transfers[0].bytes, 2000);
    CHECK(!(f.rows.transfers[0].flags & FT_XFER_FILE_DELETED));
    CHECK_STR(f.rows.transfers[1].path, "/data/old.bin");
    CHECK_U64(f.rows.transfers[1].bytes, 1000);
    CHECK(f.rows.transfers[1].flags & FT_XFER_FILE_DELETED);
    CHECK_U64(f.rows.transfers[0].ino, f.rows.transfers[1].ino);
    fixture_close(&f);
}

static void processes_count_their_files(void)
{
    struct fixture f;
    struct ft_query q;

    fixture_open(&f);
    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_exec(&f, PID_B, PID_A, "nginx", 1001);
    emit_file(&f, 11, "/var/www/a.bin", false);
    emit_file(&f, 12, "/var/www/b.bin", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 1, 443), 3000, 0);
    emit_flow(&f, SOCK_B, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 2, 443), 1000, 0);
    emit_flow(&f, 0x1003, PID_B, FT_PROTO_TCP, endpoint(203, 0, 113, 3, 443), 500, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 1000, 0, 0);
    emit_transfer(&f, SOCK_A, PID_A, 12, FT_METHOD_SENDFILE, 2000, 0, 0);
    emit_transfer(&f, SOCK_B, PID_A, 11, FT_METHOD_SENDFILE, 1000, 0, 0);
    emit_transfer(&f, 0x1003, PID_B, 11, FT_METHOD_SENDFILE, 500, 0, 0);

    /* The same file sent over two sockets is two transfers of one file. */
    ft_query_init(&q, FT_Q_PROCESSES);
    q.pid = PID_A;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.processes[0].files, 2);
    CHECK_U64(f.rows.processes[0].transfers, 3);
    CHECK_U64(f.rows.processes[0].active_transfers, 3);

    q.flags = FT_QF_INCLUDE_CHILDREN;
    run_query(&f, &q);
    CHECK_U64(f.rows.processes[0].transfers, 4);
    CHECK_U64(f.rows.processes[0].tx_bytes, 4500);

    f.now += 60 * FT_NS_PER_SEC;
    q.flags = 0;
    run_query(&f, &q);
    CHECK_U64(f.rows.processes[0].transfers, 3);
    CHECK_U64(f.rows.processes[0].active_transfers, 0);
    fixture_close(&f);
}

static void rates_cover_recent_seconds(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_row_stats stats = {0};

    fixture_open(&f);
    f.now = 1000 * FT_NS_PER_SEC + 500 * FT_NS_PER_MS;
    emit_exec(&f, PID_A, 1, "nginx", 900);
    emit_file(&f, 11, "/data/steady.bin", false);
    emit_file(&f, 12, "/data/finished.bin", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 1, 443), 3'000'000, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 3'000'000, 0, 0);

    /* Half a second into the current second, the window is a second and a half. */
    ft_query_init(&q, FT_Q_PROCESSES);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.processes[0].tx_rate, 2'000'000);
    CHECK_U64(f.rows.processes[0].rx_rate, 0);

    f.now = 1001 * FT_NS_PER_SEC;
    ft_query_init(&q, FT_Q_FLOWS);
    run_query(&f, &q);
    CHECK_U64(f.rows.flows[0].tx_rate, 3'000'000);
    ft_query_init(&q, FT_Q_CONNECTIONS);
    run_query(&f, &q);
    CHECK_U64(f.rows.connections[0].tx_rate, 3'000'000);
    ft_state_fill_stats(f.st, f.now, &stats);
    CHECK_U64(stats.tx_rate, 3'000'000);

    /* A larger transfer that has gone quiet ranks below one still moving. */
    emit_flow(&f, SOCK_B, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 2, 443), 9'000'000, 0);
    emit_transfer(&f, SOCK_B, PID_A, 12, FT_METHOD_SENDFILE, 9'000'000, 0, 0);
    f.now = 1003 * FT_NS_PER_SEC;
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 1, 443), 1'000'000, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 1'000'000, 0, 0);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.sort = FT_SORT_RATE;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    CHECK_STR(f.rows.transfers[0].path, "/data/steady.bin");
    CHECK_U64(f.rows.transfers[0].rate, 1'000'000);
    CHECK_U64(f.rows.transfers[1].rate, 0);
    q.sort = FT_SORT_BYTES;
    run_query(&f, &q);
    CHECK_STR(f.rows.transfers[0].path, "/data/finished.bin");
    q.sort = FT_SORT_FILE;
    run_query(&f, &q);
    CHECK_STR(f.rows.transfers[0].path, "/data/finished.bin");
    CHECK_STR(f.rows.transfers[1].path, "/data/steady.bin");
    /* The steady transfer ran from 1000.5 s to 1003 s, the other within one instant. */
    q.sort = FT_SORT_DURATION;
    run_query(&f, &q);
    CHECK_STR(f.rows.transfers[0].path, "/data/steady.bin");

    f.now = 1006 * FT_NS_PER_SEC;
    ft_query_init(&q, FT_Q_PROCESSES);
    run_query(&f, &q);
    CHECK_U64(f.rows.processes[0].tx_rate, 0);
    fixture_close(&f);
}

static void emit_loss(struct fixture *f, uint64_t count)
{
    struct ft_event ev = {.type = FT_EVENT_LOSS, .ts_ns = f->now};
    ev.loss.kind = FT_LOSS_EVENT_QUEUE;
    ev.loss.count = count;
    ev.loss.since_ns = f->now;
    ft_state_ingest(f->st, &ev);
}

static void events_are_logged_in_order(void)
{
    static const uint8_t expected[] = {
        FT_REC_PROCESS_EXEC, FT_REC_SOCKET_CONNECT, FT_REC_NETWORK_SEND, FT_REC_NETWORK_RECEIVE,
        FT_REC_FILE_SEEN,    FT_REC_FILE_TRANSFER,  FT_REC_EVENT_LOSS,
    };
    struct ft_endpoint local = endpoint(10, 0, 0, 10, 443);
    struct ft_endpoint remote = endpoint(203, 0, 113, 42, 52144);
    struct fixture f;
    struct ft_query q;

    fixture_open(&f);
    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_socket(&f, SOCK_A, PID_A, FT_SOCK_CONNECTING, local, remote);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 700, 9000);
    emit_file(&f, 11, "/var/www/a.bin", false);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 4096, 0, 0);
    emit_loss(&f, 3);

    ft_query_init(&q, FT_Q_EVENTS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, FT_ARRAY_LEN(expected));
    for (size_t i = 0; i < FT_ARRAY_LEN(expected) && i < f.rows.count; i++) {
        CHECK_U64(f.rows.events[i].type, expected[i]);
        CHECK_U64(f.rows.events[i].seq, i + 1);
    }
    CHECK_STR(f.rows.events[0].text, "/usr/sbin/nginx");
    CHECK_U64(f.rows.events[2].bytes, 700);
    CHECK_U64(f.rows.events[3].bytes, 9000);
    CHECK_STR(f.rows.events[3].comm, "nginx");
    CHECK_U64(f.rows.events[4].file_size, 11 * 1024 * 1024);
    CHECK_U64(f.rows.events[6].bytes, 3);

    const struct ft_row_event *transfer = &f.rows.events[5];
    CHECK_U64(transfer->bytes, 4096);
    CHECK_U64(transfer->method, FT_METHOD_SENDFILE);
    CHECK(transfer->flags & FT_EVENT_HAS_CONFIDENCE);
    CHECK_U64(transfer->confidence, FT_CONF_EXACT);
    CHECK_U64(transfer->pid, PID_A);
    CHECK_U64(transfer->remote.port, 52144);
    CHECK_STR(transfer->text, "/var/www/a.bin");

    ft_query_init(&q, FT_Q_EVENTS);
    q.event_types = 1u << FT_REC_FILE_TRANSFER | 1u << FT_REC_FILE_SEEN;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);

    /* A network filter leaves out the records that have no socket. */
    ft_query_init(&q, FT_Q_EVENTS);
    CHECK(ft_addr_parse("203.0.113.0", &q.remote));
    q.remote_host_bits = 8;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 4);
    CHECK_U64(f.rows.events[3].type, FT_REC_FILE_TRANSFER);

    ft_query_init(&q, FT_Q_EVENTS);
    ft_strlcpy(q.path, "/var/www/*", sizeof(q.path));
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);

    /* A limit keeps the most recent records, still oldest first. */
    ft_query_init(&q, FT_Q_EVENTS);
    q.limit = 2;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    CHECK_U64(f.rows.events[0].type, FT_REC_FILE_TRANSFER);
    CHECK_U64(f.rows.events[1].type, FT_REC_EVENT_LOSS);

    ft_query_init(&q, FT_Q_EVENTS);
    q.since_wall_ns = ft_clock_mono_to_wall(f.now) + 60 * FT_NS_PER_SEC;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);

    /* Bytes counted before the last record but collected after it do not turn time back. */
    f.now -= 5 * FT_NS_PER_MS;
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 100, 0);
    ft_query_init(&q, FT_Q_EVENTS);
    q.limit = 2;
    run_query(&f, &q);
    CHECK_U64(f.rows.events[1].type, FT_REC_NETWORK_SEND);
    CHECK(f.rows.events[1].time_ns >= f.rows.events[0].time_ns);
    fixture_close(&f);
}

static void event_log_keeps_the_most_recent(void)
{
    struct ft_evlog *log = ft_evlog_create(1000);
    struct ft_row_event *row = calloc(2, sizeof(*row));
    struct ft_evlog_cursor cur;

    /* Each record takes 4 bytes for its size and 160 for itself. */
    for (uint64_t seq = 1; seq <= 100; seq++) {
        row->seq = seq;
        snprintf(row->text, sizeof(row->text), "/data/%09" PRIu64, seq);
        CHECK_U64(ft_row_event_size(row), 160);
        ft_evlog_append(log, row, ft_row_event_size(row));
    }
    CHECK_U64(ft_evlog_records(log), 6);
    CHECK_U64(ft_evlog_discarded(log), 94);

    uint64_t expected = 95;
    for (ft_evlog_rewind(log, &cur); ft_evlog_peek(log, &cur, &row[1]);
         ft_evlog_advance(log, &cur)) {
        char path[32];
        snprintf(path, sizeof(path), "/data/%09" PRIu64, expected);
        CHECK_U64(row[1].seq, expected);
        CHECK_STR(row[1].text, path);
        expected++;
    }
    CHECK_U64(expected, 101);

    /* A record larger than the whole log is not stored and displaces nothing. */
    ft_evlog_append(log, row, 2000);
    CHECK_U64(ft_evlog_records(log), 6);
    ft_evlog_destroy(log);
    free(row);
}

static void event_floods_stay_in_their_class(void)
{
    struct ft_state_config cfg;
    struct fixture f = {0};
    struct ft_query q;

    ft_state_config_defaults(&cfg);
    cfg.event_log_bytes = 64 * 1024;
    f.st = ft_state_create(&cfg);
    f.now = ft_clock_mono_ns();
    f.st->start_ns = f.now;
    f.rows.transfers = calloc(16, sizeof(struct ft_row_transfer));
    f.rows.events = calloc(16, sizeof(struct ft_row_event));

    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_file(&f, 11, "/var/www/a.bin", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 1, 443), 4096, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 4096, 0, 0);
    f.now += FT_NS_PER_SEC;
    for (uint32_t i = 0; i < 2000; i++)
        emit_exec(&f, 5000 + i, 1, "sh", 2000 + i);

    ft_query_init(&q, FT_Q_EVENTS);
    q.event_types = 1u << FT_REC_FILE_TRANSFER;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    uint64_t start = f.end.observed_since_wall_ns;

    /* The process records pushed out their own oldest, and the answer says from when. */
    q.event_types = 1u << FT_REC_PROCESS_EXEC;
    q.limit = 1;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.events[0].pid, 6999);
    CHECK(f.end.observed_since_wall_ns > start);
    fixture_close(&f);
}

static void fixture_open_with(struct fixture *f, const struct ft_state_config *cfg)
{
    memset(f, 0, sizeof(*f));
    f->st = ft_state_create(cfg);
    f->rows.transfers = calloc(16, sizeof(struct ft_row_transfer));
    f->rows.events = calloc(16, sizeof(struct ft_row_event));
    f->now = ft_clock_mono_ns();
    f->st->start_ns = f->now;
}

static bool listed_row(const struct fixture *f, const char *path)
{
    for (size_t i = 0; i < f->rows.count; i++) {
        if (strcmp(f->rows.transfers[i].path, path) == 0)
            return f->rows.transfers[i].confidence == FT_CONF_INFERRED;
    }
    return false;
}

/* A listed file is reported however few bytes followed its read; the others keep the minimums. */
static void listed_files_have_no_minimum(void)
{
    static const char *const listed[] = {"/etc/host*", "/home/*/.aws/*"};
    struct ft_state_config cfg;
    struct fixture f;
    struct ft_query q;

    ft_state_config_defaults(&cfg);
    cfg.no_minimum_paths = listed;
    cfg.no_minimum_path_count = FT_ARRAY_LEN(listed);
    fixture_open_with(&f, &cfg);
    emit_exec(&f, PID_B, 1, "python", 2000);
    emit_file(&f, 11, "/etc/ssl/certs/ca-certificates.crt", false);
    emit_file(&f, 13, "/etc/hosts", false);
    emit_file(&f, 14, "/home/dev/.aws/credentials", false);
    emit_flow(&f, SOCK_A, PID_B, FT_PROTO_TCP, endpoint(192, 0, 2, 10, 443), 90000000, 4096);

    /* Below both minimums: the /etc/hosts case of inference_needs_evidence, listed here. */
    emit_transfer(&f, SOCK_A, PID_B, 13, FT_METHOD_READ_SEND, 40, 120, 1);
    emit_transfer(&f, SOCK_A, PID_B, 14, FT_METHOD_READ_SEND, 200, 200, 1);
    /* Below the percentage and not listed. */
    emit_transfer(&f, SOCK_A, PID_B, 11, FT_METHOD_READ_SEND, 517, 200000, 1);
    /* Sent before its path is known: unlisted until then, listed after. */
    emit_transfer(&f, SOCK_A, PID_B, 15, FT_METHOD_READ_SEND, 30, 30, 1);

    ft_query_init(&q, FT_Q_TRANSFERS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    CHECK(listed_row(&f, "/etc/hosts"));
    CHECK(listed_row(&f, "/home/dev/.aws/credentials"));

    emit_file(&f, 15, "/etc/hostname", false);
    emit_transfer(&f, SOCK_A, PID_B, 15, FT_METHOD_READ_SEND, 10, 10, 1);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 3);
    CHECK(listed_row(&f, "/etc/hostname"));
    CHECK(!listed_row(&f, "/etc/ssl/certs/ca-certificates.crt"));
    fixture_close(&f);

    /* The list does not lower confidence_threshold = "exact". */
    cfg.min_confidence = FT_CONF_EXACT;
    fixture_open_with(&f, &cfg);
    emit_exec(&f, PID_B, 1, "python", 2000);
    emit_file(&f, 13, "/etc/hosts", false);
    emit_flow(&f, SOCK_A, PID_B, FT_PROTO_TCP, endpoint(192, 0, 2, 10, 443), 90000000, 4096);
    emit_transfer(&f, SOCK_A, PID_B, 13, FT_METHOD_READ_SEND, 40, 120, 1);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);
    fixture_close(&f);
}

/* A background file counts as sent only when a send took all that was read of it. */
static void background_files_need_the_whole_read(void)
{
    static const char *const listed[] = {"/etc/passwd"};
    struct ft_state_config cfg;
    struct fixture f;
    struct ft_query q;

    ft_state_config_defaults(&cfg);
    fixture_open_with(&f, &cfg);
    emit_exec(&f, PID_B, 1, "curl", 2000);
    emit_file(&f, 11, "/etc/ssl/certs/ca-certificates.crt", false);
    emit_file(&f, 12, "/etc/gai.conf", false);
    emit_file(&f, 13, "/srv/upload/passwd-copy", false);
    emit_flow(&f, SOCK_A, PID_B, FT_PROTO_TCP, endpoint(192, 0, 2, 10, 443), 90000000, 4096);

    /* Part of each read went: a ClientHello after the bundle, a request after gai.conf. */
    emit_transfer_of(&f, SOCK_A, PID_B, 11, FT_METHOD_READ_SEND, 60000, 200000, 1, true);
    emit_transfer_of(&f, SOCK_A, PID_B, 12, FT_METHOD_READ_SEND, 1551, 2584, 1, true);
    /* All of it went: a whole file uploaded. */
    emit_transfer_of(&f, SOCK_A, PID_B, 13, FT_METHOD_READ_SEND, 4096, 4096, 1, true);

    ft_query_init(&q, FT_Q_TRANSFERS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK(listed_row(&f, "/srv/upload/passwd-copy"));
    fixture_close(&f);

    /* The minimums still apply, and no_minimum_paths lifts them as for any file. */
    fixture_open_with(&f, &cfg);
    emit_exec(&f, PID_B, 1, "curl", 2000);
    emit_file(&f, 14, "/etc/passwd", false);
    emit_flow(&f, SOCK_A, PID_B, FT_PROTO_TCP, endpoint(192, 0, 2, 10, 443), 90000000, 4096);
    emit_transfer_of(&f, SOCK_A, PID_B, 14, FT_METHOD_READ_SEND, 839, 839, 1, true);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);
    fixture_close(&f);

    cfg.no_minimum_paths = listed;
    cfg.no_minimum_path_count = FT_ARRAY_LEN(listed);
    fixture_open_with(&f, &cfg);
    emit_exec(&f, PID_B, 1, "curl", 2000);
    emit_file(&f, 14, "/etc/passwd", false);
    emit_flow(&f, SOCK_A, PID_B, FT_PROTO_TCP, endpoint(192, 0, 2, 10, 443), 90000000, 4096);
    emit_transfer_of(&f, SOCK_A, PID_B, 14, FT_METHOD_READ_SEND, 300, 839, 1, true);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);
    emit_transfer_of(&f, SOCK_A, PID_B, 14, FT_METHOD_READ_SEND, 539, 0, 1, true);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK(listed_row(&f, "/etc/passwd"));
    fixture_close(&f);
}

static void configured_exclusions(void)
{
    static const char *const processes[] = {"systemd*", "sshd"};
    static const char *const paths[] = {"/proc/*", "/sys/*"};
    struct ft_state_config cfg;
    struct fixture f;
    struct ft_query q;

    ft_state_config_defaults(&cfg);
    cfg.exclude_processes = processes;
    cfg.exclude_process_count = FT_ARRAY_LEN(processes);
    cfg.exclude_paths = paths;
    cfg.exclude_path_count = FT_ARRAY_LEN(paths);
    cfg.ignore_udp = true;
    cfg.ignore_ipv6 = true;
    fixture_open_with(&f, &cfg);

    emit_exec(&f, PID_A, 1, "nginx", 1000);
    emit_exec(&f, PID_B, 1, "systemd-resolve", 1001);
    emit_file(&f, 11, "/var/www/a.bin", false);
    emit_file(&f, 12, "/proc/meminfo", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 1, 443), 5000, 0);
    emit_flow(&f, SOCK_B, PID_B, FT_PROTO_TCP, endpoint(203, 0, 113, 2, 443), 7000, 0);
    emit_flow(&f, 0x1003, PID_A, FT_PROTO_UDP, endpoint(203, 0, 113, 3, 53), 300, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 2000, 0, 0);
    emit_transfer(&f, SOCK_A, PID_A, 12, FT_METHOD_SENDFILE, 1000, 0, 0);
    emit_transfer(&f, SOCK_B, PID_B, 11, FT_METHOD_SENDFILE, 7000, 0, 0);
    emit_transfer(&f, 0x1003, PID_A, 11, FT_METHOD_SENDFILE, 300, 0, 0);

    /* Neither the excluded process nor the ignored protocol left any trace. */
    ft_query_init(&q, FT_Q_PROCESSES);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.processes[0].pid, PID_A);
    CHECK_U64(f.rows.processes[0].tx_bytes, 5000);
    ft_query_init(&q, FT_Q_CONNECTIONS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    ft_query_init(&q, FT_Q_TRANSFERS);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_STR(f.rows.transfers[0].path, "/var/www/a.bin");
    CHECK_U64(f.rows.transfers[0].bytes, 2000);

    /* The bytes of an excluded file stay counted on the socket, without a file. */
    q.flags = FT_QF_INCLUDE_UNKNOWN;
    q.confidence = FT_CONF_UNKNOWN;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    CHECK_U64(f.rows.transfers[0].bytes, 3000);

    ft_query_init(&q, FT_Q_EVENTS);
    q.pid = PID_B;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 0);
    struct ft_row_stats stats = {0};
    ft_state_fill_stats(f.st, f.now, &stats);
    CHECK_U64(stats.tx_bytes, 5000);
    fixture_close(&f);
}

static void confidence_threshold(void)
{
    struct ft_state_config cfg;
    struct fixture f;
    struct ft_query q;

    ft_state_config_defaults(&cfg);
    cfg.min_confidence = FT_CONF_EXACT;
    fixture_open_with(&f, &cfg);
    emit_exec(&f, PID_A, 1, "python", 1000);
    emit_file(&f, 11, "/data/exact.bin", false);
    emit_file(&f, 12, "/data/inferred.bin", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 1, 443), 200000, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 100000, 0, 0);
    emit_transfer(&f, SOCK_A, PID_A, 12, FT_METHOD_READ_SEND, 100000, 100000, 8);

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.flags = FT_QF_INCLUDE_UNKNOWN;
    q.sort = FT_SORT_FILE;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    CHECK_STR(f.rows.transfers[0].path, "/data/exact.bin");
    /* What the inferred association would have claimed is reported as unattributed. */
    CHECK_U64(f.rows.transfers[1].confidence, FT_CONF_UNKNOWN);
    CHECK_U64(f.rows.transfers[1].bytes, 100000);
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

/* What /proc holds for a few processes; arguments are written with '|' for the NULs. */
static struct {
    uint32_t pid;
    char args[FT_CMDLINE_MAX];
    size_t len;
    char cwd[FT_PATH_MAX];
} procfs[4];
static unsigned procfs_reads;

static void procfs_set(uint32_t pid, const char *args, const char *cwd)
{
    size_t slot = 0;
    while (slot + 1 < FT_ARRAY_LEN(procfs) && procfs[slot].pid && procfs[slot].pid != pid)
        slot++;
    procfs[slot].pid = pid;
    procfs[slot].len = 0;
    for (const char *p = args; *p && procfs[slot].len + 1 < sizeof(procfs[slot].args); p++)
        procfs[slot].args[procfs[slot].len++] = *p == '|' ? '\0' : *p;
    procfs[slot].args[procfs[slot].len++] = '\0';
    ft_strlcpy(procfs[slot].cwd, cwd, sizeof(procfs[slot].cwd));
}

static void procfs_clear(void)
{
    memset(procfs, 0, sizeof(procfs));
    procfs_reads = 0;
}

static bool procfs_read(uint32_t pid, struct ft_process_text *out)
{
    procfs_reads++;
    for (size_t i = 0; i < FT_ARRAY_LEN(procfs); i++) {
        if (procfs[i].pid != pid)
            continue;
        out->args_len = procfs[i].len < sizeof(out->args) ? procfs[i].len : sizeof(out->args);
        memcpy(out->args, procfs[i].args, out->args_len);
        ft_strlcpy(out->cwd, procfs[i].cwd, sizeof(out->cwd));
        return true;
    }
    return false;
}

static void fixture_open_procfs(struct fixture *f, bool arguments)
{
    struct ft_state_config cfg;

    ft_state_config_defaults(&cfg);
    cfg.read_process_text = procfs_read;
    cfg.command_line_arguments = arguments;
    procfs_clear();
    fixture_open_with(f, &cfg);
}

static void emit_fork(struct fixture *f, uint32_t pid, uint32_t ppid, const char *comm,
                      uint64_t start_s)
{
    struct ft_event ev = {.type = FT_EVENT_PROCESS_FORK, .ts_ns = f->now};
    ev.process.pid = pid;
    ev.process.ppid = ppid;
    ev.process.start_ns = start_s * FT_NS_PER_SEC;
    ft_strlcpy(ev.process.comm, comm, sizeof(ev.process.comm));
    ft_state_ingest(f->st, &ev);
}

static struct ft_process_strings transfer_strings(struct fixture *f, uint32_t pid)
{
    struct ft_process_strings s = {"", "", ""};
    struct ft_query q;

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.pid = pid;
    run_query(f, &q);
    if (f->rows.count == 1)
        ft_row_transfer_strings(&f->rows.transfers[0], &s);
    return s;
}

/* An interpreter's records say what it runs, as read when it started it. */
static void processes_carry_their_command_line(void)
{
    struct fixture f;
    struct ft_query q;
    struct ft_process_strings s;
    struct ft_endpoint remote = endpoint(203, 0, 113, 42, 443);

    fixture_open_procfs(&f, true);
    procfs_set(PID_A, "python3|-W|ignore|export.py|--token=abc", "/srv/app");
    emit_exec(&f, PID_A, 1, "python3", 1000);
    emit_file(&f, 11, "/data/users.csv", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 4096, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 4096, 0, 0);

    s = transfer_strings(&f, PID_A);
    CHECK_STR(s.command_line, "python3 -W ignore export.py --token=abc");
    CHECK_STR(s.cwd, "/srv/app");
    CHECK_STR(s.script, "/srv/app/export.py");
    CHECK_U64(ft_row_transfer_size(&f.rows.transfers[0]),
              offsetof(struct ft_row_transfer, path) + sizeof("/data/users.csv") +
                  sizeof("python3 -W ignore export.py --token=abc") + sizeof("/srv/app") +
                  sizeof("/srv/app/export.py"));

    ft_query_init(&q, FT_Q_PROCESSES);
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 1);
    ft_row_process_strings(&f.rows.processes[0], &s);
    CHECK_STR(s.script, "/srv/app/export.py");
    CHECK_STR(s.cwd, "/srv/app");

    ft_query_init(&q, FT_Q_EVENTS);
    q.event_types = 1u << FT_REC_PROCESS_EXEC | 1u << FT_REC_FILE_TRANSFER;
    run_query(&f, &q);
    CHECK_U64(f.rows.count, 2);
    ft_row_event_strings(&f.rows.events[0], &s);
    CHECK_STR(f.rows.events[0].text, "/usr/sbin/python3");
    CHECK_STR(s.command_line, "python3 -W ignore export.py --token=abc");
    ft_row_event_strings(&f.rows.events[1], &s);
    CHECK_STR(f.rows.events[1].text, "/data/users.csv");
    CHECK_STR(s.script, "/srv/app/export.py");

    /* The script keeps the directory it was started in; the directory itself follows. */
    procfs_set(PID_A, "python3|-W|ignore|export.py|--token=abc", "/tmp");
    unsigned reads = procfs_reads;
    f.now += FT_NS_PER_SEC;
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 10, 0);
    CHECK_U64(procfs_reads, reads);
    f.now += 10 * FT_NS_PER_SEC;
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 10, 0);
    CHECK_U64(procfs_reads, reads + 1);
    s = transfer_strings(&f, PID_A);
    CHECK_STR(s.cwd, "/tmp");
    CHECK_STR(s.script, "/srv/app/export.py");

    /* Once it has exited its ID is not read again: another process may hold it. */
    emit_exit(&f, PID_A, 1000);
    procfs_set(PID_A, "sshd", "/");
    f.now += 30 * FT_NS_PER_SEC;
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, remote, 10, 0);
    s = transfer_strings(&f, PID_A);
    CHECK_STR(s.command_line, "python3 -W ignore export.py --token=abc");

    /* A program that is gone before its start is read leaves nothing behind. */
    procfs_set(PID_B, "python3|old.py", "/srv");
    emit_exec(&f, PID_B, 1, "python3", 2000);
    procfs_set(PID_B, "", "");
    procfs[1].pid = 0;
    emit_exec(&f, PID_B, 1, "python3", 2000);
    emit_flow(&f, SOCK_B, PID_B, FT_PROTO_TCP, remote, 4096, 0);
    emit_transfer(&f, SOCK_B, PID_B, 11, FT_METHOD_SENDFILE, 4096, 0, 0);
    s = transfer_strings(&f, PID_B);
    CHECK_STR(s.command_line, "");
    CHECK(!(f.rows.transfers[0].flags & FT_XFER_PROCESS_TEXT));
    fixture_close(&f);
}

/* A PHP-FPM worker is forked, then names itself after its pool; it is read again once it sends. */
static void forked_workers_are_read_again(void)
{
    constexpr uint32_t MASTER = 700;
    constexpr uint32_t WORKER = 701;
    struct fixture f;
    struct ft_process_strings s;
    struct ft_endpoint remote = endpoint(203, 0, 113, 42, 443);

    fixture_open_procfs(&f, true);
    procfs_set(MASTER, "php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)", "/");
    emit_exec(&f, MASTER, 1, "php-fpm8.2", 100);
    emit_fork(&f, WORKER, MASTER, "php-fpm8.2", 200);

    struct ft_process *worker = ft_table_find(f.st->processes, &WORKER);
    CHECK(worker && worker->command_line &&
          strcmp(worker->command_line, "php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)") ==
              0);
    CHECK(worker && !worker->script);

    procfs_set(WORKER, "php-fpm: pool site1|||", "/");
    emit_file(&f, 12, "/var/www/site1/backup.zip", false);
    emit_flow(&f, SOCK_A, WORKER, FT_PROTO_TCP, remote, 8192, 0);
    emit_transfer(&f, SOCK_A, WORKER, 12, FT_METHOD_SENDFILE, 8192, 0, 0);
    s = transfer_strings(&f, WORKER);
    CHECK_STR(s.command_line, "php-fpm: pool site1");
    CHECK_STR(s.script, "pool:site1");
    fixture_close(&f);
}

/* Without arguments the command line is the program alone; the script is still derived. */
static void arguments_can_be_left_out(void)
{
    struct fixture f;
    struct ft_process_strings s;

    fixture_open_procfs(&f, false);
    procfs_set(PID_A, "/usr/bin/python3|export.py|--password|hunter2", "/srv/app");
    emit_exec(&f, PID_A, 1, "python3", 1000);
    emit_file(&f, 11, "/data/users.csv", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 42, 443), 4096, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 4096, 0, 0);

    s = transfer_strings(&f, PID_A);
    CHECK_STR(s.command_line, "/usr/bin/python3");
    CHECK_STR(s.script, "/srv/app/export.py");
    const struct ft_row_transfer *row = &f.rows.transfers[0];
    CHECK(memmem(row, ft_row_transfer_size(row), "hunter2", 7) == nullptr);

    struct ft_query q;
    ft_query_init(&q, FT_Q_EVENTS);
    run_query(&f, &q);
    for (size_t i = 0; i < f.rows.count; i++)
        CHECK(memmem(&f.rows.events[i], ft_row_event_size(&f.rows.events[i]), "hunter2", 7) ==
              nullptr);
    fixture_close(&f);
}

/* Each string is capped and a row stays within a frame; evicted processes free theirs. */
static void process_text_is_bounded(void)
{
    static char args[FT_CMDLINE_MAX * 2];
    static char cwd[FT_PATH_MAX * 2];
    struct ft_state_config cfg;
    struct fixture f;
    struct ft_process_strings s;

    memset(args, 'a', sizeof(args) - 1);
    memcpy(args, "python3|", 8);
    memset(cwd, 'd', sizeof(cwd) - 1);
    cwd[0] = '/';

    ft_state_config_defaults(&cfg);
    cfg.read_process_text = procfs_read;
    cfg.max_processes = 64;
    procfs_clear();
    fixture_open_with(&f, &cfg);
    procfs_set(PID_A, args, cwd);
    emit_exec(&f, PID_A, 1, "python3", 1000);
    emit_file(&f, 11, "/data/users.csv", false);
    emit_flow(&f, SOCK_A, PID_A, FT_PROTO_TCP, endpoint(203, 0, 113, 42, 443), 4096, 0);
    emit_transfer(&f, SOCK_A, PID_A, 11, FT_METHOD_SENDFILE, 4096, 0, 0);

    s = transfer_strings(&f, PID_A);
    CHECK_U64(strlen(s.command_line), FT_CMDLINE_MAX - 1);
    CHECK_U64(strlen(s.cwd), FT_PATH_MAX - 1);
    CHECK(strlen(s.script) < FT_PATH_MAX);
    CHECK(ft_row_transfer_size(&f.rows.transfers[0]) <= FT_WIRE_MAX_PAYLOAD);
    CHECK(sizeof(struct ft_row_event) <= FT_WIRE_MAX_PAYLOAD);

    for (uint32_t pid = 10; pid < 300; pid++) {
        procfs_set(PID_B, "python3|x.py", "/srv");
        procfs[1].pid = pid;
        emit_exec(&f, pid, 1, "python3", pid);
    }
    struct ft_row_stats stats = {0};
    ft_state_fill_stats(f.st, f.now, &stats);
    CHECK_U64(stats.processes.count, 64);
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
    reused_inode_is_another_file();
    processes_count_their_files();
    rates_cover_recent_seconds();
    events_are_logged_in_order();
    event_log_keeps_the_most_recent();
    event_floods_stay_in_their_class();
    configured_exclusions();
    listed_files_have_no_minimum();
    background_files_need_the_whole_read();
    confidence_threshold();
    tables_stay_bounded();
    processes_carry_their_command_line();
    forked_workers_are_read_again();
    arguments_can_be_left_out();
    process_text_is_bounded();
}
