#include "unit/test.h"

#include "filetrace/clock.h"
#include "filetrace/state.h"

#include <stdio.h>
#include <stdlib.h>

constexpr uint32_t CURL = 3312;
constexpr uint32_t NGINX = 1840;
constexpr uint64_t SOCK = 0x2001;

struct fixture {
    struct ft_state *st;
    uint64_t now;
};

/* The rows of the latest query: the last of each kind, and the name of every record. */
static struct {
    struct ft_row_connection connection;
    struct ft_row_flow flow;
    struct ft_row_transfer transfer;
    struct ft_row_event event;
    char record_names[8][FT_NAME_MAX];
    uint8_t record_sources[8];
    size_t count;
    size_t size;
    struct ft_remote_names names;
    char shown[3 * FT_NAME_MAX];
} got;

static void keep(void *ctx, uint16_t type, const void *row, size_t size)
{
    (void)ctx;
    switch (type) {
    case FT_MSG_ROW_CONNECTION:
        memset(&got.connection, 0, sizeof(got.connection));
        memcpy(&got.connection, row, size);
        break;
    case FT_MSG_ROW_FLOW:
        memset(&got.flow, 0, sizeof(got.flow));
        memcpy(&got.flow, row, size);
        break;
    case FT_MSG_ROW_TRANSFER:
        memset(&got.transfer, 0, sizeof(got.transfer));
        memcpy(&got.transfer, row, size);
        break;
    case FT_MSG_ROW_EVENT:
        memset(&got.event, 0, sizeof(got.event));
        memcpy(&got.event, row, size);
        if (got.count < FT_ARRAY_LEN(got.record_names)) {
            ft_strlcpy(got.record_names[got.count], ft_row_event_name(&got.event), FT_NAME_MAX);
            got.record_sources[got.count] = got.event.name_source;
        }
        break;
    default:
        return;
    }
    got.size = size;
    got.count++;
}

static void fixture_open(struct fixture *f, const struct ft_state_config *cfg)
{
    struct ft_state_config defaults;

    ft_state_config_defaults(&defaults);
    f->st = ft_state_create(cfg ? cfg : &defaults);
    f->now = ft_clock_mono_ns();
    f->st->start_ns = f->now;
}

static void fixture_close(struct fixture *f)
{
    ft_state_destroy(f->st);
}

static struct ft_endpoint address(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    uint8_t raw[16] = {a, b, c, d};
    struct ft_endpoint ep;
    ft_endpoint_set(&ep, false, raw, port);
    return ep;
}

/* Every event is a millisecond after the one before. */
static struct ft_event event(struct fixture *f, enum ft_event_type type)
{
    f->now += FT_NS_PER_MS;
    return (struct ft_event){.type = type, .ts_ns = f->now};
}

static void process(struct fixture *f, enum ft_event_type type, uint32_t pid, uint32_t ppid,
                    uint64_t start_s)
{
    struct ft_event ev = event(f, type);
    ev.process.pid = pid;
    ev.process.ppid = ppid;
    ev.process.start_ns = start_s * FT_NS_PER_SEC;
    snprintf(ev.process.comm, sizeof(ev.process.comm), "p%u", pid);
    ft_state_ingest(f->st, &ev);
}

static void exec(struct fixture *f, uint32_t pid)
{
    process(f, FT_EVENT_PROCESS_EXEC, pid, 1, pid);
}

static void fork_from(struct fixture *f, uint32_t pid, uint32_t ppid)
{
    process(f, FT_EVENT_PROCESS_FORK, pid, ppid, pid);
}

static void lookup(struct fixture *f, uint32_t pid, uint32_t tid, const char *name,
                   struct ft_endpoint addr)
{
    struct ft_event ev = event(f, FT_EVENT_NAME_LOOKUP);
    ev.lookup.pid = pid;
    ev.lookup.tid = tid;
    ev.lookup.name = name;
    ev.lookup.addr_count = 1;
    ev.lookup.addrs[0] = addr;
    ft_state_ingest(f->st, &ev);
}

static void socket_state(struct fixture *f, uint64_t sock, uint32_t pid, uint32_t tid,
                         enum ft_sock_state state, struct ft_endpoint remote)
{
    struct ft_event ev = event(f, FT_EVENT_SOCKET_STATE);
    ev.socket.sock_id = sock;
    ev.socket.pid = pid;
    ev.socket.tid = tid;
    ev.socket.proto = FT_PROTO_TCP;
    ev.socket.state = state;
    ev.socket.local = address(10, 0, 0, 12, 50412);
    ev.socket.remote = remote;
    ft_state_ingest(f->st, &ev);
}

static void connect_to(struct fixture *f, uint64_t sock, uint32_t pid, uint32_t tid,
                       struct ft_endpoint remote)
{
    socket_state(f, sock, pid, tid, FT_SOCK_CONNECTING, remote);
    socket_state(f, sock, pid, 0, FT_SOCK_ESTABLISHED, remote);
}

static void tls_name(struct fixture *f, uint64_t sock, uint32_t pid, const char *name)
{
    struct ft_event ev = event(f, FT_EVENT_TLS_NAME);
    ev.tls_name.sock_id = sock;
    ev.tls_name.pid = pid;
    ev.tls_name.name = name;
    ft_state_ingest(f->st, &ev);
}

static void bytes_sent(struct fixture *f, uint64_t sock, uint32_t pid, uint16_t proto,
                       struct ft_endpoint remote)
{
    struct ft_event ev = event(f, FT_EVENT_FLOW);
    ev.flow.sock_id = sock;
    ev.flow.pid = pid;
    ev.flow.proto = proto;
    ev.flow.local = address(10, 0, 0, 12, 50412);
    ev.flow.remote = remote;
    ev.flow.first_ns = f->now;
    ev.flow.tx_bytes = 4096;
    ev.flow.tx_ops = 1;
    ft_state_ingest(f->st, &ev);
}

static void file_sent(struct fixture *f, uint64_t sock, uint32_t pid)
{
    struct ft_event ev = event(f, FT_EVENT_FILE_SEEN);
    ev.file.id = (struct ft_file_id){.dev = 2049, .ino = 77};
    ev.file.path = "/data/invoice.pdf";
    ev.file.size = 65536;
    ft_state_ingest(f->st, &ev);

    ev = event(f, FT_EVENT_TRANSFER);
    ev.transfer.sock_id = sock;
    ev.transfer.pid = pid;
    ev.transfer.method = FT_METHOD_SENDFILE;
    ev.transfer.file = (struct ft_file_id){.dev = 2049, .ino = 77};
    ev.transfer.first_ns = f->now;
    ev.transfer.bytes = 65536;
    ev.transfer.ops = 1;
    ft_state_ingest(f->st, &ev);
}

static void run(struct fixture *f, const struct ft_query *q)
{
    struct ft_msg_end end;
    struct ft_error err;

    got.count = 0;
    got.size = 0;
    CHECK(ft_state_query(f->st, q, f->now, keep, nullptr, &end, &err));
}

/* What the NAME column of the socket's connection shows, with got.names to look closer. */
static const char *connection(struct fixture *f, uint64_t sock)
{
    struct ft_query q;

    ft_query_init(&q, FT_Q_CONNECTIONS);
    q.sock_id = sock;
    run(f, &q);
    CHECK_U64(got.count, 1);
    ft_row_connection_names(&got.connection, &got.names);
    ft_remote_name_format(&got.names, got.shown, sizeof(got.shown));
    return got.shown;
}

static const char *flow_to(struct fixture *f, uint64_t sock, struct ft_endpoint remote)
{
    struct ft_query q;

    ft_query_init(&q, FT_Q_FLOWS);
    q.sock_id = sock;
    q.remote = remote;
    q.remote.port = 0;
    run(f, &q);
    CHECK_U64(got.count, 1);
    ft_row_flow_names(&got.flow, &got.names);
    ft_remote_name_format(&got.names, got.shown, sizeof(got.shown));
    return got.shown;
}

static const char *transfer(struct fixture *f, uint64_t sock)
{
    struct ft_query q;

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.sock_id = sock;
    run(f, &q);
    CHECK_U64(got.count, 1);
    ft_row_transfer_names(&got.transfer, &got.names);
    ft_remote_name_format(&got.names, got.shown, sizeof(got.shown));
    return got.shown;
}

static void records(struct fixture *f, uint64_t sock, enum ft_record_type type)
{
    struct ft_query q;

    ft_query_init(&q, FT_Q_EVENTS);
    q.sock_id = sock;
    q.event_types = 1u << type;
    run(f, &q);
}

static void lookup_names_the_connection(void)
{
    struct fixture f;
    struct ft_endpoint files = address(203, 0, 113, 25, 0);

    fixture_open(&f, nullptr);
    exec(&f, CURL);
    exec(&f, NGINX);
    lookup(&f, CURL, CURL, "Files.Example.com.", files);

    connect_to(&f, SOCK, CURL, CURL, address(203, 0, 113, 25, 443));
    CHECK_STR(connection(&f, SOCK), "files.example.com");
    CHECK_U64(ft_remote_name_source(&got.names), FT_NAME_SOURCE_LOOKUP);
    CHECK_U64(got.names.count, 1);
    CHECK_U64(got.size, offsetof(struct ft_row_connection, text) + sizeof("files.example.com"));

    bytes_sent(&f, SOCK, CURL, FT_PROTO_TCP, address(203, 0, 113, 25, 443));
    CHECK_STR(flow_to(&f, SOCK, files), "files.example.com");
    file_sent(&f, SOCK, CURL);
    CHECK_STR(transfer(&f, SOCK), "files.example.com");
    struct ft_process_strings text;
    ft_row_transfer_strings(&got.transfer, &text);
    CHECK_STR(got.transfer.path, "/data/invoice.pdf");
    CHECK_STR(text.command_line, "");

    records(&f, SOCK, FT_REC_SOCKET_CONNECT);
    CHECK_U64(got.count, 1);
    CHECK_STR(got.record_names[0], "files.example.com");
    CHECK_U64(got.record_sources[0], FT_NAME_SOURCE_LOOKUP);
    records(&f, SOCK, FT_REC_FILE_TRANSFER);
    CHECK_STR(got.record_names[0], "files.example.com");
    CHECK_STR(got.event.text, "/data/invoice.pdf");

    /* The name belongs to the address it was returned for, whatever the port. */
    connect_to(&f, SOCK + 1, CURL, CURL, address(203, 0, 113, 26, 443));
    CHECK_STR(connection(&f, SOCK + 1), "");
    CHECK_U64(got.size, offsetof(struct ft_row_connection, text));
    connect_to(&f, SOCK + 2, CURL, CURL, address(203, 0, 113, 25, 8080));
    CHECK_STR(connection(&f, SOCK + 2), "files.example.com");

    /* What one process looked up names nothing of another's. */
    connect_to(&f, SOCK + 3, NGINX, NGINX, address(203, 0, 113, 25, 443));
    CHECK_STR(connection(&f, SOCK + 3), "");

    /* An accepted connection's remote end is a client nobody looked up. */
    socket_state(&f, SOCK + 4, CURL, 0, FT_SOCK_ESTABLISHED, address(203, 0, 113, 25, 51344));
    CHECK_STR(connection(&f, SOCK + 4), "");
    records(&f, SOCK + 4, FT_REC_SOCKET_ESTABLISHED);
    CHECK_STR(got.record_names[0], "");
    CHECK_U64(got.size, offsetof(struct ft_row_event, text) + 1);
    fixture_close(&f);
}

static void several_names_for_one_address(void)
{
    struct fixture f;
    struct ft_endpoint shared = address(203, 0, 113, 25, 80);
    constexpr uint32_t RESOLVER = CURL + 1;

    fixture_open(&f, nullptr);
    exec(&f, CURL);
    lookup(&f, CURL, CURL, "cdn.example.com", shared);
    lookup(&f, CURL, RESOLVER, "static.example.com", shared);

    /* The connecting thread's own lookup leads; without one, the latest does. */
    connect_to(&f, SOCK, CURL, CURL, shared);
    CHECK_STR(connection(&f, SOCK), "cdn.example.com (+1)");
    CHECK_STR(got.names.resolved[1], "static.example.com");
    CHECK_U64(got.names.count, 2);
    connect_to(&f, SOCK + 1, CURL, RESOLVER, shared);
    CHECK_STR(connection(&f, SOCK + 1), "static.example.com (+1)");
    connect_to(&f, SOCK + 2, CURL, CURL + 7, shared);
    CHECK_STR(connection(&f, SOCK + 2), "static.example.com (+1)");
    connect_to(&f, SOCK + 3, CURL, 0, shared);
    CHECK_STR(connection(&f, SOCK + 3), "static.example.com (+1)");

    /* Looked up again, a name is the latest and still one name. */
    lookup(&f, CURL, RESOLVER, "cdn.example.com", shared);
    connect_to(&f, SOCK + 4, CURL, 0, shared);
    CHECK_STR(connection(&f, SOCK + 4), "cdn.example.com (+1)");

    /* A row lists four; the count says how many there were. */
    for (unsigned i = 0; i < 5; i++) {
        char name[32];
        snprintf(name, sizeof(name), "n%u.example.com", i);
        lookup(&f, CURL, CURL, name, shared);
    }
    connect_to(&f, SOCK + 5, CURL, CURL, shared);
    CHECK_STR(connection(&f, SOCK + 5), "n4.example.com (+6)");
    CHECK_U64(got.names.listed, FT_RESOLVED_NAMES);
    CHECK_STR(got.names.resolved[3], "n1.example.com");
    fixture_close(&f);
}

static void a_connection_keeps_its_names(void)
{
    struct fixture f;
    struct ft_endpoint shared = address(127, 0, 0, 2, 443);

    fixture_open(&f, nullptr);
    exec(&f, CURL);
    lookup(&f, CURL, CURL, "files.ft.test", shared);
    connect_to(&f, SOCK, CURL, CURL, shared);
    lookup(&f, CURL, CURL, "later.ft.test", shared);
    CHECK_STR(connection(&f, SOCK), "files.ft.test");
    connect_to(&f, SOCK + 1, CURL, CURL, shared);
    CHECK_STR(connection(&f, SOCK + 1), "later.ft.test (+1)");

    /* A socket that connects again is another connection. */
    socket_state(&f, SOCK, CURL, CURL, FT_SOCK_CONNECTING, address(127, 0, 0, 9, 443));
    CHECK_STR(connection(&f, SOCK), "");
    socket_state(&f, SOCK, CURL, CURL, FT_SOCK_CONNECTING, shared);
    CHECK_STR(connection(&f, SOCK), "later.ft.test (+1)");
    fixture_close(&f);
}

static void fork_inherits_and_exec_forgets(void)
{
    struct fixture f;
    struct ft_endpoint upstream = address(10, 0, 0, 5, 8080);
    struct ft_endpoint later = address(10, 0, 0, 6, 8080);
    constexpr uint32_t WORKER = 5000;

    fixture_open(&f, nullptr);
    exec(&f, NGINX);
    lookup(&f, NGINX, NGINX, "app.internal", upstream);
    fork_from(&f, WORKER, NGINX);
    lookup(&f, NGINX, NGINX, "late.internal", later);

    connect_to(&f, SOCK, WORKER, WORKER, upstream);
    CHECK_STR(connection(&f, SOCK), "app.internal");
    /* What the parent looks up after the fork, the child never had. */
    connect_to(&f, SOCK + 1, WORKER, WORKER, later);
    CHECK_STR(connection(&f, SOCK + 1), "");

    /* Four generations down the name still holds, the fifth has none. */
    for (uint32_t i = 1; i <= 4; i++)
        fork_from(&f, WORKER + i, WORKER + i - 1);
    connect_to(&f, SOCK + 2, WORKER + 3, WORKER + 3, upstream);
    CHECK_STR(connection(&f, SOCK + 2), "app.internal");
    connect_to(&f, SOCK + 3, WORKER + 4, WORKER + 4, upstream);
    CHECK_STR(connection(&f, SOCK + 3), "");

    /* The parent may be gone by the time the child connects. */
    process(&f, FT_EVENT_PROCESS_EXIT, NGINX, 1, NGINX);
    ft_state_sweep(f.st, f.now + 10 * FT_NS_PER_SEC);
    CHECK(ft_table_find(f.st->processes, &(uint32_t){NGINX}) == nullptr);
    connect_to(&f, SOCK + 4, WORKER, WORKER, upstream);
    CHECK_STR(connection(&f, SOCK + 4), "app.internal");

    /* A child's own lookup leads what it inherited. */
    lookup(&f, WORKER, WORKER, "own.internal", upstream);
    connect_to(&f, SOCK + 5, WORKER, WORKER, upstream);
    CHECK_STR(connection(&f, SOCK + 5), "own.internal (+1)");

    /* Another program under the same PID has neither its own lookups nor its parents'. */
    exec(&f, WORKER);
    connect_to(&f, SOCK + 6, WORKER, WORKER, upstream);
    CHECK_STR(connection(&f, SOCK + 6), "");
    connect_to(&f, SOCK + 7, WORKER + 1, WORKER + 1, upstream);
    CHECK_STR(connection(&f, SOCK + 7), "app.internal");

    /* So does another process that was given the PID. */
    lookup(&f, CURL, CURL, "files.example.com", upstream);
    process(&f, FT_EVENT_PROCESS_FORK, CURL, 1, 90000);
    connect_to(&f, SOCK + 8, CURL, CURL, upstream);
    CHECK_STR(connection(&f, SOCK + 8), "");
    fixture_close(&f);
}

static void addresses_and_names_that_do_not_count(void)
{
    static const uint8_t mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 3};
    struct fixture f;
    struct ft_endpoint v6 = {.family = 6};
    struct ft_endpoint none = {0};

    fixture_open(&f, nullptr);
    exec(&f, CURL);

    /* An IPv4-mapped address is the IPv4 address, whichever side has it in that form. */
    memcpy(v6.addr, mapped, sizeof(mapped));
    lookup(&f, CURL, CURL, "alone.ft.test", v6);
    connect_to(&f, SOCK, CURL, CURL, address(127, 0, 0, 3, 4433));
    CHECK_STR(connection(&f, SOCK), "alone.ft.test");
    lookup(&f, CURL, CURL, "other.ft.test", address(127, 0, 0, 4, 0));
    v6.addr[15] = 4;
    v6.port = 4433;
    connect_to(&f, SOCK + 1, CURL, CURL, v6);
    CHECK_STR(connection(&f, SOCK + 1), "other.ft.test");

    /* An address looked up as a name names nothing and is not held against the process. */
    lookup(&f, CURL, CURL, "127.0.0.5", address(127, 0, 0, 5, 0));
    lookup(&f, CURL, CURL, "::1", address(127, 0, 0, 5, 0));
    lookup(&f, CURL, CURL, nullptr, address(127, 0, 0, 5, 0));
    connect_to(&f, SOCK + 2, CURL, CURL, address(127, 0, 0, 5, 80));
    CHECK_STR(connection(&f, SOCK + 2), "");
    CHECK_U64(ft_names_invalid(f.st->names), 0);

    /* What no host name can hold is refused and counted. */
    lookup(&f, CURL, CURL, "bad\x1b[2Jname", address(127, 0, 0, 6, 0));
    connect_to(&f, SOCK + 3, CURL, CURL, address(127, 0, 0, 6, 80));
    CHECK_STR(connection(&f, SOCK + 3), "");
    CHECK_U64(ft_names_invalid(f.st->names), 1);

    /* A lookup that returned no usable address keeps nothing. */
    size_t kept = ft_names_count(f.st->names);
    lookup(&f, CURL, CURL, "empty.ft.test", none);
    CHECK_U64(ft_names_count(f.st->names), kept);
    fixture_close(&f);
}

static void old_lookups_can_be_left_out(void)
{
    struct ft_state_config cfg;
    struct fixture f;
    struct ft_endpoint addr = address(192, 0, 2, 80, 443);

    ft_state_config_defaults(&cfg);
    cfg.name_max_age_ns = 60 * FT_NS_PER_SEC;
    fixture_open(&f, &cfg);
    exec(&f, CURL);
    lookup(&f, CURL, CURL, "api.example.org", addr);
    f.now += 59 * FT_NS_PER_SEC;
    connect_to(&f, SOCK, CURL, CURL, addr);
    CHECK_STR(connection(&f, SOCK), "api.example.org");
    f.now += 2 * FT_NS_PER_SEC;
    connect_to(&f, SOCK + 1, CURL, CURL, addr);
    CHECK_STR(connection(&f, SOCK + 1), "");
    /* The connection made in time keeps its name. */
    CHECK_STR(connection(&f, SOCK), "api.example.org");
    fixture_close(&f);
}

static void datagrams_are_named_per_peer(void)
{
    struct fixture f;
    struct ft_endpoint logs = address(192, 0, 2, 53, 514);
    struct ft_endpoint literal = address(192, 0, 2, 54, 514);

    fixture_open(&f, nullptr);
    exec(&f, CURL);
    lookup(&f, CURL, CURL, "logs.example.net", logs);

    bytes_sent(&f, SOCK, CURL, FT_PROTO_UDP, logs);
    CHECK_STR(flow_to(&f, SOCK, logs), "logs.example.net");
    /* A socket with one peer is that peer's connection. */
    CHECK_STR(connection(&f, SOCK), "logs.example.net");
    records(&f, SOCK, FT_REC_NETWORK_SEND);
    CHECK_STR(got.record_names[0], "logs.example.net");

    bytes_sent(&f, SOCK, CURL, FT_PROTO_UDP, literal);
    CHECK_STR(flow_to(&f, SOCK, logs), "logs.example.net");
    CHECK_STR(flow_to(&f, SOCK, literal), "");
    CHECK_STR(connection(&f, SOCK), "");

    /* A flow is named when it is first seen, and not again. */
    lookup(&f, CURL, CURL, "late.example.net", literal);
    bytes_sent(&f, SOCK, CURL, FT_PROTO_UDP, literal);
    CHECK_STR(flow_to(&f, SOCK, literal), "");
    fixture_close(&f);
}

static void tls_server_name(void)
{
    struct fixture f;
    struct ft_endpoint shared = address(127, 0, 0, 2, 4433);
    struct ft_endpoint proxy = address(127, 0, 0, 5, 3128);

    fixture_open(&f, nullptr);
    exec(&f, CURL);
    lookup(&f, CURL, CURL, "files.ft.test", shared);
    lookup(&f, CURL, CURL, "other.ft.test", shared);
    lookup(&f, CURL, CURL, "proxy.ft.test", proxy);

    /* Among the names looked up, it says which one the connection is for. */
    connect_to(&f, SOCK, CURL, CURL, shared);
    CHECK_STR(connection(&f, SOCK), "other.ft.test (+1)");
    tls_name(&f, SOCK, CURL, "Files.FT.test");
    CHECK_STR(connection(&f, SOCK), "files.ft.test");
    CHECK_U64(ft_remote_name_source(&got.names), FT_NAME_SOURCE_LOOKUP_TLS);
    CHECK_U64(got.names.count, 2);

    /* With nothing looked up, it is the only name. */
    connect_to(&f, SOCK + 1, CURL, CURL, address(127, 0, 0, 4, 4433));
    tls_name(&f, SOCK + 1, CURL, "files.ft.test");
    CHECK_STR(connection(&f, SOCK + 1), "files.ft.test");
    CHECK_U64(ft_remote_name_source(&got.names), FT_NAME_SOURCE_TLS);
    CHECK_U64(got.names.listed, 0);

    /* Through a proxy the address has the proxy's name and the connection the target's. */
    connect_to(&f, SOCK + 2, CURL, CURL, proxy);
    file_sent(&f, SOCK + 2, CURL);
    tls_name(&f, SOCK + 2, CURL, "proxy.ft.test");
    file_sent(&f, SOCK + 2, CURL);
    /* A second handshake on the socket is the one that reaches the target. */
    tls_name(&f, SOCK + 2, CURL, "s3.ft.test");
    file_sent(&f, SOCK + 2, CURL);
    CHECK_STR(connection(&f, SOCK + 2), "s3.ft.test via proxy.ft.test");
    CHECK_STR(transfer(&f, SOCK + 2), "s3.ft.test via proxy.ft.test");
    CHECK_U64(ft_remote_name_source(&got.names), FT_NAME_SOURCE_TLS);

    /* Each record has the name the connection had when it was made. */
    records(&f, SOCK + 2, FT_REC_FILE_TRANSFER);
    CHECK_U64(got.count, 3);
    CHECK_STR(got.record_names[0], "proxy.ft.test");
    CHECK_U64(got.record_sources[0], FT_NAME_SOURCE_LOOKUP);
    CHECK_STR(got.record_names[1], "proxy.ft.test");
    CHECK_U64(got.record_sources[1], FT_NAME_SOURCE_LOOKUP_TLS);
    CHECK_STR(got.record_names[2], "s3.ft.test");
    CHECK_U64(got.record_sources[2], FT_NAME_SOURCE_TLS);

    /* A server name for a socket nobody has seen is dropped. */
    tls_name(&f, SOCK + 9, CURL, "files.ft.test");
    CHECK(ft_table_find(f.st->sockets, &(uint64_t){SOCK + 9}) == nullptr);

    /* The handshake may come from another process than the one that connected. */
    connect_to(&f, SOCK + 3, CURL, CURL, shared);
    tls_name(&f, SOCK + 3, NGINX, "files.ft.test.");
    CHECK_STR(connection(&f, SOCK + 3), "files.ft.test");
    CHECK_U64(ft_remote_name_source(&got.names), FT_NAME_SOURCE_LOOKUP_TLS);

    /* An address given as the server name is no name, and is not held against anyone. */
    connect_to(&f, SOCK + 4, CURL, CURL, shared);
    tls_name(&f, SOCK + 4, CURL, "127.0.0.2");
    CHECK_STR(connection(&f, SOCK + 4), "other.ft.test (+1)");
    CHECK_U64(ft_remote_name_source(&got.names), FT_NAME_SOURCE_LOOKUP);
    connect_to(&f, SOCK + 5, CURL, CURL, address(127, 0, 0, 4, 4433));
    tls_name(&f, SOCK + 5, CURL, "::1");
    CHECK_STR(connection(&f, SOCK + 5), "");
    CHECK_U64(ft_names_invalid(f.st->names), 0);
    fixture_close(&f);

    /* The same name sent again for a socket, as a retried handshake does, holds it once. */
    struct ft_state_config cfg;
    ft_state_config_defaults(&cfg);
    cfg.max_names = 1;
    fixture_open(&f, &cfg);
    exec(&f, CURL);
    connect_to(&f, SOCK, CURL, CURL, shared);
    tls_name(&f, SOCK, CURL, "files.ft.test");
    tls_name(&f, SOCK, CURL, "files.ft.test");
    CHECK_STR(connection(&f, SOCK), "files.ft.test");
    socket_state(&f, SOCK, CURL, CURL, FT_SOCK_CONNECTING, shared);
    tls_name(&f, SOCK, CURL, "other.ft.test");
    CHECK_STR(connection(&f, SOCK), "other.ft.test");
    CHECK_U64(ft_names_refused(f.st->names), 0);
    fixture_close(&f);
}

static struct ft_endpoint numbered(unsigned i)
{
    return address(198, 51, (uint8_t)(i >> 8), (uint8_t)i, 443);
}

static void lookup_numbered(struct fixture *f, uint32_t pid, unsigned i)
{
    char name[40];
    snprintf(name, sizeof(name), "host%u.example", i);
    lookup(f, pid, pid, name, numbered(i));
}

static void full_tables(void)
{
    struct ft_state_config cfg;
    struct fixture f;

    /* Two names, both held by listed connections: a third is refused, and its connection bare. */
    ft_state_config_defaults(&cfg);
    cfg.max_names = 2;
    fixture_open(&f, &cfg);
    for (unsigned i = 0; i < 3; i++) {
        exec(&f, CURL + i);
        lookup_numbered(&f, CURL + i, i);
        connect_to(&f, SOCK + i, CURL + i, CURL + i, numbered(i));
    }
    CHECK_STR(connection(&f, SOCK), "host0.example");
    CHECK_STR(connection(&f, SOCK + 1), "host1.example");
    CHECK_STR(connection(&f, SOCK + 2), "");
    CHECK_U64(ft_names_refused(f.st->names), 1);
    CHECK_U64(ft_names_forgotten(f.st->names), 0);

    struct ft_row_stats stats = {0};
    lookup(&f, CURL, CURL, "no name", numbered(9));
    ft_state_fill_stats(f.st, f.now, &stats);
    CHECK_U64(stats.names.count, 2);
    CHECK_U64(stats.names.capacity, 2);
    CHECK_U64(stats.names.evictions, 0);
    CHECK_U64(stats.name_lookups.count, 2);
    CHECK_U64(stats.name_lookups.capacity, 16384);
    CHECK_U64(stats.names_refused, 1);
    CHECK_U64(stats.names_invalid, 1);
    fixture_close(&f);

    /*
     * An upstream looked up once and connected to ever since keeps its name while thousands of
     * other names and lookups pass through tables far too small for them.
     */
    ft_state_config_defaults(&cfg);
    cfg.max_names = 8;
    cfg.max_name_lookups = 8;
    cfg.max_sockets = 4;
    fixture_open(&f, &cfg);
    exec(&f, NGINX);
    exec(&f, CURL);
    lookup(&f, NGINX, NGINX, "upstream.internal", address(10, 0, 0, 5, 0));
    for (unsigned round = 0; round < 500; round++) {
        for (unsigned i = 0; i < 6; i++) {
            lookup_numbered(&f, CURL, round * 6 + i);
            if (i % 2 == 0)
                connect_to(&f, SOCK + 100 + round * 6 + i, CURL, CURL, numbered(round * 6 + i));
        }
        /* Each of its connections is a socket of its own, soon pushed out of the table. */
        connect_to(&f, SOCK + 50000 + round, NGINX, NGINX, address(10, 0, 0, 5, 8080));
        if (strcmp(connection(&f, SOCK + 50000 + round), "upstream.internal") != 0) {
            CHECK_U64(round, UINT64_MAX);
            break;
        }
    }
    CHECK(ft_names_forgotten(f.st->names) > 2000);
    CHECK(ft_table_evictions(f.st->lookups) > 2000);
    CHECK_U64(ft_names_refused(f.st->names), 0);
    CHECK_U64(ft_names_count(f.st->names), 8);

    /* Left alone that long instead, it goes like any other. */
    for (unsigned i = 0; i < 50; i++) {
        lookup_numbered(&f, CURL, 10000 + i);
        connect_to(&f, SOCK + 5000 + i, CURL, CURL, numbered(10000 + i));
    }
    connect_to(&f, SOCK + 9000, NGINX, NGINX, address(10, 0, 0, 5, 8080));
    CHECK_STR(connection(&f, SOCK + 9000), "");
    fixture_close(&f);
}

static void names_off(void)
{
    struct ft_state_config cfg;
    struct fixture f;
    struct ft_endpoint addr = address(203, 0, 113, 25, 443);

    ft_state_config_defaults(&cfg);
    cfg.names = false;
    fixture_open(&f, &cfg);
    CHECK(f.st->names == nullptr);
    CHECK(f.st->lookups == nullptr);

    exec(&f, CURL);
    lookup(&f, CURL, CURL, "files.example.com", addr);
    connect_to(&f, SOCK, CURL, CURL, addr);
    tls_name(&f, SOCK, CURL, "files.example.com");
    bytes_sent(&f, SOCK, CURL, FT_PROTO_TCP, addr);
    bytes_sent(&f, SOCK + 1, CURL, FT_PROTO_UDP, addr);
    file_sent(&f, SOCK, CURL);

    /* Every row ends where it ends without names. */
    CHECK_STR(connection(&f, SOCK), "");
    CHECK_U64(got.size, offsetof(struct ft_row_connection, text));
    CHECK_U64(got.connection.names.count + got.connection.names.listed + got.connection.names.tls,
              0);
    CHECK_STR(flow_to(&f, SOCK + 1, addr), "");
    CHECK_U64(got.size, offsetof(struct ft_row_flow, text));
    CHECK_STR(transfer(&f, SOCK), "");
    CHECK_U64(got.size, offsetof(struct ft_row_transfer, path) + sizeof("/data/invoice.pdf"));

    struct ft_query q;
    ft_query_init(&q, FT_Q_EVENTS);
    run(&f, &q);
    CHECK(got.count >= 5);
    for (size_t i = 0; i < got.count && i < FT_ARRAY_LEN(got.record_names); i++) {
        CHECK_STR(got.record_names[i], "");
        CHECK_U64(got.record_sources[i], FT_NAME_SOURCE_NONE);
    }

    struct ft_row_stats stats = {0};
    ft_state_fill_stats(f.st, f.now, &stats);
    CHECK_U64(stats.names.capacity + stats.name_lookups.capacity, 0);
    CHECK_U64(stats.names.count + stats.name_lookups.count, 0);
    CHECK_U64(stats.names_invalid + stats.names_refused, 0);
    fixture_close(&f);
}

void test_binding(void)
{
    lookup_names_the_connection();
    several_names_for_one_address();
    a_connection_keeps_its_names();
    fork_inherits_and_exec_forgets();
    addresses_and_names_that_do_not_count();
    old_lookups_can_be_left_out();
    datagrams_are_named_per_peer();
    tls_server_name();
    full_tables();
    names_off();
}
