#include "unit/test.h"

#include "agent/telemetry.h"
#include "filetrace/clock.h"
#include "rpc/grpc.h"

#include "filetrace/v1/filetrace.pb-c.h"

#include <stdlib.h>
#include <unistd.h>

typedef Filetrace__V1__Connection Connection;
typedef Filetrace__V1__TransferFilter TransferFilter;
typedef Filetrace__V1__ListTransfersResponse ListResponse;

/* A service that echoes, refuses, streams, or answers only when told to. */
struct echo {
    struct ft_grpc_call *held;
    int ended;
};

static void echo_call(void *ctx, struct ft_grpc_call *call, const char *path,
                      const uint8_t *request, size_t size)
{
    struct echo *e = ctx;

    if (strcmp(path, "/test.Echo/Unary") == 0) {
        CHECK(ft_grpc_send(call, request, size));
        ft_grpc_finish(call, FT_GRPC_OK, nullptr);
    } else if (strcmp(path, "/test.Echo/Stream") == 0) {
        for (uint8_t i = 0; i < 3; i++) {
            uint8_t message[2] = {request[0], i};
            CHECK(ft_grpc_send(call, message, sizeof(message)));
        }
        ft_grpc_finish(call, FT_GRPC_OK, nullptr);
    } else if (strcmp(path, "/test.Echo/Held") == 0) {
        e->held = call;
    } else {
        ft_grpc_finish(call, FT_GRPC_NOT_FOUND, "no such thing: 100% \xe2\x82\xac");
    }
}

static void echo_end(void *ctx, struct ft_grpc_call *call)
{
    struct echo *e = ctx;

    if (e->held == call)
        e->held = nullptr;
    e->ended++;
}

struct outcome {
    bool done;
    enum ft_grpc_status status;
    char message[160];
    uint8_t reply[70000];
    size_t reply_len;
    int messages;
};

static void on_done(void *ctx, enum ft_grpc_status status, const char *message,
                    const uint8_t *reply, size_t size)
{
    struct outcome *o = ctx;

    o->done = true;
    o->status = status;
    ft_strlcpy(o->message, message, sizeof(o->message));
    if (size <= sizeof(o->reply)) {
        memcpy(o->reply, reply, size);
        o->reply_len = size;
    }
}

static void on_message(void *ctx, const uint8_t *message, size_t size)
{
    struct outcome *o = ctx;

    if (size == 2 && message[0] == 7 && message[1] == o->messages)
        o->messages++;
}

/* Runs both ends until the call is done or a second has passed. */
static void run(struct ft_grpc_server *server, struct ft_grpc_client *client,
                const struct outcome *o)
{
    static struct ft_poller poller;
    uint64_t give_up_ns = ft_clock_mono_ns() + FT_NS_PER_SEC;

    while (!o->done && ft_clock_mono_ns() < give_up_ns) {
        uint64_t now_ns = ft_clock_mono_ns();

        ft_poller_begin(&poller, now_ns + 20 * FT_NS_PER_MS);
        if (server)
            ft_grpc_server_poll(server, &poller);
        ft_grpc_client_poll(client, &poller);
        ft_poller_wait(&poller, now_ns);
        if (server)
            ft_grpc_server_dispatch(server, &poller);
        ft_grpc_client_dispatch(client, &poller, ft_clock_mono_ns());
    }
}

static uint64_t soon(void)
{
    return ft_clock_mono_ns() + 5 * FT_NS_PER_SEC;
}

static void calls_reach_the_service_and_come_back(void)
{
    char dir[] = "/tmp/filetrace-grpc-XXXXXX";
    char target[96];
    struct ft_net_addr addr;
    struct ft_error err = {0};
    struct echo echo = {0};
    struct ft_grpc_service service = {.ctx = &echo, .on_call = echo_call, .on_end = echo_end};
    struct outcome *o = calloc(1, sizeof(*o));
    uint8_t *large = malloc(70000);

    CHECK(mkdtemp(dir) != nullptr);
    snprintf(target, sizeof(target), "unix:%s/api.sock", dir);
    CHECK(ft_net_addr_parse(target, &addr));
    int listen_fd = ft_net_listen(&addr, &err);
    CHECK(listen_fd >= 0);
    struct ft_grpc_server *server = ft_grpc_server_new(listen_fd, true, &service);
    struct ft_grpc_client *client = ft_grpc_client_new(&addr, "localhost");

    ft_grpc_client_call(client, "/test.Echo/Unary", (const uint8_t *)"hello", 5, soon(), on_done,
                        o);
    run(server, client, o);
    CHECK(o->done);
    CHECK_U64(o->status, FT_GRPC_OK);
    CHECK_U64(o->reply_len, 5);
    CHECK(memcmp(o->reply, "hello", 5) == 0);

    /* Larger than one HTTP/2 frame and than the initial flow-control window. */
    for (size_t i = 0; i < 70000; i++)
        large[i] = (uint8_t)(i * 31);
    *o = (struct outcome){0};
    ft_grpc_client_call(client, "/test.Echo/Unary", large, 60000, soon(), on_done, o);
    run(server, client, o);
    CHECK_U64(o->status, FT_GRPC_OK);
    CHECK_U64(o->reply_len, 60000);
    CHECK(memcmp(o->reply, large, 60000) == 0);

    *o = (struct outcome){0};
    ft_grpc_client_call(client, "/test.Echo/Missing", nullptr, 0, soon(), on_done, o);
    run(server, client, o);
    CHECK_U64(o->status, FT_GRPC_NOT_FOUND);
    CHECK_STR(o->message, "no such thing: 100% \xe2\x82\xac");

    *o = (struct outcome){0};
    uint8_t seven = 7;
    ft_grpc_client_stream(client, "/test.Echo/Stream", &seven, 1, soon(), on_message, on_done, o);
    run(server, client, o);
    CHECK_U64(o->status, FT_GRPC_OK);
    CHECK_U64(o->messages, 3);

    /* An answer may come long after the request: the call waits for it. */
    *o = (struct outcome){0};
    ft_grpc_client_stream(client, "/test.Echo/Held", &seven, 1, soon(), on_message, on_done, o);
    struct outcome never = {0};
    run(server, client, &never);
    CHECK(echo.held != nullptr);
    CHECK(!o->done);
    if (echo.held) {
        uint8_t first[2] = {7, 0};
        CHECK(ft_grpc_send(echo.held, first, sizeof(first)));
        ft_grpc_finish(echo.held, FT_GRPC_ABORTED, "enough");
    }
    run(server, client, o);
    CHECK_U64(o->status, FT_GRPC_ABORTED);
    CHECK_STR(o->message, "enough");
    CHECK_U64(o->messages, 1);
    CHECK_U64(echo.ended, 5);

    /* A call nobody answers ends at its deadline. */
    *o = (struct outcome){0};
    ft_grpc_client_call(client, "/test.Echo/Held", &seven, 1,
                        ft_clock_mono_ns() + 50 * FT_NS_PER_MS, on_done, o);
    run(server, client, o);
    CHECK_U64(o->status, FT_GRPC_DEADLINE_EXCEEDED);

    /* Without a server the call fails, and so does the next one, without another attempt. */
    ft_grpc_server_free(server);
    *o = (struct outcome){0};
    ft_grpc_client_call(client, "/test.Echo/Unary", &seven, 1, soon(), on_done, o);
    run(nullptr, client, o);
    CHECK_U64(o->status, FT_GRPC_UNAVAILABLE);
    *o = (struct outcome){0};
    ft_grpc_client_call(client, "/test.Echo/Unary", &seven, 1, soon(), on_done, o);
    CHECK(o->done);
    CHECK_U64(o->status, FT_GRPC_UNAVAILABLE);

    ft_grpc_client_free(client);
    unlink(target + 5);
    rmdir(dir);
    free(large);
    free(o);
}

static void addresses(void)
{
    struct ft_net_addr addr;

    CHECK(ft_net_addr_parse("127.0.0.1:4317", &addr) && !ft_net_addr_is_unix(&addr));
    CHECK(ft_net_addr_parse("localhost:4317", &addr));
    CHECK(ft_net_addr_parse("[::1]:4317", &addr));
    CHECK(ft_net_addr_parse("unix:/run/filetrace/api.sock", &addr) && ft_net_addr_is_unix(&addr));
    CHECK(!ft_net_addr_parse("collector.example.com:4317", &addr));
    CHECK(!ft_net_addr_parse("127.0.0.1", &addr));
    CHECK(!ft_net_addr_parse("127.0.0.1:0", &addr));
    CHECK(!ft_net_addr_parse("::1:4317", &addr));
    CHECK(!ft_net_addr_parse("unix:", &addr));
}

constexpr uint32_t CURL = 3312;
constexpr uint64_t BY_LOOKUP = 41; /* two names looked up to the address */
constexpr uint64_t BY_TLS = 42;    /* a TLS server name through a looked-up proxy */
constexpr uint64_t BY_BOTH = 43;   /* the TLS server name is the one looked up */
constexpr uint64_t NAMELESS = 44;

/* The agent's API on a state of its own, called through a client in the same process. */
struct api {
    char dir[32];
    char listen[64];
    struct ft_state *st;
    struct ft_api *api;
    struct ft_grpc_client *client;
    uint64_t now;
};

/* What a call of the API answered, and what a watch received. */
struct answer {
    bool done;
    enum ft_grpc_status status;
    char message[160];
    uint8_t *reply;
    size_t reply_len;
    Filetrace__V1__WatchTransfersResponse *events[8];
    size_t event_count;
};

static void no_stats(void *agent, uint64_t now_ns, struct ft_row_stats *row)
{
    (void)agent;
    (void)now_ns;
    (void)row;
}

static void to_api(void *ctx, const struct ft_row_event *row)
{
    struct api *a = ctx;
    ft_api_record(a->api, row);
}

static void ingest(struct api *a, struct ft_event *ev)
{
    a->now += FT_NS_PER_MS;
    ev->ts_ns = a->now;
    ft_state_ingest(a->st, ev);
}

static struct ft_endpoint v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    uint8_t raw[16] = {a, b, c, d};
    struct ft_endpoint ep;
    ft_endpoint_set(&ep, false, raw, port);
    return ep;
}

static void lookup(struct api *a, const char *name, struct ft_endpoint addr)
{
    struct ft_event ev = {.type = FT_EVENT_NAME_LOOKUP};
    ev.lookup.pid = CURL;
    ev.lookup.tid = CURL;
    ev.lookup.name = name;
    ev.lookup.addr_count = 1;
    ev.lookup.addrs[0] = addr;
    ingest(a, &ev);
}

static void connect_to(struct api *a, uint64_t sock, struct ft_endpoint remote)
{
    static const enum ft_sock_state states[] = {FT_SOCK_CONNECTING, FT_SOCK_ESTABLISHED};

    for (size_t i = 0; i < FT_ARRAY_LEN(states); i++) {
        struct ft_event ev = {.type = FT_EVENT_SOCKET_STATE};
        ev.socket.sock_id = sock;
        ev.socket.pid = CURL;
        ev.socket.tid = CURL;
        ev.socket.proto = FT_PROTO_TCP;
        ev.socket.state = states[i];
        ev.socket.local = v4(10, 0, 0, 12, (uint16_t)(50000 + sock));
        ev.socket.remote = remote;
        ingest(a, &ev);
    }
}

static void tls_name(struct api *a, uint64_t sock, const char *name)
{
    struct ft_event ev = {.type = FT_EVENT_TLS_NAME};
    ev.tls_name.sock_id = sock;
    ev.tls_name.pid = CURL;
    ev.tls_name.name = name;
    ingest(a, &ev);
}

/* A file of its own for each socket, sent in one call. */
static void file_sent(struct api *a, uint64_t sock)
{
    char path[32];
    struct ft_event ev = {.type = FT_EVENT_FILE_SEEN};

    snprintf(path, sizeof(path), "/data/%llu.bin", (unsigned long long)sock);
    ev.file.id = (struct ft_file_id){.dev = 2049, .ino = sock};
    ev.file.path = path;
    ev.file.size = 65536;
    ingest(a, &ev);

    ev = (struct ft_event){.type = FT_EVENT_TRANSFER};
    ev.transfer.sock_id = sock;
    ev.transfer.pid = CURL;
    ev.transfer.method = FT_METHOD_SENDFILE;
    ev.transfer.file = (struct ft_file_id){.dev = 2049, .ino = sock};
    ev.transfer.first_ns = a->now;
    ev.transfer.bytes = 65536;
    ev.transfer.ops = 1;
    ingest(a, &ev);
}

static void api_open(struct api *a, bool names)
{
    struct ft_state_config cfg;
    struct ft_net_addr addr;
    struct ft_error err = {0};
    struct ft_api_config api_cfg = {.enabled = true};

    *a = (struct api){0};
    ft_strlcpy(a->dir, "/tmp/filetrace-api-XXXXXX", sizeof(a->dir));
    CHECK(mkdtemp(a->dir) != nullptr);
    snprintf(a->listen, sizeof(a->listen), "unix:%s/api.sock", a->dir);
    ft_strlcpy(api_cfg.listen, a->listen, sizeof(api_cfg.listen));

    ft_state_config_defaults(&cfg);
    cfg.names = names;
    a->st = ft_state_create(&cfg);
    a->now = ft_clock_mono_ns();
    struct ft_telemetry_source src = {.state = a->st, .stats = no_stats, .host = "web-01"};
    a->api = ft_api_open(&api_cfg, &src, &err);
    CHECK(a->api != nullptr);
    a->st->on_record = to_api;
    a->st->on_record_ctx = a;
    CHECK(ft_net_addr_parse(a->listen, &addr));
    a->client = ft_grpc_client_new(&addr, "localhost");

    struct ft_event ev = {.type = FT_EVENT_PROCESS_EXEC};
    ev.process.pid = CURL;
    ev.process.ppid = 1;
    ev.process.start_ns = a->now;
    ft_strlcpy(ev.process.comm, "curl", sizeof(ev.process.comm));
    ingest(a, &ev);

    lookup(a, "static.example.com", v4(203, 0, 113, 25, 0));
    lookup(a, "cdn.example.com", v4(203, 0, 113, 25, 0));
    connect_to(a, BY_LOOKUP, v4(203, 0, 113, 25, 80));
    lookup(a, "proxy.corp.example", v4(10, 0, 0, 5, 0));
    connect_to(a, BY_TLS, v4(10, 0, 0, 5, 3128));
    tls_name(a, BY_TLS, "files.example.com");
    lookup(a, "s3.example.com", v4(52, 219, 170, 52, 0));
    connect_to(a, BY_BOTH, v4(52, 219, 170, 52, 443));
    tls_name(a, BY_BOTH, "S3.example.com");
    connect_to(a, NAMELESS, v4(198, 51, 100, 7, 443));
    for (uint64_t sock = BY_LOOKUP; sock <= NAMELESS; sock++)
        file_sent(a, sock);
}

static void api_close(struct api *a)
{
    ft_grpc_client_free(a->client);
    ft_api_close(a->api);
    ft_state_destroy(a->st);
    rmdir(a->dir);
}

static void answer_free(struct answer *r)
{
    free(r->reply);
    for (size_t i = 0; i < r->event_count; i++) {
        if (r->events[i])
            filetrace__v1__watch_transfers_response__free_unpacked(r->events[i], nullptr);
    }
    *r = (struct answer){0};
}

static void answered(void *ctx, enum ft_grpc_status status, const char *message,
                     const uint8_t *reply, size_t size)
{
    struct answer *r = ctx;

    r->done = true;
    r->status = status;
    ft_strlcpy(r->message, message, sizeof(r->message));
    r->reply = malloc(size ? size : 1);
    if (size)
        memcpy(r->reply, reply, size);
    r->reply_len = size;
}

static void watched(void *ctx, const uint8_t *message, size_t size)
{
    struct answer *r = ctx;

    if (r->event_count < FT_ARRAY_LEN(r->events))
        r->events[r->event_count++] =
            filetrace__v1__watch_transfers_response__unpack(nullptr, size, message);
}

/* Runs the API and the client until the call ends, the events arrive, or a second has passed. */
static void api_run(struct api *a, const struct answer *r, size_t events)
{
    static struct ft_poller poller;
    uint64_t give_up_ns = ft_clock_mono_ns() + FT_NS_PER_SEC;

    while (!r->done && r->event_count < events && ft_clock_mono_ns() < give_up_ns) {
        uint64_t now_ns = ft_clock_mono_ns();

        ft_poller_begin(&poller, now_ns + 10 * FT_NS_PER_MS);
        ft_api_poll(a->api, &poller);
        ft_grpc_client_poll(a->client, &poller);
        ft_poller_wait(&poller, now_ns);
        ft_api_dispatch(a->api, &poller);
        ft_grpc_client_dispatch(a->client, &poller, ft_clock_mono_ns());
    }
}

static ListResponse *list(struct api *a, TransferFilter *filter, struct answer *r)
{
    Filetrace__V1__ListTransfersRequest request = FILETRACE__V1__LIST_TRANSFERS_REQUEST__INIT;
    uint8_t message[1024];

    request.filter = filter;
    size_t size = filetrace__v1__list_transfers_request__pack(&request, message);
    ft_grpc_client_call(a->client, "/filetrace.v1.FiletraceService/ListTransfers", message, size,
                        soon(), answered, r);
    api_run(a, r, SIZE_MAX);
    CHECK(r->done);
    return r->status == FT_GRPC_OK
               ? filetrace__v1__list_transfers_response__unpack(nullptr, r->reply_len, r->reply)
               : nullptr;
}

static void watch(struct api *a, TransferFilter *filter, struct answer *r)
{
    Filetrace__V1__WatchTransfersRequest request = FILETRACE__V1__WATCH_TRANSFERS_REQUEST__INIT;
    uint8_t message[1024];

    request.filter = filter;
    size_t size = filetrace__v1__watch_transfers_request__pack(&request, message);
    ft_grpc_client_stream(a->client, "/filetrace.v1.FiletraceService/WatchTransfers", message, size,
                          soon(), watched, answered, r);
    /* Calls on one connection are read in order: once a later one is answered, the watch is on. */
    struct answer listed = {0};
    ListResponse *l = list(a, nullptr, &listed);
    if (l)
        filetrace__v1__list_transfers_response__free_unpacked(l, nullptr);
    answer_free(&listed);
}

static const Connection *on_socket(const ListResponse *l, uint64_t sock)
{
    for (size_t i = 0; l && i < l->n_transfers; i++) {
        if (l->transfers[i]->connection->socket_id == sock)
            return l->transfers[i]->connection;
    }
    return nullptr;
}

static const Connection *event_connection(const struct answer *r, size_t i)
{
    return i < r->event_count && r->events[i] && r->events[i]->event
               ? r->events[i]->event->connection
               : nullptr;
}

static void check_names(const Connection *c, const char *name, Filetrace__V1__NameSource source,
                        const char *resolved, uint32_t count)
{
    char joined[256] = "";

    CHECK(c != nullptr);
    if (!c)
        return;
    CHECK_STR(c->remote_name, name);
    CHECK_U64(c->remote_name_source, source);
    for (size_t i = 0; i < c->n_resolved_names; i++)
        snprintf(joined + strlen(joined), sizeof(joined) - strlen(joined), "%s%s", i ? "," : "",
                 c->resolved_names[i]);
    CHECK_STR(joined, resolved);
    CHECK_U64(c->resolved_name_count, count);
}

static void lists_the_names_of_each_connection(void)
{
    struct api a;
    struct answer r = {0};

    api_open(&a, true);
    ListResponse *l = list(&a, nullptr, &r);
    CHECK(l != nullptr && l->n_transfers == 4);
    check_names(on_socket(l, BY_LOOKUP), "cdn.example.com",
                FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_LOOKUP,
                "cdn.example.com,static.example.com", 2);
    check_names(on_socket(l, BY_TLS), "files.example.com",
                FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_TLS, "proxy.corp.example", 1);
    check_names(on_socket(l, BY_BOTH), "s3.example.com",
                FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_LOOKUP_AND_TLS, "s3.example.com", 1);
    check_names(on_socket(l, NAMELESS), "", FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_UNSPECIFIED, "",
                0);
    if (l)
        filetrace__v1__list_transfers_response__free_unpacked(l, nullptr);
    answer_free(&r);

    /* A watcher's events carry the names their connection had when they were made. */
    watch(&a, nullptr, &r);
    file_sent(&a, BY_LOOKUP);
    file_sent(&a, BY_TLS);
    file_sent(&a, NAMELESS);
    api_run(&a, &r, 3);
    CHECK_U64(r.event_count, 3);
    check_names(event_connection(&r, 0), "cdn.example.com",
                FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_LOOKUP,
                "cdn.example.com,static.example.com", 2);
    check_names(event_connection(&r, 1), "files.example.com",
                FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_TLS, "proxy.corp.example", 1);
    check_names(event_connection(&r, 2), "", FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_UNSPECIFIED,
                "", 0);
    answer_free(&r);
    api_close(&a);
}

/* What two runs see apart: times and rates, read off a clock that moves between them. */
static void forget_times(ListResponse *l)
{
    l->observed_since_unix_nano = 0;
    for (size_t i = 0; i < l->n_transfers; i++) {
        l->transfers[i]->start_time_unix_nano = 0;
        l->transfers[i]->last_time_unix_nano = 0;
        l->transfers[i]->bytes_per_second = 0;
    }
}

/* An unpacked message owns its strings, which the default allocator took from malloc. */
static void forget_names(ListResponse *l)
{
    for (size_t i = 0; i < l->n_transfers; i++) {
        Connection *c = l->transfers[i]->connection;
        if (c->remote_name[0])
            c->remote_name[0] = '\0';
        c->remote_name_source = FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_UNSPECIFIED;
        for (size_t n = 0; n < c->n_resolved_names; n++)
            free(c->resolved_names[n]);
        c->n_resolved_names = 0;
        c->resolved_name_count = 0;
    }
}

static uint8_t *pack_list(const ListResponse *l, size_t *size)
{
    *size = filetrace__v1__list_transfers_response__get_packed_size(l);
    uint8_t *bytes = malloc(*size ? *size : 1);
    filetrace__v1__list_transfers_response__pack(l, bytes);
    return bytes;
}

/* With names off, an answer is the named one without its name fields, byte for byte. */
static void answers_without_names_as_before(void)
{
    struct api named;
    struct api off;
    struct answer r = {0};
    struct answer q = {0};
    size_t named_size = 0;
    size_t off_size = 0;

    api_open(&named, true);
    api_open(&off, false);
    ListResponse *with = list(&named, nullptr, &r);
    ListResponse *without = list(&off, nullptr, &q);
    CHECK(with && without && with->n_transfers == 4 && without->n_transfers == 4);
    if (with && without) {
        for (size_t i = 0; i < without->n_transfers; i++)
            check_names(without->transfers[i]->connection, "",
                        FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_UNSPECIFIED, "", 0);
        forget_times(with);
        forget_times(without);
        forget_names(with);
        uint8_t *stripped = pack_list(with, &named_size);
        uint8_t *bare = pack_list(without, &off_size);
        CHECK(named_size == off_size && memcmp(stripped, bare, off_size) == 0);
        free(stripped);
        free(bare);
    }
    if (with)
        filetrace__v1__list_transfers_response__free_unpacked(with, nullptr);
    if (without)
        filetrace__v1__list_transfers_response__free_unpacked(without, nullptr);
    answer_free(&q);
    watch(&off, nullptr, &q);
    file_sent(&off, BY_LOOKUP);
    api_run(&off, &q, 1);
    CHECK_U64(q.event_count, 1);
    check_names(event_connection(&q, 0), "", FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_UNSPECIFIED,
                "", 0);
    answer_free(&r);
    answer_free(&q);
    api_close(&named);
    api_close(&off);
}

void test_grpc(void)
{
    addresses();
    calls_reach_the_service_and_come_back();
    lists_the_names_of_each_connection();
    answers_without_names_as_before();
}
