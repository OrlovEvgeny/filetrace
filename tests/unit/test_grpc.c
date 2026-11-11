#include "unit/test.h"

#include "filetrace/clock.h"
#include "rpc/grpc.h"

#include <stdlib.h>
#include <unistd.h>

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

void test_grpc(void)
{
    addresses();
    calls_reach_the_service_and_come_back();
}
