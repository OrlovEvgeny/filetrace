#include "rpc/grpc.h"

#include "filetrace/clock.h"
#include "rpc/h2.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

constexpr size_t MAX_CALLS = 4;
constexpr uint64_t CONNECT_TIMEOUT_NS = 5 * FT_NS_PER_SEC;
constexpr uint64_t MIN_PAUSE_NS = FT_NS_PER_SEC;
constexpr uint64_t MAX_PAUSE_NS = 30 * FT_NS_PER_SEC;

struct call {
    struct ft_grpc_client *client;
    bool used;
    int32_t stream_id; /* 0 until the request is submitted */
    char path[128];
    uint8_t prefix[5];
    const uint8_t *request;
    size_t request_len;
    size_t sent; /* of the prefix and the request together */
    uint8_t *reply;
    size_t reply_len;
    size_t reply_cap;
    int http_status;
    int grpc_status; /* -1 until the server names one */
    char message[160];
    uint64_t deadline_ns;
    ft_grpc_message_fn *on_message; /* set for a call answered with a stream */
    ft_grpc_done_fn *done;
    void *ctx;
};

enum state : uint8_t {
    IDLE,
    CONNECTING,
    READY,
};

struct ft_grpc_client {
    struct ft_net_addr addr;
    char authority[108];
    struct ft_h2 h2;
    enum state state;
    size_t slot;
    uint64_t connect_deadline_ns;
    uint64_t retry_ns; /* no attempt to connect before this */
    uint64_t pause_ns;
    char failure[128]; /* why the server could not be reached last time */
    struct call calls[MAX_CALLS];
};

struct ft_grpc_client *ft_grpc_client_new(const struct ft_net_addr *addr, const char *authority)
{
    struct ft_grpc_client *c = calloc(1, sizeof(*c));
    if (!c)
        return nullptr;
    c->addr = *addr;
    c->h2.fd = -1;
    c->slot = FT_POLLER_NONE;
    c->pause_ns = MIN_PAUSE_NS;
    ft_strlcpy(c->authority, authority, sizeof(c->authority));
    return c;
}

static void finish(struct call *call, enum ft_grpc_status status, const char *message)
{
    const uint8_t *reply = nullptr;
    size_t size = 0;
    ft_grpc_done_fn *done = call->done;
    void *ctx = call->ctx;
    uint8_t *body = call->reply;
    char text[sizeof(call->message)];

    ft_strlcpy(text, message, sizeof(text));
    if (status == FT_GRPC_OK && !call->on_message &&
        !ft_grpc_unwrap(body, call->reply_len, &reply, &size)) {
        status = FT_GRPC_INTERNAL;
        ft_strlcpy(text, "the response is not one gRPC message", sizeof(text));
    }
    /* The slot is free before the callback, which may start the next call. */
    *call = (struct call){.client = call->client};
    done(ctx, status, text, reply, size);
    free(body);
}

static void disconnect(struct ft_grpc_client *c, const char *reason)
{
    bool wanted = c->state == CONNECTING;

    for (size_t i = 0; i < MAX_CALLS; i++)
        wanted = wanted || c->calls[i].used;

    ft_h2_close(&c->h2);
    c->state = IDLE;
    ft_strlcpy(c->failure, reason, sizeof(c->failure));
    /* A server that closes an idle connection has not failed anyone. */
    if (wanted) {
        c->retry_ns = ft_clock_mono_ns() + c->pause_ns;
        c->pause_ns = c->pause_ns * 2 > MAX_PAUSE_NS ? MAX_PAUSE_NS : c->pause_ns * 2;
    }

    for (size_t i = 0; i < MAX_CALLS; i++) {
        if (c->calls[i].used)
            finish(&c->calls[i], FT_GRPC_UNAVAILABLE, c->failure);
    }
}

void ft_grpc_client_free(struct ft_grpc_client *c)
{
    if (!c)
        return;
    ft_h2_close(&c->h2);
    for (size_t i = 0; i < MAX_CALLS; i++)
        free(c->calls[i].reply);
    free(c);
}

static struct call *call_of(struct ft_grpc_client *c, int32_t stream_id)
{
    for (size_t i = 0; i < MAX_CALLS; i++) {
        if (c->calls[i].used && c->calls[i].stream_id == stream_id)
            return &c->calls[i];
    }
    return nullptr;
}

static bool is(const uint8_t *name, size_t len, const char *expected)
{
    return len == strlen(expected) && memcmp(name, expected, len) == 0;
}

static int number(const uint8_t *value, size_t len)
{
    int n = 0;

    for (size_t i = 0; i < len && i < 6; i++) {
        if (value[i] < '0' || value[i] > '9')
            return -1;
        n = n * 10 + (value[i] - '0');
    }
    return len ? n : -1;
}

static int hex_digit(uint8_t c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c |= 0x20;
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

static int on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                     size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                     void *user_data)
{
    struct call *call = call_of(user_data, frame->hd.stream_id);

    (void)session;
    (void)flags;
    if (!call || frame->hd.type != NGHTTP2_HEADERS)
        return 0;
    if (is(name, namelen, ":status")) {
        call->http_status = number(value, valuelen);
    } else if (is(name, namelen, "grpc-status")) {
        call->grpc_status = number(value, valuelen);
    } else if (is(name, namelen, "grpc-message")) {
        size_t n = 0;

        /* The value is percent-encoded. */
        for (size_t i = 0; i < valuelen && n + 1 < sizeof(call->message); i++) {
            int high = i + 2 < valuelen && value[i] == '%' ? hex_digit(value[i + 1]) : -1;
            int low = high >= 0 ? hex_digit(value[i + 2]) : -1;

            if (low >= 0) {
                call->message[n++] = (char)(high << 4 | low);
                i += 2;
            } else {
                call->message[n++] = (char)value[i];
            }
        }
        call->message[n] = '\0';
    }
    return 0;
}

static int on_data(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                   size_t len, void *user_data)
{
    struct call *call = call_of(user_data, stream_id);

    (void)flags;
    if (!call)
        return 0;
    if (call->reply_len + len > FT_GRPC_MAX_MESSAGE + 5) {
        nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE, stream_id, NGHTTP2_CANCEL);
        return 0;
    }
    if (call->reply_len + len > call->reply_cap) {
        size_t cap = call->reply_cap ? call->reply_cap : 256;
        while (cap < call->reply_len + len)
            cap *= 2;
        uint8_t *grown = realloc(call->reply, cap);
        if (!grown)
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        call->reply = grown;
        call->reply_cap = cap;
    }
    memcpy(call->reply + call->reply_len, data, len);
    call->reply_len += len;

    while (call->on_message && call->reply_len >= 5) {
        const uint8_t *r = call->reply;
        size_t size = (size_t)r[1] << 24 | (size_t)r[2] << 16 | (size_t)r[3] << 8 | r[4];

        if (call->reply_len < 5 + size)
            break;
        call->on_message(call->ctx, r + 5, size);
        call->reply_len -= 5 + size;
        memmove(call->reply, call->reply + 5 + size, call->reply_len);
    }
    return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                           void *user_data)
{
    struct ft_grpc_client *c = user_data;
    struct call *call = call_of(c, stream_id);
    char why[64];

    (void)session;
    if (!call)
        return 0;
    if (call->grpc_status >= 0) {
        /* The server answered, whatever it said: it is reachable. */
        c->pause_ns = MIN_PAUSE_NS;
        finish(call, (enum ft_grpc_status)call->grpc_status, call->message);
    } else if (error_code != NGHTTP2_NO_ERROR) {
        snprintf(why, sizeof(why), "the server reset the stream (%s)",
                 nghttp2_http2_strerror(error_code));
        finish(call, FT_GRPC_UNAVAILABLE, why);
    } else {
        bool busy = call->http_status == 429 || call->http_status == 502 ||
                    call->http_status == 503 || call->http_status == 504;
        snprintf(why, sizeof(why), "HTTP status %d without a gRPC status", call->http_status);
        finish(call, busy ? FT_GRPC_UNAVAILABLE : FT_GRPC_UNKNOWN, why);
    }
    return 0;
}

static nghttp2_ssize read_request(nghttp2_session *session, int32_t stream_id, uint8_t *buf,
                                  size_t length, uint32_t *data_flags, nghttp2_data_source *source,
                                  void *user_data)
{
    struct call *call = source->ptr;
    size_t total = sizeof(call->prefix) + call->request_len;
    size_t n = 0;

    (void)session;
    (void)stream_id;
    (void)user_data;
    while (n < length && call->sent < total) {
        size_t take;
        if (call->sent < sizeof(call->prefix)) {
            take = sizeof(call->prefix) - call->sent;
            take = take < length - n ? take : length - n;
            memcpy(buf + n, call->prefix + call->sent, take);
        } else {
            size_t off = call->sent - sizeof(call->prefix);
            take = call->request_len - off;
            take = take < length - n ? take : length - n;
            memcpy(buf + n, call->request + off, take);
        }
        n += take;
        call->sent += take;
    }
    if (call->sent == total)
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    return (nghttp2_ssize)n;
}

static bool submit(struct ft_grpc_client *c, struct call *call)
{
    const nghttp2_nv headers[] = {
        FT_H2_NV(":method", "POST"),
        FT_H2_NV(":scheme", "http"),
        FT_H2_NV(":path", call->path),
        FT_H2_NV(":authority", c->authority),
        FT_H2_NV("content-type", "application/grpc"),
        FT_H2_NV("te", "trailers"),
        FT_H2_NV("user-agent", "filetrace/" FT_VERSION),
    };
    nghttp2_data_provider2 body = {.source.ptr = call, .read_callback = read_request};

    call->stream_id = nghttp2_submit_request2(c->h2.session, nullptr, headers,
                                              FT_ARRAY_LEN(headers), &body, call);
    return call->stream_id > 0;
}

static bool session_open(struct ft_grpc_client *c)
{
    nghttp2_session_callbacks *callbacks;

    if (nghttp2_session_callbacks_new(&callbacks) != 0)
        return false;
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close);
    int rc = nghttp2_session_client_new(&c->h2.session, callbacks, c);
    nghttp2_session_callbacks_del(callbacks);
    return rc == 0 && nghttp2_submit_settings(c->h2.session, NGHTTP2_FLAG_NONE, nullptr, 0) == 0;
}

void ft_grpc_client_call(struct ft_grpc_client *c, const char *path, const uint8_t *request,
                         size_t size, uint64_t deadline_ns, ft_grpc_done_fn *done, void *ctx)
{
    ft_grpc_client_stream(c, path, request, size, deadline_ns, nullptr, done, ctx);
}

void ft_grpc_client_stream(struct ft_grpc_client *c, const char *path, const uint8_t *request,
                           size_t size, uint64_t deadline_ns, ft_grpc_message_fn *on_message,
                           ft_grpc_done_fn *done, void *ctx)
{
    uint64_t now_ns = ft_clock_mono_ns();
    struct call *call = nullptr;

    for (size_t i = 0; i < MAX_CALLS && !call; i++) {
        if (!c->calls[i].used)
            call = &c->calls[i];
    }
    if (!call || strlen(path) >= sizeof(call->path) || size > FT_GRPC_MAX_MESSAGE) {
        done(ctx, FT_GRPC_RESOURCE_EXHAUSTED,
             call ? "the request is too large" : "too many calls in progress", nullptr, 0);
        return;
    }
    *call = (struct call){
        .client = c,
        .used = true,
        .request = request,
        .request_len = size,
        .grpc_status = -1,
        .deadline_ns = deadline_ns,
        .on_message = on_message,
        .done = done,
        .ctx = ctx,
    };
    ft_strlcpy(call->path, path, sizeof(call->path));
    ft_grpc_prefix(call->prefix, size);

    if (c->state == READY) {
        if (!submit(c, call))
            finish(call, FT_GRPC_INTERNAL, "the request could not be queued");
        return;
    }
    if (c->state == CONNECTING)
        return;
    if (now_ns < c->retry_ns) {
        finish(call, FT_GRPC_UNAVAILABLE, c->failure);
        return;
    }
    c->h2.fd = ft_net_connect(&c->addr);
    if (c->h2.fd < 0) {
        disconnect(c, strerror(errno));
        return;
    }
    c->state = CONNECTING;
    c->connect_deadline_ns = now_ns + CONNECT_TIMEOUT_NS;
}

void ft_grpc_client_poll(struct ft_grpc_client *c, struct ft_poller *p)
{
    c->slot = FT_POLLER_NONE;
    if (c->state == CONNECTING) {
        c->slot = ft_poller_add(p, c->h2.fd, POLLOUT);
        ft_poller_wake_by(p, c->connect_deadline_ns);
    } else if (c->state == READY) {
        c->slot = ft_poller_add(p, c->h2.fd, ft_h2_events(&c->h2));
    }
    for (size_t i = 0; i < MAX_CALLS; i++) {
        if (c->calls[i].used)
            ft_poller_wake_by(p, c->calls[i].deadline_ns);
    }
}

void ft_grpc_client_dispatch(struct ft_grpc_client *c, const struct ft_poller *p, uint64_t now_ns)
{
    short revents = ft_poller_revents(p, c->slot);

    if (c->state == CONNECTING) {
        if (revents) {
            int error = ft_net_connect_result(c->h2.fd);
            if (error != 0) {
                disconnect(c, strerror(error));
            } else if (!session_open(c)) {
                disconnect(c, "out of memory");
            } else {
                c->state = READY;
                for (size_t i = 0; i < MAX_CALLS; i++) {
                    if (c->calls[i].used && !submit(c, &c->calls[i]))
                        finish(&c->calls[i], FT_GRPC_INTERNAL, "the request could not be queued");
                }
            }
        } else if (now_ns >= c->connect_deadline_ns) {
            disconnect(c, "the connection attempt timed out");
        }
    }
    if (c->state != READY)
        return;

    for (size_t i = 0; i < MAX_CALLS; i++) {
        struct call *call = &c->calls[i];
        if (call->used && now_ns >= call->deadline_ns) {
            nghttp2_submit_rst_stream(c->h2.session, NGHTTP2_FLAG_NONE, call->stream_id,
                                      NGHTTP2_CANCEL);
            finish(call, FT_GRPC_DEADLINE_EXCEEDED, "the server did not answer in time");
        }
    }
    if ((revents & (POLLIN | POLLHUP | POLLERR)) && !ft_h2_read(&c->h2)) {
        disconnect(c, "the server closed the connection");
        return;
    }
    if (!ft_h2_write(&c->h2))
        disconnect(c, "the server closed the connection");
}
