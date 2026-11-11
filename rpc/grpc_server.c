#include "rpc/grpc.h"

#include "rpc/h2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

constexpr size_t MAX_CONNECTIONS = 16;
constexpr uint32_t MAX_STREAMS = 32;
constexpr size_t MAX_REQUEST_BYTES = 64 * 1024;
/* A call with more than this unread is sent nothing further until its reader catches up. */
constexpr size_t MAX_UNREAD_BYTES = 1024 * 1024;

struct connection;

struct ft_grpc_call {
    struct connection *conn;
    struct ft_grpc_call *next;
    int32_t stream_id;
    char path[128];
    bool is_grpc;    /* the content type says so */
    bool oversized;  /* the request outgrew its limit */
    bool responding; /* response headers are submitted */
    bool finished;
    bool waiting; /* the stream is paused until there is more to send */
    enum ft_grpc_status status;
    char message[160];
    uint8_t *in;
    size_t in_len;
    size_t in_cap;
    uint8_t *out;
    size_t out_len;
    size_t out_off;
    size_t out_cap;
    void *data;
};

struct connection {
    struct ft_grpc_server *server;
    struct ft_h2 h2;
    size_t slot;
    struct ft_grpc_call *calls;
};

struct ft_grpc_server {
    struct ft_grpc_service service;
    int listen_fd;
    size_t listen_slot;
    bool trusted_only;
    struct connection conns[MAX_CONNECTIONS];
    size_t count;
};

static void call_free(struct ft_grpc_call *call)
{
    struct ft_grpc_call **link = &call->conn->calls;

    while (*link && *link != call)
        link = &(*link)->next;
    if (*link)
        *link = call->next;
    call->conn->server->service.on_end(call->conn->server->service.ctx, call);
    free(call->in);
    free(call->out);
    free(call);
}

/* Percent-encodes what a header value cannot carry as it is. */
static void encode_message(const char *in, char *out, size_t size)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t n = 0;

    for (const unsigned char *p = (const unsigned char *)in; *p && n + 4 < size; p++) {
        if (*p >= 0x20 && *p < 0x7f && *p != '%') {
            out[n++] = (char)*p;
        } else {
            out[n++] = '%';
            out[n++] = hex[*p >> 4];
            out[n++] = hex[*p & 15];
        }
    }
    out[n] = '\0';
}

static void submit_trailers(struct ft_grpc_call *call)
{
    char status[12];
    char message[sizeof(call->message) * 3];

    snprintf(status, sizeof(status), "%d", (int)call->status);
    encode_message(call->message, message, sizeof(message));
    const nghttp2_nv trailers[] = {
        FT_H2_NV("grpc-status", status),
        FT_H2_NV("grpc-message", message),
    };
    nghttp2_submit_trailer(call->conn->h2.session, call->stream_id, trailers, message[0] ? 2 : 1);
}

static nghttp2_ssize read_response(nghttp2_session *session, int32_t stream_id, uint8_t *buf,
                                   size_t length, uint32_t *data_flags, nghttp2_data_source *source,
                                   void *user_data)
{
    struct ft_grpc_call *call = source->ptr;
    size_t unread = call->out_len - call->out_off;
    size_t n = unread < length ? unread : length;

    (void)session;
    (void)stream_id;
    (void)user_data;
    if (n == 0 && !call->finished) {
        call->waiting = true;
        return NGHTTP2_ERR_DEFERRED;
    }
    memcpy(buf, call->out + call->out_off, n);
    call->out_off += n;
    if (call->out_off == call->out_len && call->finished) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF | NGHTTP2_DATA_FLAG_NO_END_STREAM;
        submit_trailers(call);
    }
    return (nghttp2_ssize)n;
}

static void resume(struct ft_grpc_call *call)
{
    if (!call->waiting)
        return;
    call->waiting = false;
    nghttp2_session_resume_data(call->conn->h2.session, call->stream_id);
}

bool ft_grpc_send(struct ft_grpc_call *call, const uint8_t *message, size_t size)
{
    size_t unread = call->out_len - call->out_off;
    uint8_t prefix[5];

    if (call->finished || size > FT_GRPC_MAX_MESSAGE || unread > MAX_UNREAD_BYTES)
        return false;
    if (call->out_off == call->out_len) {
        call->out_off = 0;
        call->out_len = 0;
    }
    size_t need = call->out_len + sizeof(prefix) + size;
    if (need > call->out_cap) {
        size_t cap = call->out_cap ? call->out_cap : 1024;
        while (cap < need)
            cap *= 2;
        uint8_t *grown = realloc(call->out, cap);
        if (!grown)
            return false;
        call->out = grown;
        call->out_cap = cap;
    }
    ft_grpc_prefix(prefix, size);
    memcpy(call->out + call->out_len, prefix, sizeof(prefix));
    if (size)
        memcpy(call->out + call->out_len + sizeof(prefix), message, size);
    call->out_len = need;

    if (!call->responding) {
        const nghttp2_nv headers[] = {
            FT_H2_NV(":status", "200"),
            FT_H2_NV("content-type", "application/grpc"),
        };
        nghttp2_data_provider2 body = {.source.ptr = call, .read_callback = read_response};

        call->responding = true;
        nghttp2_submit_response2(call->conn->h2.session, call->stream_id, headers,
                                 FT_ARRAY_LEN(headers), &body);
    }
    resume(call);
    return true;
}

void ft_grpc_finish(struct ft_grpc_call *call, enum ft_grpc_status status, const char *message)
{
    if (call->finished)
        return;
    call->finished = true;
    call->status = status;
    ft_strlcpy(call->message, message ? message : "", sizeof(call->message));

    if (call->responding) {
        resume(call);
        return;
    }
    char code[12];
    char text[sizeof(call->message) * 3];

    snprintf(code, sizeof(code), "%d", (int)status);
    encode_message(call->message, text, sizeof(text));
    const nghttp2_nv headers[] = {
        FT_H2_NV(":status", "200"),
        FT_H2_NV("content-type", "application/grpc"),
        FT_H2_NV("grpc-status", code),
        FT_H2_NV("grpc-message", text),
    };
    call->responding = true;
    nghttp2_submit_response2(call->conn->h2.session, call->stream_id, headers, text[0] ? 4 : 3,
                             nullptr);
}

void ft_grpc_call_set_data(struct ft_grpc_call *call, void *data)
{
    call->data = data;
}

void *ft_grpc_call_data(const struct ft_grpc_call *call)
{
    return call->data;
}

static int on_begin_headers(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    struct connection *conn = user_data;

    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    struct ft_grpc_call *call = calloc(1, sizeof(*call));
    if (!call)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    call->conn = conn;
    call->stream_id = frame->hd.stream_id;
    call->next = conn->calls;
    conn->calls = call;
    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, call);
    return 0;
}

static int on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name,
                     size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags,
                     void *user_data)
{
    static const char path[] = ":path";
    static const char type[] = "content-type";
    static const char grpc[] = "application/grpc";
    struct ft_grpc_call *call = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    (void)flags;
    (void)user_data;
    if (!call || frame->hd.type != NGHTTP2_HEADERS)
        return 0;
    if (namelen == sizeof(path) - 1 && memcmp(name, path, namelen) == 0) {
        if (valuelen < sizeof(call->path)) {
            memcpy(call->path, value, valuelen);
            call->path[valuelen] = '\0';
        }
    } else if (namelen == sizeof(type) - 1 && memcmp(name, type, namelen) == 0) {
        call->is_grpc = valuelen >= sizeof(grpc) - 1 && memcmp(value, grpc, sizeof(grpc) - 1) == 0;
    }
    return 0;
}

static int on_data(nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data,
                   size_t len, void *user_data)
{
    struct ft_grpc_call *call = nghttp2_session_get_stream_user_data(session, stream_id);

    (void)flags;
    (void)user_data;
    if (!call || call->oversized)
        return 0;
    if (call->in_len + len > MAX_REQUEST_BYTES) {
        call->oversized = true;
        return 0;
    }
    if (call->in_len + len > call->in_cap) {
        size_t cap = call->in_cap ? call->in_cap : 256;
        while (cap < call->in_len + len)
            cap *= 2;
        uint8_t *grown = realloc(call->in, cap);
        if (!grown)
            return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        call->in = grown;
        call->in_cap = cap;
    }
    memcpy(call->in + call->in_len, data, len);
    call->in_len += len;
    return 0;
}

static void answer(struct ft_grpc_call *call)
{
    const struct ft_grpc_service *service = &call->conn->server->service;
    const uint8_t *request;
    size_t size;

    if (!call->is_grpc) {
        const nghttp2_nv headers[] = {FT_H2_NV(":status", "415")};
        call->responding = true;
        call->finished = true;
        nghttp2_submit_response2(call->conn->h2.session, call->stream_id, headers, 1, nullptr);
    } else if (call->oversized) {
        ft_grpc_finish(call, FT_GRPC_RESOURCE_EXHAUSTED, "the request is too large");
    } else if (call->in_len >= 1 && call->in[0] != 0) {
        ft_grpc_finish(call, FT_GRPC_UNIMPLEMENTED, "compressed messages are not accepted");
    } else if (!ft_grpc_unwrap(call->in, call->in_len, &request, &size)) {
        ft_grpc_finish(call, FT_GRPC_INVALID_ARGUMENT, "expected exactly one request message");
    } else {
        service->on_call(service->ctx, call, call->path, request, size);
    }
}

static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    (void)user_data;
    if ((frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) ||
        !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
        return 0;
    struct ft_grpc_call *call = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (call && !call->responding)
        answer(call);
    return 0;
}

static int on_stream_close(nghttp2_session *session, int32_t stream_id, uint32_t error_code,
                           void *user_data)
{
    struct ft_grpc_call *call = nghttp2_session_get_stream_user_data(session, stream_id);

    (void)error_code;
    (void)user_data;
    if (call) {
        nghttp2_session_set_stream_user_data(session, stream_id, nullptr);
        call_free(call);
    }
    return 0;
}

static bool connection_open(struct connection *conn, struct ft_grpc_server *s, int fd)
{
    const nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, MAX_STREAMS},
    };
    nghttp2_session_callbacks *callbacks;

    *conn = (struct connection){.server = s, .h2.fd = fd, .slot = FT_POLLER_NONE};
    if (nghttp2_session_callbacks_new(&callbacks) != 0)
        return false;
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close);
    int rc = nghttp2_session_server_new(&conn->h2.session, callbacks, conn);
    nghttp2_session_callbacks_del(callbacks);
    return rc == 0 && nghttp2_submit_settings(conn->h2.session, NGHTTP2_FLAG_NONE, settings,
                                              FT_ARRAY_LEN(settings)) == 0;
}

static void connection_close(struct connection *conn)
{
    while (conn->calls)
        call_free(conn->calls);
    ft_h2_close(&conn->h2);
}

struct ft_grpc_server *ft_grpc_server_new(int listen_fd, bool trusted_only,
                                          const struct ft_grpc_service *service)
{
    struct ft_grpc_server *s = calloc(1, sizeof(*s));
    if (!s)
        return nullptr;
    s->service = *service;
    s->listen_fd = listen_fd;
    s->listen_slot = FT_POLLER_NONE;
    s->trusted_only = trusted_only;
    return s;
}

void ft_grpc_server_free(struct ft_grpc_server *s)
{
    if (!s)
        return;
    for (size_t i = 0; i < s->count; i++)
        connection_close(&s->conns[i]);
    close(s->listen_fd);
    free(s);
}

void ft_grpc_server_poll(struct ft_grpc_server *s, struct ft_poller *p)
{
    s->listen_slot =
        s->count < MAX_CONNECTIONS ? ft_poller_add(p, s->listen_fd, POLLIN) : FT_POLLER_NONE;
    for (size_t i = 0; i < s->count; i++)
        s->conns[i].slot = ft_poller_add(p, s->conns[i].h2.fd, ft_h2_events(&s->conns[i].h2));
}

/* Calls point at their connection, so one that moves takes them along. */
static void connection_move(struct connection *to, struct connection *from)
{
    *to = *from;
    nghttp2_session_set_user_data(to->h2.session, to);
    for (struct ft_grpc_call *call = to->calls; call; call = call->next)
        call->conn = to;
}

void ft_grpc_server_dispatch(struct ft_grpc_server *s, const struct ft_poller *p)
{
    for (size_t i = s->count; i-- > 0;) {
        struct connection *conn = &s->conns[i];
        short revents = ft_poller_revents(p, conn->slot);
        bool alive = true;

        if (revents & (POLLIN | POLLHUP | POLLERR))
            alive = ft_h2_read(&conn->h2);
        if (alive)
            alive = ft_h2_write(&conn->h2);
        if (!alive) {
            connection_close(conn);
            if (i != --s->count)
                connection_move(conn, &s->conns[s->count]);
        }
    }
    while (s->count < MAX_CONNECTIONS && (ft_poller_revents(p, s->listen_slot) & POLLIN)) {
        int fd = ft_net_accept(s->listen_fd);
        if (fd < 0)
            break;
        if (s->trusted_only && !ft_net_peer_trusted(fd)) {
            ft_log(FT_LOG_WARN, "rejected an API client that is neither root nor the agent's user");
            close(fd);
            continue;
        }
        if (connection_open(&s->conns[s->count], s, fd))
            s->count++;
        else
            ft_h2_close(&s->conns[s->count].h2);
    }
}
