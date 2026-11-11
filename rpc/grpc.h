#ifndef FILETRACE_GRPC_H
#define FILETRACE_GRPC_H

#include "filetrace/net.h"
#include "filetrace/poller.h"

/*
 * gRPC over cleartext HTTP/2: unary calls and server streams, with uncompressed messages.
 * Everything runs inside the caller's poll loop and nothing blocks.
 */

enum ft_grpc_status : int {
    FT_GRPC_OK = 0,
    FT_GRPC_CANCELLED = 1,
    FT_GRPC_UNKNOWN = 2,
    FT_GRPC_INVALID_ARGUMENT = 3,
    FT_GRPC_DEADLINE_EXCEEDED = 4,
    FT_GRPC_NOT_FOUND = 5,
    FT_GRPC_RESOURCE_EXHAUSTED = 8,
    FT_GRPC_ABORTED = 10,
    FT_GRPC_OUT_OF_RANGE = 11,
    FT_GRPC_UNIMPLEMENTED = 12,
    FT_GRPC_INTERNAL = 13,
    FT_GRPC_UNAVAILABLE = 14,
    FT_GRPC_DATA_LOSS = 15,
};

#define FT_GRPC_MAX_MESSAGE (4u * 1024u * 1024u)

/* Client. */

struct ft_grpc_client;

/* reply is the response message and is valid only during the call. */
typedef void ft_grpc_done_fn(void *ctx, enum ft_grpc_status status, const char *message,
                             const uint8_t *reply, size_t size);

struct ft_grpc_client *ft_grpc_client_new(const struct ft_net_addr *addr, const char *authority);
void ft_grpc_client_free(struct ft_grpc_client *c);

/*
 * Starts a unary call, connecting first if need be. request must stay valid until done is
 * called, which happens exactly once and possibly before this returns. A server that cannot be
 * reached answers FT_GRPC_UNAVAILABLE, and is not tried again until a growing pause has passed.
 */
void ft_grpc_client_call(struct ft_grpc_client *c, const char *path, const uint8_t *request,
                         size_t size, uint64_t deadline_ns, ft_grpc_done_fn *done, void *ctx);

typedef void ft_grpc_message_fn(void *ctx, const uint8_t *message, size_t size);

/*
 * The same for a call the server answers with a stream: on_message receives each message as it
 * arrives and done the final status, with no reply.
 */
void ft_grpc_client_stream(struct ft_grpc_client *c, const char *path, const uint8_t *request,
                           size_t size, uint64_t deadline_ns, ft_grpc_message_fn *on_message,
                           ft_grpc_done_fn *done, void *ctx);

void ft_grpc_client_poll(struct ft_grpc_client *c, struct ft_poller *p);
void ft_grpc_client_dispatch(struct ft_grpc_client *c, const struct ft_poller *p, uint64_t now_ns);

/* Server. */

struct ft_grpc_server;
struct ft_grpc_call;

struct ft_grpc_service {
    void *ctx;

    /* A whole request arrived. Answer with ft_grpc_send and ft_grpc_finish, now or later. */
    void (*on_call)(void *ctx, struct ft_grpc_call *call, const char *path, const uint8_t *request,
                    size_t size);

    /* Called once for every call when it is over; the call must not be used afterwards. */
    void (*on_end)(void *ctx, struct ft_grpc_call *call);
};

/* Takes ownership of listen_fd. With trusted_only, a Unix peer must be root or this user. */
struct ft_grpc_server *ft_grpc_server_new(int listen_fd, bool trusted_only,
                                          const struct ft_grpc_service *service);
void ft_grpc_server_free(struct ft_grpc_server *s);

void ft_grpc_server_poll(struct ft_grpc_server *s, struct ft_poller *p);
void ft_grpc_server_dispatch(struct ft_grpc_server *s, const struct ft_poller *p);

/* Queues one response message. False when the caller has too much unread: nothing was queued. */
bool ft_grpc_send(struct ft_grpc_call *call, const uint8_t *message, size_t size);

void ft_grpc_finish(struct ft_grpc_call *call, enum ft_grpc_status status, const char *message);

void ft_grpc_call_set_data(struct ft_grpc_call *call, void *data);
void *ft_grpc_call_data(const struct ft_grpc_call *call);

#endif
