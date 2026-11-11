#ifndef FILETRACE_H2_H
#define FILETRACE_H2_H

#include "filetrace/base.h"

#include <nghttp2/nghttp2.h>

/* One HTTP/2 connection on a non-blocking socket. */
struct ft_h2 {
    int fd;
    nghttp2_session *session;
    const uint8_t *out; /* serialized frames the socket has not taken yet */
    size_t out_len;
};

#define FT_H2_NV(n, v)                                                                             \
    {(uint8_t *)(n), (uint8_t *)(v), sizeof(n) - 1, strlen(v), NGHTTP2_NV_FLAG_NONE}

/* Each returns false once the connection is of no further use. */
bool ft_h2_read(struct ft_h2 *h);
bool ft_h2_write(struct ft_h2 *h);

short ft_h2_events(const struct ft_h2 *h);
void ft_h2_close(struct ft_h2 *h);

/* The five bytes that precede a gRPC message of size bytes. */
void ft_grpc_prefix(uint8_t prefix[static 5], size_t size);

/* The message inside a body that holds exactly one; false for anything else. */
bool ft_grpc_unwrap(const uint8_t *body, size_t body_len, const uint8_t **message, size_t *size);

#endif
