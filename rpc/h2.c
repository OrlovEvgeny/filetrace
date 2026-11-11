#include "rpc/h2.h"

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

bool ft_h2_read(struct ft_h2 *h)
{
    uint8_t buf[16384];

    for (;;) {
        ssize_t n = read(h->fd, buf, sizeof(buf));
        if (n == 0)
            return false;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
        if (nghttp2_session_mem_recv2(h->session, buf, (size_t)n) < 0)
            return false;
    }
}

bool ft_h2_write(struct ft_h2 *h)
{
    for (;;) {
        if (h->out_len == 0) {
            nghttp2_ssize n = nghttp2_session_mem_send2(h->session, &h->out);
            if (n < 0)
                return false;
            if (n == 0)
                break;
            h->out_len = (size_t)n;
        }
#if defined(MSG_NOSIGNAL)
        ssize_t n = send(h->fd, h->out, h->out_len, MSG_NOSIGNAL);
#else
        ssize_t n = write(h->fd, h->out, h->out_len);
#endif
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
        h->out += n;
        h->out_len -= (size_t)n;
    }
    return nghttp2_session_want_read(h->session) || nghttp2_session_want_write(h->session);
}

short ft_h2_events(const struct ft_h2 *h)
{
    bool writing = h->out_len || nghttp2_session_want_write(h->session);
    return (short)(POLLIN | (writing ? POLLOUT : 0));
}

void ft_h2_close(struct ft_h2 *h)
{
    if (h->session)
        nghttp2_session_del(h->session);
    if (h->fd >= 0)
        close(h->fd);
    *h = (struct ft_h2){.fd = -1};
}

void ft_grpc_prefix(uint8_t prefix[static 5], size_t size)
{
    prefix[0] = 0;
    prefix[1] = (uint8_t)(size >> 24);
    prefix[2] = (uint8_t)(size >> 16);
    prefix[3] = (uint8_t)(size >> 8);
    prefix[4] = (uint8_t)size;
}

bool ft_grpc_unwrap(const uint8_t *body, size_t body_len, const uint8_t **message, size_t *size)
{
    if (body_len < 5 || body[0] != 0)
        return false;
    size_t len = (size_t)body[1] << 24 | (size_t)body[2] << 16 | (size_t)body[3] << 8 | body[4];
    if (len != body_len - 5)
        return false;
    *message = body + 5;
    *size = len;
    return true;
}
