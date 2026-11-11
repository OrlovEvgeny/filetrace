#include "filetrace/client.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct ft_client {
    int fd;
    unsigned char *payload;
};

static bool write_all(int fd, const void *buf, size_t size)
{
    const unsigned char *p = buf;
    while (size) {
#if defined(MSG_NOSIGNAL)
        ssize_t n = send(fd, p, size, MSG_NOSIGNAL);
#else
        ssize_t n = write(fd, p, size);
#endif
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        p += n;
        size -= (size_t)n;
    }
    return true;
}

static bool read_all(int fd, void *buf, size_t size)
{
    unsigned char *p = buf;
    while (size) {
        ssize_t n = read(fd, p, size);
        if (n == 0)
            return false;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        p += n;
        size -= (size_t)n;
    }
    return true;
}

bool ft_wire_send(int fd, uint16_t type, const void *payload, size_t size)
{
    struct ft_frame_hdr hdr = {
        .magic = FT_WIRE_MAGIC,
        .version = FT_WIRE_VERSION,
        .type = type,
        .length = (uint32_t)size,
    };
    return write_all(fd, &hdr, sizeof(hdr)) && (size == 0 || write_all(fd, payload, size));
}

struct ft_client *ft_client_adopt(int fd)
{
    struct ft_client *c = calloc(1, sizeof(*c));
    if (c) {
        c->fd = fd;
        c->payload = malloc(FT_WIRE_MAX_PAYLOAD);
    }
    if (!c || !c->payload) {
        free(c);
        close(fd);
        return nullptr;
    }
#if defined(SO_NOSIGPIPE)
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    return c;
}

struct ft_client *ft_client_connect(const char *socket_path, struct ft_error *err)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};

    if (strlen(socket_path) >= sizeof(addr.sun_path)) {
        ft_error_set(err, FT_EXIT_USAGE, "Socket path is too long: %s", socket_path);
        return nullptr;
    }
    ft_strlcpy(addr.sun_path, socket_path, sizeof(addr.sun_path));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot create a socket: %s", strerror(errno));
        return nullptr;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;
        close(fd);
        if (saved == EACCES || saved == EPERM)
            ft_error_set(err, FT_EXIT_PERMISSION,
                         "Permission denied.\n\n"
                         "The daemon socket %s is not accessible to this user.\n"
                         "Run the command with sudo.",
                         socket_path);
        else
            ft_error_set(err, FT_EXIT_NO_DAEMON,
                         "The Filetrace daemon is not running (%s: %s).\n\n"
                         "Start it with:\n"
                         "  sudo filetrace daemon run\n\n"
                         "To check what this machine supports:\n"
                         "  sudo filetrace doctor",
                         socket_path, strerror(saved));
        return nullptr;
    }

    struct ft_client *c = ft_client_adopt(fd);
    if (!c)
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
    return c;
}

void ft_client_close(struct ft_client *c)
{
    if (!c)
        return;
    close(c->fd);
    free(c->payload);
    free(c);
}

static int broken(struct ft_error *err)
{
    return ft_error_set(err, FT_EXIT_NO_DAEMON, "The connection to the daemon was lost.");
}

int ft_client_query(struct ft_client *c, const struct ft_query *q, ft_client_row_fn *on_row,
                    void *ctx, struct ft_msg_end *end, struct ft_error *err)
{
    /* The path filter is sent only up to its terminator. */
    size_t size = offsetof(struct ft_query, path) + strnlen(q->path, FT_PATH_MAX - 1) + 1;
    /* A peer that has already given up may have left an error to read. */
    ft_wire_send(c->fd, FT_MSG_QUERY, q, size);

    for (;;) {
        struct ft_frame_hdr hdr;
        if (!read_all(c->fd, &hdr, sizeof(hdr)))
            return broken(err);
        if (hdr.magic != FT_WIRE_MAGIC || hdr.version != FT_WIRE_VERSION ||
            hdr.length > FT_WIRE_MAX_PAYLOAD)
            return ft_error_set(err, FT_EXIT_ERROR,
                                "The daemon speaks a different protocol version. "
                                "Upgrade filetrace and filetraced together.");
        if (hdr.length && !read_all(c->fd, c->payload, hdr.length))
            return broken(err);

        if (hdr.type == FT_MSG_END) {
            struct ft_msg_end local = {0};
            memcpy(&local, c->payload, hdr.length < sizeof(local) ? hdr.length : sizeof(local));
            if (end)
                *end = local;
            return FT_EXIT_OK;
        }
        if (hdr.type == FT_MSG_ERROR) {
            struct ft_msg_error e = {0};
            memcpy(&e, c->payload, hdr.length < sizeof(e) ? hdr.length : sizeof(e));
            e.msg[sizeof(e.msg) - 1] = '\0';
            return ft_error_set(err, (int)e.code, "%s", e.msg);
        }
        if (on_row)
            on_row(ctx, hdr.type, c->payload, hdr.length);
    }
}

int ft_client_shutdown(struct ft_client *c, struct ft_error *err)
{
    if (!ft_wire_send(c->fd, FT_MSG_SHUTDOWN, nullptr, 0))
        return broken(err);

    struct ft_frame_hdr hdr;
    if (!read_all(c->fd, &hdr, sizeof(hdr)))
        return FT_EXIT_OK;
    if (hdr.length > FT_WIRE_MAX_PAYLOAD ||
        (hdr.length && !read_all(c->fd, c->payload, hdr.length)))
        return broken(err);
    if (hdr.type == FT_MSG_ERROR) {
        struct ft_msg_error e = {0};
        memcpy(&e, c->payload, hdr.length < sizeof(e) ? hdr.length : sizeof(e));
        e.msg[sizeof(e.msg) - 1] = '\0';
        return ft_error_set(err, (int)e.code, "%s", e.msg);
    }
    return FT_EXIT_OK;
}
