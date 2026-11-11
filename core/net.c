#include "filetrace/net.h"

#include "filetrace/format.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

bool ft_net_addr_parse(const char *text, struct ft_net_addr *out)
{
    char host[64];
    uint32_t port;

    memset(out, 0, sizeof(*out));
    if (strncmp(text, "unix:", 5) == 0) {
        struct sockaddr_un *un = (struct sockaddr_un *)&out->ss;
        const char *path = text + 5;

        if (!path[0] || strlen(path) >= sizeof(un->sun_path))
            return false;
        un->sun_family = AF_UNIX;
        ft_strlcpy(un->sun_path, path, sizeof(un->sun_path));
        out->len = sizeof(*un);
        return true;
    }

    const char *colon = strrchr(text, ':');
    if (!colon || !ft_parse_u32(colon + 1, &port) || port == 0 || port > 65535)
        return false;
    size_t len = (size_t)(colon - text);
    bool bracketed = len >= 2 && text[0] == '[' && text[len - 1] == ']';
    if (bracketed) {
        text++;
        len -= 2;
    }
    if (len == 0 || len >= sizeof(host))
        return false;
    memcpy(host, text, len);
    host[len] = '\0';

    struct sockaddr_in *in = (struct sockaddr_in *)&out->ss;
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&out->ss;
    if (!bracketed && inet_pton(AF_INET, strcmp(host, "localhost") == 0 ? "127.0.0.1" : host,
                                &in->sin_addr) == 1) {
        in->sin_family = AF_INET;
        in->sin_port = htons((uint16_t)port);
        out->len = sizeof(*in);
        return true;
    }
    if (bracketed && inet_pton(AF_INET6, host, &in6->sin6_addr) == 1) {
        in6->sin6_family = AF_INET6;
        in6->sin6_port = htons((uint16_t)port);
        out->len = sizeof(*in6);
        return true;
    }
    return false;
}

bool ft_net_addr_is_unix(const struct ft_net_addr *addr)
{
    return addr->ss.ss_family == AF_UNIX;
}

static void prepare(int fd, bool stream_over_ip)
{
    int on = 1;
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#if defined(SO_NOSIGPIPE)
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
    if (stream_over_ip)
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
}

int ft_net_listen(const struct ft_net_addr *addr, struct ft_error *err)
{
    const struct sockaddr *sa = (const struct sockaddr *)&addr->ss;
    bool is_unix = ft_net_addr_is_unix(addr);
    int on = 1;

    int fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot create a socket: %s", strerror(errno));
        return -1;
    }
    mode_t old_mask = 0;
    if (is_unix) {
        unlink(((const struct sockaddr_un *)sa)->sun_path);
        old_mask = umask(0177);
    } else {
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
    int rc = bind(fd, sa, addr->len);
    int saved = errno;
    if (is_unix)
        umask(old_mask);
    if (rc != 0 || listen(fd, 16) != 0) {
        if (rc == 0)
            saved = errno;
        close(fd);
        ft_error_set(err, saved == EACCES ? FT_EXIT_PERMISSION : FT_EXIT_ERROR, "%s",
                     strerror(saved));
        return -1;
    }
    prepare(fd, false);
    return fd;
}

int ft_net_accept(int listen_fd)
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);

    int fd = accept(listen_fd, (struct sockaddr *)&ss, &len);
    if (fd >= 0)
        prepare(fd, ss.ss_family != AF_UNIX);
    return fd;
}

int ft_net_connect(const struct ft_net_addr *addr)
{
    const struct sockaddr *sa = (const struct sockaddr *)&addr->ss;

    int fd = socket(sa->sa_family, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    prepare(fd, sa->sa_family != AF_UNIX);
    if (connect(fd, sa, addr->len) != 0 && errno != EINPROGRESS && errno != EINTR) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

int ft_net_connect_result(int fd)
{
    int error = 0;
    socklen_t len = sizeof(error);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) != 0)
        return errno;
    return error;
}

bool ft_net_peer_trusted(int fd)
{
    uid_t uid;
#if defined(__linux__)
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
        return false;
    uid = cred.uid;
#else
    gid_t gid;
    if (getpeereid(fd, &uid, &gid) != 0)
        return false;
#endif
    return uid == 0 || uid == geteuid();
}
