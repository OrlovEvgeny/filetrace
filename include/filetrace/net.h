#ifndef FILETRACE_NET_H
#define FILETRACE_NET_H

#include "filetrace/base.h"

#include <sys/socket.h>

struct ft_net_addr {
    struct sockaddr_storage ss;
    socklen_t len;
};

/*
 * "127.0.0.1:4317", "[::1]:4317", "localhost:4317" or "unix:/run/filetrace/api.sock".
 * Other names are refused: resolving one could stall the agent.
 */
bool ft_net_addr_parse(const char *text, struct ft_net_addr *out);

bool ft_net_addr_is_unix(const struct ft_net_addr *addr);

/* A non-blocking listening socket, or -1 with err set. A Unix socket admits only its owner. */
int ft_net_listen(const struct ft_net_addr *addr, struct ft_error *err);

/* A non-blocking accepted connection, or -1 when none is waiting. */
int ft_net_accept(int listen_fd);

/* A non-blocking socket on its way to addr, or -1; it turns writable once the attempt ends. */
int ft_net_connect(const struct ft_net_addr *addr);

/* How an attempt that turned writable ended: 0 or an errno value. */
int ft_net_connect_result(int fd);

/* Whether the peer of a Unix socket is root or the user this process runs as. */
bool ft_net_peer_trusted(int fd);

#endif
