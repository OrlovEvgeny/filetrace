#include "filetrace/wire.h"

#include "filetrace/event.h"

#include <string.h>

void ft_query_init(struct ft_query *q, enum ft_query_kind kind)
{
    memset(q, 0, sizeof(*q));
    q->kind = kind;
    q->state = FT_SOCK_ANY;
    q->method = FT_METHOD_ANY;
    q->confidence = FT_CONF_ANY;
}

size_t ft_row_transfer_size(const struct ft_row_transfer *row)
{
    return offsetof(struct ft_row_transfer, path) + strnlen(row->path, FT_PATH_MAX - 1) + 1;
}

const char *ft_default_socket_path(void)
{
#if defined(__linux__)
    return "/run/filetrace/filetraced.sock";
#else
    return "/var/run/filetrace/filetraced.sock";
#endif
}

const char *ft_loss_kind_name(enum ft_loss_kind kind)
{
    switch (kind) {
    case FT_LOSS_EVENT_QUEUE:
        return "event queue overflow";
    case FT_LOSS_AGGREGATION:
        return "counter table full";
    case FT_LOSS_SOCKET_IDENT:
        return "socket without identity";
    default:
        return "unknown";
    }
}
