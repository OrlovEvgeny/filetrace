#include "filetrace/wire.h"

#include "filetrace/event.h"

#include <string.h>
#include <strings.h>

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

size_t ft_row_event_size(const struct ft_row_event *row)
{
    return offsetof(struct ft_row_event, text) + strnlen(row->text, FT_PATH_MAX - 1) + 1;
}

static const char *const record_type_names[FT_REC_TYPE_COUNT] = {
    [FT_REC_PROCESS_EXEC] = "process_exec",   [FT_REC_PROCESS_FORK] = "process_fork",
    [FT_REC_PROCESS_EXIT] = "process_exit",   [FT_REC_SOCKET_CONNECT] = "socket_connect",
    [FT_REC_SOCKET_LISTEN] = "socket_listen", [FT_REC_SOCKET_ESTABLISHED] = "socket_established",
    [FT_REC_SOCKET_CLOSE] = "socket_close",   [FT_REC_FILE_SEEN] = "file_seen",
    [FT_REC_NETWORK_SEND] = "network_send",   [FT_REC_NETWORK_RECEIVE] = "network_receive",
    [FT_REC_FILE_TRANSFER] = "file_transfer", [FT_REC_EVENT_LOSS] = "event_loss",
};

const char *ft_record_type_name(enum ft_record_type type)
{
    return type > 0 && type < FT_REC_TYPE_COUNT ? record_type_names[type] : "unknown";
}

bool ft_record_type_parse(const char *text, enum ft_record_type *type)
{
    for (int i = 1; i < FT_REC_TYPE_COUNT; i++) {
        if (strcasecmp(text, record_type_names[i]) == 0) {
            *type = (enum ft_record_type)i;
            return true;
        }
    }
    return false;
}

const char *ft_default_socket_path(void)
{
#if defined(__linux__)
    return "/run/filetrace/agent.sock";
#else
    return "/var/run/filetrace/agent.sock";
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
