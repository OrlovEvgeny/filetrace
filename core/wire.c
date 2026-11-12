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

size_t ft_process_strings_pack(char *buf, size_t size, const struct ft_process_strings *s)
{
    const char *parts[] = {s->command_line, s->cwd, s->script};
    static const size_t caps[] = {FT_CMDLINE_MAX, FT_PATH_MAX, FT_PATH_MAX};
    size_t used = 0;

    for (size_t i = 0; i < FT_ARRAY_LEN(parts) && used < size; i++) {
        const char *part = parts[i] ? parts[i] : "";
        size_t len = strnlen(part, caps[i] - 1);
        if (len > size - used - 1)
            len = size - used - 1;
        memcpy(buf + used, part, len);
        buf[used + len] = '\0';
        used += len + 1;
    }
    return used;
}

/* Finds the strings ft_process_strings_pack wrote; returns the bytes they take. */
static size_t unpack(const char *buf, size_t size, struct ft_process_strings *out)
{
    const char **parts[] = {&out->command_line, &out->cwd, &out->script};
    size_t used = 0;

    for (size_t i = 0; i < FT_ARRAY_LEN(parts); i++) {
        size_t len = used < size ? strnlen(buf + used, size - used) : 0;
        if (used >= size || used + len == size) {
            *parts[i] = "";
            continue;
        }
        *parts[i] = buf + used;
        used += len + 1;
    }
    return used;
}

static size_t lead_size(const char *text)
{
    return strnlen(text, FT_PATH_MAX - 1) + 1;
}

void ft_row_process_strings(const struct ft_row_process *row, struct ft_process_strings *out)
{
    unpack(row->text, sizeof(row->text), out);
}

void ft_row_transfer_strings(const struct ft_row_transfer *row, struct ft_process_strings *out)
{
    size_t lead = lead_size(row->path);

    if (row->flags & FT_XFER_PROCESS_TEXT)
        unpack(row->path + lead, sizeof(row->path) - lead, out);
    else
        *out = (struct ft_process_strings){"", "", ""};
}

void ft_row_event_strings(const struct ft_row_event *row, struct ft_process_strings *out)
{
    size_t lead = lead_size(row->text);

    if (row->flags & FT_EVENT_PROCESS_TEXT)
        unpack(row->text + lead, sizeof(row->text) - lead, out);
    else
        *out = (struct ft_process_strings){"", "", ""};
}

size_t ft_row_process_size(const struct ft_row_process *row)
{
    struct ft_process_strings ignored;
    return offsetof(struct ft_row_process, text) + unpack(row->text, sizeof(row->text), &ignored);
}

size_t ft_row_transfer_size(const struct ft_row_transfer *row)
{
    struct ft_process_strings ignored;
    size_t lead = lead_size(row->path);
    size_t size = offsetof(struct ft_row_transfer, path) + lead;

    if (row->flags & FT_XFER_PROCESS_TEXT)
        size += unpack(row->path + lead, sizeof(row->path) - lead, &ignored);
    return size;
}

size_t ft_row_event_size(const struct ft_row_event *row)
{
    struct ft_process_strings ignored;
    size_t lead = lead_size(row->text);
    size_t size = offsetof(struct ft_row_event, text) + lead;

    if (row->flags & FT_EVENT_PROCESS_TEXT)
        size += unpack(row->text + lead, sizeof(row->text) - lead, &ignored);
    return size;
}

size_t ft_row_leader_size(const struct ft_row_leader *row)
{
    return offsetof(struct ft_row_leader, text) + lead_size(row->text);
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
    case FT_LOSS_PATH_BUSY:
        return "path buffer busy";
    default:
        return "unknown";
    }
}

const char *ft_loss_kind_label(enum ft_loss_kind kind)
{
    switch (kind) {
    case FT_LOSS_EVENT_QUEUE:
        return "event_queue";
    case FT_LOSS_AGGREGATION:
        return "counter_table";
    case FT_LOSS_SOCKET_IDENT:
        return "socket_identity";
    case FT_LOSS_PATH_BUSY:
        return "path_buffer";
    default:
        return "unknown";
    }
}
