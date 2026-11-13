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

size_t ft_remote_names_pack(const struct ft_remote_names *names, struct ft_row_names *fixed,
                            char *buf, size_t size)
{
    size_t used = 0;

    *fixed = (struct ft_row_names){0};
    for (uint32_t i = 0; i <= names->listed && i <= FT_RESOLVED_NAMES; i++) {
        const char *name = i == 0 ? names->tls : names->resolved[i - 1];
        size_t len = strnlen(name, FT_NAME_MAX - 1);
        if ((i == 0 && len == 0) || len + 1 > size - used)
            continue;
        memcpy(buf + used, name, len);
        buf[used + len] = '\0';
        used += len + 1;
        if (i == 0)
            fixed->tls = 1;
        else
            fixed->listed++;
    }
    uint32_t count = names->count > fixed->listed ? names->count : fixed->listed;
    fixed->count = (uint16_t)(count > UINT16_MAX ? UINT16_MAX : count);
    return used;
}

/* Finds the names ft_remote_names_pack wrote; returns the bytes they take. */
static size_t unpack_names(const struct ft_row_names *fixed, const char *buf, size_t size,
                           struct ft_remote_names *out)
{
    size_t used = 0;

    *out = (struct ft_remote_names){.tls = ""};
    for (unsigned i = 0; i <= FT_RESOLVED_NAMES; i++) {
        if (i == 0 ? !fixed->tls : i > fixed->listed)
            continue;
        size_t len = used < size ? strnlen(buf + used, size - used) : 0;
        /* A name is never empty and never runs to the end of the row. */
        if (len == 0 || used + len >= size)
            break;
        if (i == 0)
            out->tls = buf + used;
        else
            out->resolved[out->listed++] = buf + used;
        used += len + 1;
    }
    out->count = fixed->count > out->listed ? fixed->count : out->listed;
    return used;
}

/* Where a transfer row's names start: after its path and any process strings. */
static size_t transfer_names_offset(const struct ft_row_transfer *row)
{
    struct ft_process_strings ignored;
    size_t lead = lead_size(row->path);

    if (row->flags & FT_XFER_PROCESS_TEXT)
        lead += unpack(row->path + lead, sizeof(row->path) - lead, &ignored);
    return lead;
}

static size_t event_name_offset(const struct ft_row_event *row)
{
    struct ft_process_strings ignored;
    size_t lead = lead_size(row->text);

    if (row->flags & FT_EVENT_PROCESS_TEXT)
        lead += unpack(row->text + lead, sizeof(row->text) - lead, &ignored);
    return lead;
}

void ft_row_connection_names(const struct ft_row_connection *row, struct ft_remote_names *out)
{
    unpack_names(&row->names, row->text, sizeof(row->text), out);
}

void ft_row_flow_names(const struct ft_row_flow *row, struct ft_remote_names *out)
{
    unpack_names(&row->names, row->text, sizeof(row->text), out);
}

void ft_row_transfer_names(const struct ft_row_transfer *row, struct ft_remote_names *out)
{
    size_t at = transfer_names_offset(row);
    unpack_names(&row->names, row->path + at, sizeof(row->path) - at, out);
}

void ft_row_event_set_name(struct ft_row_event *row, enum ft_name_source source, const char *name)
{
    size_t at = event_name_offset(row);

    row->name_source = FT_NAME_SOURCE_NONE;
    if (source == FT_NAME_SOURCE_NONE || !name[0] || at + FT_NAME_MAX > sizeof(row->text))
        return;
    ft_strlcpy(row->text + at, name, FT_NAME_MAX);
    row->name_source = source;
}

const char *ft_row_event_name(const struct ft_row_event *row)
{
    size_t at = event_name_offset(row);

    if (row->name_source == FT_NAME_SOURCE_NONE || at >= sizeof(row->text) ||
        strnlen(row->text + at, sizeof(row->text) - at) == sizeof(row->text) - at)
        return "";
    return row->text + at;
}

size_t ft_row_process_size(const struct ft_row_process *row)
{
    struct ft_process_strings ignored;
    return offsetof(struct ft_row_process, text) + unpack(row->text, sizeof(row->text), &ignored);
}

size_t ft_row_connection_size(const struct ft_row_connection *row)
{
    struct ft_remote_names ignored;
    return offsetof(struct ft_row_connection, text) +
           unpack_names(&row->names, row->text, sizeof(row->text), &ignored);
}

size_t ft_row_flow_size(const struct ft_row_flow *row)
{
    struct ft_remote_names ignored;
    return offsetof(struct ft_row_flow, text) +
           unpack_names(&row->names, row->text, sizeof(row->text), &ignored);
}

size_t ft_row_transfer_size(const struct ft_row_transfer *row)
{
    struct ft_remote_names ignored;
    size_t at = transfer_names_offset(row);

    return offsetof(struct ft_row_transfer, path) + at +
           unpack_names(&row->names, row->path + at, sizeof(row->path) - at, &ignored);
}

size_t ft_row_event_size(const struct ft_row_event *row)
{
    size_t at = event_name_offset(row);
    const char *name = ft_row_event_name(row);

    return offsetof(struct ft_row_event, text) + at + (name[0] ? strlen(name) + 1 : 0);
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
