#include "ui/top/document.h"

#include "exporters/exporters.h"
#include "filetrace/format.h"
#include "filetrace/sysinfo.h"
#include "ui/top/once.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

constexpr size_t MAX_DEPTH = 8;
constexpr size_t PREFIX_MAX = 48;

/* What a CSV line holds: the values of a row, the names of the columns, or nothing at all. */
enum cells : uint8_t {
    CELLS_VALUES,
    CELLS_NAMES,
    CELLS_BLANK,
};

struct writer {
    FILE *out;
    bool csv;
    bool indent;
    size_t depth;
    bool has[MAX_DEPTH]; /* JSON: the container at each depth holds an element */
    enum cells cells;    /* CSV */
    size_t columns;      /* CSV: written on this line */
    char prefix[PREFIX_MAX];
    size_t prefix_at[MAX_DEPTH];
    char *clean; /* a copy of the text being written, valid UTF-8 */
    size_t clean_size;
};

static void newline(const struct writer *w)
{
    if (!w->indent)
        return;
    fputc('\n', w->out);
    for (size_t i = 0; i < w->depth; i++)
        fputs("  ", w->out);
}

/* Starts the next element of the container the writer is in; objects name their elements. */
static void element(struct writer *w, const char *name)
{
    if (w->depth > 0) {
        if (w->has[w->depth])
            fputc(',', w->out);
        w->has[w->depth] = true;
        newline(w);
    }
    if (name) {
        ft_json_string(w->out, name);
        fputs(w->indent ? ": " : ":", w->out);
    }
}

static void open_container(struct writer *w, const char *name, char brace)
{
    element(w, name);
    fputc(brace, w->out);
    w->depth++;
    w->has[w->depth] = false;
}

static void close_container(struct writer *w, char brace)
{
    bool had = w->has[w->depth];

    w->depth--;
    if (had)
        newline(w);
    fputc(brace, w->out);
}

/* Paths and command lines are bytes, and JSON text must be UTF-8. */
static const char *valid_utf8(struct writer *w, const char *s)
{
    size_t size = strlen(s) + 1;

    if (size > w->clean_size) {
        char *grown = realloc(w->clean, size);
        if (!grown)
            return "";
        w->clean = grown;
        w->clean_size = size;
    }
    ft_utf8_copy(w->clean, s, size);
    return w->clean;
}

/* A column: nested members are named after their objects, "remote.address". */
static void cell(struct writer *w, const char *name, const char *text)
{
    if (w->columns++ > 0)
        fputc(',', w->out);
    switch (w->cells) {
    case CELLS_NAMES: {
        char full[PREFIX_MAX + 48];

        snprintf(full, sizeof(full), "%s%s", w->prefix, name);
        ft_csv_field(w->out, full);
        break;
    }
    case CELLS_VALUES:
        if (text && text[0])
            ft_csv_field(w->out, valid_utf8(w, text));
        break;
    case CELLS_BLANK:
        break;
    }
}

static void begin_object(struct writer *w, const char *name)
{
    if (!w->csv) {
        open_container(w, name, '{');
        return;
    }
    size_t at = strlen(w->prefix);

    w->prefix_at[w->depth++] = at;
    snprintf(w->prefix + at, sizeof(w->prefix) - at, "%s.", name);
}

static void end_object(struct writer *w)
{
    if (!w->csv) {
        close_container(w, '}');
        return;
    }
    w->prefix[w->prefix_at[--w->depth]] = '\0';
}

/* An absent value is null in JSON, never an empty string, and an empty cell in CSV. */
static void put_text(struct writer *w, const char *name, const char *s)
{
    if (w->csv) {
        cell(w, name, s);
        return;
    }
    element(w, name);
    if (s && s[0])
        ft_json_string(w->out, valid_utf8(w, s));
    else
        fputs("null", w->out);
}

static void put_uint(struct writer *w, const char *name, uint64_t value)
{
    if (w->csv) {
        char text[24];

        snprintf(text, sizeof(text), "%" PRIu64, value);
        cell(w, name, text);
        return;
    }
    element(w, name);
    fprintf(w->out, "%" PRIu64, value);
}

static void put_null(struct writer *w, const char *name)
{
    if (w->csv) {
        cell(w, name, nullptr);
        return;
    }
    element(w, name);
    fputs("null", w->out);
}

static void put_known(struct writer *w, const char *name, uint64_t value, bool known)
{
    if (known)
        put_uint(w, name, value);
    else
        put_null(w, name);
}

static void put_bool(struct writer *w, const char *name, bool value)
{
    if (w->csv) {
        cell(w, name, value ? "true" : "false");
        return;
    }
    element(w, name);
    fputs(value ? "true" : "false", w->out);
}

/* Shares, progress and times in seconds: four decimals, without the trailing zeros. */
static void put_number(struct writer *w, const char *name, double value)
{
    char text[40];

    if (!(value >= 0.0 && value < 1e15))
        value = 0.0;
    int len = snprintf(text, sizeof(text), "%.4f", value);
    while (len > 1 && text[len - 1] == '0')
        len--;
    if (text[len - 1] == '.')
        len--;
    text[len] = '\0';
    if (w->csv) {
        cell(w, name, text);
        return;
    }
    element(w, name);
    fputs(text, w->out);
}

static void put_time(struct writer *w, const char *name, uint64_t wall_ns)
{
    char text[40];

    if (wall_ns == 0) {
        put_null(w, name);
        return;
    }
    ft_format_time_rfc3339(wall_ns, text, sizeof(text));
    if (w->csv) {
        cell(w, name, text);
        return;
    }
    element(w, name);
    ft_json_string(w->out, text);
}

/* Items for one CSV cell, joined as the other commands join them. */
struct list {
    char *text;
    size_t len;
    size_t size;
};

static void list_add(struct list *l, const char *item)
{
    size_t add = strlen(item) + 1;

    if (l->len + add + 1 > l->size) {
        size_t size = (l->len + add + 1) * 2;
        char *grown = realloc(l->text, size);
        if (!grown)
            return;
        l->text = grown;
        l->size = size;
    }
    l->len += (size_t)snprintf(l->text + l->len, l->size - l->len, "%s%s", l->len ? ";" : "", item);
}

static void put_list(struct writer *w, const char *name, const struct list *l)
{
    cell(w, name, l->text);
}

/* A list of numbers on one line. */
static void put_uints(struct writer *w, const char *name, const uint64_t *values, size_t count)
{
    if (w->csv) {
        struct list l = {0};
        char text[24];

        for (size_t i = 0; i < count; i++) {
            snprintf(text, sizeof(text), "%" PRIu64, values[i]);
            list_add(&l, text);
        }
        put_list(w, name, &l);
        free(l.text);
        return;
    }
    element(w, name);
    fputc('[', w->out);
    for (size_t i = 0; i < count; i++)
        fprintf(w->out, "%s%" PRIu64, i ? (w->indent ? ", " : ",") : "", values[i]);
    fputc(']', w->out);
}

static const char *method_text(uint8_t method)
{
    return method == FT_METHOD_NONE ? nullptr : ft_method_name((enum ft_method)method);
}

static void write_totals(struct writer *w, const struct ft_top_totals *t)
{
    open_container(w, "totals", '{');
    put_uint(w, "rate", t->rate.value);
    put_uint(w, "rate_exact", t->rate_exact);
    put_uint(w, "rate_public", t->rate_public);
    put_uint(w, "rate_private", t->rate_private);
    open_container(w, "rate_by_method", '{');
    for (size_t i = 0; i < FT_TOP_METHODS; i++)
        put_uint(w, ft_method_name((enum ft_method)i), t->rate_by_method[i]);
    close_container(w, '}');
    put_number(w, "exact_share", t->exact_share);
    put_number(w, "public_share", t->public_share);
    put_number(w, "sendfile_share", t->sendfile_share);
    put_uint(w, "transfers", t->transfers);
    open_container(w, "transfers_by_method", '{');
    for (size_t i = 0; i < FT_TOP_METHODS; i++)
        put_uint(w, ft_method_name((enum ft_method)i), t->transfers_by_method[i]);
    close_container(w, '}');
    open_container(w, "transfers_by_confidence", '{');
    for (size_t i = 0; i < FT_TOP_CONFIDENCES; i++)
        put_uint(w, ft_confidence_name((enum ft_confidence)i), t->transfers_by_confidence[i]);
    close_container(w, '}');
    put_uint(w, "started_per_second", t->started.value);
    put_uint(w, "processes", t->processes.value);
    put_uint(w, "files", t->files.value);
    put_uint(w, "fanout", t->fanout.value);
    put_uint(w, "destinations", t->destinations);
    put_uint(w, "destinations_public", t->destinations_public);
    put_uint(w, "destinations_private", t->destinations_private);
    put_uint(w, "new_destinations", t->new_destinations.value);
    if (t->agent) {
        open_container(w, "agent", '{');
        put_text(w, "backend", t->backend);
        put_bool(w, "degraded", t->degraded);
        put_uint(w, "queue_percent", t->queue_percent);
        put_uint(w, "events_dropped", t->events_dropped);
        close_container(w, '}');
    } else {
        put_null(w, "agent");
    }
    close_container(w, '}');
}

static bool in_tree(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return mode == FT_TOP_PROCESSES && ft_top_tree_of(m);
}

/* Leaders and the tree show no groups, whatever was asked for. */
static enum ft_top_group grouping(const struct ft_top_model *m, enum ft_top_mode mode)
{
    if (mode == FT_TOP_LEADERS || in_tree(m, mode))
        return FT_TOP_GROUP_NONE;
    return ft_top_group_of(m, mode);
}

/* How the mode is sorted, grouped and filtered, and how many of its items that leaves. */
static void write_view(struct writer *w, const struct ft_top_model *m, enum ft_top_mode mode)
{
    const struct ft_top_view *view = ft_top_view_of(m, mode);
    enum ft_top_group group = grouping(m, mode);

    open_container(w, "view", '{');
    if (mode != FT_TOP_LEADERS) {
        enum ft_top_sort sort;
        bool descending;

        ft_top_sort_of(m, mode, &sort, &descending);
        put_text(w, "sort", ft_top_sort_name(sort));
        put_bool(w, "descending", descending);
        put_text(w, "group", group == FT_TOP_GROUP_NONE ? nullptr : ft_top_group_name(group));
        if (mode == FT_TOP_PROCESSES)
            put_bool(w, "tree", in_tree(m, mode));
    }
    put_text(w, "filter", ft_top_filter_of(m, mode));
    put_uint(w, "shown", view->shown);
    put_uint(w, "total", view->total);
    close_container(w, '}');
}

struct view {
    enum ft_top_mode mode;
    bool grouped;
    bool tree;
    enum ft_leader_key key; /* what a row of Leaders stands for */
};

static struct view view_of(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return (struct view){
        .mode = mode,
        .grouped = grouping(m, mode) != FT_TOP_GROUP_NONE,
        .tree = in_tree(m, mode),
        .key = mode == FT_TOP_LEADERS ? ft_top_leaders(m)->key : FT_LEADER_FILE,
    };
}

static const struct ft_top_process *process_of(const struct ft_top_transfer *t)
{
    static const struct ft_top_process none;
    return t->process ? t->process : &none;
}

static void put_remote(struct writer *w, const struct ft_top_transfer *t)
{
    const struct ft_top_destination *d = t->destination;
    bool known = t->remote.family != 0;
    char address[64];

    address[0] = '\0';
    if (known)
        ft_addr_format(&t->remote, address, sizeof(address));
    begin_object(w, "remote");
    put_text(w, "address", address);
    put_known(w, "port", t->remote.port, t->remote.port != 0);
    if (known)
        put_bool(w, "public", t->is_public);
    else
        put_null(w, "public");
    put_text(w, "host", d && d->host_state == FT_TOP_HOST_NAMED ? d->host : nullptr);
    end_object(w);
}

static void transfer_members(struct writer *w, const struct ft_top_transfer *t)
{
    const struct ft_top_process *p = process_of(t);
    const struct ft_top_file *f = t->file;
    bool file_known = f && (f->dev != 0 || f->ino != 0);
    struct ft_row_transfer key = {.id = t->id, .flags = file_known ? FT_XFER_FILE_KNOWN : 0};
    char id[32];

    ft_transfer_id_format(&key, id, sizeof(id));
    put_text(w, "id", id);
    put_uint(w, "pid", t->pid);
    put_text(w, "user", p->user);
    put_text(w, "process", p->title);
    put_text(w, "comm", p->comm);
    put_text(w, "script", t->script);
    put_text(w, "file", t->path_known ? t->path : nullptr);
    put_known(w, "device", file_known ? f->dev : 0, file_known);
    put_known(w, "inode", file_known ? f->ino : 0, file_known);
    put_known(w, "size", t->size, t->size != 0);
    put_uint(w, "bytes_sent", t->bytes);
    if (t->progress >= 0.0)
        put_number(w, "progress", t->progress);
    else
        put_null(w, "progress");
    put_uint(w, "rate", t->rate);
    put_text(w, "method", method_text(t->method));
    put_text(w, "confidence", ft_confidence_name((enum ft_confidence)t->confidence));
    put_bool(w, "incomplete", t->incomplete);
    put_bool(w, "deleted", t->deleted);
    put_bool(w, "done", t->done);
    put_remote(w, t);
    put_number(w, "age_seconds", (double)t->age_ns / (double)FT_NS_PER_SEC);
    put_time(w, "started", t->first_wall_ns);
    put_text(w, "command_line", p->command_line);
    put_text(w, "cwd", p->cwd);
}

static void process_members(struct writer *w, const struct ft_top_process *p)
{
    put_uint(w, "pid", p->pid);
    put_known(w, "ppid", p->ppid, p->ppid != 0);
    put_text(w, "user", p->user);
    put_text(w, "process", p->title);
    put_text(w, "command_line", p->command_line);
    put_text(w, "script", p->script);
    put_uint(w, "rate", p->rate);
    put_uint(w, "total", p->total);
    put_uint(w, "files", p->files);
    put_uint(w, "destinations", p->destinations);
    put_text(w, "method", method_text(p->method));
}

static void put_pids(struct writer *w, const char *name, const struct ft_top_fold *f)
{
    struct list l = {0};
    char text[16];

    if (w->csv) {
        for (size_t i = 0; i < f->count; i++) {
            snprintf(text, sizeof(text), "%" PRIu32, f->members[i]->pid);
            list_add(&l, text);
        }
        put_list(w, name, &l);
        free(l.text);
        return;
    }
    element(w, name);
    fputc('[', w->out);
    for (size_t i = 0; i < f->count; i++)
        fprintf(w->out, "%s%" PRIu32, i ? (w->indent ? ", " : ",") : "", f->members[i]->pid);
    fputc(']', w->out);
}

static void fold_members(struct writer *w, const struct ft_top_fold *f)
{
    put_text(w, "process", f->title);
    put_uint(w, "count", f->count);
    put_pids(w, "pids", f);
    put_uint(w, "rate", f->rate);
    put_uint(w, "total", f->total);
    put_uint(w, "files", f->files);
    put_uint(w, "destinations", f->destinations);
    put_text(w, "method", method_text(f->method));
}

static void destination_members(struct writer *w, const struct ft_top_destination *d)
{
    put_text(w, "address", d->text);
    put_text(w, "label", d->label);
    put_bool(w, "public", d->is_public);
    put_bool(w, "new", d->is_new);
    put_text(w, "host", d->host_state == FT_TOP_HOST_NAMED ? d->host : nullptr);
    put_uint(w, "rate", d->rate);
    put_uint(w, "total", d->total);
    put_uint(w, "files", d->files);
    put_uint(w, "processes", d->processes);
    put_text(w, "top_process", d->top_process ? d->top_process->title : nullptr);
    put_text(w, "top_file", d->top && d->top->path_known ? d->top->path : nullptr);
    put_uints(w, "trend", d->trend, FT_TOP_TREND);
}

/* An array of objects in JSON; in CSV just the names, in one cell. */
static void put_file_senders(struct writer *w, const struct ft_top_file *f)
{
    struct list names = {0};

    if (w->csv) {
        for (size_t i = 0; i < f->nsenders; i++) {
            const struct ft_top_process *p = f->by_sender[i].process;
            list_add(&names, p ? p->name : "");
        }
        put_list(w, "senders", &names);
        free(names.text);
        return;
    }
    open_container(w, "senders", '[');
    for (size_t i = 0; i < f->nsenders; i++) {
        const struct ft_top_sender *s = &f->by_sender[i];

        open_container(w, nullptr, '{');
        put_text(w, "process", s->process ? s->process->name : nullptr);
        put_uint(w, "transfers", s->transfers);
        put_uint(w, "rate", s->rate);
        close_container(w, '}');
    }
    close_container(w, ']');
}

static void file_members(struct writer *w, const struct ft_top_file *f)
{
    bool file_known = f->dev != 0 || f->ino != 0;

    put_text(w, "file", f->path_known ? f->path : nullptr);
    put_known(w, "device", f->dev, file_known);
    put_known(w, "inode", f->ino, file_known);
    put_known(w, "size", f->size, f->size != 0);
    put_uint(w, "rate", f->rate);
    put_uint(w, "active", f->active);
    put_uint(w, "destinations", f->destinations);
    put_file_senders(w, f);
    put_text(w, "method", method_text(f->method));
    put_number(w, "public_share", f->public_share);
    put_bool(w, "deleted", f->deleted);
}

/* What a row is read from; the column names and the cells a row leaves blank take empty ones. */
struct entities {
    const struct ft_top_transfer *transfer;
    const struct ft_top_process *process;
    const struct ft_top_destination *destination;
    const struct ft_top_file *file;
    const struct ft_top_leader *leader;
    const struct ft_top_fold *fold;
};

static struct entities entities_of(const struct ft_top_row *r)
{
    static const struct ft_top_transfer no_transfer;
    static const struct ft_top_process no_process;
    static const struct ft_top_destination no_destination;
    static const struct ft_top_file no_file;
    static const struct ft_row_leader no_row;
    static const struct ft_top_leader no_leader = {.row = &no_row};
    static const struct ft_top_fold no_fold;
    struct entities e = {&no_transfer, &no_process, &no_destination,
                         &no_file,     &no_leader,  &no_fold};

    if (!r)
        return e;
    switch (r->kind) {
    case FT_TOP_ROW_TRANSFER:
        e.transfer = r->transfer;
        break;
    case FT_TOP_ROW_PROCESS:
        e.process = r->process;
        break;
    case FT_TOP_ROW_DESTINATION:
        e.destination = r->destination;
        break;
    case FT_TOP_ROW_FILE:
        e.file = r->file;
        break;
    case FT_TOP_ROW_LEADER:
        e.leader = r->leader;
        break;
    case FT_TOP_ROW_FOLD:
        e.fold = r->fold;
        break;
    default:
        break;
    }
    return e;
}

/* JSON leaves out a part a row lacks; CSV keeps its columns, empty. */
static bool begin_part(struct writer *w, bool present, enum cells *before)
{
    *before = w->cells;
    if (present)
        return true;
    if (!w->csv)
        return false;
    if (w->cells == CELLS_VALUES)
        w->cells = CELLS_BLANK;
    return true;
}

/* A tree row carries its depth and is a process, a fold of siblings or a transfer. */
static void tree_row(struct writer *w, const struct ft_top_row *r, const struct entities *e)
{
    enum ft_top_row_kind kind = r ? r->kind : FT_TOP_ROW_SECTION;
    enum cells before;

    put_uint(w, "depth", r ? r->depth : 0);
    if (begin_part(w, kind == FT_TOP_ROW_PROCESS, &before))
        process_members(w, e->process);
    w->cells = before;
    if (begin_part(w, kind == FT_TOP_ROW_FOLD, &before)) {
        begin_object(w, "fold");
        fold_members(w, e->fold);
        end_object(w);
    }
    w->cells = before;
    if (begin_part(w, kind == FT_TOP_ROW_TRANSFER, &before)) {
        begin_object(w, "transfer");
        transfer_members(w, e->transfer);
        end_object(w);
    }
    w->cells = before;
}

static const char *const key_names[FT_LEADER_KEY_COUNT] = {
    [FT_LEADER_FILE] = "file",
    [FT_LEADER_DIRECTORY] = "directory",
    [FT_LEADER_EXTENSION] = "extension",
    [FT_LEADER_DESTINATION] = "destination",
};

static void put_leader_senders(struct writer *w, const struct ft_row_leader *row)
{
    struct list names = {0};

    if (w->csv) {
        for (size_t i = 0; i < FT_LEADER_SENDERS && row->senders[i].name[0]; i++)
            list_add(&names, row->senders[i].name);
        put_list(w, "senders", &names);
        free(names.text);
        return;
    }
    open_container(w, "senders", '[');
    for (size_t i = 0; i < FT_LEADER_SENDERS && row->senders[i].name[0]; i++) {
        open_container(w, nullptr, '{');
        put_text(w, "name", row->senders[i].name);
        put_uint(w, "bytes", row->senders[i].bytes);
        put_uint(w, "transfers", row->senders[i].transfers);
        close_container(w, '}');
    }
    close_container(w, ']');
}

/* The ranking's own text is named after what it ranks; a destination has its address and host. */
static void leader_members(struct writer *w, const struct ft_top_leader *l, enum ft_leader_key key)
{
    const struct ft_row_leader *row = l->row;

    put_uint(w, "rank", row->rank);
    put_known(w, "previous_rank", row->previous_rank, row->previous_rank != 0);
    if (key == FT_LEADER_DESTINATION) {
        put_text(w, "address", l->remote_text);
        put_text(w, "host", l->host_state == FT_TOP_HOST_NAMED ? l->host : nullptr);
    } else {
        put_text(w, key_names[key], row->text);
    }
    if (key == FT_LEADER_FILE) {
        bool file_known = row->dev != 0 || row->ino != 0;

        put_known(w, "device", row->dev, file_known);
        put_known(w, "inode", row->ino, file_known);
        put_known(w, "size", row->file_size, row->file_size != 0);
    }
    put_uint(w, "bytes", row->bytes);
    put_number(w, "share", l->share);
    put_uint(w, "bytes_error", row->bytes_error);
    put_uint(w, "bytes_exact", row->bytes_exact);
    put_uint(w, "transfers", row->transfers);
    put_uint(w, "transfers_error", row->transfers_error);
    put_uint(w, "destinations", row->destinations);
    if (key != FT_LEADER_FILE)
        put_uint(w, "files", row->files);
    put_leader_senders(w, row);
    put_bool(w, "more_senders", (row->flags & FT_LEADER_MORE_SENDERS) != 0);
    put_text(w, "method", method_text(row->method));
    put_text(w, "confidence", ft_confidence_name((enum ft_confidence)row->confidence));
    put_time(w, "first_sent", row->first_wall_ns);
    put_time(w, "last_sent", row->last_wall_ns);
    put_uints(w, "trend", row->trend, FT_LEADER_SLOTS);
    if (key == FT_LEADER_FILE)
        put_bool(w, "deleted", (row->flags & FT_LEADER_DELETED) != 0);
}

/* A row of the view; without a row, the columns of the view. */
static void write_row(struct writer *w, const struct view *view, const struct ft_top_row *r,
                      const char *group)
{
    struct entities e = entities_of(r);

    if (view->tree) {
        tree_row(w, r, &e);
        return;
    }
    if (view->grouped)
        put_text(w, "group", group);
    switch (view->mode) {
    case FT_TOP_TRANSFERS:
        transfer_members(w, e.transfer);
        break;
    case FT_TOP_PROCESSES:
        process_members(w, e.process);
        break;
    case FT_TOP_DESTINATIONS:
        destination_members(w, e.destination);
        break;
    case FT_TOP_FILES:
        file_members(w, e.file);
        break;
    case FT_TOP_LEADERS:
        leader_members(w, e.leader, view->key);
        break;
    default:
        break;
    }
}

/* The rows as an array; group headings go into the rows they head. */
static size_t write_rows(struct writer *w, const struct ft_top_model *m, enum ft_top_mode mode,
                         const char *name)
{
    struct view view = view_of(m, mode);
    size_t count = ft_top_row_count(m, mode);
    const char *group = nullptr;
    size_t written = 0;

    open_container(w, name, '[');
    for (size_t i = 0; i < count; i++) {
        const struct ft_top_row *r = ft_top_row_at(m, mode, i);

        if (!r)
            continue;
        if (r->kind == FT_TOP_ROW_SECTION) {
            group = r->section->title;
            continue;
        }
        open_container(w, nullptr, '{');
        write_row(w, &view, r, group);
        close_container(w, '}');
        written++;
    }
    close_container(w, ']');
    return written;
}

static size_t write_live(struct writer *w, const struct ft_top_model *m, enum ft_top_mode mode,
                         const char *host)
{
    const struct ft_top_totals *totals = ft_top_totals(m);

    put_time(w, "time", totals->now_wall_ns);
    put_text(w, "host", host);
    write_totals(w, totals);
    write_view(w, m, mode);
    return write_rows(w, m, mode, ft_top_mode_name(mode));
}

static void write_summary(struct writer *w, const struct ft_top_leaders *leaders)
{
    const struct ft_row_leader_summary *s = &leaders->summary;

    open_container(w, "summary", '{');
    put_uint(w, "window_ns", s->window_ns);
    put_uint(w, "slot_ns", s->slot_ns);
    put_uint(w, "bytes", s->bytes);
    put_uint(w, "bytes_exact", s->bytes_exact);
    put_number(w, "exact_share", leaders->exact_share);
    put_uint(w, "top_bytes", s->top_bytes);
    put_number(w, "concentration", leaders->concentration);
    put_uint(w, "transfers", s->transfers);
    put_uint(w, "files", s->files);
    put_uint(w, "processes", s->processes);
    put_uint(w, "scripts", s->scripts);
    put_uint(w, "destinations_public", s->destinations_public);
    put_uint(w, "destinations_private", s->destinations_private);
    put_bool(w, "short_history", (s->flags & FT_LEADERS_SHORT_HISTORY) != 0);
    put_bool(w, "capped", (s->flags & FT_LEADERS_CAPPED) != 0);
    close_container(w, '}');
}

static void write_side(struct writer *w, const char *name, const struct ft_top_leader *rows,
                       size_t count, enum ft_leader_key key)
{
    open_container(w, name, '[');
    for (size_t i = 0; i < count; i++) {
        open_container(w, nullptr, '{');
        leader_members(w, &rows[i], key);
        close_container(w, '}');
    }
    close_container(w, ']');
}

/* The ranking is named after its key; the side lists are left out when it is one of them. */
static size_t write_leaders(struct writer *w, const struct ft_top_model *m, const char *host)
{
    static const char *const ranking_names[FT_LEADER_KEY_COUNT] = {
        [FT_LEADER_FILE] = "files",
        [FT_LEADER_DIRECTORY] = "directories",
        [FT_LEADER_EXTENSION] = "extensions",
        [FT_LEADER_DESTINATION] = "destinations",
    };
    const struct ft_top_leaders *leaders = ft_top_leaders(m);
    const struct ft_row_leader_summary *s = &leaders->summary;
    size_t rows;

    put_time(w, "time", s->to_wall_ns);
    put_text(w, "host", host);
    put_text(w, "window", ft_leader_window_name(leaders->window));
    put_text(w, "by", ft_top_sort_name(leaders->by));
    put_text(w, "key", key_names[leaders->key]);
    put_time(w, "from", s->from_wall_ns);
    put_time(w, "to", s->to_wall_ns);
    put_time(w, "previous_from", s->previous_from_wall_ns);
    write_summary(w, leaders);
    write_view(w, m, FT_TOP_LEADERS);
    rows = write_rows(w, m, FT_TOP_LEADERS, ranking_names[leaders->key]);
    if (leaders->key != FT_LEADER_DIRECTORY)
        write_side(w, "directories", leaders->directories, leaders->ndirectories,
                   FT_LEADER_DIRECTORY);
    if (leaders->key != FT_LEADER_DESTINATION)
        write_side(w, "destinations", leaders->destinations, leaders->ndestinations,
                   FT_LEADER_DESTINATION);
    return rows;
}

size_t ft_top_write_document(const struct ft_top_model *m, enum ft_top_mode mode,
                             const char *source, bool indent, FILE *out)
{
    struct writer w = {.out = out, .indent = indent};
    const struct ft_row_stats *stats = ft_top_totals(m)->stats;
    struct ft_host_info host;
    size_t rows;

    ft_sysinfo_host(&host);
    open_container(&w, nullptr, '{');
    put_text(&w, "mode", ft_top_mode_name(mode));
    if (source)
        put_text(&w, "source", source);
    if (stats && stats->start_wall_ns)
        put_time(&w, "since", stats->start_wall_ns);
    if (mode == FT_TOP_LEADERS)
        rows = write_leaders(&w, m, host.hostname);
    else
        rows = write_live(&w, m, mode, host.hostname);
    close_container(&w, '}');
    fputc('\n', out);
    free(w.clean);
    return rows;
}

size_t ft_top_write_csv(const struct ft_top_model *m, enum ft_top_mode mode, FILE *out)
{
    struct writer w = {.out = out, .csv = true, .cells = CELLS_NAMES};
    struct view view = view_of(m, mode);
    size_t count = ft_top_row_count(m, mode);
    const char *group = nullptr;
    size_t written = 0;

    write_row(&w, &view, nullptr, nullptr);
    fputc('\n', out);
    w.cells = CELLS_VALUES;
    for (size_t i = 0; i < count; i++) {
        const struct ft_top_row *r = ft_top_row_at(m, mode, i);

        if (!r)
            continue;
        if (r->kind == FT_TOP_ROW_SECTION) {
            group = r->section->title;
            continue;
        }
        w.columns = 0;
        write_row(&w, &view, r, group);
        fputc('\n', out);
        written++;
    }
    free(w.clean);
    return written;
}

static void section_members(struct writer *w, const struct ft_top_section *section)
{
    put_text(w, "group", section->title);
    put_uint(w, "rows", section->rows);
    put_uint(w, "processes", section->processes);
    put_uint(w, "files", section->files);
    put_uint(w, "destinations", section->destinations);
    put_uint(w, "rate", section->rate);
}

/* The heading above a row, which the row names as its group. */
static const char *group_above(const struct ft_top_model *m, enum ft_top_mode mode, size_t index)
{
    for (size_t i = index + 1; i-- > 0;) {
        const struct ft_top_row *r = ft_top_row_at(m, mode, i);

        if (r && r->kind == FT_TOP_ROW_SECTION)
            return r->section->title;
    }
    return nullptr;
}

void ft_top_row_json(const struct ft_top_model *m, enum ft_top_mode mode, size_t index, FILE *out)
{
    const struct ft_top_row *r = ft_top_row_at(m, mode, index);
    struct writer w = {.out = out, .indent = true};
    struct view view = view_of(m, mode);

    if (!r)
        return;
    open_container(&w, nullptr, '{');
    if (r->kind == FT_TOP_ROW_SECTION)
        section_members(&w, r->section);
    else
        write_row(&w, &view, r, view.grouped ? group_above(m, mode, index) : nullptr);
    close_container(&w, '}');
    free(w.clean);
}
