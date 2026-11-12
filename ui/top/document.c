#include "ui/top/document.h"

#include "exporters/exporters.h"
#include "filetrace/format.h"
#include "filetrace/sysinfo.h"
#include "ui/top/once.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

constexpr size_t MAX_DEPTH = 8;

struct writer {
    FILE *out;
    bool indent;
    size_t depth;
    bool has[MAX_DEPTH]; /* the container at each depth holds an element */
    char *clean;         /* a copy of the text being written, valid UTF-8 */
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

/* An absent value is null, never an empty string. */
static void put_text(struct writer *w, const char *name, const char *s)
{
    element(w, name);
    if (s && s[0])
        ft_json_string(w->out, valid_utf8(w, s));
    else
        fputs("null", w->out);
}

static void put_uint(struct writer *w, const char *name, uint64_t value)
{
    element(w, name);
    fprintf(w->out, "%" PRIu64, value);
}

static void put_null(struct writer *w, const char *name)
{
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
    element(w, name);
    fprintf(w->out, "%.*s", len, text);
}

static void put_time(struct writer *w, const char *name, uint64_t wall_ns)
{
    char text[40];

    if (wall_ns == 0) {
        put_null(w, name);
        return;
    }
    ft_format_time_rfc3339(wall_ns, text, sizeof(text));
    element(w, name);
    ft_json_string(w->out, text);
}

/* A list of numbers on one line. */
static void put_uints(struct writer *w, const char *name, const uint64_t *values, size_t count)
{
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

static enum ft_top_group grouping(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return mode == FT_TOP_LEADERS ? FT_TOP_GROUP_NONE : ft_top_group_of(m, mode);
}

/* What the filter, the sort and the grouping left of the mode's items. */
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
    }
    put_text(w, "filter", ft_top_filter_of(m, mode));
    put_uint(w, "shown", view->shown);
    put_uint(w, "total", view->total);
    close_container(w, '}');
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
    open_container(w, "remote", '{');
    put_text(w, "address", address);
    put_known(w, "port", t->remote.port, t->remote.port != 0);
    if (known)
        put_bool(w, "public", t->is_public);
    else
        put_null(w, "public");
    put_text(w, "host", d && d->host_state == FT_TOP_HOST_NAMED ? d->host : nullptr);
    close_container(w, '}');
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
    put_text(w, "method", method_text(f->method));
    put_number(w, "public_share", f->public_share);
    put_bool(w, "deleted", f->deleted);
}

static void write_row(struct writer *w, const struct ft_top_row *r, const char *group, bool grouped)
{
    if (grouped)
        put_text(w, "group", group);
    switch (r->kind) {
    case FT_TOP_ROW_TRANSFER:
        transfer_members(w, r->transfer);
        break;
    case FT_TOP_ROW_PROCESS:
        process_members(w, r->process);
        break;
    case FT_TOP_ROW_DESTINATION:
        destination_members(w, r->destination);
        break;
    case FT_TOP_ROW_FILE:
        file_members(w, r->file);
        break;
    default:
        break;
    }
}

/* The rows as an array named after the mode; group headings go into the rows they head. */
static size_t write_rows(struct writer *w, const struct ft_top_model *m, enum ft_top_mode mode)
{
    bool grouped = grouping(m, mode) != FT_TOP_GROUP_NONE;
    size_t count = ft_top_row_count(m, mode);
    const char *group = nullptr;
    size_t written = 0;

    open_container(w, ft_top_mode_name(mode), '[');
    for (size_t i = 0; i < count; i++) {
        const struct ft_top_row *r = ft_top_row_at(m, mode, i);

        if (!r)
            continue;
        if (r->kind == FT_TOP_ROW_SECTION) {
            group = r->section->title;
            continue;
        }
        open_container(w, nullptr, '{');
        write_row(w, r, group, grouped);
        close_container(w, '}');
        written++;
    }
    close_container(w, ']');
    return written;
}

size_t ft_top_write_document(const struct ft_top_model *m, enum ft_top_mode mode, bool indent,
                             FILE *out)
{
    struct writer w = {.out = out, .indent = indent};
    const struct ft_top_totals *totals = ft_top_totals(m);
    struct ft_host_info host;
    size_t rows;

    ft_sysinfo_host(&host);
    open_container(&w, nullptr, '{');
    put_text(&w, "mode", ft_top_mode_name(mode));
    put_time(&w, "time", totals->now_wall_ns);
    put_text(&w, "host", host.hostname);
    write_totals(&w, totals);
    write_view(&w, m, mode);
    rows = write_rows(&w, m, mode);
    close_container(&w, '}');
    fputc('\n', out);
    free(w.clean);
    return rows;
}

size_t ft_top_write_csv(const struct ft_top_model *m, enum ft_top_mode mode, FILE *out)
{
    (void)m;
    (void)mode;
    (void)out;
    return 0;
}

void ft_top_row_json(const struct ft_top_model *m, enum ft_top_mode mode, size_t index, FILE *out)
{
    (void)m;
    (void)mode;
    (void)index;
    (void)out;
}
