#include "ui/top/views.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* The width the column widths are given for; flex columns grow with the columns beyond it. */
constexpr int REFERENCE_COLS = 174;
constexpr int COLUMNS_MAX = 12;
constexpr int PROGRESS_CELLS = 8;
constexpr int EGRESS_CELLS = 10;
constexpr int TREE_PATH_MIN = 12;
constexpr uint32_t FAN_OUT_LOUD = 20;

enum column_id : uint8_t {
    COL_PID,
    COL_USER,
    COL_PROCESS,
    COL_SCRIPT,
    COL_FILE,
    COL_DESTINATION,
    COL_RATE,
    COL_SENT,
    COL_PROGRESS,
    COL_METHOD,
    COL_CONF,
    COL_AGE,
    COL_TOTAL,
    COL_FILES,
    COL_DESTS,
    COL_COMMAND,
    COL_KIND,
    COL_NAME,
    COL_RDNS,
    COL_PROCS,
    COL_TOP_PROCESS,
    COL_TOP_FILE,
    COL_TREND,
    COL_SIZE,
    COL_ACTIVE,
    COL_SENDERS,
    COL_EGRESS,
};

struct column_spec {
    enum column_id id;
    const char *label;
    int width; /* with one column of right padding; 0 for the flex column */
    bool right;
    enum ft_top_sort sort; /* what a click on its header sorts by; DEFAULT for none */
    enum ft_top_sort also; /* another key the column shows */
};

/* Applied in order while the columns do not fit: a width of 0 drops the column. */
struct squeeze {
    enum column_id id;
    int width;
};

struct table_spec {
    const struct column_spec *columns;
    size_t count;
    enum column_id flex;
    int flex_min;
    int flex_natural; /* its width at the reference width; 0: it takes all that is left */
    const struct squeeze *squeezes;
    size_t nsqueezes;
};

struct column {
    const struct column_spec *spec;
    int x;
    int width;
};

struct columns {
    struct column list[COLUMNS_MAX];
    size_t count;
};

static const struct column_spec transfer_columns[] = {
    {COL_PID, "PID", 7, true, FT_TOP_SORT_PID, FT_TOP_SORT_DEFAULT},
    {COL_USER, "USER", 10, false, FT_TOP_SORT_USER, FT_TOP_SORT_DEFAULT},
    {COL_PROCESS, "PROCESS", 18, false, FT_TOP_SORT_PROCESS, FT_TOP_SORT_DEFAULT},
    {COL_SCRIPT, "SCRIPT", 20, false, FT_TOP_SORT_SCRIPT, FT_TOP_SORT_DEFAULT},
    {COL_FILE, "FILE", 0, false, FT_TOP_SORT_FILE, FT_TOP_SORT_DEFAULT},
    {COL_DESTINATION, "DESTINATION", 25, false, FT_TOP_SORT_DESTINATION, FT_TOP_SORT_DEFAULT},
    {COL_RATE, "RATE", 10, true, FT_TOP_SORT_RATE, FT_TOP_SORT_DEFAULT},
    {COL_SENT, "SENT/SIZE", 15, true, FT_TOP_SORT_BYTES, FT_TOP_SORT_SIZE},
    {COL_PROGRESS, "PROGRESS", 15, false, FT_TOP_SORT_PROGRESS, FT_TOP_SORT_DEFAULT},
    {COL_METHOD, "METHOD", 12, false, FT_TOP_SORT_METHOD, FT_TOP_SORT_DEFAULT},
    {COL_CONF, "CONF", 10, false, FT_TOP_SORT_CONFIDENCE, FT_TOP_SORT_DEFAULT},
    {COL_AGE, "AGE", 7, true, FT_TOP_SORT_AGE, FT_TOP_SORT_DEFAULT},
};

static const struct squeeze transfer_squeezes[] = {
    {COL_CONF, 0},   {COL_USER, 0},         {COL_PROGRESS, 0}, {COL_AGE, 0},
    {COL_SCRIPT, 0}, {COL_DESTINATION, 18}, {COL_SENT, 0},
};

static const struct column_spec process_columns[] = {
    {COL_PID, "PID", 7, true, FT_TOP_SORT_PID, FT_TOP_SORT_DEFAULT},
    {COL_USER, "USER", 10, false, FT_TOP_SORT_USER, FT_TOP_SORT_DEFAULT},
    {COL_RATE, "RATE", 10, true, FT_TOP_SORT_RATE, FT_TOP_SORT_DEFAULT},
    {COL_TOTAL, "TOTAL", 9, true, FT_TOP_SORT_TOTAL, FT_TOP_SORT_DEFAULT},
    {COL_FILES, "FILES", 6, true, FT_TOP_SORT_FILES, FT_TOP_SORT_DEFAULT},
    {COL_DESTS, "DESTS", 6, true, FT_TOP_SORT_DESTINATIONS, FT_TOP_SORT_DEFAULT},
    {COL_METHOD, "METHOD", 11, false, FT_TOP_SORT_METHOD, FT_TOP_SORT_DEFAULT},
    {COL_COMMAND, "COMMAND", 0, false, FT_TOP_SORT_PROCESS, FT_TOP_SORT_DEFAULT},
};

static const struct squeeze process_squeezes[] = {
    {COL_USER, 0},
    {COL_DESTS, 0},
    {COL_FILES, 0},
    {COL_TOTAL, 0},
};

static const struct column_spec destination_columns[] = {
    {COL_DESTINATION, "DESTINATION", 20, false, FT_TOP_SORT_DESTINATION, FT_TOP_SORT_DEFAULT},
    {COL_KIND, "KIND", 9, false, FT_TOP_SORT_KIND, FT_TOP_SORT_DEFAULT},
    {COL_RDNS, "rDNS", 0, false, FT_TOP_SORT_HOSTNAME, FT_TOP_SORT_DEFAULT},
    {COL_RATE, "RATE", 10, true, FT_TOP_SORT_RATE, FT_TOP_SORT_DEFAULT},
    {COL_TOTAL, "TOTAL", 9, true, FT_TOP_SORT_TOTAL, FT_TOP_SORT_DEFAULT},
    {COL_FILES, "FILES", 6, true, FT_TOP_SORT_FILES, FT_TOP_SORT_DEFAULT},
    {COL_PROCS, "PROCS", 6, true, FT_TOP_SORT_PROCESSES, FT_TOP_SORT_DEFAULT},
    {COL_TOP_PROCESS, "TOP PROCESS", 20, false, FT_TOP_SORT_PROCESS, FT_TOP_SORT_DEFAULT},
    {COL_TOP_FILE, "TOP FILE", 30, false, FT_TOP_SORT_FILE, FT_TOP_SORT_DEFAULT},
    {COL_TREND, "TREND 5m", 12, false, FT_TOP_SORT_DEFAULT, FT_TOP_SORT_DEFAULT},
};

static const struct squeeze destination_squeezes[] = {
    {COL_TREND, 0},
    {COL_TOP_PROCESS, 0},
    {COL_PROCS, 0},
    {COL_TOP_FILE, 20},
};

/* With names on the screen; rDNS then shows only while reverse lookups are on. */
static const struct column_spec named_destination_columns[] = {
    {COL_DESTINATION, "DESTINATION", 20, false, FT_TOP_SORT_DESTINATION, FT_TOP_SORT_DEFAULT},
    {COL_KIND, "KIND", 9, false, FT_TOP_SORT_KIND, FT_TOP_SORT_DEFAULT},
    {COL_NAME, "NAME", 0, false, FT_TOP_SORT_DEFAULT, FT_TOP_SORT_DEFAULT},
    {COL_RDNS, "rDNS", 20, false, FT_TOP_SORT_HOSTNAME, FT_TOP_SORT_DEFAULT},
    {COL_RATE, "RATE", 10, true, FT_TOP_SORT_RATE, FT_TOP_SORT_DEFAULT},
    {COL_TOTAL, "TOTAL", 9, true, FT_TOP_SORT_TOTAL, FT_TOP_SORT_DEFAULT},
    {COL_FILES, "FILES", 6, true, FT_TOP_SORT_FILES, FT_TOP_SORT_DEFAULT},
    {COL_PROCS, "PROCS", 6, true, FT_TOP_SORT_PROCESSES, FT_TOP_SORT_DEFAULT},
    {COL_TOP_PROCESS, "TOP PROCESS", 20, false, FT_TOP_SORT_PROCESS, FT_TOP_SORT_DEFAULT},
    {COL_TOP_FILE, "TOP FILE", 30, false, FT_TOP_SORT_FILE, FT_TOP_SORT_DEFAULT},
    {COL_TREND, "TREND 5m", 12, false, FT_TOP_SORT_DEFAULT, FT_TOP_SORT_DEFAULT},
};

static const struct squeeze named_destination_squeezes[] = {
    {COL_TREND, 0}, {COL_TOP_PROCESS, 0}, {COL_PROCS, 0}, {COL_RDNS, 0}, {COL_TOP_FILE, 20},
};

static const struct column_spec file_columns[] = {
    {COL_FILE, "FILE", 0, false, FT_TOP_SORT_FILE, FT_TOP_SORT_DEFAULT},
    {COL_SIZE, "SIZE", 8, true, FT_TOP_SORT_SIZE, FT_TOP_SORT_DEFAULT},
    {COL_RATE, "RATE", 10, true, FT_TOP_SORT_RATE, FT_TOP_SORT_DEFAULT},
    {COL_ACTIVE, "ACTIVE", 8, true, FT_TOP_SORT_TRANSFERS, FT_TOP_SORT_DEFAULT},
    {COL_DESTS, "DESTS", 7, true, FT_TOP_SORT_DESTINATIONS, FT_TOP_SORT_DEFAULT},
    {COL_SENDERS, "SENDERS", 20, false, FT_TOP_SORT_PROCESS, FT_TOP_SORT_DEFAULT},
    {COL_METHOD, "METHOD", 11, false, FT_TOP_SORT_METHOD, FT_TOP_SORT_DEFAULT},
    {COL_EGRESS, "EGRESS", 16, false, FT_TOP_SORT_DEFAULT, FT_TOP_SORT_DEFAULT},
};

static const struct squeeze file_squeezes[] = {
    {COL_EGRESS, 0},
    {COL_SENDERS, 0},
};

static const struct table_spec tables[] = {
    [FT_TOP_TRANSFERS] = {transfer_columns, FT_ARRAY_LEN(transfer_columns), COL_FILE, 30, 44,
                          transfer_squeezes, FT_ARRAY_LEN(transfer_squeezes)},
    [FT_TOP_PROCESSES] = {process_columns, FT_ARRAY_LEN(process_columns), COL_COMMAND, 24, 0,
                          process_squeezes, FT_ARRAY_LEN(process_squeezes)},
    [FT_TOP_DESTINATIONS] = {destination_columns, FT_ARRAY_LEN(destination_columns), COL_RDNS, 16,
                             30, destination_squeezes, FT_ARRAY_LEN(destination_squeezes)},
    [FT_TOP_FILES] = {file_columns, FT_ARRAY_LEN(file_columns), COL_FILE, 30, 52, file_squeezes,
                      FT_ARRAY_LEN(file_squeezes)},
};

static const struct table_spec named_destinations = {
    named_destination_columns,  FT_ARRAY_LEN(named_destination_columns),  COL_NAME, 16, 30,
    named_destination_squeezes, FT_ARRAY_LEN(named_destination_squeezes),
};

static const struct table_spec *table_of(const struct ft_top_draw *d, enum ft_top_mode mode)
{
    if (mode == FT_TOP_DESTINATIONS && !d->ui->addresses && ft_top_view_of(d->model, mode)->named)
        return &named_destinations;
    return &tables[mode];
}

static bool column_shown(const struct ft_top_draw *d, const struct table_spec *t,
                         const struct column_spec *c)
{
    if (c->id == COL_SCRIPT)
        return d->ui->script_column;
    if (c->id == COL_RDNS && t->flex != COL_RDNS)
        return ft_top_resolve_of(d->model);
    return true;
}

static void fit_columns(const struct table_spec *t, const struct ft_top_draw *d, int width,
                        struct columns *out)
{
    int widths[COLUMNS_MAX];
    int fixed = 0;
    size_t n = t->count < COLUMNS_MAX ? t->count : COLUMNS_MAX;

    for (size_t i = 0; i < n; i++) {
        const struct column_spec *c = &t->columns[i];
        widths[i] = column_shown(d, t, c) ? c->width : 0;
        fixed += widths[i];
    }
    for (size_t s = 0; s < t->nsqueezes && fixed + t->flex_min > width; s++) {
        for (size_t i = 0; i < n; i++) {
            if (t->columns[i].id != t->squeezes[s].id || widths[i] == 0)
                continue;
            int to = t->squeezes[s].width < widths[i] ? t->squeezes[s].width : widths[i];
            fixed -= widths[i] - to;
            widths[i] = to;
        }
    }

    int flex = width - fixed;
    if (t->flex_natural > 0) {
        int cap = t->flex_natural + (width > REFERENCE_COLS ? width - REFERENCE_COLS : 0);
        flex = flex < cap ? flex : cap;
    }
    if (flex < 2)
        flex = 2;

    out->count = 0;
    int x = 0;
    for (size_t i = 0; i < n; i++) {
        const struct column_spec *c = &t->columns[i];
        int w = c->id == t->flex ? flex : widths[i];
        if (w == 0)
            continue;
        out->list[out->count++] = (struct column){.spec = c, .x = x, .width = w};
        x += w;
    }
}

/* Text drawn in a row, marked for the search and filter once the selection bar is on. */
struct piece {
    int x;
    int width;
    const char *text;
    enum ft_cut cut;
    enum ft_top_field field;
};

constexpr size_t ROW_PIECES = 12;
constexpr size_t ROW_TEXTS = 6;
constexpr size_t ROW_TEXT_BYTES = 256;

struct row_draw {
    struct ft_top_draw *d;
    int y;
    bool done;
    bool selected;
    bool tagged;
    bool first_cell; /* the next cell drawn is the row's first */
    struct piece pieces[ROW_PIECES];
    size_t npieces;
    char texts[ROW_TEXTS][ROW_TEXT_BYTES];
    size_t ntexts;
};

static char *row_text(struct row_draw *rd)
{
    static char spare[ROW_TEXT_BYTES];
    return rd->ntexts < ROW_TEXTS ? rd->texts[rd->ntexts++] : spare;
}

static void remember(struct row_draw *rd, int x, int width, const char *text, enum ft_cut cut,
                     enum ft_top_field field)
{
    if (field == FT_TOP_FIELD_COUNT || rd->npieces == ROW_PIECES || width <= 1)
        return;
    rd->pieces[rd->npieces++] =
        (struct piece){.x = x, .width = width, .text = text, .cut = cut, .field = field};
}

static struct ft_style style(const struct row_draw *rd, enum ft_color fg, bool bold)
{
    if (rd->done)
        return ft_top_fg(FT_COLOR_DIM, false);
    return ft_top_fg(fg, bold);
}

static struct ft_style first_style(struct row_draw *rd, struct ft_style s)
{
    bool first = rd->first_cell;
    rd->first_cell = false;
    return first && rd->tagged ? ft_top_fg(FT_COLOR_AMBER, true) : s;
}

/* A text cell; field FT_TOP_FIELD_COUNT is never marked. */
static void cell(struct row_draw *rd, const struct column *c, struct ft_style s, const char *text,
                 enum ft_top_field field)
{
    s = first_style(rd, s);
    int n = ft_top_cell(rd->d, c->x, rd->y, c->width, c->spec->right, s, text);
    if (c->spec->right)
        remember(rd, c->x + c->width - 1 - n, n + 1, text, FT_CUT_END, field);
    else
        remember(rd, c->x, c->width, text, FT_CUT_END, field);
}

static void path_cell(struct row_draw *rd, const struct column *c, const char *path,
                      uint32_t name_offset, struct ft_style name)
{
    struct ft_top_draw *d = rd->d;
    bool tagged = rd->first_cell && rd->tagged;

    rd->first_cell = false;
    if (tagged) {
        struct ft_style amber = ft_top_fg(FT_COLOR_AMBER, true);
        ft_canvas_path(d->canvas, c->x, rd->y, c->width - 1, amber, amber,
                       ft_top_path_text(d, path, name_offset));
    } else if (rd->done) {
        struct ft_style dim = ft_top_fg(FT_COLOR_DIM, false);
        ft_canvas_text_cut(d->canvas, c->x, rd->y, c->width - 1, dim,
                           ft_top_path_text(d, path, name_offset), FT_CUT_START);
    } else {
        ft_top_path_cell(d, c->x, rd->y, c->width, path, name_offset, name);
    }
    remember(rd, c->x, c->width, ft_top_path_text(d, path, name_offset), FT_CUT_START,
             FT_TOP_FIELD_FILE);
}

/* Bytes of the longest start of text that takes at most cols columns. */
static size_t prefix_bytes(const char *text, int cols)
{
    size_t len = strlen(text);
    size_t off = 0;
    int used = 0;

    while (off < len) {
        int w;
        size_t n = ft_text_next(text + off, len - off, &w);
        if (used + w > cols)
            break;
        used += w;
        off += n;
    }
    return off;
}

/* An address with its port, cut in the middle when it is wider than cols so that the port stays. */
static const char *keep_port(struct row_draw *rd, const char *text, int cols)
{
    if (cols <= 0 || ft_text_columns(text) <= cols)
        return text;

    const char *colon = strrchr(text, ':');
    int port_cols = colon ? ft_text_columns(colon) : 0;
    if (!colon || port_cols + 2 > cols)
        return text;
    char *out = row_text(rd);
    size_t head = prefix_bytes(text, cols - port_cols - 1);
    snprintf(out, ROW_TEXT_BYTES, "%.*s…%s", (int)head, text, colon);
    return out;
}

static const char *cut_end(struct row_draw *rd, const char *text, int cols)
{
    if (cols <= 0 || ft_text_columns(text) <= cols)
        return text;
    char *out = row_text(rd);
    snprintf(out, ROW_TEXT_BYTES, "%.*s…", (int)prefix_bytes(text, cols - 1), text);
    return out;
}

/*
 * Where a transfer goes: the name the process used, else the host name with the port when one
 * is known, else the address.
 */
static const char *endpoint_text(struct row_draw *rd, const struct ft_top_transfer *t, int cols)
{
    const char *full = t->remote_text;

    if (t->names && !rd->d->ui->addresses) {
        char *name = row_text(rd);
        ft_remote_name_cell(t->names, t->remote.port, name, ROW_TEXT_BYTES);
        return cut_end(rd, name, cols);
    }
    if (t->destination && t->destination->host_state == FT_TOP_HOST_NAMED && t->destination->host) {
        char *buf = row_text(rd);
        snprintf(buf, ROW_TEXT_BYTES, "%s:%u", t->destination->host, (unsigned)t->remote.port);
        full = buf;
    }
    return keep_port(rd, full, cols);
}

static enum ft_color destination_color(const struct row_draw *rd, bool is_public)
{
    return rd->d->ui->color_by_method ? FT_COLOR_TEXT : ft_top_egress_color(is_public);
}

static struct ft_style file_name_style(const struct row_draw *rd, uint8_t method)
{
    enum ft_color c = rd->d->ui->color_by_method ? ft_top_method_color(method) : FT_COLOR_BRIGHT;
    return style(rd, c, true);
}

static enum ft_color confidence_color(uint8_t confidence)
{
    return confidence == FT_CONF_EXACT ? FT_COLOR_GREEN : FT_COLOR_AMBER;
}

static void rate_cell(struct row_draw *rd, const struct column *c, uint64_t rate, bool always_bold)
{
    char text[32];
    struct ft_style s = ft_top_rate_style(rate);

    if (rd->done) {
        cell(rd, c, style(rd, FT_COLOR_DIM, false), "done", FT_TOP_FIELD_COUNT);
        return;
    }
    if (always_bold)
        s.attrs |= FT_ATTR_BOLD;
    ft_top_format_rate(rate, text, sizeof(text));
    cell(rd, c, s, text, FT_TOP_FIELD_COUNT);
}

static void count_cell(struct row_draw *rd, const struct column *c, uint64_t value)
{
    char text[24];
    snprintf(text, sizeof(text), "%" PRIu64, value);
    cell(rd, c, style(rd, FT_COLOR_TEXT, false), text, FT_TOP_FIELD_COUNT);
}

static void size_cell(struct row_draw *rd, const struct column *c, uint64_t bytes, bool known)
{
    char text[24];
    if (known)
        ft_top_format_size(bytes, text, sizeof(text));
    else
        ft_strlcpy(text, "?", sizeof(text));
    cell(rd, c, style(rd, FT_COLOR_TEXT, false), text, FT_TOP_FIELD_COUNT);
}

static void progress_cell(struct row_draw *rd, const struct column *c,
                          const struct ft_top_transfer *t)
{
    char percent[8];

    rd->first_cell = false;
    if (t->progress < 0 || c->width < PROGRESS_CELLS + 1)
        return;
    struct ft_bar_part part = {t->progress, style(rd, FT_COLOR_GREEN, false)};
    struct ft_bar bar = {
        .parts = &part,
        .count = 1,
        .total = 1,
        .empty_rune = U'░',
        .empty = style(rd, FT_COLOR_TRACK, false),
    };
    ft_canvas_bar(rd->d->canvas, c->x, rd->y, PROGRESS_CELLS, &bar);
    ft_top_format_percent(t->progress, percent, sizeof(percent));
    ft_canvas_text(rd->d->canvas, c->x + PROGRESS_CELLS + 1, rd->y,
                   c->width - 1 - PROGRESS_CELLS - 1, style(rd, FT_COLOR_TEXT, false), percent);
}

/* The title when the column holds it, else its head: "nginx: worker" for "nginx: worker process".
 */
static const char *process_label(const struct ft_top_process *p, int width)
{
    if (!p->title[0] || ft_text_columns(p->title) <= width || !p->head[0])
        return p->title;
    return p->head;
}

static void transfer_cells(struct row_draw *rd, const struct columns *cols,
                           const struct ft_top_transfer *t)
{
    const struct ft_top_process *p = t->process;
    char text[64];
    char size[24];

    for (size_t i = 0; i < cols->count; i++) {
        const struct column *c = &cols->list[i];
        switch (c->spec->id) {
        case COL_PID: {
            char *pid = row_text(rd);
            snprintf(pid, ROW_TEXT_BYTES, "%" PRIu32, t->pid);
            cell(rd, c, style(rd, FT_COLOR_DIM, false), pid, FT_TOP_FIELD_PID);
            break;
        }
        case COL_USER:
            cell(rd, c, style(rd, FT_COLOR_TEXT, false), p ? p->user : "", FT_TOP_FIELD_USER);
            break;
        case COL_PROCESS:
            cell(rd, c, style(rd, FT_COLOR_BRIGHT, false), p ? process_label(p, c->width - 1) : "",
                 FT_TOP_FIELD_PROC);
            break;
        case COL_SCRIPT: {
            const char *script = t->script_name && t->script_name[0] ? t->script_name
                                 : p && p->script_name               ? p->script_name
                                                                     : "";
            if (script[0])
                cell(rd, c, style(rd, FT_COLOR_AMBER, false), script, FT_TOP_FIELD_SCRIPT);
            else
                cell(rd, c, style(rd, FT_COLOR_DIM, false), "—", FT_TOP_FIELD_COUNT);
            break;
        }
        case COL_FILE:
            path_cell(rd, c, t->path, t->name_offset, file_name_style(rd, t->method));
            break;
        case COL_DESTINATION:
            cell(rd, c, style(rd, destination_color(rd, t->is_public), false),
                 endpoint_text(rd, t, c->width - 1), FT_TOP_FIELD_DEST);
            break;
        case COL_RATE:
            rate_cell(rd, c, t->rate, false);
            break;
        case COL_SENT:
            ft_top_format_size(t->bytes, text, sizeof(text));
            if (t->size) {
                ft_top_format_size(t->size, size, sizeof(size));
            } else {
                ft_strlcpy(size, "?", sizeof(size));
            }
            ft_strlcpy(text + strlen(text), "/", sizeof(text) - strlen(text));
            ft_strlcpy(text + strlen(text), size, sizeof(text) - strlen(text));
            cell(rd, c, style(rd, FT_COLOR_TEXT, false), text, FT_TOP_FIELD_COUNT);
            break;
        case COL_PROGRESS:
            progress_cell(rd, c, t);
            break;
        case COL_METHOD:
            cell(rd, c, style(rd, ft_top_method_color(t->method), false),
                 ft_top_method_word(t->method), FT_TOP_FIELD_METHOD);
            break;
        case COL_CONF:
            cell(rd, c, style(rd, confidence_color(t->confidence), false),
                 ft_top_confidence_word(t->confidence, t->incomplete), FT_TOP_FIELD_CONF);
            break;
        case COL_AGE:
            ft_top_format_age(t->age_ns, text, sizeof(text));
            cell(rd, c, style(rd, FT_COLOR_DIM, false), text, FT_TOP_FIELD_COUNT);
            break;
        default:
            break;
        }
    }
}

/* Draws text in [*x, end) cut at its end and moves *x past it; false once the room is gone. */
static bool put(struct row_draw *rd, int *x, int end, struct ft_style s, const char *text,
                enum ft_top_field field)
{
    if (*x >= end)
        return false;
    int n = ft_canvas_text_cut(rd->d->canvas, *x, rd->y, end - *x, s, text, FT_CUT_END);
    remember(rd, *x, end - *x + 1, text, FT_CUT_END, field);
    *x += n;
    return *x < end;
}

/* The tree's guides of a row and, for a node, its mark; returns the mark's column or -1. */
static int guides(struct row_draw *rd, const struct ft_top_row *r, int *x, int end, bool node)
{
    char text[ROW_TEXT_BYTES];
    size_t len = 0;
    int mark = -1;

    text[0] = '\0';
    if (r->depth >= 1) {
        len += (size_t)snprintf(text + len, sizeof(text) - len, "  ");
        for (unsigned level = 1; level < r->depth && len + 8 < sizeof(text); level++) {
            bool rail = level < 32 && (r->rails & (1u << level));
            len += (size_t)snprintf(text + len, sizeof(text) - len, "%s", rail ? "│  " : "   ");
        }
        if (len + 8 < sizeof(text))
            len += (size_t)snprintf(text + len, sizeof(text) - len, "%s",
                                    r->flags & FT_TOP_ROW_LAST ? "└─ " : "├─ ");
    }
    put(rd, x, end, style(rd, FT_COLOR_DIM, false), text, FT_TOP_FIELD_COUNT);
    if (node) {
        const char *sign = r->node == FT_TOP_NODE_EXPANDED    ? "- "
                           : r->node == FT_TOP_NODE_COLLAPSED ? "+ "
                                                              : "  ";
        if (r->node != FT_TOP_NODE_LEAF)
            mark = *x;
        put(rd, x, end, style(rd, FT_COLOR_DIM, false), sign, FT_TOP_FIELD_COUNT);
    }
    return mark < end ? mark : -1;
}

static void script_suffix(struct row_draw *rd, int *x, int end, const char *script_name)
{
    if (!script_name || !script_name[0] || *x >= end)
        return;
    char *text = row_text(rd);
    snprintf(text, ROW_TEXT_BYTES, "  [%s]", script_name);
    put(rd, x, end, style(rd, FT_COLOR_AMBER, false), text, FT_TOP_FIELD_COUNT);
}

static int command_cell(struct row_draw *rd, const struct column *c, const struct ft_top_row *r,
                        bool tree)
{
    const struct ft_top_process *p = r->process;
    int x = c->x;
    int end = c->x + c->width - 1;
    int mark = tree ? guides(rd, r, &x, end, true) : -1;

    if (!p->title[0]) {
        char *pid = row_text(rd);
        snprintf(pid, ROW_TEXT_BYTES, "%" PRIu32, p->pid);
        put(rd, &x, end, style(rd, FT_COLOR_DIM, false), pid, FT_TOP_FIELD_PID);
        return mark;
    }
    if (!put(rd, &x, end, style(rd, FT_COLOR_BRIGHT, true), p->head, FT_TOP_FIELD_PROC))
        return mark;
    if (p->rest && p->rest[0]) {
        x++;
        if (!put(rd, &x, end, style(rd, FT_COLOR_DIM, false), p->rest, FT_TOP_FIELD_PROC))
            return mark;
    }
    script_suffix(rd, &x, end, p->script_name);
    return mark;
}

static void process_cells(struct row_draw *rd, const struct columns *cols,
                          const struct ft_top_row *r, bool tree, int *toggle)
{
    const struct ft_top_process *p = r->process;
    char text[32];

    for (size_t i = 0; i < cols->count; i++) {
        const struct column *c = &cols->list[i];
        switch (c->spec->id) {
        case COL_PID: {
            char *pid = row_text(rd);
            snprintf(pid, ROW_TEXT_BYTES, "%" PRIu32, p->pid);
            cell(rd, c, style(rd, FT_COLOR_DIM, false), pid, FT_TOP_FIELD_PID);
            break;
        }
        case COL_USER:
            cell(rd, c, style(rd, FT_COLOR_TEXT, false), p->user, FT_TOP_FIELD_USER);
            break;
        case COL_RATE:
            ft_top_format_rate(p->rate, text, sizeof(text));
            cell(rd, c, style(rd, FT_COLOR_BRIGHT, true), text, FT_TOP_FIELD_COUNT);
            break;
        case COL_TOTAL:
            size_cell(rd, c, p->total, true);
            break;
        case COL_FILES:
            count_cell(rd, c, p->files);
            break;
        case COL_DESTS:
            count_cell(rd, c, p->destinations);
            break;
        case COL_METHOD:
            cell(rd, c, style(rd, ft_top_method_color(p->method), false),
                 ft_top_method_word(p->method), FT_TOP_FIELD_METHOD);
            break;
        case COL_COMMAND:
            *toggle = command_cell(rd, c, r, tree);
            break;
        default:
            break;
        }
    }
}

static void fold_cells(struct row_draw *rd, const struct columns *cols, const struct ft_top_row *r,
                       int *toggle)
{
    const struct ft_top_fold *f = r->fold;
    char text[48];

    rd->first_cell = false;
    for (size_t i = 0; i < cols->count; i++) {
        const struct column *c = &cols->list[i];
        switch (c->spec->id) {
        case COL_RATE:
            ft_top_format_rate(f->rate, text, sizeof(text));
            cell(rd, c, style(rd, FT_COLOR_BRIGHT, true), text, FT_TOP_FIELD_COUNT);
            break;
        case COL_TOTAL:
            size_cell(rd, c, f->total, true);
            break;
        case COL_FILES:
            count_cell(rd, c, f->files);
            break;
        case COL_DESTS:
            count_cell(rd, c, f->destinations);
            break;
        case COL_METHOD:
            cell(rd, c, style(rd, ft_top_method_color(f->method), false),
                 ft_top_method_word(f->method), FT_TOP_FIELD_METHOD);
            break;
        case COL_COMMAND: {
            int x = c->x;
            int end = c->x + c->width - 1;
            *toggle = guides(rd, r, &x, end, true);
            char *title = row_text(rd);
            snprintf(title, ROW_TEXT_BYTES, "%zu more %s", f->count, f->name ? f->name : "");
            if (!put(rd, &x, end, style(rd, FT_COLOR_BRIGHT, true), title, FT_TOP_FIELD_ANY))
                break;
            char *pids = row_text(rd);
            size_t len = 0;
            pids[0] = '\0';
            for (size_t k = 0; k < f->count && len + 12 < ROW_TEXT_BYTES; k++)
                len += (size_t)snprintf(pids + len, ROW_TEXT_BYTES - len, " %" PRIu32,
                                        f->members[k]->pid);
            put(rd, &x, end, style(rd, FT_COLOR_DIM, false), pids, FT_TOP_FIELD_COUNT);
            break;
        }
        default:
            break;
        }
    }
}

static void tree_transfer_cells(struct row_draw *rd, const struct columns *cols,
                                const struct ft_top_row *r)
{
    const struct ft_top_transfer *t = r->transfer;
    struct ft_top_draw *d = rd->d;
    char text[32];

    rd->first_cell = false;
    for (size_t i = 0; i < cols->count; i++) {
        const struct column *c = &cols->list[i];
        switch (c->spec->id) {
        case COL_RATE:
            if (rd->done) {
                rate_cell(rd, c, 0, false);
            } else {
                ft_top_format_rate(t->rate, text, sizeof(text));
                cell(rd, c, style(rd, FT_COLOR_TEXT, true), text, FT_TOP_FIELD_COUNT);
            }
            break;
        case COL_METHOD:
            cell(rd, c, style(rd, confidence_color(t->confidence), false),
                 ft_top_confidence_word(t->confidence, t->incomplete), FT_TOP_FIELD_CONF);
            break;
        case COL_COMMAND: {
            int x = c->x;
            int end = c->x + c->width - 1;
            guides(rd, r, &x, end, false);
            int room = end - x;
            if (room <= 0)
                break;
            const char *dest = endpoint_text(rd, t, 0);
            int dest_cols = ft_text_columns(dest);
            int path_min = room / 2 < TREE_PATH_MIN ? room / 2 : TREE_PATH_MIN;
            if (room - 3 - dest_cols < path_min) {
                dest_cols = room - 3 - path_min;
                dest = endpoint_text(rd, t, dest_cols);
            }
            int path_cols = room - 3 - ft_text_columns(dest);
            const char *path = ft_top_path_text(d, t->path, t->name_offset);
            enum ft_color path_color =
                d->ui->color_by_method ? ft_top_method_color(t->method) : FT_COLOR_TEXT;
            if (path_cols > 0) {
                int n = ft_canvas_text_cut(d->canvas, x, rd->y, path_cols,
                                           style(rd, path_color, false), path, FT_CUT_START);
                remember(rd, x, path_cols + 1, path, FT_CUT_START, FT_TOP_FIELD_FILE);
                x += n;
            }
            struct ft_style to = style(rd, destination_color(rd, t->is_public), false);
            put(rd, &x, end, to, " → ", FT_TOP_FIELD_COUNT);
            put(rd, &x, end, to, dest, FT_TOP_FIELD_DEST);
            break;
        }
        default:
            break;
        }
    }
}

/* As much of the path's end as fits, starting after a '/' when the whole does not. */
static const char *path_tail(const char *path, int cols)
{
    if (ft_text_columns(path) <= cols)
        return path;
    for (const char *p = strchr(path, '/'); p; p = strchr(p + 1, '/')) {
        if (p[1] && ft_text_columns(p + 1) <= cols)
            return p + 1;
    }
    return nullptr;
}

static void top_file_cell(struct row_draw *rd, const struct column *c,
                          const struct ft_top_destination *dst)
{
    const struct ft_top_transfer *top = dst->top;

    rd->first_cell = false;
    if (!top || c->width <= 1)
        return;
    const char *path = ft_top_path_text(rd->d, top->path, top->name_offset);
    enum ft_color color =
        rd->d->ui->color_by_method ? ft_top_method_color(top->method) : FT_COLOR_BRIGHT;
    const char *tail = path_tail(path, c->width - 1);
    enum ft_cut cut = FT_CUT_END;
    if (!tail) {
        tail = top->path + top->name_offset;
        cut = FT_CUT_START;
    }
    ft_canvas_text_cut(rd->d->canvas, c->x, rd->y, c->width - 1, style(rd, color, false), tail,
                       cut);
    remember(rd, c->x, c->width, tail, cut, FT_TOP_FIELD_FILE);
}

static void top_process_cell(struct row_draw *rd, const struct column *c,
                             const struct ft_top_destination *dst)
{
    const struct ft_top_process *p = dst->top_process;
    const char *script = dst->top ? dst->top->script_name : nullptr;
    char *text = row_text(rd);

    if (!p) {
        cell(rd, c, style(rd, FT_COLOR_TEXT, false), "", FT_TOP_FIELD_COUNT);
        return;
    }
    /* A request's script, as of a PHP worker, names what the process alone does not. */
    if (script && script[0] && strcmp(dst->top->script, p->script ? p->script : "") != 0) {
        const char *dot = strrchr(script, '.');
        int stem = dot && dot != script ? (int)(dot - script) : (int)strlen(script);
        snprintf(text, ROW_TEXT_BYTES, "%s [%.*s]", p->name && p->name[0] ? p->name : p->title,
                 stem, script);
    } else {
        ft_strlcpy(text, process_label(p, c->width - 1), ROW_TEXT_BYTES);
    }
    cell(rd, c, style(rd, FT_COLOR_TEXT, false), text, FT_TOP_FIELD_PROC);
}

static void destination_cells(struct row_draw *rd, const struct columns *cols,
                              const struct ft_top_destination *dst)
{
    for (size_t i = 0; i < cols->count; i++) {
        const struct column *c = &cols->list[i];
        switch (c->spec->id) {
        case COL_DESTINATION:
            cell(rd, c, style(rd, destination_color(rd, dst->is_public), true),
                 keep_port(rd, dst->label, c->width - 1), FT_TOP_FIELD_DEST);
            break;
        case COL_KIND: {
            char *kind = row_text(rd);
            snprintf(kind, ROW_TEXT_BYTES, "%s%s", dst->is_public ? "public" : "private",
                     dst->is_new ? "*" : "");
            cell(rd, c, style(rd, ft_top_egress_color(dst->is_public), false), kind,
                 FT_TOP_FIELD_COUNT);
            break;
        }
        case COL_NAME:
            cell(rd, c, style(rd, FT_COLOR_TEXT, false), dst->name, FT_TOP_FIELD_DEST);
            break;
        case COL_RDNS: {
            const char *name = dst->host_state == FT_TOP_HOST_NAMED && dst->host ? dst->host
                               : dst->host_state == FT_TOP_HOST_NAMELESS         ? "(no PTR)"
                                                                                 : "";
            cell(rd, c, style(rd, FT_COLOR_DIM, false), name, FT_TOP_FIELD_DEST);
            break;
        }
        case COL_RATE:
            rate_cell(rd, c, dst->rate, true);
            break;
        case COL_TOTAL:
            size_cell(rd, c, dst->total, true);
            break;
        case COL_FILES:
            count_cell(rd, c, dst->files);
            break;
        case COL_PROCS:
            count_cell(rd, c, dst->processes);
            break;
        case COL_TOP_PROCESS:
            top_process_cell(rd, c, dst);
            break;
        case COL_TOP_FILE:
            top_file_cell(rd, c, dst);
            break;
        case COL_TREND: {
            double values[FT_TOP_TREND];
            for (size_t k = 0; k < FT_TOP_TREND; k++)
                values[k] = (double)dst->trend[k];
            enum ft_color color = dst->is_new ? FT_COLOR_AMBER : FT_COLOR_BLUE;
            ft_canvas_spark(rd->d->canvas, c->x, rd->y, c->width, values, FT_TOP_TREND, 0,
                            style(rd, color, false));
            break;
        }
        default:
            break;
        }
    }
}

static void egress_cell(struct row_draw *rd, const struct column *c, const struct ft_top_file *f)
{
    double cells = EGRESS_CELLS;
    double pub = f->public_share;

    /* Idle transfers have no rate to share, so they count one each. */
    if (!f->rate && f->ntransfers) {
        size_t public_ones = 0;
        for (size_t i = 0; i < f->ntransfers; i++)
            public_ones += f->transfers[i]->is_public;
        pub = (double)public_ones / (double)f->ntransfers;
    }
    double priv = 1 - pub;
    /* A share too small to round to a cell still gets one. */
    struct ft_bar_part parts[] = {
        {pub > 0 && pub < 1 / cells ? 1 / cells : pub, style(rd, FT_COLOR_PURPLE, false)},
        {priv > 0 && priv < 1 / cells ? 1 / cells : priv, style(rd, FT_COLOR_BLUE, false)},
    };
    struct ft_bar bar = {.parts = parts, .count = FT_ARRAY_LEN(parts)};
    int width = c->width - 1 < EGRESS_CELLS ? c->width - 1 : EGRESS_CELLS;

    ft_canvas_bar(rd->d->canvas, c->x, rd->y, width, &bar);
}

static void file_cells(struct row_draw *rd, const struct columns *cols, const struct ft_top_file *f)
{
    for (size_t i = 0; i < cols->count; i++) {
        const struct column *c = &cols->list[i];
        switch (c->spec->id) {
        case COL_FILE:
            path_cell(rd, c, f->path, f->name_offset, file_name_style(rd, f->method));
            break;
        case COL_SIZE:
            size_cell(rd, c, f->size, f->size > 0);
            break;
        case COL_RATE:
            rate_cell(rd, c, f->rate, true);
            break;
        case COL_ACTIVE: {
            bool loud = f->active >= FAN_OUT_LOUD;
            char text[16];
            snprintf(text, sizeof(text), "%" PRIu32, f->active);
            cell(rd, c, style(rd, loud ? FT_COLOR_PURPLE : FT_COLOR_TEXT, loud), text,
                 FT_TOP_FIELD_COUNT);
            break;
        }
        case COL_DESTS:
            count_cell(rd, c, f->destinations);
            break;
        case COL_SENDERS:
            cell(rd, c, style(rd, FT_COLOR_TEXT, false), f->senders ? f->senders : "",
                 FT_TOP_FIELD_PROC);
            break;
        case COL_METHOD:
            cell(rd, c, style(rd, ft_top_method_color(f->method), false),
                 ft_top_method_word(f->method), FT_TOP_FIELD_METHOD);
            break;
        case COL_EGRESS:
            egress_cell(rd, c, f);
            break;
        default:
            break;
        }
    }
}

static void section_cells(struct row_draw *rd, struct ft_rect row, const struct ft_top_section *s,
                          enum ft_top_node node)
{
    char rate[32];
    char *title = row_text(rd);
    char *sums = row_text(rd);
    int x = row.x;
    int end = row.x + row.w - 1;

    ft_top_format_rate(s->rate, rate, sizeof(rate));
    snprintf(title, ROW_TEXT_BYTES, "%s", s->title && s->title[0] ? s->title : "(none)");
    snprintf(sums, ROW_TEXT_BYTES, "  %" PRIu32 " proc%s · %" PRIu32 " file%s · %s", s->processes,
             s->processes == 1 ? "" : "s", s->files, s->files == 1 ? "" : "s", rate);
    put(rd, &x, end, ft_top_fg(FT_COLOR_AMBER, true), node == FT_TOP_NODE_COLLAPSED ? "▸ " : "▾ ",
        FT_TOP_FIELD_COUNT);
    if (put(rd, &x, end, ft_top_fg(FT_COLOR_AMBER, true), title, FT_TOP_FIELD_ANY))
        put(rd, &x, end, ft_top_fg(FT_COLOR_DIM, false), sums, FT_TOP_FIELD_COUNT);
}

/* The selection over a finished row: a dim bar, so the row is seen to fade while it stays. */
static void fade_row(struct ft_top_draw *d, struct ft_rect row)
{
    struct ft_style s = {.fg = FT_COLOR_BG, .bg = FT_COLOR_DIM};
    if (d->depth == FT_DEPTH_NONE)
        s.attrs = FT_ATTR_REVERSE;
    ft_canvas_restyle(d->canvas, row, s);
}

static void draw_row(struct ft_top_draw *d, enum ft_top_mode mode, const struct columns *cols,
                     struct ft_rect row, size_t index, const struct ft_top_row *r)
{
    struct row_draw rd = {
        .d = d,
        .y = row.y,
        .done = r->flags & FT_TOP_ROW_DONE,
        .selected = (r->flags & FT_TOP_ROW_SELECTED) && !d->ui->no_selection,
        .tagged = r->flags & FT_TOP_ROW_TAGGED,
        .first_cell = true,
    };
    bool tree = mode == FT_TOP_PROCESSES && ft_top_tree_of(d->model);
    int toggle = -1;

    ft_top_hits_add(d->hits, row, FT_TOP_TARGET_ROW, (uint32_t)index);
    switch (r->kind) {
    case FT_TOP_ROW_SECTION:
        section_cells(&rd, row, r->section, r->node);
        toggle = row.x;
        break;
    case FT_TOP_ROW_TRANSFER:
        if (mode == FT_TOP_TRANSFERS)
            transfer_cells(&rd, cols, r->transfer);
        else
            tree_transfer_cells(&rd, cols, r);
        break;
    case FT_TOP_ROW_PROCESS:
        process_cells(&rd, cols, r, tree, &toggle);
        break;
    case FT_TOP_ROW_FOLD:
        fold_cells(&rd, cols, r, &toggle);
        break;
    case FT_TOP_ROW_DESTINATION:
        destination_cells(&rd, cols, r->destination);
        break;
    case FT_TOP_ROW_FILE:
        file_cells(&rd, cols, r->file);
        break;
    default:
        break;
    }

    if (rd.selected) {
        if (rd.tagged)
            ft_canvas_text(d->canvas, row.x + row.w - 1, row.y, 1, ft_top_fg(FT_COLOR_BG, true),
                           "•");
        if (rd.done)
            fade_row(d, row);
        else
            ft_top_select_row(d, row);
    }
    for (size_t i = 0; i < rd.npieces; i++) {
        const struct piece *p = &rd.pieces[i];
        ft_top_mark_matches(d, p->x, row.y, p->width, p->text, p->cut, p->field, rd.selected);
    }
    if (toggle >= 0)
        ft_top_hits_add(d->hits, (struct ft_rect){toggle, row.y, 2, 1}, FT_TOP_TARGET_TOGGLE,
                        (uint32_t)index);
}

static void header_label(const struct ft_top_draw *d, const struct column *c, bool sorted,
                         bool descending, char *buf, size_t size)
{
    const char *arrow = descending ? "▼" : "▲";
    bool tree = c->spec->id == COL_COMMAND && ft_top_tree_of(d->model);
    const char *label = tree ? "COMMAND / FILE → DESTINATION" : c->spec->label;
    int room = c->width - 1;
    int cols = ft_text_columns(label);

    if (!sorted) {
        ft_strlcpy(buf, label, size);
        return;
    }
    if (d->depth == FT_DEPTH_NONE && cols + 3 <= room)
        snprintf(buf, size, "[%s%s]", label, arrow);
    else if (cols + 2 <= room)
        snprintf(buf, size, "%s %s", label, arrow);
    else if (cols + 1 <= room)
        snprintf(buf, size, "%s%s", label, arrow);
    else
        snprintf(buf, size, "%.*s%s", (int)prefix_bytes(label, room - 1), label, arrow);
}

static void draw_header(struct ft_top_draw *d, enum ft_top_mode mode, const struct columns *cols,
                        struct ft_rect header)
{
    enum ft_top_sort key;
    bool descending;
    char label[64];

    ft_top_sort_of(d->model, mode, &key, &descending);
    ft_top_bar_row(d, header, FT_COLOR_GREEN);
    for (size_t i = 0; i < cols->count; i++) {
        const struct column *c = &cols->list[i];
        struct ft_rect r = {c->x, header.y, c->width, 1};
        bool sorted = key != FT_TOP_SORT_DEFAULT && (c->spec->sort == key || c->spec->also == key);
        enum ft_color bar = sorted ? FT_COLOR_CYAN : FT_COLOR_GREEN;
        if (sorted)
            ft_top_bar_row(d, r, FT_COLOR_CYAN);
        header_label(d, c, sorted, descending, label, sizeof(label));
        ft_top_cell(d, r.x, r.y, c->width, c->spec->right, ft_top_on(bar, true), label);
        if (c->spec->sort != FT_TOP_SORT_DEFAULT)
            ft_top_hits_add(d->hits, r, FT_TOP_TARGET_HEADER, c->spec->sort);
    }
}

static void draw_empty(struct ft_top_draw *d, enum ft_top_mode mode, struct ft_rect rows)
{
    static const char *const nouns[] = {
        [FT_TOP_TRANSFERS] = "active transfers",
        [FT_TOP_PROCESSES] = "sending processes",
        [FT_TOP_DESTINATIONS] = "destinations",
        [FT_TOP_FILES] = "files in flight",
    };
    static const char *const nothing[] = {
        [FT_TOP_TRANSFERS] = "No file transfers in progress.",
        [FT_TOP_PROCESSES] = "No processes are sending files.",
        [FT_TOP_DESTINATIONS] = "No destinations are receiving files.",
        [FT_TOP_FILES] = "No files are being sent.",
    };
    const char *filter = ft_top_filter_of(d->model, mode);
    const char *search = ft_top_search_of(d->model, mode);
    char text[640];

    if (d->ui->starting)
        return;
    if (filter && filter[0])
        snprintf(text, sizeof(text), "No %s match the filter. Esc clears it.", nouns[mode]);
    else if (search && search[0])
        snprintf(text, sizeof(text), "No %s match \"%s\". Esc clears the search.", nouns[mode],
                 search);
    else
        ft_strlcpy(text, nothing[mode], sizeof(text));
    ft_canvas_text_cut(d->canvas, rows.x + 1, rows.y, rows.w - 1, ft_top_fg(FT_COLOR_DIM, false),
                       text, FT_CUT_END);

    /* A screen that collects by itself starts empty: say that it is watching, and since when. */
    bool unfiltered = !(filter && filter[0]) && !(search && search[0]);
    if (d->ui->session_only && d->ui->since_wall_ns && unfiltered && rows.h > 1) {
        char since[32];
        ft_top_since_text(d->ui->since_wall_ns, ft_top_totals(d->model)->now_wall_ns, true, since,
                          sizeof(since));
        snprintf(text, sizeof(text), "Watching since %s: what is sent from now on shows here.",
                 since);
        ft_canvas_text_cut(d->canvas, rows.x + 1, rows.y + 1, rows.w - 1,
                           ft_top_fg(FT_COLOR_DIM, false), text, FT_CUT_END);
    }
}

void ft_top_draw_table(struct ft_top_draw *d, enum ft_top_mode mode, struct ft_rect header,
                       struct ft_rect rows, size_t first)
{
    struct columns cols;

    if (mode >= FT_TOP_LEADERS)
        return;
    /* The header, when there is one, sits directly above the rows and as wide. */
    struct ft_rect area = rows;
    if (header.h > 0)
        area = (struct ft_rect){header.x, header.y, header.w, header.h + rows.h};
    if (area.w <= 0 || area.h <= 0)
        return;
    struct ft_rect previous = ft_canvas_clip(d->canvas, area);

    fit_columns(table_of(d, mode), d, area.w, &cols);
    for (size_t i = 0; i < cols.count; i++)
        cols.list[i].x += area.x;
    if (header.h > 0)
        draw_header(d, mode, &cols, header);

    size_t count = ft_top_row_count(d->model, mode);
    if (count == 0 && rows.h > 0)
        draw_empty(d, mode, rows);
    for (int y = 0; y < rows.h && first + (size_t)y < count; y++) {
        size_t index = first + (size_t)y;
        const struct ft_top_row *r = ft_top_row_at(d->model, mode, index);
        if (r)
            draw_row(d, mode, &cols, (struct ft_rect){rows.x, rows.y + y, rows.w, 1}, index, r);
    }
    ft_canvas_clip(d->canvas, previous);
}
