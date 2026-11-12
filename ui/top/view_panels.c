#include "filetrace/format.h"
#include "ui/top/views.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

/* A run of text in one style; a line is drawn from several. */
struct seg {
    const char *text;
    struct ft_style style;
};

static struct ft_style dim(void)
{
    return ft_top_fg(FT_COLOR_DIM, false);
}

static struct ft_style plain(enum ft_color fg)
{
    return ft_top_fg(fg, false);
}

/* Draws the runs one after another, cutting the one that reaches the width with "…". */
static int draw_segs(struct ft_canvas *c, int x, int y, int width, const struct seg *segs, size_t n)
{
    int used = 0;
    for (size_t i = 0; i < n && used < width; i++)
        used += ft_canvas_text_cut(c, x + used, y, width - used, segs[i].style, segs[i].text,
                                   FT_CUT_END);
    return used;
}

/* A label in a column of its own and the runs after it. */
static void label_line(struct ft_top_draw *d, int x, int y, int width, int label_width,
                       const char *label, const struct seg *segs, size_t n)
{
    if (width <= 0)
        return;
    ft_canvas_text_cut(d->canvas, x, y, label_width < width ? label_width : width, dim(), label,
                       FT_CUT_END);
    if (width > label_width)
        draw_segs(d->canvas, x + label_width, y, width - label_width, segs, n);
}

/* Key hints, "f follow  c copy path": whole items only, each one clickable. */
static void hint_line(struct ft_top_draw *d, int x, int y, int width, const char *const *pairs,
                      size_t npairs)
{
    int used = 0;
    for (size_t i = 0; i + 1 < npairs * 2; i += 2) {
        const char *key = pairs[i];
        const char *word = pairs[i + 1];
        int need = (used ? 2 : 0) + ft_text_columns(key) + 1 + ft_text_columns(word);
        if (used + need > width)
            break;
        if (used)
            used += 2;
        int start = x + used;
        used += ft_canvas_text(d->canvas, x + used, y, width - used, plain(FT_COLOR_BRIGHT), key);
        used += ft_canvas_text(d->canvas, x + used, y, width - used, dim(), " ");
        used += ft_canvas_text(d->canvas, x + used, y, width - used, dim(), word);
        struct ft_rect area = {start, y, x + used - start, 1};
        if (strcmp(key, "Enter") == 0)
            ft_top_hits_add_key(d->hits, area, FT_KEY_ENTER, 0);
        else if (strcmp(key, "Esc") == 0)
            ft_top_hits_add_key(d->hits, area, FT_KEY_ESC, 0);
        else if (key[0] && !key[1])
            ft_top_hits_add_key(d->hits, area, FT_KEY_CHAR, (uint32_t)(unsigned char)key[0]);
    }
}

/* A text cut in its middle so that its end, from the last ':', stays: "s3.eu-ce…:443". */
static void middle_cut(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                       const char *text)
{
    const char *colon = strrchr(text, ':');
    int cols = ft_text_columns(text);

    if (cols <= width || !colon || ft_text_columns(colon) + 2 > width) {
        ft_canvas_text_cut(c, x, y, width, s, text, FT_CUT_END);
        return;
    }
    char head[256];
    size_t n = (size_t)(colon - text) < sizeof(head) ? (size_t)(colon - text) : sizeof(head) - 1;
    memcpy(head, text, n);
    head[n] = '\0';
    int tail = ft_text_columns(colon);
    int used = ft_canvas_text_cut(c, x, y, width - tail, s, head, FT_CUT_END);
    ft_canvas_text(c, x + used, y, width - used, s, colon);
}

static void count_words(uint64_t n, const char *one, const char *many, char *buf, size_t size)
{
    char digits[32];
    ft_format_count(n, digits, sizeof(digits));
    snprintf(buf, size, "%s %s", digits, n == 1 ? one : many);
}

const enum ft_top_group *ft_top_mode_groups(enum ft_top_mode mode, size_t *count)
{
    static const enum ft_top_group transfers[] = {
        FT_TOP_GROUP_NONE,        FT_TOP_GROUP_PROCESS,   FT_TOP_GROUP_SCRIPT,
        FT_TOP_GROUP_DESTINATION, FT_TOP_GROUP_DIRECTORY, FT_TOP_GROUP_SUBNET,
    };
    static const enum ft_top_group processes[] = {FT_TOP_GROUP_NONE, FT_TOP_GROUP_SCRIPT};
    static const enum ft_top_group destinations[] = {FT_TOP_GROUP_NONE, FT_TOP_GROUP_SUBNET,
                                                     FT_TOP_GROUP_PROCESS};
    static const enum ft_top_group files[] = {FT_TOP_GROUP_NONE, FT_TOP_GROUP_DIRECTORY,
                                              FT_TOP_GROUP_PROCESS};
    static const enum ft_top_group none[] = {FT_TOP_GROUP_NONE};

    switch (mode) {
    case FT_TOP_TRANSFERS:
        *count = FT_ARRAY_LEN(transfers);
        return transfers;
    case FT_TOP_PROCESSES:
        *count = FT_ARRAY_LEN(processes);
        return processes;
    case FT_TOP_DESTINATIONS:
        *count = FT_ARRAY_LEN(destinations);
        return destinations;
    case FT_TOP_FILES:
        *count = FT_ARRAY_LEN(files);
        return files;
    default:
        *count = FT_ARRAY_LEN(none);
        return none;
    }
}

static const char *group_label(enum ft_top_group group)
{
    static const char *const labels[FT_TOP_GROUP_COUNT] = {
        [FT_TOP_GROUP_NONE] = "none",           [FT_TOP_GROUP_PROCESS] = "process",
        [FT_TOP_GROUP_SCRIPT] = "script",       [FT_TOP_GROUP_DESTINATION] = "destination",
        [FT_TOP_GROUP_DIRECTORY] = "directory", [FT_TOP_GROUP_SUBNET] = "/24 subnet",
    };
    return group < FT_TOP_GROUP_COUNT ? labels[group] : "";
}

static void panel_item(struct ft_top_draw *d, int x, int y, int width, const char *label,
                       bool current, bool cursor, enum ft_top_target target, size_t index)
{
    struct ft_style s = cursor    ? ft_top_on(FT_COLOR_CYAN, true)
                        : current ? ft_top_fg(FT_COLOR_BRIGHT, true)
                                  : plain(FT_COLOR_TEXT);
    char text[64];

    if (cursor)
        ft_top_bar_row(d, (struct ft_rect){x, y, width, 1}, FT_COLOR_CYAN);
    snprintf(text, sizeof(text), "%s%s", current ? "▶ " : "  ", label);
    ft_canvas_text_cut(d->canvas, x + 1, y, width - 1, s, text, FT_CUT_END);
    ft_top_hits_add(d->hits, (struct ft_rect){x, y, width, 1}, target, (uint32_t)index);
}

void ft_top_draw_panel(struct ft_top_draw *d, struct ft_rect r)
{
    enum ft_top_mode mode = d->ui->mode;
    size_t nsorts;
    size_t ngroups;
    const struct ft_top_sort_option *sorts = ft_top_mode_sorts(mode, &nsorts);
    const enum ft_top_group *groups = ft_top_mode_groups(mode, &ngroups);
    enum ft_top_sort key;
    bool descending;
    enum ft_top_group group = ft_top_group_of(d->model, mode);
    int width = r.w - 1;
    int bottom = r.y + r.h;

    if (r.w < 2 || r.h <= 0)
        return;
    struct ft_rect clip = ft_canvas_clip(d->canvas, r);
    ft_top_sort_of(d->model, mode, &key, &descending);
    ft_canvas_fill(d->canvas, (struct ft_rect){r.x + r.w - 1, r.y, 1, r.h}, U'│',
                   plain(FT_COLOR_RULE));

    /* Rows the panel can do without, given up in this order when it is short. */
    int lists = 1 + (int)nsorts + 2 + 1 + (int)ngroups;
    bool hints = lists + 2 + 2 <= r.h;
    bool gaps = lists + 2 <= r.h;

    int y = r.y;
    ft_top_title_row(d, (struct ft_rect){r.x, y++, width, 1}, FT_COLOR_GREEN, "Sort by", nullptr);
    for (size_t i = 0; i < nsorts && y < bottom; i++, y++)
        panel_item(d, r.x, y, width, sorts[i].label, sorts[i].key == key,
                   d->ui->panel == FT_TOP_PANEL_SORT && d->ui->panel_cursor == i,
                   FT_TOP_TARGET_SORT, i);
    y += gaps;
    const struct seg order[] = {
        {"order  ", dim()},
        {descending ? "▼ desc" : "▲ asc", plain(FT_COLOR_BRIGHT)},
    };
    draw_segs(d->canvas, r.x + 1, y++, width - 1, order, FT_ARRAY_LEN(order));
    const struct seg invert[] = {{"I", plain(FT_COLOR_BRIGHT)}, {" invert", dim()}};
    draw_segs(d->canvas, r.x + 1, y, width - 1, invert, FT_ARRAY_LEN(invert));
    ft_top_hits_add_key(d->hits, (struct ft_rect){r.x, y++, width, 1}, FT_KEY_CHAR, 'I');
    y += gaps;
    if (y < bottom)
        ft_top_title_row(d, (struct ft_rect){r.x, y++, width, 1}, FT_COLOR_GREEN, "Group by (F7)",
                         nullptr);
    for (size_t i = 0; i < ngroups && y < bottom; i++, y++)
        panel_item(d, r.x, y, width, group_label(groups[i]), groups[i] == group,
                   d->ui->panel == FT_TOP_PANEL_GROUP && d->ui->panel_cursor == i,
                   FT_TOP_TARGET_GROUP, i);

    if (hints) {
        static const char *const move[] = {"↑↓", "move", "Enter", "apply"};
        static const char *const cancel[] = {"Esc", "cancel"};
        hint_line(d, r.x + 1, bottom - 2, width - 1, move, 2);
        hint_line(d, r.x + 1, bottom - 1, width - 1, cancel, 1);
        ft_canvas_restyle(d->canvas, (struct ft_rect){r.x + 1, bottom - 2, width - 1, 2}, dim());
    }
    ft_canvas_clip(d->canvas, clip);
}

struct inspect {
    struct ft_top_draw *d;
    struct ft_rect r;
    int lx; /* the left half */
    int lw;
    int rx; /* the right half */
    int rw;
};

static int line_y(const struct inspect *in, int row)
{
    return in->r.y + row;
}

/*
 * A title bar: prefix, middle and suffix on the left, the middle cut from its start when the
 * whole does not fit, and right at the right end.
 */
static void title_bar(struct ft_top_draw *d, struct ft_rect r, const char *prefix,
                      const char *middle, const char *suffix, const char *right)
{
    struct ft_style s = ft_top_on(FT_COLOR_CYAN, true);
    int right_cols = right ? ft_text_columns(right) : 0;
    int avail = r.w - 2 - (right_cols ? right_cols + 2 : 0);

    ft_top_bar_row(d, r, FT_COLOR_CYAN);
    if (right_cols)
        ft_canvas_text(d->canvas, r.x + r.w - 1 - right_cols, r.y, right_cols, s, right);
    if (avail <= 0)
        return;
    int x = r.x + 1;
    int fixed = ft_text_columns(prefix) + ft_text_columns(suffix);
    int whole = fixed + ft_text_columns(middle);
    if (whole <= avail || fixed + 2 > avail) {
        char text[1024];
        snprintf(text, sizeof(text), "%s%s%s", prefix, middle, suffix);
        ft_canvas_text_cut(d->canvas, x, r.y, avail, s, text, FT_CUT_END);
        return;
    }
    x += ft_canvas_text(d->canvas, x, r.y, avail, s, prefix);
    x += ft_canvas_text_cut(d->canvas, x, r.y, avail - fixed, s, middle, FT_CUT_START);
    ft_canvas_text(d->canvas, x, r.y, r.x + 1 + avail - x, s, suffix);
}

static void close_hit(struct ft_top_draw *d, struct ft_rect r)
{
    constexpr int CLOSE = 9; /* "Esc close" */
    ft_top_hits_add(d->hits, (struct ft_rect){r.x + r.w - 1 - CLOSE, r.y, CLOSE, 1},
                    FT_TOP_TARGET_CLOSE, 0);
}

static void inspect_frame(struct inspect *in, const char *prefix, const char *middle,
                          const char *suffix)
{
    struct ft_top_draw *d = in->d;
    struct ft_rect r = in->r;
    struct ft_style edge = plain(FT_COLOR_CYAN);

    ft_canvas_box(d->canvas, r, edge);
    title_bar(d, (struct ft_rect){r.x, r.y, r.w, 1}, prefix, middle, suffix, "Esc close");
    close_hit(d, r);
}

static const char *method_explanation(uint8_t method)
{
    switch (method) {
    case FT_METHOD_SENDFILE:
        return "sendfile(file → socket)";
    case FT_METHOD_READ_SEND:
        return "read(file) → write(socket)";
    case FT_METHOD_SPLICE:
        return "splice(file → pipe → socket)";
    case FT_METHOD_MMAP:
        return "mmap(file) → write(socket)";
    case FT_METHOD_IO_URING:
        return "io_uring(file → socket)";
    default:
        return "";
    }
}

static void method_words(uint8_t method, uint8_t confidence, char *buf, size_t size)
{
    snprintf(buf, size, "%s · %s", ft_top_method_word(method),
             ft_top_confidence_word(confidence, false));
}

/* The address a transfer goes to as the screen names it: the host name when one is known. */
static void destination_text(const struct ft_top_transfer *t, char *buf, size_t size)
{
    const struct ft_top_destination *dest = t->destination;
    if (dest && dest->host_state == FT_TOP_HOST_NAMED && dest->host)
        snprintf(buf, size, "%s:%u", dest->host, t->remote.port);
    else
        ft_strlcpy(buf, t->remote_text, size);
}

static void percent_cell(struct ft_top_draw *d, int x, int y, int width, double progress)
{
    char text[16];
    if (progress < 0 || width <= 0)
        return;
    ft_top_format_percent(progress, text, sizeof(text));
    ft_canvas_text_right(d->canvas, x, y, width, plain(FT_COLOR_GREEN), text);
}

/* A transfer's rate, right-aligned; "done" once it has finished. */
static void rate_cell(struct ft_top_draw *d, int x, int y, int width,
                      const struct ft_top_transfer *t)
{
    char text[24];
    if (t->done) {
        ft_canvas_text_right(d->canvas, x, y, width, dim(), "done");
        return;
    }
    ft_top_format_rate(t->rate, text, sizeof(text));
    ft_canvas_text_right(d->canvas, x, y, width, plain(FT_COLOR_BRIGHT), text);
}

static void more_line(struct ft_top_draw *d, int x, int y, int width, size_t more)
{
    char text[48];
    snprintf(text, sizeof(text), "… and %zu more", more);
    ft_canvas_text_cut(d->canvas, x, y, width, dim(), text, FT_CUT_END);
}

/* Whether the Processes mode lists the process, so that its rollup is current. */
static bool process_listed(const struct ft_top_model *m, const struct ft_top_process *p)
{
    size_t n = ft_top_row_count(m, FT_TOP_PROCESSES);
    for (size_t i = 0; i < n; i++) {
        const struct ft_top_row *row = ft_top_row_at(m, FT_TOP_PROCESSES, i);
        if (row->kind == FT_TOP_ROW_PROCESS && row->process == p)
            return true;
    }
    return false;
}

static void process_transfers(struct inspect *in, const struct ft_top_transfer *const *list,
                              size_t n)
{
    struct ft_top_draw *d = in->d;
    int x = in->rx;
    int dest_w = 22;
    int file_w = in->rw - 8 - dest_w - 14;
    if (file_w < 16) {
        dest_w = 18;
        file_w = in->rw - 8 - dest_w - 14;
    }
    file_w = file_w > 29 ? 29 : file_w;
    int dest_x = x + 8 + file_w;
    int rate_x = dest_x + dest_w;
    int done_x = rate_x + 7;
    int y = line_y(in, 1);

    ft_canvas_text(d->canvas, x, y, in->rw, dim(), "ACTIVE");
    ft_canvas_text(d->canvas, x + 8, y, file_w, dim(), "FILE");
    ft_canvas_text(d->canvas, dest_x, y, dest_w, dim(), "DESTINATION");
    ft_canvas_text_right(d->canvas, rate_x, y, 7, dim(), "RATE");
    ft_canvas_text_right(d->canvas, done_x, y, 7, dim(), "DONE");
    if (n == 0) {
        ft_canvas_text(d->canvas, x + 8, line_y(in, 2), in->rw - 8, dim(), "no active transfers");
        return;
    }
    size_t shown = n > 3 ? 2 : n;
    for (size_t i = 0; i < shown; i++) {
        const struct ft_top_transfer *t = list[i];
        char text[160];
        y = line_y(in, 2 + (int)i);
        snprintf(text, sizeof(text), "%zu", i + 1);
        ft_canvas_text_right(d->canvas, x, y, 3, dim(), text);
        ft_canvas_text_cut(d->canvas, x + 8, y, file_w - 1, plain(FT_COLOR_BRIGHT),
                           t->path + t->name_offset, FT_CUT_START);
        destination_text(t, text, sizeof(text));
        middle_cut(d->canvas, dest_x, y, dest_w - 1, plain(ft_top_egress_color(t->is_public)),
                   text);
        rate_cell(d, rate_x, y, 7, t);
        percent_cell(d, done_x, y, 7, t->progress);
    }
    if (n > 3)
        more_line(d, x + 8, line_y(in, 4), in->rw - 8, n - 2);
}

static void inspect_process(struct inspect *in, const struct ft_top_process *p,
                            const struct ft_top_transfer *from)
{
    struct ft_top_draw *d = in->d;
    char pid[16];
    char title[256];
    char text[256];
    int lx = in->lx;
    int lw = in->lw;

    snprintf(pid, sizeof(pid), "%" PRIu32, p->pid);
    snprintf(title, sizeof(title), "%s%s", p->title[0] ? " " : "", p->title);
    char prefix[48];
    snprintf(prefix, sizeof(prefix), "F8 Inspect · process %s", pid);
    inspect_frame(in, prefix, title, "");

    bool listed = d->ui->mode == FT_TOP_PROCESSES || process_listed(d->model, p);
    const char *exe = p->exe && p->exe[0] ? p->exe : p->comm;
    const struct seg exe_segs[] = {{exe && exe[0] ? exe : "—", plain(FT_COLOR_TEXT)}};
    label_line(d, lx, line_y(in, 1), lw, 9, "exe", exe_segs, 1);

    char ppid[16];
    snprintf(ppid, sizeof(ppid), "%" PRIu32, p->ppid);
    const struct seg user_segs[] = {
        {p->user[0] ? p->user : "—", plain(p->user[0] ? FT_COLOR_TEXT : FT_COLOR_DIM)},
        {"   ppid ", dim()},
        {p->ppid ? ppid : "—", plain(p->ppid ? FT_COLOR_TEXT : FT_COLOR_DIM)},
        {"   cwd ", dim()},
        {p->cwd && p->cwd[0] ? p->cwd : "—", plain(FT_COLOR_TEXT)},
    };
    label_line(d, lx, line_y(in, 2), lw, 9, "user", user_segs, FT_ARRAY_LEN(user_segs));

    /* A transfer's own script differs from its process's only for a PHP request. */
    const struct ft_top_transfer *top = from                      ? from
                                        : listed && p->ntransfers ? p->transfers[0]
                                                                  : nullptr;
    const char *script = top && top->script[0] ? top->script : p->script;
    const char *note = strcmp(script, p->script) != 0 ? "  (PHP-FPM request)" : "";
    const struct seg script_segs[] = {
        {script[0] ? script : "—", script[0] ? ft_top_fg(FT_COLOR_AMBER, true) : dim()},
        {note, dim()},
    };
    label_line(d, lx, line_y(in, 3), lw, 9, "script", script_segs, FT_ARRAY_LEN(script_segs));

    uint8_t method = listed ? p->method : from ? from->method : FT_METHOD_NONE;
    uint8_t confidence = listed ? p->confidence : from ? from->confidence : FT_CONF_UNKNOWN;
    method_words(method, confidence, text, sizeof(text));
    char explain[64];
    snprintf(explain, sizeof(explain), "  %s", method_explanation(method));
    const struct seg method_segs[] = {
        {text, plain(ft_top_method_color(method))},
        {explain, dim()},
    };
    label_line(d, lx, line_y(in, 4), lw, 9, "method", method_segs,
               method == FT_METHOD_NONE ? 0 : FT_ARRAY_LEN(method_segs));

    char total[24];
    char files[24];
    char transfers[24];
    size_t ntransfers = listed ? p->ntransfers : 0;
    ft_top_format_size(p->total, total, sizeof(total));
    ft_format_count(listed ? p->files : 0, files, sizeof(files));
    ft_format_count(ntransfers, transfers, sizeof(transfers));
    const struct seg total_segs[] = {
        {total, plain(FT_COLOR_BRIGHT)},
        {" since the agent started · ", plain(FT_COLOR_TEXT)},
        {files, plain(FT_COLOR_BRIGHT)},
        {listed && p->files == 1 ? " file in " : " files in ", plain(FT_COLOR_TEXT)},
        {transfers, plain(FT_COLOR_BRIGHT)},
        {ntransfers == 1 ? " transfer now" : " transfers now", plain(FT_COLOR_TEXT)},
    };
    const struct seg total_only[] = {
        {total, plain(FT_COLOR_BRIGHT)},
        {" since the agent started", plain(FT_COLOR_TEXT)},
    };
    if (listed)
        label_line(d, lx, line_y(in, 5), lw, 9, "total", total_segs, FT_ARRAY_LEN(total_segs));
    else
        label_line(d, lx, line_y(in, 5), lw, 9, "total", total_only, FT_ARRAY_LEN(total_only));

    if (listed)
        process_transfers(in, p->transfers, p->ntransfers);
    else
        process_transfers(in, from ? &from : nullptr, from ? 1 : 0);
    static const char *const keys[] = {"f", "follow",          "c", "copy path", "e", "events",
                                       "o", "open in Leaders", "j", "JSON"};
    hint_line(d, in->rx, line_y(in, 5), in->rw, keys, FT_ARRAY_LEN(keys) / 2);
}

static void subnet_text(const struct ft_endpoint *address, char *buf, size_t size)
{
    struct ft_endpoint net = *address;
    unsigned bits = net.family == 6 ? 64 : 24;
    char text[64];

    memset(net.addr + bits / 8, 0, sizeof(net.addr) - bits / 8);
    net.port = 0;
    ft_addr_format(&net, text, sizeof(text));
    snprintf(buf, size, "%s/%u", text, bits);
}

static void inspect_destination(struct inspect *in, const struct ft_top_destination *dest)
{
    struct ft_top_draw *d = in->d;
    char suffix[160];
    char seen[24] = "";
    const char *host = dest->host_state == FT_TOP_HOST_NAMED && dest->host ? dest->host
                       : dest->host_state == FT_TOP_HOST_NAMELESS          ? "no PTR"
                                                                           : "";
    if (dest->first_seen_wall_ns)
        ft_format_clock_local(dest->first_seen_wall_ns, seen, sizeof(seen));
    snprintf(suffix, sizeof(suffix), " · %s%s%s%s%s", dest->is_public ? "public" : "private",
             host[0] ? " · " : "", host, seen[0] ? " · first seen " : "", seen);
    inspect_frame(in, "F8 Inspect · destination ", dest->label, suffix);

    int x = in->lx;
    int file_w = in->lw - 35 > 37 ? 37 : in->lw - 35;
    int proc_x = x + file_w;
    int rate_x = proc_x + 21;
    int done_x = rate_x + 8;
    int y = line_y(in, 1);
    ft_canvas_text(d->canvas, x, y, file_w, dim(), "FILE");
    ft_canvas_text(d->canvas, proc_x, y, 21, dim(), "PROCESS");
    ft_canvas_text_right(d->canvas, rate_x, y, 8, dim(), "RATE");
    ft_canvas_text_right(d->canvas, done_x, y, 6, dim(), "DONE");
    size_t shown = dest->ntransfers > 3 ? 2 : dest->ntransfers;
    for (size_t i = 0; i < shown; i++) {
        const struct ft_top_transfer *t = dest->transfers[i];
        y = line_y(in, 2 + (int)i);
        ft_top_path_cell(d, x, y, file_w, t->path, t->name_offset, plain(FT_COLOR_BRIGHT));
        ft_top_cell(d, proc_x, y, 21, false, plain(FT_COLOR_TEXT), t->process->title);
        rate_cell(d, rate_x, y, 8, t);
        percent_cell(d, done_x, y, 6, t->progress);
    }
    if (dest->ntransfers > 3)
        more_line(d, x, line_y(in, 4), file_w, dest->ntransfers - 2);

    char count[24];
    char ports[96] = "";
    size_t len = 0;
    unsigned listed = 0;
    for (size_t i = 0; i < dest->ntransfers && listed < 3 && len < sizeof(ports); i++) {
        uint16_t port = dest->transfers[i]->remote.port;
        bool seen_port = false;
        for (size_t k = 0; k < i && !seen_port; k++)
            seen_port = dest->transfers[k]->remote.port == port;
        if (seen_port)
            continue;
        int w = snprintf(ports + len, sizeof(ports) - len, "%s%u", listed ? ", " : "", port);
        len += w > 0 ? (size_t)w : 0;
        listed++;
    }
    if (dest->ports > listed && len < sizeof(ports))
        snprintf(ports + len, sizeof(ports) - len, " +%" PRIu32, dest->ports - listed);
    char method[64];
    ft_format_count(dest->ntransfers, count, sizeof(count));
    method_words(dest->method, dest->confidence, method, sizeof(method));
    const struct seg info[] = {
        {"transfers ", dim()},
        {count, plain(FT_COLOR_TEXT)},
        {" · ", plain(FT_COLOR_TEXT)},
        {dest->ports == 1 ? "port " : "ports ", dim()},
        {ports, plain(FT_COLOR_TEXT)},
        {" · ", plain(FT_COLOR_TEXT)},
        {"method ", dim()},
        {method, plain(ft_top_method_color(dest->method))},
    };
    draw_segs(d->canvas, x, line_y(in, 5), in->lw, info, FT_ARRAY_LEN(info));

    constexpr int LABEL = 11;
    char total[24];
    ft_top_format_size(dest->total, total, sizeof(total));
    const struct seg total_segs[] = {
        {total, plain(FT_COLOR_BRIGHT)},
        {" since the agent started", plain(FT_COLOR_TEXT)},
    };
    label_line(d, in->rx, line_y(in, 1), in->rw, LABEL, "total", total_segs, 2);

    char subnet[96];
    char hosts[48];
    subnet_text(&dest->address, subnet, sizeof(subnet));
    ft_format_count(dest->subnet_destinations, count, sizeof(count));
    snprintf(hosts, sizeof(hosts), " active %s", dest->subnet_destinations == 1 ? "host" : "hosts");
    const struct seg subnet_segs[] = {
        {subnet, plain(FT_COLOR_TEXT)},
        {" · ", plain(FT_COLOR_TEXT)},
        {count, plain(FT_COLOR_BRIGHT)},
        {hosts, plain(FT_COLOR_TEXT)},
    };
    label_line(d, in->rx, line_y(in, 2), in->rw, LABEL, "subnet", subnet_segs,
               dest->address.family ? FT_ARRAY_LEN(subnet_segs) : 0);

    const struct ft_top_process *p = dest->top_process;
    if (p) {
        char user[96];
        if (p->uid_known && p->user[0] && strspn(p->user, "0123456789") != strlen(p->user))
            snprintf(user, sizeof(user), "%s (uid %" PRIu32 ")", p->user, p->uid);
        else if (p->uid_known)
            snprintf(user, sizeof(user), "uid %" PRIu32, p->uid);
        else
            ft_strlcpy(user, "—", sizeof(user));
        const struct seg user_segs[] = {
            {user, plain(FT_COLOR_TEXT)},
            {" · cwd ", plain(FT_COLOR_TEXT)},
            {p->cwd && p->cwd[0] ? p->cwd : "—", plain(FT_COLOR_TEXT)},
        };
        label_line(d, in->rx, line_y(in, 3), in->rw, LABEL, "user", user_segs,
                   FT_ARRAY_LEN(user_segs));
    }
    static const char *const keys[] = {
        "f", "follow", "o", "open in Leaders", "e", "events", "c", "copy", "j", "JSON"};
    hint_line(d, in->rx, line_y(in, 5), in->rw, keys, FT_ARRAY_LEN(keys) / 2);
}

static void share_bar(struct ft_top_draw *d, int x, int y, int cells, double share, uint8_t method)
{
    double value = share > 0 && share < 1.0 / cells ? 1.0 / cells : share;
    struct ft_bar_part part = {.value = value, .style = plain(ft_top_method_color(method))};
    struct ft_bar bar = {
        .parts = &part,
        .count = 1,
        .total = 1.0,
        .empty_rune = U'░',
        .empty = plain(FT_COLOR_TRACK),
    };
    if (cells > 0)
        ft_canvas_bar(d->canvas, x, y, cells, &bar);
}

static const char *sender_name(const struct ft_top_process *p, int width)
{
    if (!p->title[0])
        return p->comm;
    return ft_text_columns(p->title) < width || !p->head[0] ? p->title : p->head;
}

static void inspect_file(struct inspect *in, const struct ft_top_file *f)
{
    struct ft_top_draw *d = in->d;
    char suffix[96] = "";
    char size[24];
    char active[48];

    count_words(f->active, "active transfer", "active transfers", active, sizeof(active));
    if (f->size) {
        ft_top_format_size(f->size, size, sizeof(size));
        snprintf(suffix, sizeof(suffix), " · %s · %s", size, active);
    } else {
        snprintf(suffix, sizeof(suffix), " · %s", active);
    }
    inspect_frame(in, "F8 Inspect · file ", f->path, suffix);

    int x = in->lx;
    int name_w = in->lw - 35 > 20 ? 20 : in->lw - 35;
    int pid_x = x + name_w;
    int xfers_x = pid_x + 6;
    int rate_x = xfers_x + 10;
    int share_x = rate_x + 12;
    int y = line_y(in, 1);
    ft_canvas_text(d->canvas, x, y, name_w, dim(), "SENDER");
    ft_canvas_text_right(d->canvas, pid_x, y, 6, dim(), "PID");
    ft_canvas_text_right(d->canvas, xfers_x, y, 10, dim(), "XFERS");
    ft_canvas_text_right(d->canvas, rate_x, y, 10, dim(), "RATE");
    ft_canvas_text(d->canvas, share_x, y, 8, dim(), "SHARE");
    size_t shown = f->nsenders > 4 ? 3 : f->nsenders;
    for (size_t i = 0; i < shown; i++) {
        const struct ft_top_sender *s = &f->by_sender[i];
        char text[32];
        y = line_y(in, 2 + (int)i);
        ft_top_cell(d, x, y, name_w, false, plain(FT_COLOR_BRIGHT),
                    sender_name(s->process, name_w - 1));
        snprintf(text, sizeof(text), "%" PRIu32, s->process->pid);
        ft_canvas_text_right(d->canvas, pid_x, y, 6, dim(), text);
        ft_format_count(s->transfers, text, sizeof(text));
        ft_canvas_text_right(d->canvas, xfers_x, y, 10, plain(FT_COLOR_TEXT), text);
        ft_top_format_rate(s->rate, text, sizeof(text));
        ft_canvas_text_right(d->canvas, rate_x, y, 10, plain(FT_COLOR_BRIGHT), text);
        share_bar(d, share_x, y, 8, f->rate ? (double)s->rate / (double)f->rate : 0, f->method);
    }
    if (f->nsenders > 4)
        more_line(d, x, line_y(in, 5), in->lw, f->nsenders - 3);

    int dest_w = in->rw - 14 > 27 ? 27 : in->rw - 14;
    int rrate_x = in->rx + dest_w;
    int rdone_x = rrate_x + 7;
    char header[48];
    snprintf(header, sizeof(header), "TOP DESTINATIONS (%" PRIu32 ")", f->destinations);
    y = line_y(in, 1);
    ft_canvas_text_cut(d->canvas, in->rx, y, dest_w - 1, dim(), header, FT_CUT_END);
    ft_canvas_text_right(d->canvas, rrate_x, y, 7, dim(), "RATE");
    ft_canvas_text_right(d->canvas, rdone_x, y, 7, dim(), "DONE");
    for (size_t i = 0; i < f->ntransfers && i < 3; i++) {
        const struct ft_top_transfer *t = f->transfers[i];
        char text[160];
        y = line_y(in, 2 + (int)i);
        destination_text(t, text, sizeof(text));
        middle_cut(d->canvas, in->rx, y, dest_w - 1, plain(ft_top_egress_color(t->is_public)),
                   text);
        rate_cell(d, rrate_x, y, 7, t);
        percent_cell(d, rdone_x, y, 7, t->progress);
    }
    static const char *const keys[] = {"d", "all destinations", "o", "open in Leaders",
                                       "c", "copy path",        "j", "JSON"};
    hint_line(d, in->rx, line_y(in, 5), in->rw, keys, FT_ARRAY_LEN(keys) / 2);
}

static const char *leader_noun(enum ft_leader_key key)
{
    switch (key) {
    case FT_LEADER_DIRECTORY:
        return "directory";
    case FT_LEADER_EXTENSION:
        return "extension";
    case FT_LEADER_DESTINATION:
        return "destination";
    default:
        return "file";
    }
}

static const char *comparison_word(enum ft_leader_window window)
{
    static const char *const words[FT_WINDOW_COUNT] = {
        [FT_WINDOW_LIFETIME] = "",         [FT_WINDOW_1M] = "previous minute",
        [FT_WINDOW_5M] = "previous 5 min", [FT_WINDOW_15M] = "previous 15 min",
        [FT_WINDOW_1H] = "previous hour",  [FT_WINDOW_24H] = "previous day",
        [FT_WINDOW_7D] = "previous week",
    };
    return window < FT_WINDOW_COUNT ? words[window] : "";
}

static void inspect_leader(struct inspect *in, const struct ft_top_leader *l)
{
    struct ft_top_draw *d = in->d;
    const struct ft_top_leaders *all = ft_top_leaders(d->model);
    const struct ft_row_leader *row = l->row;
    const char *window = ft_leader_window_name(all->window);
    bool file = all->key == FT_LEADER_FILE && !row->remote.family;
    char prefix[48];
    char suffix[128];
    char bytes[24];
    char size[24];

    snprintf(prefix, sizeof(prefix), "F8 Inspect · %s ", leader_noun(all->key));
    ft_top_format_size(row->bytes, bytes, sizeof(bytes));
    if (file && row->file_size && !(row->flags & FT_LEADER_DELETED)) {
        double copies = (double)row->bytes / (double)row->file_size;
        char count[32];
        ft_top_format_size(row->file_size, size, sizeof(size));
        if (copies < 10)
            snprintf(count, sizeof(count), "%.1f", copies);
        else
            ft_format_count((uint64_t)(copies + 0.5), count, sizeof(count));
        snprintf(suffix, sizeof(suffix), " · %s · ≈ %s copies in %s", size, count, window);
    } else {
        snprintf(suffix, sizeof(suffix), " · %s in %s", bytes, window);
    }
    const char *name =
        row->remote.family
            ? (l->host_state == FT_TOP_HOST_NAMED && l->host ? l->host : l->remote_text)
            : row->text;
    inspect_frame(in, prefix, name, suffix);

    int x = in->lx;
    int name_w = in->lw - 29 > 20 ? 20 : in->lw - 29;
    int xfers_x = x + name_w;
    int bytes_x = xfers_x + 10;
    int share_x = bytes_x + 12;
    int y = line_y(in, 1);
    ft_canvas_text(d->canvas, x, y, name_w, dim(), "SENDER");
    ft_canvas_text_right(d->canvas, xfers_x, y, 10, dim(), "XFERS");
    ft_canvas_text_right(d->canvas, bytes_x, y, 10, dim(), "BYTES");
    ft_canvas_text(d->canvas, share_x, y, 8, dim(), "SHARE");
    size_t listed = 0;
    for (; listed < FT_LEADER_SENDERS && row->senders[listed].name[0]; listed++) {
        const struct ft_leader_sender *s = &row->senders[listed];
        char text[32];
        y = line_y(in, 2 + (int)listed);
        ft_top_cell(d, x, y, name_w, false, plain(FT_COLOR_BRIGHT), s->name);
        ft_format_count(s->transfers, text, sizeof(text));
        ft_canvas_text_right(d->canvas, xfers_x, y, 10, plain(FT_COLOR_TEXT), text);
        ft_top_format_size(s->bytes, text, sizeof(text));
        ft_canvas_text_right(d->canvas, bytes_x, y, 10, plain(FT_COLOR_BRIGHT), text);
        share_bar(d, share_x, y, 8, row->bytes ? (double)s->bytes / (double)row->bytes : 0,
                  row->method);
    }
    if (row->flags & FT_LEADER_MORE_SENDERS)
        ft_canvas_text(d->canvas, x, line_y(in, 2 + (int)listed), in->lw, dim(),
                       "… and more senders");

    constexpr int LABEL = 11;
    char rank[96];
    const char *by = all->by == FT_TOP_SORT_TRANSFERS      ? "transfers"
                     : all->by == FT_TOP_SORT_DESTINATIONS ? "destinations"
                                                           : "bytes";
    char change[64] = "";
    if (all->summary.previous_from_wall_ns) {
        if (l->is_new)
            snprintf(change, sizeof(change), " · new since the %s", comparison_word(all->window));
        else if (l->rank_change)
            snprintf(change, sizeof(change), " · %s%" PRId32 " vs %s",
                     l->rank_change > 0 ? "▲" : "▼",
                     l->rank_change > 0 ? l->rank_change : -l->rank_change,
                     comparison_word(all->window));
        else
            snprintf(change, sizeof(change), " · same as the %s", comparison_word(all->window));
    }
    snprintf(rank, sizeof(rank), "#%" PRIu32 " by %s%s", row->rank, by, change);
    const struct seg rank_segs[] = {{rank, plain(FT_COLOR_TEXT)}};
    label_line(d, in->rx, line_y(in, 1), in->rw, LABEL, "rank", rank_segs, 1);

    char count[32];
    char what[96];
    char dests[48];
    count_words(row->destinations, "remote address", "remote addresses", dests, sizeof(dests));
    if (file) {
        snprintf(what, sizeof(what), "%s%s",
                 row->destinations > FT_LEADER_EXACT_DESTINATIONS ? "about " : "", dests);
        const struct seg seg_dests[] = {{what, plain(FT_COLOR_TEXT)}};
        label_line(d, in->rx, line_y(in, 2), in->rw, LABEL, "sent to", seg_dests, 1);
    } else {
        count_words(row->files, "file", "files", count, sizeof(count));
        snprintf(what, sizeof(what), "%s to %s", count, dests);
        const struct seg seg_files[] = {{what, plain(FT_COLOR_TEXT)}};
        label_line(d, in->rx, line_y(in, 2), in->rw, LABEL, "holds", seg_files, 1);
    }

    char method[64];
    method_words(row->method, row->confidence, method, sizeof(method));
    const struct seg method_segs[] = {{method, plain(ft_top_method_color(row->method))}};
    label_line(d, in->rx, line_y(in, 3), in->rw, LABEL, "method", method_segs, 1);

    char first[24];
    char last[24];
    char span[64];
    ft_format_clock_local(row->first_wall_ns, first, sizeof(first));
    ft_format_clock_local(row->last_wall_ns, last, sizeof(last));
    snprintf(span, sizeof(span), "%s – %s", first, last);
    const struct seg span_segs[] = {{span, plain(FT_COLOR_TEXT)}};
    label_line(d, in->rx, line_y(in, 4), in->rw, LABEL, "sent", span_segs, 1);

    static const char *const file_keys[] = {"f", "follow",    "d", "destinations", "e", "events",
                                            "c", "copy path", "j", "JSON"};
    static const char *const other_keys[] = {"f", "follow", "c", "copy", "j", "JSON"};
    if (file)
        hint_line(d, in->rx, line_y(in, 5), in->rw, file_keys, FT_ARRAY_LEN(file_keys) / 2);
    else
        hint_line(d, in->rx, line_y(in, 5), in->rw, other_keys, FT_ARRAY_LEN(other_keys) / 2);
}

static void inspect_section(struct inspect *in, const struct ft_top_section *s)
{
    static const char *const members[FT_TOP_MODE_COUNT][2] = {
        [FT_TOP_TRANSFERS] = {"transfer", "transfers"},
        [FT_TOP_PROCESSES] = {"process", "processes"},
        [FT_TOP_DESTINATIONS] = {"destination", "destinations"},
        [FT_TOP_FILES] = {"file", "files"},
        [FT_TOP_LEADERS] = {"row", "rows"},
    };
    struct ft_top_draw *d = in->d;
    char prefix[48];
    char rate[24];
    char text[64];

    if (s->title[0])
        snprintf(prefix, sizeof(prefix), "F8 Inspect · %s ", group_label(s->by));
    else
        snprintf(prefix, sizeof(prefix), "F8 Inspect · no %s", group_label(s->by));
    inspect_frame(in, prefix, s->title, "");
    ft_top_format_rate(s->rate, rate, sizeof(rate));
    const struct seg rate_segs[] = {{rate, ft_top_rate_style(s->rate)}};
    label_line(d, in->lx, line_y(in, 1), in->lw, 9, "rate", rate_segs, 1);
    count_words(s->rows, members[d->ui->mode][0], members[d->ui->mode][1], text, sizeof(text));
    const struct seg member_segs[] = {{text, plain(FT_COLOR_TEXT)}};
    label_line(d, in->lx, line_y(in, 2), in->lw, 9, "holds", member_segs, 1);
    const uint32_t counts[] = {s->processes, s->files, s->destinations};
    const char *const labels[] = {"procs", "files", "dests"};
    for (size_t i = 0; i < FT_ARRAY_LEN(counts); i++) {
        ft_format_count(counts[i], text, sizeof(text));
        const struct seg segs[] = {{text, plain(FT_COLOR_BRIGHT)}};
        label_line(d, in->lx, line_y(in, 3 + (int)i), in->lw, 9, labels[i], segs, 1);
    }
    static const char *const keys[] = {"Enter", "open or close", "+", "expand", "-", "collapse"};
    hint_line(d, in->rx, line_y(in, 5), in->rw, keys, FT_ARRAY_LEN(keys) / 2);
}

static void inspect_fold(struct inspect *in, const struct ft_top_fold *f)
{
    struct ft_top_draw *d = in->d;
    char prefix[48];
    char text[256];
    size_t len = 0;

    snprintf(prefix, sizeof(prefix), "F8 Inspect · %zu more ", f->count);
    inspect_frame(in, prefix, f->title, "");
    text[0] = '\0';
    for (size_t i = 0; i < f->count && len + 12 < sizeof(text); i++) {
        int w = snprintf(text + len, sizeof(text) - len, "%s%" PRIu32, i ? " " : "",
                         f->members[i]->pid);
        len += w > 0 ? (size_t)w : 0;
    }
    const struct seg pid_segs[] = {{text, dim()}};
    label_line(d, in->lx, line_y(in, 1), in->lw, 9, "pids", pid_segs, 1);
    char rate[24];
    ft_top_format_rate(f->rate, rate, sizeof(rate));
    const struct seg rate_segs[] = {{rate, ft_top_rate_style(f->rate)}};
    label_line(d, in->lx, line_y(in, 2), in->lw, 9, "rate", rate_segs, 1);
    char total[24];
    ft_top_format_size(f->total, total, sizeof(total));
    const struct seg total_segs[] = {
        {total, plain(FT_COLOR_BRIGHT)},
        {" since the agent started", plain(FT_COLOR_TEXT)},
    };
    label_line(d, in->lx, line_y(in, 3), in->lw, 9, "total", total_segs, 2);
    char files[24];
    char dests[24];
    ft_format_count(f->files, files, sizeof(files));
    ft_format_count(f->destinations, dests, sizeof(dests));
    const struct seg active_segs[] = {
        {files, plain(FT_COLOR_BRIGHT)},
        {f->files == 1 ? " file · " : " files · ", plain(FT_COLOR_TEXT)},
        {dests, plain(FT_COLOR_BRIGHT)},
        {f->destinations == 1 ? " destination" : " destinations", plain(FT_COLOR_TEXT)},
    };
    label_line(d, in->lx, line_y(in, 4), in->lw, 9, "active", active_segs,
               FT_ARRAY_LEN(active_segs));
    const struct seg method_segs[] = {
        {ft_top_method_word(f->method), plain(ft_top_method_color(f->method))}};
    label_line(d, in->lx, line_y(in, 5), in->lw, 9, "method", method_segs, 1);
    static const char *const keys[] = {"+", "list them"};
    hint_line(d, in->rx, line_y(in, 5), in->rw, keys, FT_ARRAY_LEN(keys) / 2);
}

void ft_top_draw_inspect(struct ft_top_draw *d, struct ft_rect r)
{
    enum ft_top_mode mode = d->ui->mode;
    struct inspect in = {
        .d = d,
        .r = r,
        .lx = r.x + 2,
        .rx = r.x + r.w / 2 + 1,
    };

    if (r.w < 4 || r.h < 2)
        return;
    in.lw = in.rx - 2 - in.lx;
    in.rw = r.x + r.w - 2 - in.rx;
    struct ft_rect clip = ft_canvas_clip(d->canvas, r);

    size_t index = ft_top_selected(d->model, mode);
    const struct ft_top_row *row =
        index == SIZE_MAX ? nullptr : ft_top_row_at(d->model, mode, index);
    if (!row || (mode == FT_TOP_LEADERS &&
                 (d->ui->leaders_unsupported || !ft_top_leaders(d->model)->answered))) {
        inspect_frame(&in, "F8 Inspect", "", "");
        ft_canvas_text(d->canvas, in.lx, line_y(&in, 1), in.lw, dim(), "Nothing is selected.");
        ft_canvas_clip(d->canvas, clip);
        return;
    }
    switch (row->kind) {
    case FT_TOP_ROW_TRANSFER:
        inspect_process(&in, row->transfer->process, row->transfer);
        break;
    case FT_TOP_ROW_PROCESS:
        inspect_process(&in, row->process, nullptr);
        break;
    case FT_TOP_ROW_DESTINATION:
        inspect_destination(&in, row->destination);
        break;
    case FT_TOP_ROW_FILE:
        inspect_file(&in, row->file);
        break;
    case FT_TOP_ROW_LEADER:
        inspect_leader(&in, row->leader);
        break;
    case FT_TOP_ROW_SECTION:
        inspect_section(&in, row->section);
        break;
    case FT_TOP_ROW_FOLD:
        inspect_fold(&in, row->fold);
        break;
    }
    ft_canvas_clip(d->canvas, clip);
}

static void draw_slice(struct ft_canvas *c, int *x, int y, int right, struct ft_style s,
                       const char *text, size_t len)
{
    char buf[512];
    size_t n = len < sizeof(buf) ? len : sizeof(buf) - 1;
    memcpy(buf, text, n);
    buf[n] = '\0';
    if (*x < right)
        *x += ft_canvas_text(c, *x, y, right - *x, s, buf);
}

static bool json_literal(const char *p, const char **end)
{
    static const char *const words[] = {"true", "false", "null"};
    for (size_t i = 0; i < FT_ARRAY_LEN(words); i++) {
        size_t n = strlen(words[i]);
        if (strncmp(p, words[i], n) == 0) {
            *end = p + n;
            return true;
        }
    }
    return false;
}

/* A line of pretty-printed JSON: keys cyan, strings plain, numbers and literals bright. */
static void json_line(struct ft_canvas *c, int x, int y, int width, const char *line)
{
    int right = x + width;
    const char *p = line;

    while (*p && x < right) {
        const char *end = p + 1;
        struct ft_style s = plain(FT_COLOR_TEXT);
        if (*p == '"') {
            while (*end && *end != '"')
                end += end[0] == '\\' && end[1] ? 2 : 1;
            if (*end)
                end++;
            const char *after = end;
            while (*after == ' ')
                after++;
            s = plain(*after == ':' ? FT_COLOR_CYAN : FT_COLOR_TEXT);
        } else if (*p == '-' || (*p >= '0' && *p <= '9')) {
            while (*end && strchr("0123456789.eE+-", *end))
                end++;
            s = plain(FT_COLOR_BRIGHT);
        } else if (json_literal(p, &end)) {
            s = plain(FT_COLOR_BRIGHT);
        } else {
            while (*end && !strchr("\"-0123456789tfn", *end))
                end++;
        }
        draw_slice(c, &x, y, right, s, p, (size_t)(end - p));
        p = end;
    }
}

/* An events line: its leading time dim, the rest in text color. */
static void event_line(struct ft_canvas *c, int x, int y, int width, const char *line)
{
    size_t time = strspn(line, "0123456789:.");
    int right = x + width;

    if (time == 0 || (line[time] != ' ' && line[time] != '\0')) {
        ft_canvas_text_cut(c, x, y, width, plain(FT_COLOR_TEXT), line, FT_CUT_END);
        return;
    }
    draw_slice(c, &x, y, right, dim(), line, time);
    if (x < right)
        ft_canvas_text_cut(c, x, y, right - x, plain(FT_COLOR_TEXT), line + time, FT_CUT_END);
}

void ft_top_draw_overlay(struct ft_top_draw *d, struct ft_rect r)
{
    const struct ft_top_text *t = &d->ui->overlay_text;
    int visible = r.h - 1;
    char position[64] = "";

    if (r.w < 4 || r.h < 1)
        return;
    struct ft_rect clip = ft_canvas_clip(d->canvas, r);
    size_t first = t->scroll;
    size_t last_start = t->count > (size_t)(visible > 0 ? visible : 0)
                            ? t->count - (size_t)(visible > 0 ? visible : 0)
                            : 0;
    if (first > last_start)
        first = last_start;
    size_t shown = visible > 0 ? t->count - first : 0;
    if (shown > (size_t)(visible > 0 ? visible : 0))
        shown = (size_t)visible;
    if (t->count)
        snprintf(position, sizeof(position), "lines %zu–%zu of %zu   Esc close", first + 1,
                 first + shown, t->count);
    else
        ft_strlcpy(position, "Esc close", sizeof(position));
    title_bar(d, (struct ft_rect){r.x, r.y, r.w, 1}, t->title, "", "", position);
    close_hit(d, r);

    if (t->count == 0 && visible > 0)
        ft_canvas_text(d->canvas, r.x + 1, r.y + 1, r.w - 2, dim(), "Nothing to show.");
    for (size_t i = 0; i < shown; i++) {
        const char *line = t->lines[first + i];
        int y = r.y + 1 + (int)i;
        if (!line)
            continue;
        if (d->ui->overlay == FT_TOP_OVERLAY_JSON)
            json_line(d->canvas, r.x + 1, y, r.w - 2, line);
        else
            event_line(d->canvas, r.x + 1, y, r.w - 2, line);
    }
    ft_canvas_clip(d->canvas, clip);
}

struct help_key {
    const char *key;
    const char *text;
};

struct help_group {
    const char *title;
    struct help_key keys[7];
};

static const struct help_group help_groups[] = {
    {"Modes",
     {{"1", "Transfers: one row per active file → socket"},
      {"2", "Processes: per-process totals, tree with F5"},
      {"3", "Destinations: per remote address or subnet"},
      {"4", "Files: per file, live (no window)"},
      {"L", "Leaders: top files over a time window"},
      {"F2  Tab", "next mode"}}},
    {"Navigate",
     {{"↑ ↓ PgUp PgDn", "move selection"},
      {"Home End", "first / last row"},
      {"Space  U", "tag row / untag all"},
      {"Enter  F8", "inspect the selected row"},
      {"+ - *", "expand, collapse, expand all"},
      {"F9  z", "pause updates"}}},
    {"Sort and group",
     {{"F6", "sort-by panel"},
      {"< >", "previous / next sort column"},
      {"I", "invert sort order"},
      {"click header", "sort by that column"},
      {"F7  g", "group by process, script, dest, dir"},
      {"P B T", "sort by rate, bytes, age"}}},
    {"Search and filter",
     {{"F3  /", "incremental search, highlights matches"},
      {"n  N", "next / previous match"},
      {"F4  \\", "filter: key:value, ! negates"},
      {"Ctrl-S", "save filter as preset"},
      {"u", "filter by user of selected row"},
      {"Esc", "clear search / filter"}}},
    {"Leaders",
     {{"F2  w", "window: 1m 5m 15m 1h 24h 7d"},
      {"F6  r", "rank by bytes, transfers, dests"},
      {"F7", "group: file, directory, extension"},
      {"F9", "freeze the ranking"},
      {"e", "export current view (JSON / CSV)"},
      {"Enter", "inspect file: senders and dests"}}},
    {"Display",
     {{"n", "resolve destination hostnames"},
      {"p", "full paths or file names"},
      {"s", "show / hide SCRIPT column"},
      {"m", "color by egress or by method"},
      {"c  C", "copy the path, or the whole row"},
      {"d", "refresh delay 0.5s … 10s"},
      {"F10  q", "quit"}}},
};

static const struct help_key help_commands[] = {
    {"$ sudo filetrace top", "Transfers mode, sorted by rate"},
    {"$ sudo filetrace top --mode processes --tree", "start in the process tree"},
    {"$ sudo filetrace top --sort bytes --filter \"dest:public script:*.php\"",
     "start sorted and filtered"},
    {"$ sudo filetrace top --remote 10.0.0.0/8 --script \"*/export.php\"",
     "same flags as filetrace files"},
    {"$ sudo filetrace top --leaders --window 1h --by bytes --limit 20", "Leaders screen directly"},
    {"$ sudo filetrace top --leaders --window 24h --once --json",
     "one snapshot to stdout, no screen"},
};

constexpr int HELP_COLUMNS = 3;

static int help_keys(const struct help_group *g)
{
    int n = 0;
    while (n < (int)FT_ARRAY_LEN(g->keys) && g->keys[n].key)
        n++;
    return n;
}

/* The keys of the tallest group in a row of groups. */
static int help_row_keys(size_t row)
{
    int rows = 0;
    for (size_t g = row * HELP_COLUMNS;
         g < (row + 1) * HELP_COLUMNS && g < FT_ARRAY_LEN(help_groups); g++) {
        int n = help_keys(&help_groups[g]);
        rows = n > rows ? n : rows;
    }
    return rows;
}

/* The keys of a column of groups, as wide as its longest key and a gap of two. */
static int help_key_width(size_t column)
{
    int widest = 0;
    for (size_t g = column; g < FT_ARRAY_LEN(help_groups); g += HELP_COLUMNS) {
        for (size_t i = 0; i < FT_ARRAY_LEN(help_groups[g].keys) && help_groups[g].keys[i].key;
             i++) {
            int w = ft_text_columns(help_groups[g].keys[i].key);
            widest = w > widest ? w : widest;
        }
    }
    return widest + 2;
}

static void help_group(struct ft_top_draw *d, int x, int y, int width, int key_width, int bottom,
                       const struct help_group *g)
{
    ft_top_title_row(d, (struct ft_rect){x, y, width, 1}, FT_COLOR_GREEN, g->title, nullptr);
    for (size_t i = 0; i < FT_ARRAY_LEN(g->keys) && g->keys[i].key && y + 1 + (int)i < bottom;
         i++) {
        int row = y + 1 + (int)i;
        ft_canvas_text_cut(d->canvas, x, row, key_width - 1, ft_top_fg(FT_COLOR_CYAN, true),
                           g->keys[i].key, FT_CUT_END);
        ft_canvas_text_cut(d->canvas, x + key_width, row, width - key_width, plain(FT_COLOR_TEXT),
                           g->keys[i].text, FT_CUT_END);
    }
}

void ft_top_draw_help(struct ft_top_draw *d)
{
    int cols = ft_canvas_cols(d->canvas);
    int rows = ft_canvas_rows(d->canvas);
    int x = 2;
    int width = cols - 4;
    int bottom = rows - 1;

    if (width <= 0 || rows <= 0)
        return;
    const struct seg title[] = {
        {"filetrace top", ft_top_fg(FT_COLOR_BRIGHT, true)},
        {" — live view of files leaving this host: which process, which file, to whom, how fast.",
         dim()},
    };
    draw_segs(d->canvas, x, 1, width, title, FT_ARRAY_LEN(title));
    const struct seg data[] = {
        {"Data comes from filetrace-agent. ", dim()},
        {"EXACT", plain(FT_COLOR_GREEN)},
        {" = sendfile, the kernel moved file → socket. ", dim()},
        {"INFERRED", plain(FT_COLOR_AMBER)},
        {" = a thread read the file, then wrote to a socket.", dim()},
    };
    draw_segs(d->canvas, x, 3, width, data, FT_ARRAY_LEN(data));

    int column = (cols - 4 - 2 * 3) / HELP_COLUMNS;
    int y = 5;
    for (size_t g = 0; g < FT_ARRAY_LEN(help_groups); g++) {
        if (g && g % HELP_COLUMNS == 0)
            y += 1 + help_row_keys(g / HELP_COLUMNS - 1) + 1;
        if (y < bottom)
            help_group(d, x + (int)(g % HELP_COLUMNS) * (column + 3), y, column,
                       help_key_width(g % HELP_COLUMNS), bottom, &help_groups[g]);
    }

    /* The command lines need a rule, a heading and a free row above the key bar. */
    int cli = y + 1 + help_row_keys((FT_ARRAY_LEN(help_groups) - 1) / HELP_COLUMNS) + 1;
    int ncommands = (int)FT_ARRAY_LEN(help_commands);
    if (cli + 2 + ncommands < bottom) {
        int command_w = 0;
        for (size_t i = 0; i < FT_ARRAY_LEN(help_commands); i++) {
            int w = ft_text_columns(help_commands[i].key);
            command_w = w > command_w ? w : command_w;
        }
        command_w += 3;
        ft_canvas_repeat(d->canvas, x, cli, width, U'─', plain(FT_COLOR_RULE));
        ft_canvas_text(d->canvas, x, cli + 1, width, ft_top_on(FT_COLOR_GREEN, true),
                       " Command line ");
        for (int i = 0; i < ncommands; i++) {
            int row = cli + 2 + i;
            ft_canvas_text_cut(d->canvas, x, row, width, plain(FT_COLOR_BRIGHT),
                               help_commands[i].key, FT_CUT_END);
            if (width > command_w)
                ft_canvas_text_cut(d->canvas, x + command_w, row, width - command_w, dim(),
                                   help_commands[i].text, FT_CUT_END);
        }
    }

    int kx = x + ft_canvas_text(d->canvas, x, bottom, width, plain(FT_COLOR_BRIGHT), "Esc");
    kx += ft_canvas_text(d->canvas, kx, bottom, x + width - kx, ft_top_on(FT_COLOR_CYAN, false),
                         "Back   ");
    ft_top_hits_add_key(d->hits, (struct ft_rect){x, bottom, kx - x, 1}, FT_KEY_ESC, 0);
    ft_canvas_text(d->canvas, kx + 3, bottom, x + width - kx - 3, dim(), "Press any key to return");
}
