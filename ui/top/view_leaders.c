#include "filetrace/format.h"
#include "ui/top/views.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

constexpr int SIDE_LIST_ROWS = 7;
constexpr int SIDE_NAME = 27;
constexpr int SIDE_VALUE = 8;
constexpr int SIDE_BAR = 8;
constexpr int SIDE_LABEL = 9;
constexpr int SHARE_CELLS = 15;
constexpr int FILE_MIN = 30;
constexpr unsigned PREVIOUS_TOP = 50;

/* A run of text in one style; a line is drawn from several. */
struct seg {
    const char *text;
    struct ft_style style;
};

static int segs_columns(const struct seg *segs, size_t n)
{
    int cols = 0;
    for (size_t i = 0; i < n; i++)
        cols += ft_text_columns(segs[i].text);
    return cols;
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

static struct ft_style dim(void)
{
    return ft_top_fg(FT_COLOR_DIM, false);
}

static struct ft_style plain(enum ft_color fg)
{
    return ft_top_fg(fg, false);
}

static const char *window_comparison(enum ft_leader_window window)
{
    static const char *const words[FT_WINDOW_COUNT] = {
        [FT_WINDOW_LIFETIME] = "nothing",  [FT_WINDOW_1M] = "previous minute",
        [FT_WINDOW_5M] = "previous 5 min", [FT_WINDOW_15M] = "previous 15 min",
        [FT_WINDOW_1H] = "previous hour",  [FT_WINDOW_24H] = "previous day",
        [FT_WINDOW_7D] = "previous week",
    };
    return window < FT_WINDOW_COUNT ? words[window] : "";
}

static const char *by_word(enum ft_top_sort by)
{
    switch (by) {
    case FT_TOP_SORT_TRANSFERS:
        return "transfers";
    case FT_TOP_SORT_DESTINATIONS:
        return "destinations";
    default:
        return "bytes";
    }
}

static void local_time(uint64_t wall_ns, const char *fmt, char *buf, size_t size)
{
    time_t secs = (time_t)(wall_ns / FT_NS_PER_SEC);
    struct tm tm;

    if (wall_ns == 0 || !localtime_r(&secs, &tm) || strftime(buf, size, fmt, &tm) == 0)
        ft_strlcpy(buf, "-", size);
}

static void count_text(uint64_t n, const char *one, const char *many, char *buf, size_t size)
{
    char digits[32];
    ft_format_count(n, digits, sizeof(digits));
    snprintf(buf, size, "%s %s", digits, n == 1 ? one : many);
}

/* A card's last line, in a wide form and in a form for a narrow card. */
struct card_line {
    const struct seg *wide;
    size_t nwide;
    const struct seg *narrow;
    size_t nnarrow;
};

/* A box with a label, a value and a line; without a value the agent has not answered yet. */
static void card(struct ft_top_draw *d, struct ft_rect box, const char *label, const char *value,
                 const struct card_line *line)
{
    int x = box.x + 2;
    int width = box.w - 4;

    ft_canvas_box(d->canvas, box, plain(FT_COLOR_RULE));
    if (width <= 0)
        return;
    ft_canvas_text_cut(d->canvas, x, box.y + 1, width, dim(), label, FT_CUT_END);
    if (!value)
        return;
    ft_canvas_text_cut(d->canvas, x, box.y + 2, width, ft_top_fg(FT_COLOR_BRIGHT, true), value,
                       FT_CUT_END);
    bool wide = segs_columns(line->wide, line->nwide) <= width;
    draw_segs(d->canvas, x, box.y + 3, width, wide ? line->wide : line->narrow,
              wide ? line->nwide : line->nnarrow);
}

static unsigned whole_percent(double share)
{
    unsigned percent = (unsigned)(share * 100.0 + 0.5);
    return percent > 100 ? 100 : percent;
}

static void sent_card(struct ft_top_draw *d, struct ft_rect box, const struct ft_top_leaders *l,
                      bool known)
{
    char label[32];
    char value[32];
    char exact[32];
    char rw[32];
    char rw_short[32];
    unsigned percent = whole_percent(l->exact_share);

    snprintf(label, sizeof(label), "SENT · %s", ft_leader_window_name(l->window));
    ft_format_bytes(l->summary.bytes, value, sizeof(value));
    snprintf(exact, sizeof(exact), "%u%% sendfile", percent);
    snprintf(rw, sizeof(rw), "%u%% read-write", 100 - percent);
    snprintf(rw_short, sizeof(rw_short), "%u%% rw", 100 - percent);
    const struct seg wide[] = {
        {exact, plain(FT_COLOR_GREEN)}, {" · ", dim()}, {rw, plain(FT_COLOR_AMBER)}};
    const struct seg narrow[] = {
        {exact, plain(FT_COLOR_GREEN)}, {" · ", dim()}, {rw_short, plain(FT_COLOR_AMBER)}};
    const struct seg nothing[] = {{"nothing was sent", dim()}};
    struct card_line line = {wide, FT_ARRAY_LEN(wide), narrow, FT_ARRAY_LEN(narrow)};
    if (l->summary.bytes == 0)
        line = (struct card_line){nothing, 1, nothing, 1};
    card(d, box, label, known ? value : nullptr, &line);
}

static void files_card(struct ft_top_draw *d, struct ft_rect box, const struct ft_top_leaders *l,
                       bool known)
{
    const struct ft_row_leader_summary *s = &l->summary;
    char value[32];
    char procs[48];
    char scripts[48];
    char who[112];

    ft_format_count(s->files, value, sizeof(value));
    count_text(s->processes, "process", "processes", procs, sizeof(procs));
    count_text(s->scripts, "script", "scripts", scripts, sizeof(scripts));
    if (s->scripts)
        snprintf(who, sizeof(who), "%s, %s", procs, scripts);
    else
        ft_strlcpy(who, procs, sizeof(who));
    const struct seg wide[] = {{"from ", dim()}, {who, dim()}};
    const struct seg narrow[] = {{who, dim()}};
    struct card_line line = {wide, FT_ARRAY_LEN(wide), narrow, FT_ARRAY_LEN(narrow)};
    card(d, box, "DISTINCT FILES", known ? value : nullptr, &line);
}

static void destinations_card(struct ft_top_draw *d, struct ft_rect box,
                              const struct ft_top_leaders *l, bool known)
{
    const struct ft_row_leader_summary *s = &l->summary;
    char value[32];
    char pub[48];
    char priv[48];
    char pub_short[48];
    char priv_short[48];

    ft_format_count(s->destinations_public + s->destinations_private, value, sizeof(value));
    count_text(s->destinations_public, "public", "public", pub, sizeof(pub));
    count_text(s->destinations_private, "private", "private", priv, sizeof(priv));
    count_text(s->destinations_public, "pub", "pub", pub_short, sizeof(pub_short));
    count_text(s->destinations_private, "priv", "priv", priv_short, sizeof(priv_short));
    const struct seg wide[] = {
        {pub, plain(FT_COLOR_PURPLE)}, {" · ", dim()}, {priv, plain(FT_COLOR_BLUE)}};
    const struct seg narrow[] = {
        {pub_short, plain(FT_COLOR_PURPLE)}, {" · ", dim()}, {priv_short, plain(FT_COLOR_BLUE)}};
    struct card_line line = {wide, FT_ARRAY_LEN(wide), narrow, FT_ARRAY_LEN(narrow)};
    card(d, box, "DESTINATIONS", known ? value : nullptr, &line);
}

static void concentration_card(struct ft_top_draw *d, struct ft_rect box,
                               const struct ft_top_leaders *l, bool known)
{
    char value[32];

    snprintf(value, sizeof(value), "%u%%", whole_percent(l->concentration));
    const struct seg wide[] = {{"of bytes in the top 10 files", dim()}};
    const struct seg narrow[] = {{"in the top 10 files", dim()}};
    struct card_line line = {wide, 1, narrow, 1};
    card(d, box, "CONCENTRATION", known ? value : nullptr, &line);
}

void ft_top_draw_leaders_cards(struct ft_top_draw *d, struct ft_rect r)
{
    const struct ft_top_leaders *l = ft_top_leaders(d->model);
    bool known = l->answered && !d->ui->leaders_unsupported;
    int base = (r.w - 6) / 4;
    int extra = r.w - 6 - 4 * base;
    struct ft_rect boxes[4];

    if (base < 4 || r.h < 3)
        return;
    /* Columns that do not divide evenly go to the first cards, so the last one ends at the edge. */
    for (int i = 0, x = r.x; i < 4; i++) {
        int w = base + (i < extra ? 1 : 0);
        boxes[i] = (struct ft_rect){x, r.y, w, r.h < 5 ? r.h : 5};
        x += w + 2;
    }
    struct ft_rect clip = ft_canvas_clip(d->canvas, r);
    sent_card(d, boxes[0], l, known);
    files_card(d, boxes[1], l, known);
    destinations_card(d, boxes[2], l, known);
    concentration_card(d, boxes[3], l, known);
    ft_canvas_clip(d->canvas, clip);
}

struct word {
    const char *text;
    bool chosen;
    enum ft_top_target target;
    uint32_t arg;
};

struct selectors {
    int gap;
    bool labels;
    bool short_by;
};

static const enum ft_leader_window windows[] = {FT_WINDOW_1M, FT_WINDOW_5M,  FT_WINDOW_15M,
                                                FT_WINDOW_1H, FT_WINDOW_24H, FT_WINDOW_7D};
static const enum ft_top_sort rank_keys[] = {FT_TOP_SORT_BYTES, FT_TOP_SORT_TRANSFERS,
                                             FT_TOP_SORT_DESTINATIONS};
static const char *const rank_long[] = {"bytes", "transfers", "destinations"};
static const char *const rank_short[] = {"bytes", "xfers", "dests"};

static int selectors_width(const struct selectors *s)
{
    int w = 2 * s->gap + (s->labels ? 7 + 8 : 0);
    for (size_t i = 0; i < FT_ARRAY_LEN(windows); i++)
        w += 2 + ft_text_columns(ft_leader_window_name(windows[i]));
    for (size_t i = 0; i < FT_ARRAY_LEN(rank_keys); i++)
        w += 2 + ft_text_columns(s->short_by ? rank_short[i] : rank_long[i]);
    return w;
}

static int draw_word(struct ft_top_draw *d, int x, int y, int limit, const struct word *w,
                     enum ft_color idle)
{
    char padded[32];
    struct ft_style s = w->chosen ? ft_top_on(FT_COLOR_AMBER, true) : plain(idle);

    snprintf(padded, sizeof(padded), " %s ", w->text);
    int n = ft_canvas_text(d->canvas, x, y, limit - x, s, padded);
    ft_top_hits_add(d->hits, (struct ft_rect){x, y, n, 1}, w->target, w->arg);
    return x + n;
}

static int draw_selectors(struct ft_top_draw *d, int x, int y, int limit, const struct selectors *s)
{
    x += s->gap;
    if (s->labels)
        x += ft_canvas_text(d->canvas, x, y, limit - x, dim(), "window ");
    for (size_t i = 0; i < FT_ARRAY_LEN(windows); i++) {
        struct word w = {ft_leader_window_name(windows[i]), d->ui->window == windows[i],
                         FT_TOP_TARGET_WINDOW, windows[i]};
        x = draw_word(d, x, y, limit, &w, FT_COLOR_DIM);
    }
    x += s->gap;
    if (s->labels)
        x += ft_canvas_text(d->canvas, x, y, limit - x, dim(), "rank by ");
    for (size_t i = 0; i < FT_ARRAY_LEN(rank_keys); i++) {
        struct word w = {s->short_by ? rank_short[i] : rank_long[i], d->ui->by == rank_keys[i],
                         FT_TOP_TARGET_RANK_BY, rank_keys[i]};
        x = draw_word(d, x, y, limit, &w, FT_COLOR_TEXT);
    }
    return x;
}

/* What the right end of the bar says, from its most to its least detailed form. */
struct span_text {
    char spinner[8];
    char filtered[48];
    bool frozen;
    char full[112];
    char brief[48];
    enum ft_color color;
};

static int span_width(const struct span_text *t, int level)
{
    int w = 0;
    if (t->spinner[0])
        w += 2;
    if (t->filtered[0])
        w += ft_text_columns(t->filtered) + 1;
    if (t->frozen)
        w += 9;
    const char *text = level == 0 ? t->full : level == 1 ? t->brief : "";
    if (text[0])
        w += ft_text_columns(text);
    return w > 0 && !text[0] ? w - 1 : w;
}

static void draw_span(struct ft_top_draw *d, int right, int y, const struct span_text *t, int level)
{
    const char *text = level == 0 ? t->full : level == 1 ? t->brief : "";
    int x = right - span_width(t, level);

    if (t->spinner[0]) {
        ft_canvas_text(d->canvas, x, y, 1, plain(FT_COLOR_CYAN), t->spinner);
        x += 2;
    }
    if (t->filtered[0]) {
        x += ft_canvas_text(d->canvas, x, y, right - x, ft_top_on(FT_COLOR_AMBER, true),
                            t->filtered) +
             1;
    }
    if (t->frozen) {
        ft_canvas_text(d->canvas, x, y, right - x, ft_top_on(FT_COLOR_AMBER, true), " FROZEN ");
        x += 9;
    }
    if (text[0])
        ft_canvas_text(d->canvas, x, y, right - x, plain(t->color), text);
}

static void span_text_of(const struct ft_top_draw *d, struct span_text *t)
{
    static const char *const frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
    const struct ft_top_leaders *l = ft_top_leaders(d->model);
    const struct ft_row_leader_summary *s = &l->summary;

    *t = (struct span_text){.frozen = d->ui->frozen, .color = FT_COLOR_DIM};
    if (d->ui->waiting)
        ft_strlcpy(t->spinner, frames[d->ui->spinner % FT_ARRAY_LEN(frames)], sizeof(t->spinner));
    const struct ft_top_view *v = ft_top_view_of(d->model, FT_TOP_LEADERS);
    const char *filter = ft_top_filter_of(d->model, FT_TOP_LEADERS);
    if (filter && filter[0])
        snprintf(t->filtered, sizeof(t->filtered), " FILTERED %zu/%zu ", v->shown, v->total);
    if (!l->answered || d->ui->leaders_unsupported)
        return;

    char from[24];
    char to[24];
    if (s->flags & FT_LEADERS_SHORT_HISTORY) {
        local_time(s->from_wall_ns, "%H:%M", from, sizeof(from));
        snprintf(t->full, sizeof(t->full), "since %s · history is shorter than the window", from);
        snprintf(t->brief, sizeof(t->brief), "since %s", from);
        t->color = FT_COLOR_AMBER;
        return;
    }
    const char *fmt = l->window == FT_WINDOW_7D ? "%b %d" : "%H:%M";
    local_time(s->from_wall_ns, fmt, from, sizeof(from));
    local_time(s->to_wall_ns, fmt, to, sizeof(to));
    snprintf(t->brief, sizeof(t->brief), "%s–%s", from, to);
    if (s->previous_from_wall_ns)
        snprintf(t->full, sizeof(t->full), "%s · Δ vs %s", t->brief, window_comparison(l->window));
    else
        ft_strlcpy(t->full, t->brief, sizeof(t->full));
}

void ft_top_draw_leaders_bar(struct ft_top_draw *d, struct ft_rect r, int x)
{
    static const struct selectors forms[] = {
        {.gap = 3, .labels = true, .short_by = false},
        {.gap = 3, .labels = true, .short_by = true},
        {.gap = 2, .labels = false, .short_by = true},
    };
    struct span_text t;
    int right = r.x + r.w;
    int avail = right - x;
    struct ft_rect clip = ft_canvas_clip(d->canvas, r);

    span_text_of(d, &t);
    /* The text at the right gives way first, then the badges, then the selectors shrink. */
    for (size_t f = 0; f < FT_ARRAY_LEN(forms); f++) {
        int need = selectors_width(&forms[f]);
        for (int level = 0; level < 3; level++) {
            int span = span_width(&t, level);
            if (need + (span ? 1 + span : 0) > avail)
                continue;
            if (span)
                draw_span(d, right, r.y, &t, level);
            draw_selectors(d, x, r.y, right, &forms[f]);
            ft_canvas_clip(d->canvas, clip);
            return;
        }
    }
    draw_selectors(d, x, r.y, right, &forms[FT_ARRAY_LEN(forms) - 1]);
    ft_canvas_clip(d->canvas, clip);
}

enum column_id : uint8_t {
    COL_RANK,
    COL_DELTA,
    COL_FILE,
    COL_BYTES,
    COL_SHARE,
    COL_XFERS,
    COL_DESTS,
    COL_SENDER,
    COL_TREND,
    COL_COUNT,
};

struct column {
    const char *label;
    int width;
    bool right;
};

static const struct column columns[COL_COUNT] = {
    [COL_RANK] = {"#", 4, true},        [COL_DELTA] = {"Δ", 5, false},
    [COL_FILE] = {"FILE", 0, false},    [COL_BYTES] = {"BYTES", 9, true},
    [COL_SHARE] = {"SHARE", 16, false}, [COL_XFERS] = {"XFERS", 8, true},
    [COL_DESTS] = {"DESTS", 7, true},   [COL_SENDER] = {"TOP SENDER", 14, false},
    [COL_TREND] = {"TREND", 12, false},
};

/* Where each column starts and how wide it is; width 0 when dropped. */
struct ranking_layout {
    int x[COL_COUNT];
    int w[COL_COUNT];
};

static enum column_id ranked_column(enum ft_top_sort by)
{
    return by == FT_TOP_SORT_TRANSFERS      ? COL_XFERS
           : by == FT_TOP_SORT_DESTINATIONS ? COL_DESTS
                                            : COL_BYTES;
}

static void ranking_layout(struct ft_rect r, enum ft_top_sort by, struct ranking_layout *out)
{
    static const enum column_id drop_order[] = {COL_TREND, COL_SENDER, COL_DESTS, COL_XFERS,
                                                COL_SHARE};
    bool shown[COL_COUNT];
    int fixed = 0;

    for (int i = 0; i < COL_COUNT; i++) {
        shown[i] = true;
        fixed += columns[i].width;
    }
    for (size_t k = 0; k < FT_ARRAY_LEN(drop_order) && r.w - fixed < FILE_MIN; k++) {
        enum column_id c = drop_order[k];
        if (c == ranked_column(by))
            continue;
        shown[c] = false;
        fixed -= columns[c].width;
    }
    int x = r.x;
    for (int i = 0; i < COL_COUNT; i++) {
        int w = i == COL_FILE ? r.w - fixed : shown[i] ? columns[i].width : 0;
        out->x[i] = x;
        out->w[i] = w > 0 ? w : 0;
        x += out->w[i];
    }
}

static const char *key_label(enum ft_leader_key key)
{
    switch (key) {
    case FT_LEADER_DIRECTORY:
        return "DIRECTORY";
    case FT_LEADER_EXTENSION:
        return "EXTENSION";
    case FT_LEADER_DESTINATION:
        return "DESTINATION";
    default:
        return "FILE";
    }
}

static void draw_ranking_header(struct ft_top_draw *d, struct ft_rect header,
                                const struct ranking_layout *lay, const struct ft_top_leaders *l)
{
    enum ft_top_sort by = l->by;
    enum ft_leader_window window = l->window;
    enum ft_leader_key key = l->key;
    static const enum ft_top_sort sorts[COL_COUNT] = {
        [COL_BYTES] = FT_TOP_SORT_BYTES,
        [COL_XFERS] = FT_TOP_SORT_TRANSFERS,
        [COL_DESTS] = FT_TOP_SORT_DESTINATIONS,
    };
    struct ft_style s = ft_top_on(FT_COLOR_GREEN, true);
    enum column_id ranked = ranked_column(by);
    char trend[24];

    ft_top_bar_row(d, header, FT_COLOR_GREEN);
    snprintf(trend, sizeof(trend), "TREND %s", ft_leader_window_name(window));
    for (int i = 0; i < COL_COUNT; i++) {
        int w = lay->w[i];
        const char *label = i == COL_TREND  ? trend
                            : i == COL_FILE ? key_label(key)
                                            : columns[i].label;
        char bracketed[32];
        if (w == 0)
            continue;
        if (i == (int)ranked) {
            ft_top_bar_row(d, (struct ft_rect){lay->x[i], header.y, w, 1}, FT_COLOR_CYAN);
            if (d->depth == FT_DEPTH_NONE) {
                snprintf(bracketed, sizeof(bracketed), "[%s]", label);
                label = bracketed;
            }
        }
        /* The trend is the last column and has no padding of its own. */
        ft_top_cell(d, lay->x[i], header.y, i == COL_TREND ? w + 1 : w, columns[i].right, s, label);
        if (sorts[i])
            ft_top_hits_add(d->hits, (struct ft_rect){lay->x[i], header.y, w, 1},
                            FT_TOP_TARGET_HEADER, sorts[i]);
    }
}

/* A path cut from its start with the directory dim and the name from name_offset bright. */
static void split_path_cell(struct ft_top_draw *d, int x, int y, int width, const char *path,
                            uint32_t name_offset, struct ft_style name)
{
    int avail = width - 1;
    const char *base = path + name_offset;

    if (avail <= 0)
        return;
    if (!d->ui->full_paths) {
        ft_canvas_text_cut(d->canvas, x, y, avail, name, base, FT_CUT_START);
        return;
    }
    char dir[FT_PATH_MAX];
    size_t n = name_offset < sizeof(dir) ? name_offset : sizeof(dir) - 1;
    memcpy(dir, path, n);
    dir[n] = '\0';
    int name_cols = ft_text_columns(base);
    int dir_cols = ft_text_columns(dir);
    if (dir_cols + name_cols <= avail) {
        int used = ft_canvas_text(d->canvas, x, y, avail, dim(), dir);
        ft_canvas_text(d->canvas, x + used, y, avail - used, name, base);
    } else if (name_cols + 1 >= avail) {
        ft_canvas_text_cut(d->canvas, x, y, avail, name, base, FT_CUT_START);
    } else {
        int used = ft_canvas_text_cut(d->canvas, x, y, avail - name_cols, dim(), dir, FT_CUT_START);
        ft_canvas_text(d->canvas, x + used, y, avail - used, name, base);
    }
}

static const char *leader_text(const struct ft_top_draw *d, const struct ft_top_leader *l)
{
    if (l->row->remote.family)
        return l->host_state == FT_TOP_HOST_NAMED && l->host ? l->host : l->remote_text;
    return ft_top_path_text(d, l->row->text, l->name_offset);
}

static void draw_leader_name(struct ft_top_draw *d, int x, int y, int width,
                             const struct ft_top_leader *l, enum ft_leader_key key)
{
    const struct ft_row_leader *row = l->row;
    struct ft_style name = ft_top_fg(FT_COLOR_BRIGHT, true);

    if (row->remote.family) {
        bool is_public = !ft_addr_is_private(&row->remote);
        ft_top_cell(d, x, y, width, false, ft_top_fg(ft_top_egress_color(is_public), true),
                    leader_text(d, l));
    } else if (key == FT_LEADER_EXTENSION) {
        ft_top_cell(d, x, y, width, false, name, row->text);
    } else if (key == FT_LEADER_DIRECTORY) {
        split_path_cell(d, x, y, width, row->text, l->name_offset, name);
    } else {
        ft_top_path_cell(d, x, y, width, row->text, l->name_offset, name);
    }
}

static void delta_text(const struct ft_top_leader *l, bool compared, char *buf, size_t size,
                       enum ft_color *color)
{
    *color = FT_COLOR_DIM;
    if (!compared) {
        buf[0] = '\0';
    } else if (l->is_new) {
        ft_strlcpy(buf, "NEW", size);
        *color = FT_COLOR_CYAN;
    } else if (l->rank_change > 0) {
        snprintf(buf, size, "▲%" PRId32, l->rank_change);
        *color = FT_COLOR_GREEN;
    } else if (l->rank_change < 0) {
        snprintf(buf, size, "▼%" PRId32, -l->rank_change);
        *color = FT_COLOR_RED;
    } else {
        ft_strlcpy(buf, "=", size);
    }
}

static void draw_share(struct ft_top_draw *d, int x, int y, int cells, double bar, uint8_t method)
{
    double value = bar > 0 && bar < 1.0 / cells ? 1.0 / cells : bar;
    struct ft_bar_part part = {.value = value, .style = plain(ft_top_method_color(method))};
    struct ft_bar b = {
        .parts = &part,
        .count = 1,
        .total = 1.0,
        .empty_rune = U'░',
        .empty = plain(FT_COLOR_TRACK),
    };
    ft_canvas_bar(d->canvas, x, y, cells, &b);
}

static void draw_leader_row(struct ft_top_draw *d, struct ft_rect line,
                            const struct ranking_layout *lay, const struct ft_top_row *row,
                            size_t index, const struct ft_top_leaders *all)
{
    bool compared = all->summary.previous_from_wall_ns != 0;
    const struct ft_top_leader *l = row->leader;
    const struct ft_row_leader *lr = l->row;
    bool selected = row->flags & FT_TOP_ROW_SELECTED;
    bool tagged = row->flags & FT_TOP_ROW_TAGGED;
    int y = line.y;
    char buf[48];
    enum ft_color color;

    snprintf(buf, sizeof(buf), "%" PRIu32, lr->rank);
    enum ft_color rank_color = tagged                           ? FT_COLOR_AMBER
                               : lr->rank >= 1 && lr->rank <= 3 ? FT_COLOR_AMBER
                                                                : FT_COLOR_TEXT;
    ft_top_cell(d, lay->x[COL_RANK], y, lay->w[COL_RANK], true, ft_top_fg(rank_color, true), buf);
    delta_text(l, compared, buf, sizeof(buf), &color);
    ft_top_cell(d, lay->x[COL_DELTA], y, lay->w[COL_DELTA], false, plain(color), buf);
    draw_leader_name(d, lay->x[COL_FILE], y, lay->w[COL_FILE], l, all->key);
    ft_top_format_size(lr->bytes, buf, sizeof(buf));
    ft_top_cell(d, lay->x[COL_BYTES], y, lay->w[COL_BYTES], true, plain(FT_COLOR_BRIGHT), buf);
    if (lay->w[COL_SHARE] > 1)
        draw_share(d, lay->x[COL_SHARE], y,
                   lay->w[COL_SHARE] - 1 < SHARE_CELLS ? lay->w[COL_SHARE] - 1 : SHARE_CELLS,
                   l->bar, lr->method);
    ft_format_count(lr->transfers, buf, sizeof(buf));
    ft_top_cell(d, lay->x[COL_XFERS], y, lay->w[COL_XFERS], true, plain(FT_COLOR_TEXT), buf);
    ft_format_count(lr->destinations, buf, sizeof(buf));
    ft_top_cell(d, lay->x[COL_DESTS], y, lay->w[COL_DESTS], true, plain(FT_COLOR_TEXT), buf);
    ft_top_cell(d, lay->x[COL_SENDER], y, lay->w[COL_SENDER], false, plain(FT_COLOR_TEXT),
                lr->senders[0].name);
    if (lay->w[COL_TREND] > 0) {
        double trend[FT_LEADER_SLOTS];
        for (size_t i = 0; i < FT_LEADER_SLOTS; i++)
            trend[i] = (double)lr->trend[i];
        ft_canvas_spark(d->canvas, lay->x[COL_TREND], y, lay->w[COL_TREND], trend, FT_LEADER_SLOTS,
                        0, plain(FT_COLOR_BLUE));
    }

    if (selected) {
        ft_top_select_row(d, line);
        if (tagged)
            ft_canvas_text(d->canvas, line.x + line.w - 1, y, 1, plain(FT_COLOR_BG), "•");
    }
    ft_top_mark_matches(d, lay->x[COL_FILE], y, lay->w[COL_FILE], leader_text(d, l),
                        lr->remote.family ? FT_CUT_END : FT_CUT_START,
                        lr->remote.family ? FT_TOP_FIELD_DEST : FT_TOP_FIELD_FILE, selected);
    ft_top_mark_matches(d, lay->x[COL_SENDER], y, lay->w[COL_SENDER], lr->senders[0].name,
                        FT_CUT_END, FT_TOP_FIELD_PROC, selected);
    ft_top_hits_add(d->hits, line, FT_TOP_TARGET_ROW, (uint32_t)index);
}

static void empty_line(struct ft_top_draw *d, struct ft_rect rows, const char *text)
{
    if (rows.h > 0)
        ft_canvas_text_cut(d->canvas, rows.x + 1, rows.y, rows.w - 1, dim(), text, FT_CUT_END);
}

void ft_top_draw_leaders_table(struct ft_top_draw *d, struct ft_rect header, struct ft_rect rows,
                               size_t first)
{
    const struct ft_top_leaders *l = ft_top_leaders(d->model);
    struct ranking_layout lay;
    struct ft_rect clip = ft_canvas_clip(d->canvas, header);

    ranking_layout(header, l->by, &lay);
    if (header.h > 0)
        draw_ranking_header(d, header, &lay, l);
    ft_canvas_clip(d->canvas, rows);
    ranking_layout((struct ft_rect){rows.x, rows.y, rows.w, 1}, l->by, &lay);

    size_t count = ft_top_row_count(d->model, FT_TOP_LEADERS);
    const char *filter = ft_top_filter_of(d->model, FT_TOP_LEADERS);
    if (d->ui->leaders_unsupported)
        empty_line(d, rows,
                   "This agent does not keep rankings over time. Restart filetrace-agent to "
                   "bring it up to the version of this command.");
    else if (l->answered && count == 0)
        empty_line(d, rows,
                   filter && filter[0]
                       ? "No files in this window match the filter. F4 Esc clears it."
                       : "No files were sent in this window.");
    for (int k = 0; l->answered && !d->ui->leaders_unsupported && k < rows.h; k++) {
        size_t index = first + (size_t)k;
        const struct ft_top_row *row = ft_top_row_at(d->model, FT_TOP_LEADERS, index);
        if (!row)
            break;
        if (row->kind == FT_TOP_ROW_LEADER)
            draw_leader_row(d, (struct ft_rect){rows.x, rows.y + k, rows.w, 1}, &lay, row, index,
                            l);
    }
    ft_canvas_clip(d->canvas, clip);
}

static void side_title(struct ft_top_draw *d, struct ft_rect r, int y, const char *title)
{
    ft_top_title_row(d, (struct ft_rect){r.x, y, r.w, 1}, FT_COLOR_GREEN, title, nullptr);
}

static void directory_line(struct ft_top_draw *d, struct ft_rect r, int y,
                           const struct ft_top_leader *l)
{
    char value[24];

    ft_canvas_text_cut(d->canvas, r.x, y, SIDE_NAME - 1, plain(FT_COLOR_TEXT), l->row->text,
                       FT_CUT_START);
    ft_top_format_size(l->row->bytes, value, sizeof(value));
    ft_top_cell(d, r.x + SIDE_NAME, y, SIDE_VALUE, true, plain(FT_COLOR_BRIGHT), value);
    struct ft_bar_part part = {
        .value = l->bar > 0 && l->bar < 1.0 / SIDE_BAR ? 1.0 / SIDE_BAR : l->bar,
        .style = plain(FT_COLOR_CYAN),
    };
    struct ft_bar bar = {.parts = &part, .count = 1, .total = 1.0};
    int x = r.x + SIDE_NAME + SIDE_VALUE;
    int cells = r.x + r.w - x < SIDE_BAR ? r.x + r.w - x : SIDE_BAR;
    ft_canvas_bar(d->canvas, x, y, cells, &bar);
}

static void destination_line(struct ft_top_draw *d, struct ft_rect r, int y,
                             const struct ft_top_leader *l)
{
    char value[24];
    bool is_public = !ft_addr_is_private(&l->row->remote);
    const char *name = l->host_state == FT_TOP_HOST_NAMED && l->host ? l->host : l->remote_text;

    ft_canvas_text_cut(d->canvas, r.x, y, SIDE_NAME - 1, plain(ft_top_egress_color(is_public)),
                       name, FT_CUT_END);
    ft_top_format_size(l->row->bytes, value, sizeof(value));
    ft_top_cell(d, r.x + SIDE_NAME, y, SIDE_VALUE, true, plain(FT_COLOR_BRIGHT), value);
    int x = r.x + SIDE_NAME + SIDE_VALUE;
    ft_canvas_text_cut(d->canvas, x, y, r.x + r.w - x, dim(), l->row->senders[0].name, FT_CUT_END);
}

/* Breaks a path into lines of at most width columns, after a '/' where one falls in the line. */
static size_t wrap_path(const char *path, int width, size_t *starts, size_t max)
{
    size_t len = strlen(path);
    size_t n = 0;
    size_t off = 0;

    while (off < len && n < max) {
        starts[n++] = off;
        size_t end = off;
        size_t slash = 0;
        int cols = 0;
        while (end < len) {
            int c;
            size_t step = ft_text_next(path + end, len - end, &c);
            if (cols + c > width)
                break;
            cols += c;
            end += step;
            if (path[end - 1] == '/')
                slash = end;
        }
        if (end < len && slash > off)
            end = slash;
        if (end == off)
            end = off + ft_text_next(path + off, len - off, &(int){0});
        off = end;
    }
    return n;
}

struct selected_block {
    const struct ft_top_row *row;
    size_t lines[8];
    size_t nlines;
    bool copies;
};

static bool shows_copies(const struct ft_top_leaders *l, const struct ft_row_leader *row)
{
    return l->key == FT_LEADER_FILE && !row->remote.family && row->file_size > 0 &&
           !(row->flags & FT_LEADER_DELETED);
}

static int selected_height(const struct selected_block *b)
{
    if (!b->row)
        return 0;
    return 1 + (int)b->nlines + 2 + (b->copies ? 1 : 0);
}

static void senders_text(const struct ft_row_leader *row, char *buf, size_t size, bool brief)
{
    char transfers[48];
    char dests[48];
    char names[96];
    size_t listed = 0;

    while (listed < FT_LEADER_SENDERS && row->senders[listed].name[0])
        listed++;
    ft_strlcpy(names, listed ? row->senders[0].name : "-", sizeof(names));
    if (listed > 1 || (row->flags & FT_LEADER_MORE_SENDERS)) {
        size_t len = strlen(names);
        snprintf(names + len, sizeof(names) - len, " +%zu%s", listed - 1,
                 row->flags & FT_LEADER_MORE_SENDERS ? "+" : "");
    }
    count_text(row->transfers, brief ? "xfer" : "transfer", brief ? "xfers" : "transfers",
               transfers, sizeof(transfers));
    count_text(row->destinations, "dest", "dests", dests, sizeof(dests));
    snprintf(buf, size, "%s · %s · %s", names, transfers, dests);
}

static void draw_selected(struct ft_top_draw *d, struct ft_rect r, int y,
                          const struct selected_block *b)
{
    const struct ft_top_leaders *l = ft_top_leaders(d->model);
    const struct ft_top_leader *leader = b->row->leader;
    const struct ft_row_leader *row = leader->row;
    char title[64];
    char text[160];
    int bottom = r.y + r.h;

    snprintf(title, sizeof(title), "Selected · #%" PRIu32 " by %s", row->rank, by_word(l->by));
    side_title(d, r, y++, title);
    const char *name = row->remote.family ? leader_text(d, leader) : row->text;
    for (size_t i = 0; i < b->nlines && y < bottom; i++, y++) {
        size_t end = i + 1 < b->nlines ? b->lines[i + 1] : strlen(name);
        char line[FT_PATH_MAX];
        size_t n = end - b->lines[i] < sizeof(line) ? end - b->lines[i] : sizeof(line) - 1;
        memcpy(line, name + b->lines[i], n);
        line[n] = '\0';
        ft_canvas_text(d->canvas, r.x, y, r.w, plain(FT_COLOR_TEXT), line);
    }
    if (y >= bottom)
        return;
    int value_x = r.x + SIDE_LABEL;
    int value_w = r.w - SIDE_LABEL;
    senders_text(row, text, sizeof(text), false);
    if (ft_text_columns(text) > value_w)
        senders_text(row, text, sizeof(text), true);
    ft_canvas_text(d->canvas, r.x, y, SIDE_LABEL, dim(), "senders");
    ft_canvas_text_cut(d->canvas, value_x, y++, value_w, plain(FT_COLOR_BRIGHT), text, FT_CUT_END);
    if (y >= bottom)
        return;
    snprintf(text, sizeof(text), "%s · %s", ft_top_method_word(row->method),
             ft_top_confidence_word(row->confidence, false));
    ft_canvas_text(d->canvas, r.x, y, SIDE_LABEL, dim(), "method");
    ft_canvas_text_cut(d->canvas, value_x, y++, value_w, plain(ft_top_method_color(row->method)),
                       text, FT_CUT_END);
    if (!b->copies || y >= bottom)
        return;
    double copies = (double)row->bytes / (double)row->file_size;
    char size[24];
    char count[32];
    ft_top_format_size(row->file_size, size, sizeof(size));
    if (copies < 10)
        snprintf(count, sizeof(count), "%.1f", copies);
    else
        ft_format_count((uint64_t)(copies + 0.5), count, sizeof(count));
    snprintf(text, sizeof(text), "≈ %s × %s", count, size);
    ft_canvas_text(d->canvas, r.x, y, SIDE_LABEL, dim(), "copies");
    ft_canvas_text_cut(d->canvas, value_x, y, value_w, plain(FT_COLOR_TEXT), text, FT_CUT_END);
}

/* Rows of the two lists, shortened alike until the panel holds them and the Selected block. */
static void fit_lists(int avail, int want_a, int want_b, int *a, int *b)
{
    *a = want_a;
    *b = want_b;
    for (;;) {
        int need = (*a ? 1 + *a + 1 : 0) + (*b ? 1 + *b + 1 : 0);
        if (need <= avail || (*a == 0 && *b == 0))
            return;
        if (*b >= *a && *b > 0)
            (*b)--;
        else
            (*a)--;
    }
}

void ft_top_draw_leaders_side(struct ft_top_draw *d, struct ft_rect r)
{
    const struct ft_top_leaders *l = ft_top_leaders(d->model);
    struct selected_block sel = {0};

    if (r.w <= SIDE_LABEL || r.h <= 0 || d->ui->leaders_unsupported || !l->answered)
        return;
    size_t index = ft_top_selected(d->model, FT_TOP_LEADERS);
    const struct ft_top_row *row =
        index == SIZE_MAX ? nullptr : ft_top_row_at(d->model, FT_TOP_LEADERS, index);
    if (row && row->kind == FT_TOP_ROW_LEADER) {
        const struct ft_top_leader *leader = row->leader;
        const char *name = leader->row->remote.family ? leader_text(d, leader) : leader->row->text;
        sel.row = row;
        sel.nlines = wrap_path(name, r.w, sel.lines, FT_ARRAY_LEN(sel.lines));
        sel.copies = shows_copies(l, leader->row);
    }

    int want_dirs = (int)(l->ndirectories < SIDE_LIST_ROWS ? l->ndirectories : SIDE_LIST_ROWS);
    int want_dests = (int)(l->ndestinations < SIDE_LIST_ROWS ? l->ndestinations : SIDE_LIST_ROWS);
    int dirs;
    int dests;
    fit_lists(r.h - selected_height(&sel), want_dirs, want_dests, &dirs, &dests);

    struct ft_rect clip = ft_canvas_clip(d->canvas, r);
    int y = r.y;
    if (dirs > 0) {
        side_title(d, r, y++, "Top directories");
        for (int i = 0; i < dirs; i++)
            directory_line(d, r, y++, &l->directories[i]);
        y++;
    }
    if (dests > 0) {
        side_title(d, r, y++, "Top destinations");
        for (int i = 0; i < dests; i++)
            destination_line(d, r, y++, &l->destinations[i]);
        y++;
    }
    if (sel.row)
        draw_selected(d, r, y, &sel);
    ft_canvas_clip(d->canvas, clip);
}

void ft_top_draw_leaders_legend(struct ft_top_draw *d, struct ft_rect r)
{
    char top[48];
    snprintf(top, sizeof(top), " not in previous top %u", PREVIOUS_TOP);
    const struct seg legend[] = {
        {"█", plain(FT_COLOR_GREEN)},
        {" sendfile  ", dim()},
        {"█", plain(FT_COLOR_AMBER)},
        {" read-write   Δ ", dim()},
        {"▲", plain(FT_COLOR_GREEN)},
        {" up  ", dim()},
        {"▼", plain(FT_COLOR_RED)},
        {" down  ", dim()},
        {"NEW", plain(FT_COLOR_CYAN)},
        {top, dim()},
        {"   Enter: who sent it and where (inspect file)", dim()},
    };
    size_t n = FT_ARRAY_LEN(legend);

    if (r.h <= 0)
        return;
    /* The hint about Enter goes first when the row is short. */
    if (segs_columns(legend, n) > r.w)
        n--;
    draw_segs(d->canvas, r.x, r.y, r.w, legend, n);
}
