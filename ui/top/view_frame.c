#include "ui/top/views.h"

#include "filetrace/format.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

constexpr int ROOMY_ROWS = 36; /* from this height the spacer under the head and the rule exist */
constexpr int PANEL_COLS = 24;
constexpr int PANEL_GAP = 2; /* the rule beside the panel and a blank column */
constexpr int INSPECT_ROWS = 7;
constexpr int SIDE_COLS = 44;
constexpr int SIDE_GAP = 2;
constexpr int CARD_ROWS = 5;
constexpr int METER_LABEL = 8;
constexpr int METER_INSIDE = 44;
constexpr size_t LINE_SPANS = 32;
constexpr size_t LINE_BYTES = 1536;
constexpr size_t FKEYS_MAX = 12;

static int head_rows(enum ft_top_mode mode)
{
    switch (mode) {
    case FT_TOP_TRANSFERS:
        return 5;
    case FT_TOP_PROCESSES:
        return 2;
    case FT_TOP_DESTINATIONS:
    case FT_TOP_FILES:
        return 3;
    default:
        return CARD_ROWS;
    }
}

static int prompt_rows(enum ft_top_prompt prompt)
{
    return prompt == FT_TOP_PROMPT_FILTER ? 2 : prompt == FT_TOP_PROMPT_NONE ? 0 : 1;
}

void ft_top_layout(const struct ft_top_ui *ui, int cols, int rows, struct ft_top_layout *out)
{
    *out = (struct ft_top_layout){.cols = cols, .rows = rows};
    if (cols < FT_TOP_MIN_COLS || rows < FT_TOP_MIN_ROWS) {
        out->too_small = true;
        return;
    }

    bool roomy = rows >= ROOMY_ROWS;
    bool leaders = ui->mode == FT_TOP_LEADERS;
    bool overlay = ui->overlay != FT_TOP_OVERLAY_NONE;
    bool panel = !leaders && !overlay && ui->panel != FT_TOP_PANEL_NONE;
    int top = 0;
    int bottom = rows - 1; /* the topmost row taken by the blocks placed from the bottom up */

    if (!panel) {
        out->head = (struct ft_rect){0, 0, cols, head_rows(ui->mode) + (roomy ? 1 : 0)};
        top = out->head.h;
    }
    out->tabs = (struct ft_rect){0, top++, cols, 1};
    out->keys = (struct ft_rect){0, bottom, cols, 1};
    bottom -= prompt_rows(ui->prompt);
    out->prompt = (struct ft_rect){0, bottom, cols, prompt_rows(ui->prompt)};
    if (overlay) {
        out->overlay = (struct ft_rect){0, top, cols, bottom - top};
        return;
    }
    if (ui->inspect) {
        bottom -= INSPECT_ROWS;
        out->inspect = (struct ft_rect){0, bottom, cols, INSPECT_ROWS};
    }

    int x = 0;
    int width = cols;
    if (panel) {
        out->panel = (struct ft_rect){0, top, PANEL_COLS, bottom - top};
        x = PANEL_COLS + PANEL_GAP;
        width = cols - x;
    }
    if (leaders) {
        width = cols - SIDE_COLS - SIDE_GAP;
        out->side = (struct ft_rect){cols - SIDE_COLS, top, SIDE_COLS, bottom - top};
    }
    if (!ui->inspect) {
        if (!leaders) {
            out->status = (struct ft_rect){x, --bottom, width, 1};
        }
        out->context = (struct ft_rect){x, --bottom, width, 1};
        if (roomy)
            out->rule = (struct ft_rect){x, --bottom, width, 1};
    }
    out->header = (struct ft_rect){x, top, width, 1};
    out->table = (struct ft_rect){x, top + 1, width, bottom - top - 1};
}

/* Text in styled pieces, drawn side by side; what does not fit ends in "…". */
struct span {
    size_t at; /* offset of its text in the line's buffer */
    struct ft_style style;
};

struct line {
    struct span spans[LINE_SPANS];
    size_t count;
    char text[LINE_BYTES];
    size_t used;
};

[[gnu::format(printf, 3, 4)]]
static void add(struct line *l, struct ft_style s, const char *fmt, ...)
{
    va_list ap;
    size_t room = LINE_BYTES - l->used;

    if (l->count == LINE_SPANS || room < 2)
        return;
    va_start(ap, fmt);
    int n = vsnprintf(l->text + l->used, room, fmt, ap);
    va_end(ap);
    /* A piece that would be cut in the buffer is left out rather than split mid-character. */
    if (n < 0 || (size_t)n >= room) {
        l->text[l->used] = '\0';
        return;
    }
    l->spans[l->count++] = (struct span){.at = l->used, .style = s};
    l->used += (size_t)n + 1;
}

static int draw_line(struct ft_canvas *c, int x, int y, int width, const struct line *l)
{
    int total = 0;
    int used = 0;

    for (size_t i = 0; i < l->count; i++)
        total += ft_text_columns(l->text + l->spans[i].at);
    for (size_t i = 0; i < l->count && used < width; i++) {
        const char *text = l->text + l->spans[i].at;
        struct ft_style s = l->spans[i].style;
        int w = ft_text_columns(text);
        if (total > width && used + w > width - 1) {
            ft_canvas_text(c, x + used, y, width - used - 1, s, text);
            ft_canvas_text(c, x + width - 1, y, 1, s, "…");
            return width;
        }
        ft_canvas_text(c, x + used, y, w, s, text);
        used += w;
    }
    return used;
}

static struct ft_style fg(enum ft_color color, bool bold)
{
    return ft_top_fg(color, bold);
}

/* A badge: dark bold text on a color; reversed when there is no color to show. */
static struct ft_style badge_style(const struct ft_top_draw *d, enum ft_color color)
{
    struct ft_style s = ft_top_on(color, true);
    if (d->depth == FT_DEPTH_NONE)
        s.attrs |= FT_ATTR_REVERSE;
    return s;
}

static const char *plural(uint64_t n, const char *one, const char *many)
{
    return n == 1 ? one : many;
}

static bool filtered(const struct ft_top_draw *d, enum ft_top_mode mode)
{
    const char *f = ft_top_filter_of(d->model, mode);
    return f && f[0];
}

static bool agent_unreachable(const struct ft_top_ui *ui)
{
    return ui->agent_code != FT_EXIT_OK || ui->agent_error[0];
}

void ft_top_since_text(uint64_t since_wall_ns, uint64_t now_wall_ns, bool seconds, char *buf,
                       size_t size)
{
    time_t since = (time_t)(since_wall_ns / FT_NS_PER_SEC);
    time_t now = (time_t)((now_wall_ns ? now_wall_ns : since_wall_ns) / FT_NS_PER_SEC);
    struct tm at;
    struct tm today;

    if (!localtime_r(&since, &at) || !localtime_r(&now, &today)) {
        ft_strlcpy(buf, "-", size);
        return;
    }
    bool same_day = at.tm_year == today.tm_year && at.tm_yday == today.tm_yday;
    const char *fmt = !same_day ? "%b %d %H:%M" : seconds ? "%H:%M:%S" : "%H:%M";
    if (strftime(buf, size, fmt, &at) == 0)
        ft_strlcpy(buf, "-", size);
}

static void since_of(const struct ft_top_draw *d, bool seconds, char *buf, size_t size)
{
    ft_top_since_text(d->ui->since_wall_ns, ft_top_totals(d->model)->now_wall_ns, seconds, buf,
                      size);
}

/* The kernel release up to its third number: "6.8.0" of "6.8.0-45-generic". */
static void kernel_release(const char *release, char *buf, size_t size)
{
    size_t n = 0;
    int dots = 0;

    while (release[n] && n + 1 < size) {
        char ch = release[n];
        if (ch == '.' && ++dots == 3)
            break;
        if (ch != '.' && (ch < '0' || ch > '9'))
            break;
        n++;
    }
    if (n == 0) {
        ft_strlcpy(buf, release, size);
        return;
    }
    memcpy(buf, release, n);
    buf[n] = '\0';
}

/* "eBPF" for the Linux backends, else the backend's own name. */
static void backend_word(const char *backend, char *buf, size_t size)
{
    if (strstr(backend, "eBPF"))
        ft_strlcpy(buf, "eBPF", size);
    else
        ft_strlcpy(buf, backend[0] ? backend : "backend", size);
}

struct segment {
    double value;
    enum ft_color color;
};

/* An htop meter: label, "[", the segments, the caption right-aligned, "]". */
static void meter(struct ft_top_draw *d, int x, int y, const char *label,
                  const struct segment *segs, size_t n, double total, const char *caption)
{
    struct ft_canvas *c = d->canvas;
    struct ft_style frame = fg(FT_COLOR_BRIGHT, true);
    int caption_cols = ft_text_columns(caption);
    /* The bar keeps one blank column before its caption. */
    int area = METER_INSIDE - caption_cols - 1 > 0 ? METER_INSIDE - caption_cols - 1 : 0;
    struct ft_bar_part parts[4];
    double sum = 0;

    n = n < FT_ARRAY_LEN(parts) ? n : FT_ARRAY_LEN(parts);
    for (size_t i = 0; i < n; i++)
        sum += segs[i].value > 0 ? segs[i].value : 0;
    if (total < 0)
        total = area; /* one column for each */
    double whole = total > 0 ? total : sum;
    double least = area > 0 ? whole / area : 0;
    for (size_t i = 0; i < n; i++) {
        double v = segs[i].value;
        parts[i] = (struct ft_bar_part){v > 0 && v < least ? least : v, fg(segs[i].color, false)};
    }
    struct ft_bar bar = {.parts = parts, .count = n, .total = total, .rune = '|'};

    ft_canvas_text(c, x, y, METER_LABEL, fg(FT_COLOR_CYAN, true), label);
    ft_canvas_text(c, x + METER_LABEL, y, 1, frame, "[");
    ft_canvas_bar(c, x + METER_LABEL + 1, y, area, &bar);
    ft_canvas_text(c, x + METER_LABEL + 1 + METER_INSIDE - caption_cols, y, caption_cols,
                   fg(FT_COLOR_DIM, false), caption);
    ft_canvas_text(c, x + METER_LABEL + 1 + METER_INSIDE, y, 1, frame, "]");
}

static double scale_of(const struct ft_top_meter *m)
{
    return m->scale ? (double)m->scale : 1;
}

static void rate_meter(struct ft_top_draw *d, int x, int y, const struct ft_top_totals *t)
{
    char caption[32];
    uint64_t sendfile = t->rate_by_method[FT_METHOD_SENDFILE];
    uint64_t rest = t->rate.value > sendfile ? t->rate.value - sendfile : 0;
    struct segment segs[] = {{(double)sendfile, FT_COLOR_GREEN}, {(double)rest, FT_COLOR_AMBER}};

    ft_top_format_rate(t->rate.value, caption, sizeof(caption));
    meter(d, x, y, "TX", segs, 2, scale_of(&t->rate), caption);
}

/* How much of everything the machine sends is files; most traffic is not. */
static void outbound_meter(struct ft_top_draw *d, int x, int y, const struct ft_top_totals *t)
{
    char rate[32];
    char caption[48];

    if (!t->stats)
        return;
    uint64_t all = t->stats->tx_rate;
    /* The two rates are taken over slightly different spans, so files can seem to exceed all. */
    uint64_t files = t->rate.value < all ? t->rate.value : all;
    struct segment seg = {(double)files, FT_COLOR_TEXT};

    ft_top_format_rate(all, rate, sizeof(rate));
    if (all)
        snprintf(caption, sizeof(caption), "files %.0f%% of %s out",
                 (double)files * 100 / (double)all, rate);
    else
        ft_strlcpy(caption, "nothing is sent", sizeof(caption));
    meter(d, x, y, "NET", &seg, 1, all ? (double)all : 1, caption);
}

static void share_meter(struct ft_top_draw *d, int x, int y, const char *label, uint64_t part,
                        uint64_t whole, enum ft_color color)
{
    char rate[32];
    char caption[48];
    double share = whole ? (double)part / (double)whole : 0;
    struct segment seg = {(double)part, color};

    ft_top_format_rate(part, rate, sizeof(rate));
    snprintf(caption, sizeof(caption), "%s %.0f%%", rate, share * 100);
    meter(d, x, y, label, &seg, 1, whole ? (double)whole : 1, caption);
}

static void count_meter(struct ft_top_draw *d, int x, int y, const char *label, uint64_t value,
                        double total, enum ft_color color, const char *fmt)
{
    char count[32];
    char caption[48];
    struct segment seg = {(double)value, color};

    ft_format_count(value, count, sizeof(count));
    snprintf(caption, sizeof(caption), fmt, count);
    meter(d, x, y, label, &seg, 1, total, caption);
}

static void meters(struct ft_top_draw *d, struct ft_rect r, const struct ft_top_totals *t)
{
    char caption[48];
    int x = r.x;
    int y = r.y;

    switch (d->ui->mode) {
    case FT_TOP_TRANSFERS: {
        rate_meter(d, x, y++, t);
        count_meter(d, x, y++, "XFER/s", t->started.value, scale_of(&t->started), FT_COLOR_BLUE,
                    "%s/s");
        struct segment exact = {t->exact_share, FT_COLOR_GREEN};
        snprintf(caption, sizeof(caption), "%.1f%%", t->exact_share * 100);
        meter(d, x, y++, "EXACT", &exact, 1, 1, caption);
        struct segment egress[] = {{(double)t->rate_public, FT_COLOR_PURPLE},
                                   {(double)t->rate_private, FT_COLOR_BLUE}};
        int pub = t->rate.value ? (int)(t->public_share * 100 + 0.5) : 0;
        snprintf(caption, sizeof(caption), "pub %d%% priv %d%%", pub,
                 t->rate.value ? 100 - pub : 0);
        meter(d, x, y++, "EGRESS", egress, 2, 0, caption);
        if (y < r.y + r.h)
            outbound_meter(d, x, y, t);
        break;
    }
    case FT_TOP_PROCESSES:
        rate_meter(d, x, y++, t);
        count_meter(d, x, y, "PROCS", t->processes.value, -1, FT_COLOR_BLUE, "%s sending");
        break;
    case FT_TOP_DESTINATIONS:
        share_meter(d, x, y++, "PUBLIC", t->rate_public, t->rate.value, FT_COLOR_PURPLE);
        share_meter(d, x, y++, "PRIVATE", t->rate_private, t->rate.value, FT_COLOR_BLUE);
        count_meter(d, x, y, "NEW 5m", t->new_destinations.value, -1, FT_COLOR_AMBER,
                    "%s first seen");
        break;
    case FT_TOP_FILES: {
        count_meter(d, x, y++, "FILES", t->files.value, scale_of(&t->files), FT_COLOR_BLUE,
                    "%s in flight");
        count_meter(d, x, y++, "FAN-OUT", t->fanout.value, scale_of(&t->fanout), FT_COLOR_PURPLE,
                    "max %s xfers");
        struct segment cache = {t->sendfile_share, FT_COLOR_GREEN};
        snprintf(caption, sizeof(caption), "%.0f%% sendfile", t->sendfile_share * 100);
        meter(d, x, y, "CACHE", &cache, 1, 1, caption);
        break;
    }
    default:
        break;
    }
}

static int line_columns(const struct line *l)
{
    int total = 0;
    for (size_t i = 0; i < l->count; i++)
        total += ft_text_columns(l->text + l->spans[i].at);
    return total;
}

/* Detail 0 is the whole row; 1 leaves out the ring buffer, 2 the start as well. */
static void agent_line(const struct ft_top_draw *d, const struct ft_top_totals *t, int detail,
                       struct line *l)
{
    const struct ft_top_ui *ui = d->ui;
    char word[48];
    char drops[32];
    char since[32];

    add(l, fg(FT_COLOR_CYAN, true), ui->session_only ? "Session: " : "Agent: ");
    if (ui->session_only && ui->collector_lost) {
        add(l, fg(FT_COLOR_RED, false), "collector stopped");
    } else if (agent_unreachable(ui)) {
        add(l, fg(FT_COLOR_RED, false), "%s%s%s",
            ui->session_only ? "no answer" : "unreachable, retrying",
            ui->agent_error[0] ? " · " : "", ui->agent_error);
    } else if (!t->agent) {
        add(l, fg(FT_COLOR_DIM, false), "%s",
            ui->session_only ? "starting" : "waiting for its first answer");
    } else {
        backend_word(t->backend, word, sizeof(word));
        ft_format_count(t->events_dropped, drops, sizeof(drops));
        add(l, fg(FT_COLOR_TEXT, false), "%s", ui->session_only ? "collecting" : "running");
        if (detail < 2 && ui->since_wall_ns) {
            since_of(d, true, since, sizeof(since));
            add(l, fg(FT_COLOR_TEXT, false), " since %s", since);
        }
        add(l, fg(FT_COLOR_TEXT, false), " · %s ", word);
        if (t->degraded)
            add(l, fg(FT_COLOR_RED, false), "degraded");
        else
            add(l, fg(FT_COLOR_TEXT, false), "ok");
        if (detail < 1) {
            add(l, fg(FT_COLOR_TEXT, false), " · ringbuf ");
            add(l, fg(FT_COLOR_BRIGHT, false), "%" PRIu32 "%%", t->queue_percent);
        }
        add(l, fg(FT_COLOR_TEXT, false), " · drops ");
        add(l, fg(t->events_dropped ? FT_COLOR_RED : FT_COLOR_BRIGHT, false), "%s", drops);
    }
    if (ui->lag_ns)
        add(l, fg(FT_COLOR_AMBER, false), " · ui lag %.1fs", (double)ui->lag_ns / 1e9);
}

/* The agent row in the most detail that fits the width. */
static void agent_row(const struct ft_top_draw *d, const struct ft_top_totals *t, int width,
                      struct line *l)
{
    for (int detail = 0; detail < 3; detail++) {
        *l = (struct line){0};
        agent_line(d, t, detail, l);
        if (line_columns(l) <= width)
            return;
    }
}

static void host_line(const struct ft_top_draw *d, const struct ft_top_totals *t, struct line *l)
{
    char release[32];
    char clock[16];

    add(l, fg(FT_COLOR_CYAN, true), "Host: ");
    if (d->host && d->host->hostname[0])
        add(l, fg(FT_COLOR_TEXT, false), "%s · ", d->host->hostname);
    if (d->host && d->host->release[0]) {
        kernel_release(d->host->release, release, sizeof(release));
        add(l, fg(FT_COLOR_TEXT, false), "kernel %s · ", release);
    }
    if (t->now_wall_ns)
        ft_format_clock_local(t->now_wall_ns, clock, sizeof(clock));
    else
        ft_strlcpy(clock, "--:--:--", sizeof(clock));
    add(l, fg(FT_COLOR_TEXT, false), "%s", clock);
}

static const char *group_word(enum ft_top_mode mode, enum ft_top_group group)
{
    switch (group) {
    case FT_TOP_GROUP_PROCESS:
        return "process";
    case FT_TOP_GROUP_SCRIPT:
        return "script";
    case FT_TOP_GROUP_DESTINATION:
        return "destination";
    case FT_TOP_GROUP_DIRECTORY:
        return "directory";
    case FT_TOP_GROUP_SUBNET:
        return "/24 subnet";
    default:
        return mode == FT_TOP_DESTINATIONS ? "remote IP" : "none";
    }
}

/* "by remote IP · F7 /24 subnet, process": the grouping in effect and the others offered. */
static void grouping_line(const struct ft_top_draw *d, enum ft_top_mode mode, const char *prefix,
                          struct line *l)
{
    enum ft_top_group now = ft_top_group_of(d->model, mode);
    size_t count;
    const enum ft_top_group *groups = ft_top_mode_groups(mode, &count);
    char others[160];
    size_t len = 0;

    others[0] = '\0';
    for (size_t i = 0; i < count && len < sizeof(others); i++) {
        if (groups[i] == now)
            continue;
        len += (size_t)snprintf(others + len, sizeof(others) - len, "%s%s", len ? ", " : "",
                                group_word(mode, groups[i]));
    }
    add(l, fg(FT_COLOR_TEXT, false), "%s%s", prefix, group_word(mode, now));
    if (others[0]) {
        add(l, fg(FT_COLOR_TEXT, false), " · ");
        add(l, fg(FT_COLOR_BRIGHT, false), "F7");
        add(l, fg(FT_COLOR_TEXT, false), " %s", others);
    }
}

static void summary_lines(const struct ft_top_draw *d, const struct ft_top_totals *t, int width,
                          struct line *lines, size_t *count)
{
    enum ft_top_mode mode = d->ui->mode;
    struct ft_style label = fg(FT_COLOR_CYAN, true);
    struct ft_style text = fg(FT_COLOR_TEXT, false);
    struct ft_style bright = fg(FT_COLOR_BRIGHT, true);
    struct ft_style key = fg(FT_COLOR_BRIGHT, false);
    struct line *l = lines;

    switch (mode) {
    case FT_TOP_TRANSFERS: {
        uint64_t processes = t->processes.value;
        add(l, label, "Active: ");
        add(l, bright, "%" PRIu32, t->transfers);
        add(l, text, " %s, ", plural(t->transfers, "transfer", "transfers"));
        add(l, bright, "%" PRIu64, processes);
        add(l, text, " %s, ", plural(processes, "process", "processes"));
        add(l, bright, "%" PRIu32, t->destinations);
        add(l, text, " %s (", plural(t->destinations, "destination", "destinations"));
        add(l, fg(FT_COLOR_PURPLE, false), "%" PRIu32 " public", t->destinations_public);
        add(l, text, ")");
        l++;
        add(l, label, "Methods: ");
        add(l, fg(FT_COLOR_GREEN, false), "%" PRIu32 " sendfile/EXACT",
            t->transfers_by_method[FT_METHOD_SENDFILE]);
        add(l, text, " · ");
        add(l, fg(FT_COLOR_AMBER, false), "%" PRIu32 " read-write/INFERRED",
            t->transfers_by_method[FT_METHOD_READ_SEND]);
        for (size_t m = FT_METHOD_READ_SEND + 1; m < FT_TOP_METHODS; m++) {
            if (!t->transfers_by_method[m])
                continue;
            add(l, text, " · ");
            add(l, fg(FT_COLOR_AMBER, false), "%" PRIu32 " %s", t->transfers_by_method[m],
                ft_top_method_word((uint8_t)m));
        }
        l++;
        agent_row(d, t, width, l++);
        host_line(d, t, l++);
        struct ft_style dim = fg(FT_COLOR_DIM, false);
        add(l, fg(FT_COLOR_GREEN, false), "■");
        add(l, dim, " sendfile  ");
        add(l, fg(FT_COLOR_AMBER, false), "■");
        add(l, dim, " read-write  ");
        add(l, fg(FT_COLOR_PURPLE, false), "■");
        add(l, dim, " public dest  ");
        add(l, fg(FT_COLOR_BLUE, false), "■");
        add(l, dim, " private dest");
        l++;
        break;
    }
    case FT_TOP_PROCESSES:
        if (ft_top_tree_of(d->model)) {
            add(l, label, "Tree: ");
            add(l, text, "parent → child process → file → destination · ");
            add(l, key, "+");
            add(l, text, " collapsed, ");
            add(l, key, "-");
            add(l, text, " expanded");
        } else {
            add(l, label, "List: ");
            add(l, text, "one row per sending process · ");
            add(l, key, "F5");
            add(l, text, " shows the tree");
        }
        l++;
        add(l, label, "Totals: ");
        add(l, text, "RATE now · TOTAL since agent start · FILES / DESTS active");
        l++;
        break;
    case FT_TOP_DESTINATIONS:
        add(l, label, "Destinations: ");
        add(l, bright, "%" PRIu32, t->destinations);
        add(l, text, " active (");
        add(l, fg(FT_COLOR_PURPLE, false), "%" PRIu32 " public", t->destinations_public);
        add(l, text, ", ");
        add(l, fg(FT_COLOR_BLUE, false), "%" PRIu32 " private", t->destinations_private);
        add(l, text, ")");
        l++;
        add(l, label, "Grouping: ");
        grouping_line(d, mode, "by ", l++);
        add(l, label, "Names: ");
        add(l, text, "reverse DNS %s (", ft_top_resolve_of(d->model) ? "on" : "off");
        add(l, key, "n");
        add(l, text, ") · ");
        add(l, fg(FT_COLOR_AMBER, false), "NEW");
        add(l, text, " = first seen in the last 5 min");
        l++;
        break;
    case FT_TOP_FILES:
        add(l, label, "Files: ");
        add(l, text, "one row per file in flight, all its transfers merged");
        l++;
        add(l, label, "ACTIVE ");
        add(l, text, "= transfers now · ");
        add(l, label, "DESTS ");
        add(l, text, "= unique remotes · ");
        add(l, label, "EGRESS ");
        add(l, fg(FT_COLOR_PURPLE, false), "public");
        add(l, text, "/");
        add(l, fg(FT_COLOR_BLUE, false), "private");
        add(l, text, " split");
        l++;
        add(l, label, "Group: ");
        grouping_line(d, mode, "", l++);
        break;
    default:
        break;
    }
    *count = (size_t)(l - lines);
}

static void draw_head(struct ft_top_draw *d, struct ft_rect r)
{
    const struct ft_top_totals *t = ft_top_totals(d->model);
    struct line lines[5] = {0};
    size_t count = 0;
    int x = r.x + (r.w + 4) / 2;

    meters(d, r, t);
    summary_lines(d, t, r.x + r.w - x, lines, &count);
    for (size_t i = 0; i < count && (int)i < r.h; i++)
        draw_line(d->canvas, x, r.y + (int)i, r.x + r.w - x, &lines[i]);
}

static void delay_text(uint64_t delay_ns, char *buf, size_t size)
{
    snprintf(buf, size, "%.1fs", (double)delay_ns / 1e9);
}

/* The state of the view at the right of the tabs: "live · refresh 1.0s · rDNS off (n)". */
static void state_text(const struct ft_top_draw *d, char *buf, size_t size)
{
    const struct ft_top_ui *ui = d->ui;
    const char *live = ui->paused ? "" : "live · ";
    char delay[16];

    delay_text(ui->delay_ns, delay, sizeof(delay));
    switch (ui->mode) {
    case FT_TOP_TRANSFERS:
        snprintf(buf, size, "%srefresh %s · rDNS %s (n)", live, delay,
                 ft_top_resolve_of(d->model) ? "on" : "off");
        break;
    case FT_TOP_PROCESSES:
        snprintf(buf, size, "tree %s (F5) · %srefresh %s", ft_top_tree_of(d->model) ? "on" : "off",
                 live, delay);
        break;
    case FT_TOP_DESTINATIONS:
        snprintf(buf, size, "%srefresh %s · rDNS %s", live, delay,
                 ft_top_resolve_of(d->model) ? "on" : "off");
        break;
    default:
        snprintf(buf, size, "%srefresh %s · history of a file: L Leaders", live, delay);
        break;
    }
}

struct badge {
    char text[64];
    struct ft_style style;
};

/* Trouble with the agent, in the modes whose summary has no Agent row. */
static bool agent_badge(const struct ft_top_draw *d, struct badge *b)
{
    const struct ft_top_ui *ui = d->ui;
    const struct ft_top_totals *t = ft_top_totals(d->model);
    char count[32];

    b->style = badge_style(d, FT_COLOR_RED);
    if (ui->session_only && ui->collector_lost) {
        ft_strlcpy(b->text, " collector stopped ", sizeof(b->text));
    } else if (agent_unreachable(ui)) {
        ft_strlcpy(b->text, ui->session_only ? " no answer " : " agent unreachable ",
                   sizeof(b->text));
    } else if (ui->lag_ns) {
        b->style = badge_style(d, FT_COLOR_AMBER);
        snprintf(b->text, sizeof(b->text), " ui lag %.1fs ", (double)ui->lag_ns / 1e9);
    } else if (t->agent && t->degraded && t->events_dropped) {
        ft_format_count(t->events_dropped, count, sizeof(count));
        snprintf(b->text, sizeof(b->text), " %s %s lost ", count,
                 plural(t->events_dropped, "event", "events"));
    } else if (t->agent && t->degraded) {
        ft_strlcpy(b->text, " agent degraded ", sizeof(b->text));
    } else {
        return false;
    }
    return true;
}

static const char SESSION_BADGE[] = " SESSION ";

/* The SESSION badge, long when it is the only badge and fits with the text beside it. */
static void session_badge(const struct ft_top_draw *d, bool alone, int room, struct badge *b)
{
    char since[32];

    b->style = badge_style(d, FT_COLOR_BLUE);
    ft_strlcpy(b->text, SESSION_BADGE, sizeof(b->text));
    if (!alone || !d->ui->since_wall_ns)
        return;
    since_of(d, true, since, sizeof(since));
    char text[sizeof(b->text)];
    snprintf(text, sizeof(text), " SESSION since %s ", since);
    if (ft_text_columns(text) <= room)
        ft_strlcpy(b->text, text, sizeof(b->text));
}

static void draw_tab_state(struct ft_top_draw *d, struct ft_rect r, int from)
{
    const struct ft_top_ui *ui = d->ui;
    struct badge before[2];
    size_t nbefore = 0;
    struct badge after;
    bool has_after = ui->mode != FT_TOP_TRANSFERS && agent_badge(d, &after);
    char text[160];
    char agent[64] = "";

    if (ui->paused) {
        before[nbefore].style = badge_style(d, FT_COLOR_AMBER);
        ft_strlcpy(before[nbefore++].text, " PAUSED ", sizeof(before[0].text));
    } else if (ui->skipped_ns) {
        before[nbefore].style = badge_style(d, FT_COLOR_AMBER);
        snprintf(before[nbefore++].text, sizeof(before[0].text), " +%" PRIu64 "s ",
                 (ui->skipped_ns + FT_NS_PER_SEC / 2) / FT_NS_PER_SEC);
    }
    if (filtered(d, ui->mode)) {
        const struct ft_top_view *v = ft_top_view_of(d->model, ui->mode);
        before[nbefore].style = badge_style(d, FT_COLOR_AMBER);
        snprintf(before[nbefore++].text, sizeof(before[0].text), " FILTERED %zu/%zu ", v->shown,
                 v->total);
    }
    state_text(d, text, sizeof(text));
    int text_cols = ft_text_columns(text);
    if (!ui->session_only && ui->since_wall_ns) {
        char since[32];
        since_of(d, false, since, sizeof(since));
        snprintf(agent, sizeof(agent), "agent since %s · ", since);
    }

    /* From the right: SESSION, the agent's badge, the other badges, then the state text. */
    int room = r.x + r.w - from - 1;
    int x = r.x + r.w;
    if (ui->session_only) {
        struct badge s;
        session_badge(d, !has_after && nbefore == 0, room - text_cols - 1, &s);
        int w = ft_text_columns(s.text);
        x -= w;
        ft_canvas_text(d->canvas, x, r.y, w, s.style, s.text);
        x--;
        room -= w + 1;
    }
    if (has_after && ft_text_columns(after.text) <= room) {
        int w = ft_text_columns(after.text);
        x -= w;
        ft_canvas_text(d->canvas, x, r.y, w, after.style, after.text);
        x--;
        room -= w + 1;
    }
    for (size_t i = nbefore; i-- > 0;) {
        int w = ft_text_columns(before[i].text);
        if (w > room)
            break;
        x -= w;
        ft_canvas_text(d->canvas, x, r.y, w, before[i].style, before[i].text);
        x--;
        room -= w + 1;
    }
    int agent_cols = ft_text_columns(agent);
    if (text_cols + agent_cols <= room) {
        x -= text_cols;
        ft_canvas_text(d->canvas, x, r.y, text_cols, fg(FT_COLOR_DIM, false), text);
        ft_canvas_text(d->canvas, x - agent_cols, r.y, agent_cols, fg(FT_COLOR_DIM, false), agent);
    } else if (text_cols <= room) {
        ft_canvas_text(d->canvas, x - text_cols, r.y, text_cols, fg(FT_COLOR_DIM, false), text);
    }
}

/* Leaders has no Agent row either: its trouble takes the right end of the row from the bar. */
static struct ft_rect leaders_bar_room(struct ft_top_draw *d, struct ft_rect r, int from)
{
    struct badge b;

    if (d->ui->session_only) {
        int w = ft_text_columns(SESSION_BADGE);
        ft_canvas_text(d->canvas, r.x + r.w - w, r.y, w, badge_style(d, FT_COLOR_BLUE),
                       SESSION_BADGE);
        r.w -= w + 1;
    }
    if (!agent_badge(d, &b))
        return r;
    int w = ft_text_columns(b.text);
    if (w + 1 > r.x + r.w - from)
        return r;
    ft_canvas_text(d->canvas, r.x + r.w - w, r.y, w, b.style, b.text);
    r.w -= w + 1;
    return r;
}

static int draw_tabs(struct ft_top_draw *d, struct ft_rect r)
{
    static const char *const names[] = {
        [FT_TOP_TRANSFERS] = " 1 Transfers ",       [FT_TOP_PROCESSES] = " 2 Processes ",
        [FT_TOP_DESTINATIONS] = " 3 Destinations ", [FT_TOP_FILES] = " 4 Files ",
        [FT_TOP_LEADERS] = " L Leaders ",
    };
    int x = r.x;

    for (size_t i = 0; i < FT_ARRAY_LEN(names) && x < r.x + r.w; i++) {
        struct ft_style s = i == d->ui->mode
                                ? ft_top_on(FT_COLOR_CYAN, true)
                                : (struct ft_style){.fg = FT_COLOR_TEXT, .bg = FT_COLOR_PANEL};
        int n = ft_canvas_text(d->canvas, x, r.y, r.x + r.w - x, s, names[i]);
        ft_top_hits_add(d->hits, (struct ft_rect){x, r.y, n, 1}, FT_TOP_TARGET_TAB, (uint32_t)i);
        x += n;
    }
    return x;
}

static const char *sort_label(enum ft_top_mode mode, enum ft_top_sort key)
{
    size_t n;
    const struct ft_top_sort_option *options = ft_top_mode_sorts(mode, &n);

    for (size_t i = 0; i < n; i++) {
        if (options[i].key == key)
            return options[i].label;
    }
    return n ? options[0].label : "";
}

static void selected_process(struct line *l, const struct ft_top_process *p, const char *script)
{
    struct ft_style dim = fg(FT_COLOR_DIM, false);

    add(l, fg(FT_COLOR_CYAN, true), "▶ %" PRIu32 " ", p->pid);
    if (p->title[0])
        add(l, fg(FT_COLOR_BRIGHT, true), "%s", p->title);
    add(l, dim, "  cwd ");
    if (p->cwd && p->cwd[0])
        add(l, fg(FT_COLOR_TEXT, false), "%s", p->cwd);
    else
        add(l, dim, "—");
    add(l, dim, "  script ");
    add(l, fg(FT_COLOR_AMBER, false), "%s", script && script[0] ? script : "—");
}

static void selected_line(const struct ft_top_row *r, struct line *l)
{
    struct ft_style dim = fg(FT_COLOR_DIM, false);
    struct ft_style text = fg(FT_COLOR_TEXT, false);
    struct ft_style mark = fg(FT_COLOR_CYAN, true);
    char size[24];
    char rate[32];

    switch (r->kind) {
    case FT_TOP_ROW_TRANSFER: {
        const struct ft_top_transfer *t = r->transfer;
        const struct ft_top_process *p = t->process;
        const char *script = t->script && t->script[0] ? t->script : p ? p->script : "";
        if (p) {
            selected_process(l, p, script);
        } else {
            add(l, mark, "▶ %" PRIu32 " ", t->pid);
        }
        add(l, dim, "  → ");
        if (t->destination && t->destination->host_state == FT_TOP_HOST_NAMED &&
            t->destination->host)
            add(l, text, "%s:%u", t->destination->host, (unsigned)t->remote.port);
        else
            add(l, text, "%s", t->remote_text);
        add(l, dim, "  Enter/F8 inspect");
        break;
    }
    case FT_TOP_ROW_PROCESS:
        selected_process(l, r->process, r->process->script);
        add(l, dim, "  Enter/F8 inspect");
        break;
    case FT_TOP_ROW_FOLD:
        add(l, mark, "▶ ");
        add(l, fg(FT_COLOR_BRIGHT, true), "%zu more %s", r->fold->count, r->fold->title);
        add(l, dim, "  + expands them");
        break;
    case FT_TOP_ROW_DESTINATION: {
        const struct ft_top_destination *dst = r->destination;
        add(l, mark, "▶ ");
        add(l, fg(FT_COLOR_BRIGHT, true), "%s", dst->text);
        add(l, fg(ft_top_egress_color(dst->is_public), false), "  %s",
            dst->is_public ? "public" : "private");
        add(l, text, " · %" PRIu32 " %s from %" PRIu32 " %s", dst->files,
            plural(dst->files, "file", "files"), dst->processes,
            plural(dst->processes, "process", "processes"));
        if (dst->top_process && dst->top_process->title[0])
            add(l, text, " · top %s", dst->top_process->title);
        break;
    }
    case FT_TOP_ROW_FILE: {
        const struct ft_top_file *f = r->file;
        add(l, mark, "▶ ");
        add(l, dim, "%.*s", (int)f->name_offset, f->path);
        add(l, fg(FT_COLOR_BRIGHT, true), "%s", f->path + f->name_offset);
        if (f->size)
            ft_top_format_size(f->size, size, sizeof(size));
        else
            ft_strlcpy(size, "?", sizeof(size));
        add(l, text, "  %s · %" PRIu32 " %s to %" PRIu32 " %s", size, f->active,
            plural(f->active, "transfer", "transfers"), f->destinations,
            plural(f->destinations, "destination", "destinations"));
        break;
    }
    case FT_TOP_ROW_SECTION: {
        const struct ft_top_section *s = r->section;
        ft_top_format_rate(s->rate, rate, sizeof(rate));
        add(l, mark, "▶ ");
        add(l, fg(FT_COLOR_AMBER, true), "%s", s->title && s->title[0] ? s->title : "(none)");
        add(l, dim, "  %" PRIu32 " %s · %" PRIu32 " %s · %s", s->processes,
            plural(s->processes, "proc", "procs"), s->files, plural(s->files, "file", "files"),
            rate);
        break;
    }
    default:
        break;
    }
}

static void draw_context(struct ft_top_draw *d, struct ft_rect r)
{
    enum ft_top_mode mode = d->ui->mode;
    size_t index = ft_top_selected(d->model, mode);
    const struct ft_top_row *row =
        index == SIZE_MAX ? nullptr : ft_top_row_at(d->model, mode, index);
    struct line l = {0};

    if (!row || r.h <= 0)
        return;
    selected_line(row, &l);
    draw_line(d->canvas, r.x, r.y, r.w, &l);
}

static void status_line(const struct ft_top_draw *d, struct line *l)
{
    static const char *const names[] = {"Transfers", "Processes", "Destinations", "Files"};
    static const char *const counted[] = {"active", "sending", "active", "in flight"};
    static const char *const matched[] = {"active transfers", "sending processes",
                                          "active destinations", "files in flight"};
    const struct ft_top_ui *ui = d->ui;
    enum ft_top_mode mode = ui->mode;
    const struct ft_top_view *v = ft_top_view_of(d->model, mode);
    const char *filter = ft_top_filter_of(d->model, mode);
    const char *search = ft_top_search_of(d->model, mode);
    struct ft_style dim = fg(FT_COLOR_DIM, false);
    struct ft_style bright = fg(FT_COLOR_BRIGHT, false);
    enum ft_top_sort key;
    bool descending;
    char rate[32];

    if (mode >= FT_TOP_LEADERS)
        return;
    if (filter && filter[0]) {
        ft_top_format_rate(v->rate, rate, sizeof(rate));
        add(l, dim, "Matched ");
        add(l, bright, "%zu", v->shown);
        add(l, dim, " of %zu %s · ", v->total, matched[mode]);
        if (mode == FT_TOP_TRANSFERS) {
            add(l, bright, "%zu", v->scripts);
            add(l, dim, " %s · ", plural(v->scripts, "script", "scripts"));
        } else {
            add(l, bright, "%zu", v->transfers);
            add(l, dim, " %s · ", plural(v->transfers, "transfer", "transfers"));
        }
        add(l, fg(FT_COLOR_PURPLE, false), "%zu public", v->destinations_public);
        add(l, dim, " %s · ", plural(v->destinations_public, "destination", "destinations"));
        add(l, bright, "%s", rate);
        add(l, dim, " total");
    } else {
        add(l, dim, "%s: %zu %s, %zu shown", names[mode], v->total, counted[mode], v->shown);
    }
    ft_top_sort_of(d->model, mode, &key, &descending);
    add(l, dim, " │ sort %s %s (click header or F6)", sort_label(mode, key),
        descending ? "▼" : "▲");
    if (!filter || !filter[0])
        add(l, dim, " │ no filter");
    else if (ui->prompt != FT_TOP_PROMPT_FILTER)
        add(l, dim, " │ filter %s (F4 Esc clears)", filter);
    if (search && search[0])
        add(l, dim, " │ search \"%s\"%s", search, v->matches ? "" : " (no match)");
    add(l, dim, " │ ");
    size_t tags = ft_top_tag_count(d->model, mode);
    if (tags)
        add(l, dim, "%zu tagged  ", tags);
    add(l, dim, "↑↓ select  Space tag  F9 pause");
}

static void draw_status(struct ft_top_draw *d, struct ft_rect r)
{
    const struct ft_top_ui *ui = d->ui;
    struct line l = {0};

    if (r.h <= 0)
        return;
    if (ui->message_kind != FT_TOP_MESSAGE_NONE && ui->message[0]) {
        enum ft_color color =
            ui->message_kind == FT_TOP_MESSAGE_ERROR ? FT_COLOR_RED : FT_COLOR_TEXT;
        ft_canvas_text_cut(d->canvas, r.x, r.y, r.w, fg(color, false), ui->message, FT_CUT_END);
        return;
    }
    status_line(d, &l);
    draw_line(d->canvas, r.x, r.y, r.w, &l);
}

static void draw_filter_keys(struct ft_top_draw *d, int x, int y, int width)
{
    struct line l = {0};
    struct ft_style dim = fg(FT_COLOR_DIM, false);
    struct ft_style cyan = fg(FT_COLOR_CYAN, false);

    if (d->ui->prompt_error[0]) {
        ft_canvas_text_cut(d->canvas, x, y, width, fg(FT_COLOR_RED, false), d->ui->prompt_error,
                           FT_CUT_END);
        return;
    }
    add(&l, cyan, "keys");
    add(&l, dim,
        " pid: user: proc: script: file: dest:public|private|CIDR|host "
        "method:sendfile|rw conf:exact|inferred rate:>1M  ");
    add(&l, cyan, "!");
    add(&l, dim, "negate  space = AND  bare word = search everywhere");
    draw_line(d->canvas, x, y, width, &l);
}

static void draw_prompt(struct ft_top_draw *d, struct ft_rect r)
{
    const struct ft_top_ui *ui = d->ui;
    const char *label;
    const char *hint;
    const char *placeholder = nullptr;

    switch (ui->prompt) {
    case FT_TOP_PROMPT_SEARCH:
        label = " Search: ";
        hint = nullptr;
        placeholder = "process, file, destination, script, pid…";
        break;
    case FT_TOP_PROMPT_FILTER:
        label = " F4 Filter: ";
        hint = "Enter keep · Esc clear · Ctrl-S save as preset";
        break;
    case FT_TOP_PROMPT_EXPORT:
        label = " Export to: ";
        hint = "Enter write · Esc cancel · .json or .csv";
        break;
    case FT_TOP_PROMPT_PRESET:
        label = " Save preset as: ";
        hint = "Enter save · Esc back to the filter";
        break;
    default:
        return;
    }

    int x = r.x + ft_canvas_text(d->canvas, r.x, r.y, r.w, badge_style(d, FT_COLOR_AMBER), label);
    x++;
    int end = r.x + r.w;
    int hint_cols = hint ? ft_text_columns(hint) : 0;
    if (hint && end - hint_cols - 2 - x >= 10) {
        ft_canvas_text(d->canvas, end - hint_cols, r.y, hint_cols, fg(FT_COLOR_DIM, false), hint);
        end -= hint_cols + 2;
    }
    if (end <= x)
        return;
    if (placeholder && ui->edit.len == 0) {
        ft_canvas_text_cut(d->canvas, x, r.y, end - x, fg(FT_COLOR_DIM, false), placeholder,
                           FT_CUT_END);
        d->cursor_x = x;
    } else {
        d->cursor_x =
            ft_lineedit_draw(&ui->edit, d->canvas, x, r.y, end - x, fg(FT_COLOR_BRIGHT, false));
    }
    d->cursor_y = r.y;
    if (ui->prompt == FT_TOP_PROMPT_FILTER && r.h > 1)
        draw_filter_keys(d, r.x, r.y + 1, r.w);
}

struct fkey {
    const char *key;
    const char *label;
    int width;
    enum ft_key code;
    uint32_t rune;
    bool on;
};

static void push(struct fkey *keys, size_t *n, struct fkey k)
{
    if (*n < FKEYS_MAX)
        keys[(*n)++] = k;
}

#define FKEY(name, text, w, on) ((struct fkey){#name, text, w, FT_KEY_##name, 0, on})
#define CKEY(shown, text, w, ch, on) ((struct fkey){shown, text, w, FT_KEY_CHAR, ch, on})

static size_t fkeys_of(const struct ft_top_draw *d, struct fkey *keys)
{
    const struct ft_top_ui *ui = d->ui;
    enum ft_top_mode mode = ui->mode;
    bool prompt = ui->prompt != FT_TOP_PROMPT_NONE;
    bool back = prompt || (ui->panel != FT_TOP_PANEL_NONE && mode != FT_TOP_LEADERS);
    bool panel = back && ui->panel != FT_TOP_PANEL_NONE;
    bool filter = ui->prompt == FT_TOP_PROMPT_FILTER || filtered(d, mode);
    bool tree = ft_top_tree_of(d->model);
    size_t n = 0;

    push(keys, &n, FKEY(F1, "Help", 7, false));
    push(keys, &n, FKEY(F2, mode == FT_TOP_LEADERS ? "Window" : "Mode", 7, false));
    push(keys, &n, FKEY(F3, "Search", 7, ui->prompt == FT_TOP_PROMPT_SEARCH));
    push(keys, &n, FKEY(F4, "Filter", 7, filter));
    switch (mode) {
    case FT_TOP_TRANSFERS:
        push(keys, &n, FKEY(F5, "Tree", 7, false));
        push(keys, &n, FKEY(F6, "SortBy", 7, panel));
        push(keys, &n, FKEY(F7, "Group", 7, panel));
        break;
    case FT_TOP_PROCESSES:
        push(keys, &n, FKEY(F5, tree ? "List" : "Tree", 7, tree));
        push(keys, &n, FKEY(F6, "SortBy", 7, panel));
        if (tree && !prompt)
            push(keys, &n, CKEY("+-", "Collapse", 9, '-', false));
        else if (!tree)
            push(keys, &n, FKEY(F7, "Group", 7, panel));
        break;
    case FT_TOP_DESTINATIONS:
        push(keys, &n, FKEY(F6, "SortBy", 7, panel));
        push(keys, &n,
             FKEY(F7,
                  ft_top_group_of(d->model, mode) == FT_TOP_GROUP_SUBNET    ? "Group:/24"
                  : ft_top_group_of(d->model, mode) == FT_TOP_GROUP_PROCESS ? "Group:proc"
                                                                            : "Group:IP",
                  9, panel));
        break;
    case FT_TOP_FILES:
        push(keys, &n, FKEY(F6, "SortBy", 7, panel));
        push(keys, &n, FKEY(F7, "Group", 7, panel));
        break;
    default:
        push(keys, &n, FKEY(F6, "RankBy", 7, false));
        push(keys, &n,
             FKEY(F7,
                  ui->key == FT_LEADER_DIRECTORY   ? "Group:dir"
                  : ui->key == FT_LEADER_EXTENSION ? "Group:ext"
                                                   : "Group:file",
                  10, false));
        break;
    }
    push(keys, &n, FKEY(F8, "Inspect", 7, ui->inspect));
    if (mode == FT_TOP_LEADERS) {
        push(keys, &n, FKEY(F9, "Freeze", 7, ui->frozen));
        if (!prompt)
            push(keys, &n, CKEY(" e", "Export", 7, 'e', false));
        push(keys, &n, (struct fkey){"Esc", "Back", 7, FT_KEY_ESC, 0, false});
        if (!back)
            push(keys, &n, FKEY(F10, "Quit", 7, false));
        return n;
    }
    push(keys, &n, FKEY(F9, "Pause", 7, ui->paused));
    if (mode == FT_TOP_DESTINATIONS && !prompt)
        push(keys, &n, CKEY("  n", "rDNS", 7, 'n', false));
    if (mode == FT_TOP_FILES && !prompt)
        push(keys, &n, CKEY("  p", "FullPath", 9, 'p', false));
    if (back)
        push(keys, &n, (struct fkey){"Esc", "Back", 7, FT_KEY_ESC, 0, false});
    else
        push(keys, &n, FKEY(F10, "Quit", 7, false));
    if (mode == FT_TOP_TRANSFERS && !prompt)
        push(keys, &n, CKEY(" L", "Leaders", 8, 'L', false));
    return n;
}

static void draw_keys(struct ft_top_draw *d, struct ft_rect r)
{
    struct fkey keys[FKEYS_MAX];
    size_t n = fkeys_of(d, keys);
    int x = r.x;

    for (size_t i = 0; i < n && x < r.x + r.w; i++) {
        const struct fkey *k = &keys[i];
        int key_cols =
            ft_canvas_text(d->canvas, x, r.y, r.x + r.w - x, fg(FT_COLOR_BRIGHT, false), k->key);
        struct ft_style s =
            ft_top_on(k->on ? FT_COLOR_AMBER : FT_COLOR_CYAN, k->on && d->depth == FT_DEPTH_NONE);
        struct ft_rect label = {x + key_cols, r.y, k->width, 1};
        ft_canvas_fill(d->canvas, label, ' ', s);
        ft_canvas_text(d->canvas, label.x, r.y, k->width, s, k->label);
        ft_top_hits_add_key(d->hits, (struct ft_rect){x, r.y, key_cols + k->width, 1}, k->code,
                            k->rune);
        x += key_cols + k->width;
    }
}

static void draw_too_small(struct ft_top_draw *d)
{
    struct ft_canvas *c = d->canvas;
    int cols = ft_canvas_cols(c);
    int rows = ft_canvas_rows(c);
    char line[160];
    const char *hint = "Enlarge the window, or press q to quit.";
    int y = rows / 2 - 1 > 0 ? rows / 2 - 1 : 0;

    snprintf(line, sizeof(line),
             "filetrace top needs a terminal of at least %d×%d; this one is %d×%d.",
             FT_TOP_MIN_COLS, FT_TOP_MIN_ROWS, cols, rows);
    int w = ft_text_columns(line);
    int x = cols > w ? (cols - w) / 2 : 0;
    ft_canvas_text_cut(c, x, y, cols - x, fg(FT_COLOR_TEXT, false), line, FT_CUT_END);
    w = ft_text_columns(hint);
    x = cols > w ? (cols - w) / 2 : 0;
    ft_canvas_text_cut(c, x, y + 1, cols - x, fg(FT_COLOR_DIM, false), hint, FT_CUT_END);
}

/* Centered in the table's rows while the first answer is awaited. */
static void draw_starting(struct ft_top_draw *d, struct ft_rect r)
{
    static const char *const frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
    const struct ft_top_ui *ui = d->ui;
    char text[160];

    snprintf(text, sizeof(text), "%s %" PRIu64 "s",
             ui->session_only ? "Starting the collector: attaching the kernel probes…"
                              : "Waiting for the agent's first answer…",
             ui->starting_ns / FT_NS_PER_SEC);
    int w = 2 + ft_text_columns(text);
    int x = r.x + (r.w > w ? (r.w - w) / 2 : 0);
    int y = r.y + r.h / 2;
    ft_canvas_text(d->canvas, x, y, 1, fg(FT_COLOR_CYAN, false),
                   frames[ui->spinner % FT_ARRAY_LEN(frames)]);
    ft_canvas_text_cut(d->canvas, x + 2, y, r.x + r.w - x - 2, fg(FT_COLOR_TEXT, false), text,
                       FT_CUT_END);
}

/* Draws one block with the canvas clipped to its rectangle. */
#define CLIPPED(rect, call)                                                                        \
    do {                                                                                           \
        if ((rect).w > 0 && (rect).h > 0) {                                                        \
            struct ft_rect previous_clip = ft_canvas_clip(d->canvas, rect);                        \
            call;                                                                                  \
            ft_canvas_clip(d->canvas, previous_clip);                                              \
        }                                                                                          \
    } while (0)

void ft_top_draw(struct ft_top_draw *d)
{
    struct ft_canvas *c = d->canvas;
    const struct ft_top_ui *ui = d->ui;
    struct ft_top_layout l;
    bool leaders = ui->mode == FT_TOP_LEADERS;

    ft_canvas_clear(c, (struct ft_style){.fg = FT_COLOR_TEXT, .bg = FT_COLOR_BG});
    d->cursor_x = -1;
    d->cursor_y = -1;
    if (d->hits)
        d->hits->count = 0;
    ft_top_layout(ui, ft_canvas_cols(c), ft_canvas_rows(c), &l);
    if (l.too_small) {
        draw_too_small(d);
        return;
    }
    if (ui->help) {
        ft_top_draw_help(d);
        return;
    }

    if (leaders)
        CLIPPED(l.head, ft_top_draw_leaders_cards(d, l.head));
    else
        CLIPPED(l.head, draw_head(d, l.head));
    CLIPPED(l.tabs, {
        int x = draw_tabs(d, l.tabs);
        if (leaders)
            ft_top_draw_leaders_bar(d, leaders_bar_room(d, l.tabs, x), x);
        else
            draw_tab_state(d, l.tabs, x);
    });
    /* Before the tables, so that a full list of hits drops table rows rather than keys. */
    CLIPPED(l.keys, draw_keys(d, l.keys));

    if (ui->overlay != FT_TOP_OVERLAY_NONE) {
        CLIPPED(l.overlay, ft_top_draw_overlay(d, l.overlay));
    } else {
        struct ft_rect table = {l.header.x, l.header.y, l.header.w, l.header.h + l.table.h};
        if (leaders) {
            CLIPPED(table, ft_top_draw_leaders_table(d, l.header, l.table, ui->scroll[ui->mode]));
            CLIPPED(l.side, ft_top_draw_leaders_side(d, l.side));
        } else {
            CLIPPED(table, ft_top_draw_table(d, ui->mode, l.header, l.table, ui->scroll[ui->mode]));
        }
        if (ui->starting)
            CLIPPED(l.table, draw_starting(d, l.table));
        if (l.panel.h > 0) {
            CLIPPED(l.panel, ft_top_draw_panel(d, l.panel));
            ft_canvas_fill(c, (struct ft_rect){l.panel.x + l.panel.w, l.panel.y, 1, l.panel.h},
                           U'│', fg(FT_COLOR_RULE, false));
        }
        ft_canvas_repeat(c, l.rule.x, l.rule.y, l.rule.h > 0 ? l.rule.w : 0, U'─',
                         fg(FT_COLOR_RULE, false));
        if (leaders) {
            /* Leaders has no status row, so a message takes the legend's for as long as it shows.
             */
            if (ui->message_kind != FT_TOP_MESSAGE_NONE && ui->message[0])
                CLIPPED(l.context, draw_status(d, l.context));
            else
                CLIPPED(l.context, ft_top_draw_leaders_legend(d, l.context));
        } else {
            CLIPPED(l.context, draw_context(d, l.context));
            CLIPPED(l.status, draw_status(d, l.status));
        }
        CLIPPED(l.inspect, ft_top_draw_inspect(d, l.inspect));
    }
    CLIPPED(l.prompt, draw_prompt(d, l.prompt));
}
