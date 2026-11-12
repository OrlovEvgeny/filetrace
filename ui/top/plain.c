#include "ui/top/plain.h"

#include "filetrace/format.h"
#include "filetrace/sysinfo.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static size_t utf8_encode(uint32_t rune, char out[static 4])
{
    if (rune < 0x20 || (rune >= 0xd800 && rune <= 0xdfff) || rune > 0x10ffff)
        rune = '?';
    if (rune < 0x80) {
        out[0] = (char)rune;
        return 1;
    }
    if (rune < 0x800) {
        out[0] = (char)(0xc0 | (rune >> 6));
        out[1] = (char)(0x80 | (rune & 0x3f));
        return 2;
    }
    if (rune < 0x10000) {
        out[0] = (char)(0xe0 | (rune >> 12));
        out[1] = (char)(0x80 | ((rune >> 6) & 0x3f));
        out[2] = (char)(0x80 | (rune & 0x3f));
        return 3;
    }
    out[0] = (char)(0xf0 | (rune >> 18));
    out[1] = (char)(0x80 | ((rune >> 12) & 0x3f));
    out[2] = (char)(0x80 | ((rune >> 6) & 0x3f));
    out[3] = (char)(0x80 | (rune & 0x3f));
    return 4;
}

static void put_color(FILE *out, unsigned plane, struct ft_term_color color)
{
    if (color.kind == FT_TERM_INDEX)
        fprintf(out, ";%u;5;%u", plane, (unsigned)color.value);
    else if (color.kind == FT_TERM_RGB)
        fprintf(out, ";%u;2;%u;%u;%u", plane, (unsigned)(color.value >> 16) & 0xff,
                (unsigned)(color.value >> 8) & 0xff, (unsigned)color.value & 0xff);
}

/* Every sequence starts from a reset, so the one that follows does not depend on the last. */
static void put_style(FILE *out, const struct ft_term_style *s)
{
    fputs("\033[0", out);
    if (s->attrs & FT_ATTR_BOLD)
        fputs(";1", out);
    if (s->attrs & FT_TERM_DIM)
        fputs(";2", out);
    if (s->attrs & FT_ATTR_UNDERLINE)
        fputs(";4", out);
    if (s->attrs & FT_ATTR_REVERSE)
        fputs(";7", out);
    put_color(out, 38, s->fg);
    put_color(out, 48, s->bg);
    fputc('m', out);
}

static bool is_default(const struct ft_term_style *s)
{
    return s->attrs == 0 && s->fg.kind == FT_TERM_DEFAULT && s->bg.kind == FT_TERM_DEFAULT;
}

/* Blank cells at the end of a line show nothing, unless they are a bar or reversed. */
static bool is_blank(const struct ft_cell *c, bool colored)
{
    if (c->rune != ' ')
        return false;
    if (!colored)
        return true;
    return (c->bg == FT_COLOR_DEFAULT || c->bg == FT_COLOR_BG) &&
           !(c->attrs & (FT_ATTR_REVERSE | FT_ATTR_UNDERLINE));
}

void ft_top_print_canvas(const struct ft_canvas *canvas, enum ft_color_depth depth, FILE *out)
{
    bool colored = depth != FT_DEPTH_NONE;

    for (int y = 0; y < ft_canvas_rows(canvas); y++) {
        struct ft_cell shown = {.rune = ' '}; /* the colors and attributes the terminal has now */
        bool styled = false;
        int end = ft_canvas_cols(canvas);

        while (end > 0 && is_blank(ft_canvas_at(canvas, end - 1, y), colored))
            end--;
        for (int x = 0; x < end; x++) {
            const struct ft_cell *c = ft_canvas_at(canvas, x, y);
            char bytes[4];

            if (c->rune == 0)
                continue;
            if (colored && (c->fg != shown.fg || c->bg != shown.bg || c->attrs != shown.attrs)) {
                struct ft_term_style style = ft_theme_resolve(depth, c->fg, c->bg, c->attrs);

                if (!is_default(&style))
                    put_style(out, &style);
                else if (styled)
                    fputs("\033[0m", out);
                styled = !is_default(&style);
                shown = *c;
            }
            fwrite(bytes, 1, utf8_encode(c->rune, bytes), out);
        }
        if (styled)
            fputs("\033[0m", out);
        fputc('\n', out);
    }
}

static const char *plural(uint64_t n, const char *one, const char *many)
{
    return n == 1 ? one : many;
}

/* The clock when the span fits a day, else the date as well. */
static void time_text(uint64_t wall_ns, uint64_t window_ns, char *buf, size_t size)
{
    if (window_ns == 0 || window_ns >= 24 * 3600 * FT_NS_PER_SEC)
        ft_format_time_local(wall_ns, buf, size);
    else
        ft_format_clock_local(wall_ns, buf, size);
}

/* What the span a ranking covers is, in the lines that precede its table. */
static void print_leaders_summary(const struct ft_top_leaders *leaders, FILE *out)
{
    static const char *const before[FT_WINDOW_COUNT] = {
        [FT_WINDOW_1M] = "minute", [FT_WINDOW_5M] = "5 minutes", [FT_WINDOW_15M] = "15 minutes",
        [FT_WINDOW_1H] = "hour",   [FT_WINDOW_24H] = "24 hours", [FT_WINDOW_7D] = "7 days",
    };
    const struct ft_row_leader_summary *s = &leaders->summary;
    char from[32], to[32], bytes[32], transfers[32], files[32], procs[32], scripts[32], dests[32],
        public_dests[32];

    time_text(s->from_wall_ns, s->window_ns, from, sizeof(from));
    time_text(s->to_wall_ns, s->window_ns, to, sizeof(to));
    fprintf(out, "Window %s, %s to %s, ranked by %s.", ft_leader_window_name(leaders->window), from,
            to,
            leaders->by == FT_TOP_SORT_TRANSFERS      ? "transfers"
            : leaders->by == FT_TOP_SORT_DESTINATIONS ? "destinations"
                                                      : "bytes");
    if (s->previous_from_wall_ns != 0 && leaders->window < FT_WINDOW_COUNT &&
        before[leaders->window])
        fprintf(out, " Compared with the %s before.", before[leaders->window]);
    fputc('\n', out);

    ft_format_bytes(s->bytes, bytes, sizeof(bytes));
    ft_format_count(s->transfers, transfers, sizeof(transfers));
    fprintf(out, "Sent %s in %s %s", bytes, transfers,
            plural(s->transfers, "transfer", "transfers"));
    if (s->bytes > 0) {
        char share[8];

        ft_top_format_percent(leaders->exact_share, share, sizeof(share));
        unsigned sendfile = (unsigned)strtoul(share, nullptr, 10);
        fprintf(out, ": %u%% sendfile, %u%% read-write", sendfile, 100 - sendfile);
    }
    fputs(".\n", out);

    ft_format_count(s->files, files, sizeof(files));
    ft_format_count(s->processes, procs, sizeof(procs));
    ft_format_count(s->scripts, scripts, sizeof(scripts));
    ft_format_count(s->destinations_public + s->destinations_private, dests, sizeof(dests));
    ft_format_count(s->destinations_public, public_dests, sizeof(public_dests));
    fprintf(out, "%s %s from %s %s and %s %s to %s %s (%s public).\n", files,
            plural(s->files, "file", "files"), procs, plural(s->processes, "process", "processes"),
            scripts, plural(s->scripts, "script", "scripts"), dests,
            plural(s->destinations_public + s->destinations_private, "destination", "destinations"),
            public_dests);

    if (s->flags & FT_LEADERS_SHORT_HISTORY)
        fprintf(out, "The agent has been running since %s; the window is not full.\n", from);
}

bool ft_top_print_table(const struct ft_top_model *m, const struct ft_top_ui *ui, int cols,
                        enum ft_color_depth depth, FILE *out)
{
    enum ft_top_mode mode = ui->mode;
    size_t count = ft_top_row_count(m, mode);
    size_t body = count ? count : 1; /* the empty table says so in its first row */
    struct ft_host_info host;

    if (cols < 1 || body >= (size_t)INT_MAX)
        return false;
    struct ft_canvas *canvas = ft_canvas_create(cols, (int)body + 1);
    if (!canvas)
        return false;

    ft_sysinfo_host(&host);
    struct ft_top_draw d = {
        .canvas = canvas,
        .depth = depth,
        .model = m,
        .ui = ui,
        .host = &host,
        .cursor_x = -1,
        .cursor_y = -1,
    };
    struct ft_rect header = {0, 0, cols, 1};
    struct ft_rect rows = {0, 1, cols, (int)body};

    if (mode == FT_TOP_LEADERS) {
        const struct ft_top_leaders *leaders = ft_top_leaders(m);

        if (leaders->answered)
            print_leaders_summary(leaders, out);
        ft_top_draw_leaders_table(&d, header, rows, 0);
    } else {
        ft_top_draw_table(&d, mode, header, rows, 0);
    }
    ft_top_print_canvas(canvas, depth, out);
    ft_canvas_destroy(canvas);
    return true;
}
