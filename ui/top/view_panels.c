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

void ft_top_draw_inspect(struct ft_top_draw *d, struct ft_rect r)
{
    (void)d;
    (void)r;
}

void ft_top_draw_overlay(struct ft_top_draw *d, struct ft_rect r)
{
    (void)d;
    (void)r;
}

void ft_top_draw_help(struct ft_top_draw *d)
{
    (void)d;
}
