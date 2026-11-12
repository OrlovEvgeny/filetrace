#include "ui/top/views.h"

#include <string.h>

constexpr uint64_t RATE_BRIGHT = UINT64_C(10) << 20;
constexpr uint64_t RATE_RED = UINT64_C(50) << 20;

static void hits_push(struct ft_top_hits *hits, struct ft_top_hit hit)
{
    if (!hits || hits->count == FT_TOP_HITS_MAX || hit.rect.w <= 0 || hit.rect.h <= 0)
        return;
    hits->items[hits->count++] = hit;
}

void ft_top_hits_add(struct ft_top_hits *hits, struct ft_rect rect, enum ft_top_target target,
                     uint32_t arg)
{
    hits_push(hits, (struct ft_top_hit){.rect = rect, .target = target, .arg = arg});
}

void ft_top_hits_add_key(struct ft_top_hits *hits, struct ft_rect rect, enum ft_key key,
                         uint32_t rune)
{
    hits_push(hits, (struct ft_top_hit){
                        .rect = rect, .target = FT_TOP_TARGET_KEY, .arg = key, .rune = rune});
}

const struct ft_top_hit *ft_top_hits_at(const struct ft_top_hits *hits, int x, int y)
{
    for (size_t i = hits->count; i-- > 0;) {
        const struct ft_rect *r = &hits->items[i].rect;
        if (x >= r->x && x < r->x + r->w && y >= r->y && y < r->y + r->h)
            return &hits->items[i];
    }
    return nullptr;
}

struct ft_style ft_top_fg(enum ft_color fg, bool bold)
{
    return (struct ft_style){.fg = fg, .bg = FT_COLOR_DEFAULT, .attrs = bold ? FT_ATTR_BOLD : 0};
}

struct ft_style ft_top_on(enum ft_color bar, bool bold)
{
    return (struct ft_style){.fg = FT_COLOR_BG, .bg = bar, .attrs = bold ? FT_ATTR_BOLD : 0};
}

struct ft_style ft_top_rate_style(uint64_t bytes_per_second)
{
    if (bytes_per_second >= RATE_RED)
        return ft_top_fg(FT_COLOR_RED, true);
    if (bytes_per_second >= RATE_BRIGHT)
        return ft_top_fg(FT_COLOR_BRIGHT, true);
    return ft_top_fg(FT_COLOR_DIM, false);
}

enum ft_color ft_top_method_color(uint8_t method)
{
    return method == FT_METHOD_SENDFILE ? FT_COLOR_GREEN : FT_COLOR_AMBER;
}

enum ft_color ft_top_egress_color(bool is_public)
{
    return is_public ? FT_COLOR_PURPLE : FT_COLOR_BLUE;
}

const char *ft_top_method_word(uint8_t method)
{
    return method == FT_METHOD_NONE ? "-" : ft_method_name((enum ft_method)method);
}

const char *ft_top_confidence_word(uint8_t confidence, bool incomplete)
{
    static const char *const words[][2] = {
        [FT_CONF_UNKNOWN] = {"UNKNOWN", "UNKNOWN*"},
        [FT_CONF_INFERRED] = {"INFERRED", "INFERRED*"},
        [FT_CONF_STRONG] = {"STRONG", "STRONG*"},
        [FT_CONF_EXACT] = {"EXACT", "EXACT*"},
    };
    return words[confidence < FT_ARRAY_LEN(words) ? confidence : FT_CONF_UNKNOWN][incomplete];
}

void ft_top_bar_row(struct ft_top_draw *d, struct ft_rect r, enum ft_color bar)
{
    ft_canvas_fill(d->canvas, r, ' ', ft_top_on(bar, true));
}

void ft_top_select_row(struct ft_top_draw *d, struct ft_rect r)
{
    ft_canvas_restyle(d->canvas, r, (struct ft_style){.fg = FT_COLOR_BG, .bg = FT_COLOR_CYAN});
}

void ft_top_title_row(struct ft_top_draw *d, struct ft_rect r, enum ft_color bar, const char *left,
                      const char *right)
{
    struct ft_style s = ft_top_on(bar, true);

    ft_top_bar_row(d, r, bar);
    /* The right text first: drawing it pads the row to its left with spaces. */
    if (right)
        ft_canvas_text_right(d->canvas, r.x, r.y, r.w - 1, s, right);
    if (left)
        ft_canvas_text_cut(d->canvas, r.x + 1, r.y, r.w - 2, s, left, FT_CUT_END);
}

int ft_top_cell(struct ft_top_draw *d, int x, int y, int width, bool right, struct ft_style s,
                const char *text)
{
    if (width <= 1)
        return 0;
    if (right)
        return ft_canvas_text_right(d->canvas, x, y, width - 1, s, text);
    return ft_canvas_text_cut(d->canvas, x, y, width - 1, s, text, FT_CUT_END);
}

const char *ft_top_path_text(const struct ft_top_draw *d, const char *path, uint32_t name_offset)
{
    return d->ui->full_paths ? path : path + name_offset;
}

void ft_top_path_cell(struct ft_top_draw *d, int x, int y, int width, const char *path,
                      uint32_t name_offset, struct ft_style name)
{
    if (width <= 1)
        return;
    if (d->ui->full_paths)
        ft_canvas_path(d->canvas, x, y, width - 1, ft_top_fg(FT_COLOR_DIM, false), name, path);
    else
        ft_canvas_text_cut(d->canvas, x, y, width - 1, name, path + name_offset, FT_CUT_START);
}

static void mark(struct ft_top_draw *d, int x, int y, int width, const char *text, enum ft_cut cut,
                 const char *needle, size_t len, bool selected)
{
    size_t start;
    size_t end;

    if (!needle || len == 0 || !ft_top_find(text, needle, len, &start, &end))
        return;
    struct ft_style s = selected ? (struct ft_style){.fg = FT_COLOR_AMBER, .bg = FT_COLOR_BG}
                                 : (struct ft_style){.fg = FT_COLOR_BG, .bg = FT_COLOR_AMBER};
    ft_canvas_mark(d->canvas, x, y, width - 1, text, cut, start, end, s);
}

void ft_top_mark_matches(struct ft_top_draw *d, int x, int y, int width, const char *text,
                         enum ft_cut cut, enum ft_top_field field, bool selected)
{
    enum ft_top_mode mode = d->ui->mode;
    const struct ft_top_filter *filter = ft_top_filter_get(d->model, mode);
    const char *search = ft_top_search_of(d->model, mode);
    size_t len = 0;

    if (width <= 1)
        return;
    if (filter && field != FT_TOP_FIELD_ANY) {
        const char *needle = ft_top_filter_needle(filter, field, &len);
        mark(d, x, y, width, text, cut, needle, len, selected);
    }
    if (search)
        mark(d, x, y, width, text, cut, search, strlen(search), selected);
}
