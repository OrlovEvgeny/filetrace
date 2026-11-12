#include "ui/tui/canvas.h"

#include <limits.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* termbox2's table, so that the canvas and the terminal output agree on every width. */
int tb_wcwidth(uint32_t ch);

constexpr uint32_t ELLIPSIS = U'…';
constexpr size_t FORMAT_MAX = 1024;

struct ft_canvas {
    int cols;
    int rows;
    size_t capacity;
    struct ft_rect clip;
    struct ft_cell *cells;
};

struct glyph {
    uint32_t rune;
    int cols;
    size_t size;
};

/* What a call shows: bytes [0, head), a pad or "…", then bytes [tail, len). */
struct layout {
    size_t head;
    size_t tail;
    bool pad;
    bool ellipsis;
    int cols;
};

/* Styles of the bytes before split, of the rest, and of the "…". */
struct paint {
    struct ft_style first;
    struct ft_style second;
    struct ft_style ellipsis;
    size_t split;
};

/* Draws glyphs, or restyles the cells of bytes [start, end) when marking. */
struct pen {
    struct ft_canvas *c;
    int x;
    int y;
    int col;
    const struct paint *paint;
    bool marking;
    size_t start;
    size_t end;
    struct ft_style mark;
};

static size_t utf8_decode(const unsigned char *p, size_t n, uint32_t *rune)
{
    unsigned char lead = p[0];
    size_t len = lead < 0x80   ? 1
                 : lead < 0xc2 ? 0
                 : lead < 0xe0 ? 2
                 : lead < 0xf0 ? 3
                 : lead < 0xf5 ? 4
                               : 0;

    if (len == 0 || len > n)
        return 0;
    for (size_t i = 1; i < len; i++) {
        if ((p[i] & 0xc0) != 0x80)
            return 0;
    }
    /* Overlong forms, surrogates and code points past U+10FFFF. */
    if ((lead == 0xe0 && p[1] < 0xa0) || (lead == 0xed && p[1] > 0x9f) ||
        (lead == 0xf0 && p[1] < 0x90) || (lead == 0xf4 && p[1] > 0x8f))
        return 0;

    uint32_t r = len == 1 ? lead : lead & (0x7fu >> len);
    for (size_t i = 1; i < len; i++)
        r = r << 6 | (p[i] & 0x3fu);
    *rune = r;
    return len;
}

static int rune_cols(uint32_t r)
{
    if (r >= 0x20 && r < 0x7f)
        return 1;
    if (r < 0x20 || r == 0x7f)
        return -1;
    return tb_wcwidth(r);
}

static struct glyph next_glyph(const unsigned char *p, size_t n)
{
    struct glyph g = {.rune = '?', .cols = 1, .size = 1};
    uint32_t r = 0;
    size_t len;

    if (p[0] >= 0x20 && p[0] < 0x7f) {
        g.rune = p[0];
        return g;
    }
    len = utf8_decode(p, n, &r);
    if (len == 0)
        return g;
    g.size = len;
    int cols = rune_cols(r);
    if (cols >= 0) {
        g.rune = r;
        g.cols = cols > 2 ? 2 : cols;
    }
    return g;
}

/* A single character for fill and bars: "?" for a control, a space for a zero-width one. */
static struct glyph rune_glyph(uint32_t rune)
{
    int cols = rune_cols(rune);

    if (cols < 0)
        return (struct glyph){.rune = '?', .cols = 1};
    if (cols == 0)
        return (struct glyph){.rune = ' ', .cols = 1};
    return (struct glyph){.rune = rune, .cols = cols > 2 ? 2 : cols};
}

/* Columns of text, stopping once they exceed limit. */
static int measure(const unsigned char *p, size_t len, int limit)
{
    int cols = 0;

    for (size_t off = 0; off < len && cols <= limit;) {
        struct glyph g = next_glyph(p + off, len - off);
        cols += g.cols;
        off += g.size;
    }
    return cols;
}

static struct layout lay_out(const unsigned char *p, size_t len, int width, enum ft_cut cut)
{
    struct layout l = {.head = len, .tail = len};
    int total;

    if (width <= 0) {
        l.head = 0;
        return l;
    }
    total = measure(p, len, cut == FT_CUT_START ? INT_MAX - 2 : width);
    if (total <= width) {
        l.cols = total;
        return l;
    }

    int budget = cut == FT_CUT_CLIP ? width : width - 1;
    if (cut == FT_CUT_START) {
        int hidden = 0;
        size_t off = 0;
        while (off < len && hidden < total - budget) {
            struct glyph g = next_glyph(p + off, len - off);
            hidden += g.cols;
            off += g.size;
        }
        l.head = 0;
        l.tail = off;
        l.ellipsis = true;
        l.cols = 1 + total - hidden;
        return l;
    }

    int col = 0;
    size_t off = 0;
    while (off < len) {
        struct glyph g = next_glyph(p + off, len - off);
        if (col + g.cols > budget)
            break;
        col += g.cols;
        off += g.size;
    }
    l.head = off;
    if (cut == FT_CUT_CLIP) {
        l.pad = col < width;
        l.cols = width;
    } else {
        l.ellipsis = true;
        l.cols = col + 1;
    }
    return l;
}

static struct ft_rect intersect(struct ft_rect a, struct ft_rect b)
{
    long long x0 = a.x > b.x ? a.x : b.x;
    long long y0 = a.y > b.y ? a.y : b.y;
    long long ax1 = (long long)a.x + (a.w > 0 ? a.w : 0);
    long long bx1 = (long long)b.x + (b.w > 0 ? b.w : 0);
    long long ay1 = (long long)a.y + (a.h > 0 ? a.h : 0);
    long long by1 = (long long)b.y + (b.h > 0 ? b.h : 0);
    long long x1 = ax1 < bx1 ? ax1 : bx1;
    long long y1 = ay1 < by1 ? ay1 : by1;

    if (x1 <= x0 || y1 <= y0)
        return (struct ft_rect){0, 0, 0, 0};
    return (struct ft_rect){(int)x0, (int)y0, (int)(x1 - x0), (int)(y1 - y0)};
}

static bool visible(const struct ft_canvas *c, int x, int y)
{
    return x >= c->clip.x && x < c->clip.x + c->clip.w && y >= c->clip.y &&
           y < c->clip.y + c->clip.h;
}

static struct ft_cell *cell_at(struct ft_canvas *c, int x, int y)
{
    return &c->cells[(size_t)y * (size_t)c->cols + (size_t)x];
}

static void paint_cell(struct ft_cell *cell, struct ft_style s)
{
    if (s.fg != FT_COLOR_DEFAULT)
        cell->fg = s.fg;
    if (s.bg != FT_COLOR_DEFAULT)
        cell->bg = s.bg;
    cell->attrs = s.attrs;
}

static void restyle_cell(struct ft_cell *cell, struct ft_style s)
{
    if (s.fg != FT_COLOR_DEFAULT)
        cell->fg = s.fg;
    if (s.bg != FT_COLOR_DEFAULT)
        cell->bg = s.bg;
    cell->attrs |= s.attrs;
}

/* A wide character loses both halves when one of them is drawn over. */
static void break_wide(struct ft_canvas *c, int x, int y)
{
    if (cell_at(c, x, y)->rune == 0) {
        if (x > 0)
            cell_at(c, x - 1, y)->rune = ' ';
    } else if (x + 1 < c->cols && cell_at(c, x + 1, y)->rune == 0) {
        cell_at(c, x + 1, y)->rune = ' ';
    }
}

static void set_cell(struct ft_canvas *c, int x, int y, uint32_t rune, struct ft_style s)
{
    struct ft_cell *cell = cell_at(c, x, y);

    break_wide(c, x, y);
    cell->rune = rune;
    paint_cell(cell, s);
}

static void put(struct ft_canvas *c, int x, int y, uint32_t rune, int cols, struct ft_style s)
{
    if (cols != 2) {
        if (visible(c, x, y))
            set_cell(c, x, y, rune, s);
        return;
    }

    bool left = visible(c, x, y);
    bool right = visible(c, x + 1, y);
    if (left && right) {
        break_wide(c, x, y);
        break_wide(c, x + 1, y);
        cell_at(c, x, y)->rune = rune;
        cell_at(c, x + 1, y)->rune = 0;
        paint_cell(cell_at(c, x, y), s);
        paint_cell(cell_at(c, x + 1, y), s);
        return;
    }
    if (left)
        set_cell(c, x, y, ' ', s);
    if (right)
        set_cell(c, x + 1, y, ' ', s);
}

static void restyle_run(struct ft_canvas *c, int x, int y, int count, struct ft_style s)
{
    struct ft_rect r = intersect((struct ft_rect){x, y, count, 1}, c->clip);

    for (int i = 0; i < r.w; i++)
        restyle_cell(cell_at(c, r.x + i, r.y), s);
}

static bool overlaps(size_t from, size_t to, size_t start, size_t end)
{
    return from < end && start < to && from < to;
}

/* One glyph standing for bytes [from, to). */
static void emit(struct pen *pen, uint32_t rune, int cols, size_t from, size_t to,
                 struct ft_style s)
{
    int x = pen->x + pen->col;

    if (pen->marking) {
        if (overlaps(from, to, pen->start, pen->end))
            restyle_run(pen->c, x, pen->y, cols, pen->mark);
    } else {
        put(pen->c, x, pen->y, rune, cols, s);
    }
    pen->col += cols;
}

static struct ft_style style_at(const struct paint *paint, size_t off)
{
    return off < paint->split ? paint->first : paint->second;
}

static void emit_run(struct pen *pen, const unsigned char *p, size_t from, size_t to)
{
    int right = pen->c->clip.x + pen->c->clip.w;

    for (size_t off = from; off < to && pen->x + pen->col < right;) {
        struct glyph g = next_glyph(p + off, to - off);
        if (g.cols > 0)
            emit(pen, g.rune, g.cols, off, off + g.size, style_at(pen->paint, off));
        off += g.size;
    }
}

static int walk(struct pen *pen, int width, const char *text, enum ft_cut cut, bool align_right)
{
    const unsigned char *p = (const unsigned char *)text;
    size_t len = strlen(text);
    struct layout l = lay_out(p, len, width, cut);
    struct ft_canvas *c = pen->c;

    if (align_right)
        pen->col = width - l.cols;
    if (pen->y < c->clip.y || pen->y >= c->clip.y + c->clip.h || pen->x >= c->clip.x + c->clip.w)
        return l.cols;

    emit_run(pen, p, 0, l.head);
    if (l.pad)
        emit(pen, ' ', 1, l.head, len, style_at(pen->paint, l.head));
    if (l.ellipsis) {
        size_t from = cut == FT_CUT_START ? 0 : l.head;
        size_t to = cut == FT_CUT_START ? l.tail : len;
        emit(pen, ELLIPSIS, 1, from, to, pen->paint->ellipsis);
    }
    emit_run(pen, p, l.tail, len);
    return l.cols;
}

static int draw(struct ft_canvas *c, int x, int y, int width, const char *text, enum ft_cut cut,
                const struct paint *paint)
{
    struct pen pen = {.c = c, .x = x, .y = y, .paint = paint};

    return walk(&pen, width, text, cut, false);
}

static struct paint plain(struct ft_style s)
{
    return (struct paint){.first = s, .second = s, .ellipsis = s};
}

struct ft_canvas *ft_canvas_create(int cols, int rows)
{
    struct ft_canvas *c = calloc(1, sizeof(*c));

    if (!c)
        return nullptr;
    if (!ft_canvas_resize(c, cols, rows)) {
        free(c);
        return nullptr;
    }
    return c;
}

void ft_canvas_destroy(struct ft_canvas *c)
{
    if (!c)
        return;
    free(c->cells);
    free(c);
}

bool ft_canvas_resize(struct ft_canvas *c, int cols, int rows)
{
    size_t w = cols > 0 ? (size_t)cols : 0;
    size_t h = rows > 0 ? (size_t)rows : 0;
    size_t need = w * h;

    if (h && w > SIZE_MAX / sizeof(struct ft_cell) / h)
        return false;
    if (need > c->capacity || !c->cells) {
        size_t n = need ? need : 1;
        struct ft_cell *cells = realloc(c->cells, n * sizeof(*cells));
        if (!cells)
            return false;
        c->cells = cells;
        c->capacity = n;
    }
    c->cols = (int)w;
    c->rows = (int)h;
    ft_canvas_clear(c, (struct ft_style){0});
    return true;
}

int ft_canvas_cols(const struct ft_canvas *c)
{
    return c->cols;
}

int ft_canvas_rows(const struct ft_canvas *c)
{
    return c->rows;
}

void ft_canvas_clear(struct ft_canvas *c, struct ft_style s)
{
    struct ft_cell blank = {.rune = ' ', .fg = s.fg, .bg = s.bg, .attrs = s.attrs};
    size_t n = (size_t)c->cols * (size_t)c->rows;

    for (size_t i = 0; i < n; i++)
        c->cells[i] = blank;
    c->clip = (struct ft_rect){0, 0, c->cols, c->rows};
}

struct ft_rect ft_canvas_clip(struct ft_canvas *c, struct ft_rect r)
{
    struct ft_rect previous = c->clip;

    c->clip = intersect(r, (struct ft_rect){0, 0, c->cols, c->rows});
    return previous;
}

const struct ft_cell *ft_canvas_at(const struct ft_canvas *c, int x, int y)
{
    if (x < 0 || y < 0 || x >= c->cols || y >= c->rows)
        return nullptr;
    return &c->cells[(size_t)y * (size_t)c->cols + (size_t)x];
}

int ft_canvas_text(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                   const char *text)
{
    struct paint paint = plain(s);

    return draw(c, x, y, width, text, FT_CUT_CLIP, &paint);
}

int ft_canvas_text_cut(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                       const char *text, enum ft_cut cut)
{
    struct paint paint = plain(s);

    return draw(c, x, y, width, text, cut, &paint);
}

static int text_right(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                      const char *text, bool pad)
{
    struct paint paint = plain(s);
    struct pen pen = {.c = c, .x = x, .y = y, .paint = &paint};
    int cols = walk(&pen, width, text, FT_CUT_END, true);

    if (pad && width > cols)
        ft_canvas_repeat(c, x, y, width - cols, ' ', s);
    return cols;
}

int ft_canvas_text_right(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                         const char *text)
{
    return text_right(c, x, y, width, s, text, true);
}

int ft_canvas_textf(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                    const char *fmt, ...)
{
    char buf[FORMAT_MAX];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return ft_canvas_text(c, x, y, width, s, buf);
}

int ft_canvas_textf_right(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                          const char *fmt, ...)
{
    char buf[FORMAT_MAX];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    return ft_canvas_text_right(c, x, y, width, s, buf);
}

int ft_canvas_path(struct ft_canvas *c, int x, int y, int width, struct ft_style dir,
                   struct ft_style name, const char *path)
{
    const char *slash = strrchr(path, '/');
    struct paint paint = {
        .first = dir,
        .second = name,
        .ellipsis = dir,
        .split = slash ? (size_t)(slash - path) + 1 : 0,
    };

    return draw(c, x, y, width, path, FT_CUT_START, &paint);
}

void ft_canvas_mark(struct ft_canvas *c, int x, int y, int width, const char *text, enum ft_cut cut,
                    size_t start, size_t end, struct ft_style s)
{
    struct paint paint = plain(s);
    struct pen pen = {
        .c = c,
        .x = x,
        .y = y,
        .paint = &paint,
        .marking = true,
        .start = start,
        .end = end,
        .mark = s,
    };

    walk(&pen, width, text, cut, false);
}

int ft_text_columns(const char *text)
{
    return measure((const unsigned char *)text, strlen(text), INT_MAX - 2);
}

size_t ft_text_next(const char *text, size_t len, int *columns)
{
    struct glyph g;

    if (len == 0) {
        *columns = 0;
        return 0;
    }
    g = next_glyph((const unsigned char *)text, len);
    *columns = g.cols;
    return g.size;
}

void ft_canvas_fill(struct ft_canvas *c, struct ft_rect r, uint32_t rune, struct ft_style s)
{
    struct glyph g = rune_glyph(rune);
    struct ft_rect a = intersect(r, c->clip);

    for (int y = a.y; y < a.y + a.h; y++) {
        for (int x = a.x; x < a.x + a.w; x += g.cols)
            put(c, x, y, g.rune, g.cols, s);
    }
}

void ft_canvas_repeat(struct ft_canvas *c, int x, int y, int count, uint32_t rune,
                      struct ft_style s)
{
    ft_canvas_fill(c, (struct ft_rect){x, y, count, 1}, rune, s);
}

void ft_canvas_restyle(struct ft_canvas *c, struct ft_rect r, struct ft_style s)
{
    struct ft_rect a = intersect(r, c->clip);

    for (int y = a.y; y < a.y + a.h; y++) {
        for (int x = a.x; x < a.x + a.w; x++)
            restyle_cell(cell_at(c, x, y), s);
    }
}

void ft_canvas_box(struct ft_canvas *c, struct ft_rect r, struct ft_style s)
{
    if (r.w < 2 || r.h < 2)
        return;

    int right = r.x + r.w - 1;
    int bottom = r.y + r.h - 1;
    ft_canvas_repeat(c, r.x + 1, r.y, r.w - 2, U'─', s);
    ft_canvas_repeat(c, r.x + 1, bottom, r.w - 2, U'─', s);
    ft_canvas_fill(c, (struct ft_rect){r.x, r.y + 1, 1, r.h - 2}, U'│', s);
    ft_canvas_fill(c, (struct ft_rect){right, r.y + 1, 1, r.h - 2}, U'│', s);
    put(c, r.x, r.y, U'┌', 1, s);
    put(c, right, r.y, U'┐', 1, s);
    put(c, r.x, bottom, U'└', 1, s);
    put(c, right, bottom, U'┘', 1, s);
}

static double bar_value(double v)
{
    return isfinite(v) && v > 0 ? v : 0;
}

int ft_canvas_bar(struct ft_canvas *c, int x, int y, int width, const struct ft_bar *bar)
{
    double sum = 0;
    double total;
    double cum = 0;
    int filled = 0;
    uint32_t rune = rune_glyph(bar->rune ? bar->rune : U'█').rune;

    if (width <= 0)
        return 0;
    for (size_t i = 0; i < bar->count; i++)
        sum += bar_value(bar->parts[i].value);
    total = bar_value(bar->total) > 0 ? bar->total : sum;

    /* Rounding the running sum keeps the parts adding up to the share of the whole. */
    for (size_t i = 0; i < bar->count && total > 0; i++) {
        cum += bar_value(bar->parts[i].value);
        double share = cum / total < 1 ? cum / total : 1;
        int stop = (int)lround(share * width);
        if (stop > filled) {
            ft_canvas_repeat(c, x + filled, y, stop - filled, rune, bar->parts[i].style);
            filled = stop;
        }
    }
    if (bar->empty_rune && filled < width)
        ft_canvas_repeat(c, x + filled, y, width - filled, bar->empty_rune, bar->empty);
    return filled;
}

void ft_canvas_meter(struct ft_canvas *c, int x, int y, int width, const struct ft_bar *bar,
                     struct ft_style frame, struct ft_style text_style, const char *text)
{
    if (width < 2)
        return;
    put(c, x, y, '[', 1, frame);
    ft_canvas_bar(c, x + 1, y, width - 2, bar);
    if (text)
        text_right(c, x + 1, y, width - 2, text_style, text, false);
    put(c, x + width - 1, y, ']', 1, frame);
}

void ft_canvas_spark(struct ft_canvas *c, int x, int y, int width, const double *values,
                     size_t count, double max, struct ft_style s)
{
    static const uint32_t levels[] = {U'▁', U'▂', U'▃', U'▄', U'▅', U'▆', U'▇', U'█'};
    size_t n;
    double top = bar_value(max);

    if (width <= 0 || count == 0)
        return;
    n = count < (size_t)width ? count : (size_t)width;
    values += count - n;
    if (top == 0) {
        for (size_t i = 0; i < n; i++) {
            if (bar_value(values[i]) > top)
                top = values[i];
        }
    }

    int left = x + width - (int)n;
    for (size_t i = 0; i < n; i++) {
        double v = bar_value(values[i]);
        double f = top > 0 ? (v < top ? v / top : 1) : 0;
        put(c, left + (int)i, y, levels[lround(f * 7)], 1, s);
    }
}
