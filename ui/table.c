#include "ui/ui.h"

#include <stdlib.h>
#include <string.h>

constexpr size_t CELL_MAX = FT_PATH_MAX + 64;
constexpr size_t GAP = 2;

size_t ft_text_width(const char *s)
{
    size_t width = 0;
    for (; *s; s++) {
        if (((unsigned char)*s & 0xc0) != 0x80)
            width++;
    }
    return width;
}

static void pad(FILE *out, size_t n)
{
    while (n--)
        fputc(' ', out);
}

struct column {
    size_t natural; /* its widest cell, the title included */
    size_t width;
    bool shown;
};

struct layout {
    struct column *columns;
    size_t ncols;
    char *cell; /* storage for the text of a cell */
    char *cut;  /* that text cut to its column */
};

static void layout_free(struct layout *l)
{
    free(l->columns);
    free(l->cell);
    free(l->cut);
}

static bool layout_init(struct layout *l, size_t ncols)
{
    *l = (struct layout){
        .columns = calloc(ncols ? ncols : 1, sizeof(*l->columns)),
        .ncols = ncols,
        .cell = malloc(CELL_MAX),
        .cut = malloc(CELL_MAX),
    };
    if (l->columns && l->cell && l->cut)
        return true;
    layout_free(l);
    return false;
}

/* Sizes every column to its widest cell, and shows it whole. */
static void measure(struct layout *l, const struct ft_column_spec *cols, size_t nrows,
                    ft_cell_fn *cell, void *ctx)
{
    for (size_t c = 0; c < l->ncols; c++)
        l->columns[c].natural = ft_text_width(cols[c].title);
    for (size_t r = 0; r < nrows; r++) {
        for (size_t c = 0; c < l->ncols; c++) {
            size_t w = ft_text_width(cell(ctx, r, c, l->cell, CELL_MAX));
            if (w > l->columns[c].natural)
                l->columns[c].natural = w;
        }
    }
    for (size_t c = 0; c < l->ncols; c++) {
        l->columns[c].width = l->columns[c].natural;
        l->columns[c].shown = true;
    }
}

static size_t layout_width(const struct layout *l)
{
    size_t total = 0;
    size_t shown = 0;

    for (size_t c = 0; c < l->ncols; c++) {
        if (l->columns[c].shown) {
            total += l->columns[c].width;
            shown++;
        }
    }
    return shown ? total + GAP * (shown - 1) : 0;
}

static size_t least_width(const struct ft_column_spec *col, size_t least, size_t natural)
{
    size_t title = ft_text_width(col->title);

    if (least < title)
        least = title;
    return least < natural ? least : natural;
}

/* Cuts the shown columns in turn, each only as far as the table still needs. */
static void cut_columns(struct layout *l, const struct ft_column_spec *cols,
                        const struct ft_column_fit *fit, size_t width)
{
    for (size_t c = 0; c < l->ncols; c++)
        l->columns[c].width = l->columns[c].natural;

    size_t total = layout_width(l);
    for (int turn = 1; turn <= UINT8_MAX && total > width; turn++) {
        for (size_t c = 0; c < l->ncols && total > width; c++) {
            struct column *col = &l->columns[c];
            if (!col->shown || (fit[c].cut != turn && fit[c].early_cut != turn))
                continue;
            size_t least = fit[c].cut == turn ? fit[c].least : fit[c].early_least;
            size_t narrowest = least_width(&cols[c], least, col->natural);
            size_t give = col->width > narrowest ? col->width - narrowest : 0;
            if (give > total - width)
                give = total - width;
            col->width -= give;
            total -= give;
        }
    }
}

static bool fit_columns(struct layout *l, const struct ft_column_spec *cols,
                        const struct ft_column_fit *fit, size_t width)
{
    cut_columns(l, cols, fit, width);
    for (int turn = 1; turn <= UINT8_MAX && layout_width(l) > width; turn++) {
        bool left = false;
        for (size_t c = 0; c < l->ncols; c++) {
            if (fit[c].leave == turn) {
                l->columns[c].shown = false;
                left = true;
            }
        }
        if (left)
            cut_columns(l, cols, fit, width);
    }
    return layout_width(l) <= width;
}

/* Where the code point that follows the first n of s starts. */
static const char *skip_points(const char *s, size_t n)
{
    for (; *s; s++) {
        if (((unsigned char)*s & 0xc0) == 0x80)
            continue;
        if (n == 0)
            break;
        n--;
    }
    return s;
}

/* Where a count such as " (+2)" that ends the text starts, or the end of a text without one. */
static const char *count_start(const char *text)
{
    size_t len = strlen(text);
    size_t at = len ? len - 1 : 0;

    if (len == 0 || text[at] != ')')
        return text + len;
    while (at > 0 && text[at - 1] >= '0' && text[at - 1] <= '9')
        at--;
    if (at == len - 1 || at < 3 || memcmp(text + at - 3, " (+", 3) != 0)
        return text + len;
    return text + at - 3;
}

/* The text cut to width with "..." where it gives up some; out holds a cut one. */
static const char *cut_text(const char *text, size_t width, const struct ft_column_fit *fit,
                            char *out, size_t size)
{
    size_t have = ft_text_width(text);
    if (have <= width)
        return text;

    const char *dots = width > 3 ? "..." : "";
    size_t keep = width - strlen(dots);
    const char *count = fit && fit->keep_count ? count_start(text) : "";
    if (fit && fit->keep_end)
        snprintf(out, size, "%s%s", dots, skip_points(text, have - keep));
    else if (*count && strlen(count) < keep)
        snprintf(out, size, "%.*s%s%s", (int)(skip_points(text, keep - strlen(count)) - text), text,
                 dots, count);
    else
        snprintf(out, size, "%.*s%s", (int)(skip_points(text, keep) - text), text, dots);
    return out;
}

static void print_cell(FILE *out, const char *text, size_t width, bool right, bool last)
{
    size_t w = ft_text_width(text);

    if (right)
        pad(out, width - w);
    fputs(text, out);
    if (!last)
        pad(out, (right ? 0 : width - w) + GAP);
}

static void print_layout(FILE *out, const struct layout *l, const struct ft_column_spec *cols,
                         const struct ft_column_fit *fit, size_t nrows, ft_cell_fn *cell, void *ctx,
                         bool styled)
{
    size_t last = 0;

    for (size_t c = 0; c < l->ncols; c++) {
        if (l->columns[c].shown)
            last = c;
    }

    if (styled)
        fputs(FT_STYLE_BOLD, out);
    for (size_t c = 0; c < l->ncols; c++) {
        if (l->columns[c].shown)
            print_cell(out, cols[c].title, l->columns[c].width, cols[c].right, c == last);
    }
    if (styled)
        fputs(FT_STYLE_RESET, out);
    fputc('\n', out);

    for (size_t r = 0; r < nrows; r++) {
        for (size_t c = 0; c < l->ncols; c++) {
            const struct column *col = &l->columns[c];
            if (!col->shown)
                continue;
            const char *text = cut_text(cell(ctx, r, c, l->cell, CELL_MAX), col->width,
                                        fit ? &fit[c] : nullptr, l->cut, CELL_MAX);
            print_cell(out, text, col->width, cols[c].right, c == last);
        }
        fputc('\n', out);
    }
}

void ft_table_print(FILE *out, const struct ft_column_spec *cols, size_t ncols, size_t nrows,
                    ft_cell_fn *cell, void *ctx, bool styled)
{
    struct layout l;

    if (!layout_init(&l, ncols))
        return;
    measure(&l, cols, nrows, cell, ctx);
    print_layout(out, &l, cols, nullptr, nrows, cell, ctx, styled);
    layout_free(&l);
}

bool ft_table_print_fit(FILE *out, const struct ft_column_spec *cols,
                        const struct ft_column_fit *fit, size_t ncols, size_t nrows,
                        ft_cell_fn *cell, void *ctx, bool styled, size_t width)
{
    struct layout l;

    if (!layout_init(&l, ncols))
        return false;
    measure(&l, cols, nrows, cell, ctx);
    bool fits = fit_columns(&l, cols, fit, width);
    print_layout(out, &l, cols, fit, nrows, cell, ctx, styled);
    layout_free(&l);
    return fits;
}
