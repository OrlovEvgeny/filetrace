#include "ui/ui.h"

#include <stdlib.h>
#include <string.h>

constexpr size_t CELL_MAX = FT_PATH_MAX + 64;

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

void ft_table_print(FILE *out, const struct ft_column_spec *cols, size_t ncols, size_t nrows,
                    ft_cell_fn *cell, void *ctx, bool styled)
{
    size_t *widths = calloc(ncols ? ncols : 1, sizeof(size_t));
    char *buf = malloc(CELL_MAX);
    if (!widths || !buf) {
        free(widths);
        free(buf);
        return;
    }

    for (size_t c = 0; c < ncols; c++)
        widths[c] = ft_text_width(cols[c].title);
    for (size_t r = 0; r < nrows; r++) {
        for (size_t c = 0; c < ncols; c++) {
            size_t w = ft_text_width(cell(ctx, r, c, buf, CELL_MAX));
            if (w > widths[c])
                widths[c] = w;
        }
    }

    if (styled)
        fputs(FT_STYLE_BOLD, out);
    for (size_t c = 0; c < ncols; c++) {
        size_t w = ft_text_width(cols[c].title);
        if (cols[c].right)
            pad(out, widths[c] - w);
        fputs(cols[c].title, out);
        if (c + 1 < ncols)
            pad(out, (cols[c].right ? 0 : widths[c] - w) + 2);
    }
    if (styled)
        fputs(FT_STYLE_RESET, out);
    fputc('\n', out);

    for (size_t r = 0; r < nrows; r++) {
        for (size_t c = 0; c < ncols; c++) {
            const char *text = cell(ctx, r, c, buf, CELL_MAX);
            size_t w = ft_text_width(text);
            if (cols[c].right)
                pad(out, widths[c] - w);
            fputs(text, out);
            if (c + 1 < ncols)
                pad(out, (cols[c].right ? 0 : widths[c] - w) + 2);
        }
        fputc('\n', out);
    }
    free(widths);
    free(buf);
}
