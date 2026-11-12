#include "ui/top/plain.h"

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

bool ft_top_print_table(const struct ft_top_model *m, const struct ft_top_ui *ui, int cols,
                        enum ft_color_depth depth, FILE *out)
{
    (void)m;
    (void)ui;
    (void)cols;
    (void)depth;
    (void)out;
    return true;
}
