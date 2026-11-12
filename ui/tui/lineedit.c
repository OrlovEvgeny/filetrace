#include "ui/tui/lineedit.h"

#include <string.h>

/* Where the character at offset at ends, with the zero-width characters that follow it. */
static size_t next_boundary(const struct ft_lineedit *e, size_t at)
{
    int cols;

    if (at >= e->len)
        return e->len;
    at += ft_text_next(e->text + at, e->len - at, &cols);
    while (at < e->len) {
        size_t n = ft_text_next(e->text + at, e->len - at, &cols);
        if (cols != 0)
            break;
        at += n;
    }
    return at;
}

static size_t prev_boundary(const struct ft_lineedit *e, size_t at)
{
    size_t prev = 0;

    for (size_t pos = 0; pos < at; pos = next_boundary(e, pos))
        prev = pos;
    return prev;
}

static int columns(const struct ft_lineedit *e, size_t from, size_t to)
{
    int cols = 0;
    int w;

    while (from < to) {
        from += ft_text_next(e->text + from, to - from, &w);
        cols += w;
    }
    return cols;
}

/* UTF-8 for a character that can be typed; 0 for a control or an invalid code point. */
static size_t encode(uint32_t r, char *out)
{
    if (r < 0x20 || (r >= 0x7f && r < 0xa0) || (r >= 0xd800 && r < 0xe000) || r > 0x10ffff)
        return 0;
    if (r < 0x80) {
        out[0] = (char)r;
        return 1;
    }
    if (r < 0x800) {
        out[0] = (char)(0xc0 | r >> 6);
        out[1] = (char)(0x80 | (r & 0x3f));
        return 2;
    }
    if (r < 0x10000) {
        out[0] = (char)(0xe0 | r >> 12);
        out[1] = (char)(0x80 | (r >> 6 & 0x3f));
        out[2] = (char)(0x80 | (r & 0x3f));
        return 3;
    }
    out[0] = (char)(0xf0 | r >> 18);
    out[1] = (char)(0x80 | (r >> 12 & 0x3f));
    out[2] = (char)(0x80 | (r >> 6 & 0x3f));
    out[3] = (char)(0x80 | (r & 0x3f));
    return 4;
}

/* Replaces bytes [from, to) with n bytes and puts the cursor after them. */
static bool splice(struct ft_lineedit *e, size_t from, size_t to, const char *bytes, size_t n)
{
    if (from == to && n == 0)
        return false;
    if (e->len - (to - from) + n >= sizeof(e->text))
        return false;
    memmove(e->text + from + n, e->text + to, e->len - to + 1);
    memcpy(e->text + from, bytes, n);
    e->len = e->len - (to - from) + n;
    e->cursor = from + n;
    return true;
}

void ft_lineedit_set(struct ft_lineedit *e, const char *text)
{
    size_t len = strlen(text);
    size_t n = 0;
    int cols;

    while (n < len) {
        size_t step = ft_text_next(text + n, len - n, &cols);
        if (n + step >= sizeof(e->text))
            break;
        n += step;
    }
    memcpy(e->text, text, n);
    e->text[n] = '\0';
    e->len = n;
    e->cursor = n;
}

bool ft_lineedit_key(struct ft_lineedit *e, const struct ft_input *in)
{
    char utf8[4];
    size_t n;
    size_t start;

    if (in->kind != FT_INPUT_KEY)
        return false;
    if (e->cursor > e->len)
        e->cursor = e->len;

    switch (in->key) {
    case FT_KEY_CHAR:
    case FT_KEY_SPACE:
        if (in->mods & (FT_MOD_ALT | FT_MOD_CTRL))
            return false;
        n = encode(in->rune, utf8);
        return n > 0 && splice(e, e->cursor, e->cursor, utf8, n);
    case FT_KEY_BACKSPACE:
        return splice(e, prev_boundary(e, e->cursor), e->cursor, "", 0);
    case FT_KEY_DELETE:
        return splice(e, e->cursor, next_boundary(e, e->cursor), "", 0);
    case FT_KEY_LEFT:
        e->cursor = prev_boundary(e, e->cursor);
        return false;
    case FT_KEY_RIGHT:
        e->cursor = next_boundary(e, e->cursor);
        return false;
    case FT_KEY_HOME:
    case FT_KEY_CTRL_A:
        e->cursor = 0;
        return false;
    case FT_KEY_END:
    case FT_KEY_CTRL_E:
        e->cursor = e->len;
        return false;
    case FT_KEY_CTRL_U:
        return splice(e, 0, e->cursor, "", 0);
    case FT_KEY_CTRL_K:
        return splice(e, e->cursor, e->len, "", 0);
    case FT_KEY_CTRL_W:
        /* Bytes of a multi-byte character are never a space, so this stops on a boundary. */
        start = e->cursor;
        while (start > 0 && e->text[start - 1] == ' ')
            start--;
        while (start > 0 && e->text[start - 1] != ' ')
            start--;
        return splice(e, start, e->cursor, "", 0);
    default:
        return false;
    }
}

int ft_lineedit_draw(const struct ft_lineedit *e, struct ft_canvas *c, int x, int y, int width,
                     struct ft_style s)
{
    size_t cursor = e->cursor < e->len ? e->cursor : e->len;
    int cursor_col = columns(e, 0, cursor);
    int scroll = cursor_col < width ? 0 : cursor_col - width + 1;
    size_t from = 0;
    int col = 0;

    if (width <= 0)
        return x;
    while (from < e->len && col < scroll) {
        int w;
        from += ft_text_next(e->text + from, e->len - from, &w);
        col += w;
    }
    ft_canvas_fill(c, (struct ft_rect){x, y, width, 1}, ' ', s);
    ft_canvas_text(c, x + col - scroll, y, width - (col - scroll), s, e->text + from);
    return x + cursor_col - scroll;
}
