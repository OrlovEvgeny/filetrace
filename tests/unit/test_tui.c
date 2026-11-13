#include "unit/test.h"

#include "ui/tui/canvas.h"
#include "ui/tui/lineedit.h"
#include "ui/tui/theme.h"
#include "ui/ui.h"

#include <stdlib.h>

static const struct ft_style TEXT = {.fg = FT_COLOR_TEXT};

static size_t utf8_put(uint32_t r, char *out)
{
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

/* The characters of a row, the right halves of wide ones left out. */
static const char *row(const struct ft_canvas *c, int y)
{
    static char buf[512];
    size_t n = 0;

    for (int x = 0; x < ft_canvas_cols(c) && n + 4 < sizeof(buf); x++) {
        uint32_t r = ft_canvas_at(c, x, y)->rune;
        if (r)
            n += utf8_put(r, buf + n);
    }
    buf[n] = '\0';
    return buf;
}

/* The same without the spaces at its end. */
static const char *row_trim(const struct ft_canvas *c, int y)
{
    static char buf[512];
    size_t n;

    ft_strlcpy(buf, row(c, y), sizeof(buf));
    n = strlen(buf);
    while (n > 0 && buf[n - 1] == ' ')
        buf[--n] = '\0';
    return buf;
}

static int count_fg(const struct ft_canvas *c, int y, enum ft_color fg)
{
    int n = 0;

    for (int x = 0; x < ft_canvas_cols(c); x++)
        n += ft_canvas_at(c, x, y)->fg == fg;
    return n;
}

static void test_text_clipping(void)
{
    struct ft_canvas *c = ft_canvas_create(10, 3);

    CHECK_U64(ft_canvas_text(c, 7, 0, 10, TEXT, "abcdef"), 6);
    CHECK_STR(row(c, 0), "       abc");

    struct ft_rect saved = ft_canvas_clip(c, (struct ft_rect){2, 1, 4, 1});
    ft_canvas_text(c, 0, 1, 10, TEXT, "abcdefgh");
    ft_canvas_text(c, 0, 2, 10, TEXT, "outside");
    ft_canvas_clip(c, saved);
    CHECK_STR(row(c, 1), "  cdef    ");
    CHECK_STR(row(c, 2), "          ");

    ft_canvas_text(c, -2, 2, 10, TEXT, "abcdef");
    ft_canvas_text(c, 0, 3, 10, TEXT, "below");
    ft_canvas_text(c, 0, -1, 10, TEXT, "above");
    CHECK_STR(row(c, 2), "cdef      ");
    ft_canvas_destroy(c);
}

static void test_text_wide(void)
{
    struct ft_canvas *c = ft_canvas_create(5, 3);

    CHECK_U64(ft_canvas_text(c, 0, 0, 5, TEXT, "ab漢字"), 5);
    CHECK_STR(row(c, 0), "ab漢 ");
    CHECK_U64(ft_canvas_at(c, 3, 0)->rune, 0);
    CHECK_U64(ft_canvas_at(c, 4, 0)->rune, ' ');

    ft_canvas_text(c, 3, 1, 10, TEXT, "a漢");
    CHECK_STR(row(c, 1), "   a ");

    ft_canvas_clip(c, (struct ft_rect){1, 2, 4, 1});
    ft_canvas_text(c, 0, 2, 5, TEXT, "漢b");
    CHECK_STR(row(c, 2), "  b  ");

    /* Drawing over either half of a wide character leaves no half behind. */
    ft_canvas_clear(c, TEXT);
    ft_canvas_text(c, 0, 0, 5, TEXT, "漢字");
    ft_canvas_text(c, 1, 0, 1, TEXT, "x");
    ft_canvas_text(c, 2, 0, 1, TEXT, "y");
    CHECK_STR(row(c, 0), " xy  ");
    ft_canvas_destroy(c);
}

static void test_text_sanitized(void)
{
    struct ft_canvas *c = ft_canvas_create(20, 2);

    CHECK_U64(ft_canvas_text(c, 0, 0, 20, TEXT,
                             "a\xff"
                             "b\x1b[31mc\x7f\xc2\x9b\xc0\xaf"
                             "d"),
              14);
    CHECK_STR(row(c, 0), "a?b?[31mc????d      ");
    for (int x = 0; x < 20; x++) {
        uint32_t r = ft_canvas_at(c, x, 0)->rune;
        CHECK(r >= 0x20 && !(r >= 0x7f && r < 0xa0));
    }

    CHECK_U64(ft_text_columns("e\xcc\x81x"), 2);
    ft_canvas_destroy(c);
}

static void test_text_cut(void)
{
    struct ft_canvas *c = ft_canvas_create(5, 8);

    CHECK_U64(ft_canvas_text_cut(c, 0, 0, 5, TEXT, "abcdefghij", FT_CUT_END), 5);
    CHECK_STR(row(c, 0), "abcd…");
    CHECK_U64(ft_canvas_text_cut(c, 0, 1, 5, TEXT, "abcdefghij", FT_CUT_START), 5);
    CHECK_STR(row(c, 1), "…ghij");
    CHECK_U64(ft_canvas_text(c, 0, 2, 5, TEXT, "abcdefghij"), 5);
    CHECK_STR(row(c, 2), "abcde");
    CHECK_U64(ft_canvas_text_cut(c, 0, 3, 4, TEXT, "漢字ab", FT_CUT_START), 3);
    CHECK_STR(row(c, 3), "…ab  ");
    CHECK_U64(ft_canvas_text_cut(c, 0, 4, 4, TEXT, "ab漢字", FT_CUT_END), 3);
    CHECK_STR(row(c, 4), "ab…  ");
    CHECK_U64(ft_canvas_text_cut(c, 0, 5, 1, TEXT, "abc", FT_CUT_END), 1);
    CHECK_STR(row(c, 5), "…    ");
    CHECK_U64(ft_canvas_text_cut(c, 0, 6, 5, TEXT, "abcde", FT_CUT_START), 5);
    CHECK_STR(row(c, 6), "abcde");
    ft_canvas_destroy(c);
}

static void test_text_right(void)
{
    struct ft_canvas *c = ft_canvas_create(6, 3);

    ft_canvas_fill(c, (struct ft_rect){0, 0, 6, 3}, 'x', TEXT);
    CHECK_U64(ft_canvas_text_right(c, 0, 0, 5, TEXT, "42"), 2);
    CHECK_STR(row(c, 0), "   42x");
    CHECK_U64(ft_canvas_text_right(c, 0, 1, 4, TEXT, "123456"), 4);
    CHECK_STR(row(c, 1), "123…xx");
    CHECK_U64(ft_canvas_textf_right(c, 0, 2, 6, TEXT, "%d%%", 63), 3);
    CHECK_STR(row(c, 2), "   63%");
    ft_canvas_destroy(c);
}

static void test_text_keeps_background(void)
{
    struct ft_canvas *c = ft_canvas_create(6, 1);

    ft_canvas_clear(c, (struct ft_style){.fg = FT_COLOR_TEXT, .bg = FT_COLOR_BG});
    ft_canvas_fill(c, (struct ft_rect){0, 0, 4, 1}, ' ', (struct ft_style){.bg = FT_COLOR_GREEN});
    ft_canvas_text(c, 0, 0, 6, (struct ft_style){.fg = FT_COLOR_BG}, "ab");
    ft_canvas_text(c, 2, 0, 6, (struct ft_style){.fg = FT_COLOR_BG, .bg = FT_COLOR_BG}, "cd");
    CHECK(ft_canvas_at(c, 1, 0)->bg == FT_COLOR_GREEN);
    CHECK(ft_canvas_at(c, 1, 0)->fg == FT_COLOR_BG);
    CHECK(ft_canvas_at(c, 2, 0)->bg == FT_COLOR_BG);
    ft_canvas_destroy(c);
}

static void test_path(void)
{
    struct ft_style dir = {.fg = FT_COLOR_DIM};
    struct ft_style name = {.fg = FT_COLOR_BRIGHT, .attrs = FT_ATTR_BOLD};
    struct ft_canvas *c = ft_canvas_create(30, 4);

    CHECK_U64(ft_canvas_path(c, 0, 0, 30, dir, name, "/var/log/nginx/access.log"), 25);
    CHECK_U64(count_fg(c, 0, FT_COLOR_DIM), 15);
    CHECK_U64(count_fg(c, 0, FT_COLOR_BRIGHT), 10);
    CHECK(ft_canvas_at(c, 15, 0)->fg == FT_COLOR_BRIGHT && ft_canvas_at(c, 15, 0)->attrs);

    CHECK_U64(ft_canvas_path(c, 0, 1, 15, dir, name, "/var/log/nginx/access.log"), 15);
    CHECK_STR(row_trim(c, 1), "…inx/access.log");
    CHECK(ft_canvas_at(c, 0, 1)->fg == FT_COLOR_DIM);
    CHECK(ft_canvas_at(c, 4, 1)->fg == FT_COLOR_DIM);
    CHECK(ft_canvas_at(c, 5, 1)->fg == FT_COLOR_BRIGHT);

    CHECK_U64(ft_canvas_path(c, 0, 2, 6, dir, name, "/a/verylongname.txt"), 6);
    CHECK_STR(row_trim(c, 2), "…e.txt");
    CHECK(ft_canvas_at(c, 0, 2)->fg == FT_COLOR_DIM);
    CHECK_U64(count_fg(c, 2, FT_COLOR_BRIGHT), 5);

    ft_canvas_path(c, 0, 3, 30, dir, name, "file.txt");
    CHECK_U64(count_fg(c, 3, FT_COLOR_BRIGHT), 8);
    ft_canvas_destroy(c);
}

static void test_mark(void)
{
    const char *path = "/srv/app/storage/invoices/INV-1.pdf";
    struct ft_style hit = {.fg = FT_COLOR_BG, .bg = FT_COLOR_AMBER};
    struct ft_canvas *c = ft_canvas_create(20, 2);

    ft_canvas_path(c, 0, 0, 20, (struct ft_style){.fg = FT_COLOR_DIM},
                   (struct ft_style){.fg = FT_COLOR_BRIGHT, .attrs = FT_ATTR_BOLD}, path);
    CHECK_STR(row(c, 0), "…/invoices/INV-1.pdf");

    ft_canvas_mark(c, 0, 0, 20, path, FT_CUT_START, 9, 16, hit);
    CHECK(ft_canvas_at(c, 0, 0)->bg == FT_COLOR_AMBER);
    CHECK(ft_canvas_at(c, 1, 0)->bg != FT_COLOR_AMBER);

    ft_canvas_mark(c, 0, 0, 20, path, FT_CUT_START, 26, 29, hit);
    CHECK(ft_canvas_at(c, 10, 0)->bg != FT_COLOR_AMBER);
    CHECK(ft_canvas_at(c, 11, 0)->bg == FT_COLOR_AMBER);
    CHECK(ft_canvas_at(c, 13, 0)->bg == FT_COLOR_AMBER);
    CHECK(ft_canvas_at(c, 14, 0)->bg != FT_COLOR_AMBER);
    CHECK(ft_canvas_at(c, 11, 0)->attrs == FT_ATTR_BOLD);

    int n = ft_canvas_text_right(c, 0, 1, 8, TEXT, "12044");
    ft_canvas_mark(c, 8 - n, 1, n, "12044", FT_CUT_END, 1, 3, hit);
    CHECK(ft_canvas_at(c, 3, 1)->bg != FT_COLOR_AMBER);
    CHECK(ft_canvas_at(c, 4, 1)->bg == FT_COLOR_AMBER);
    CHECK(ft_canvas_at(c, 5, 1)->bg == FT_COLOR_AMBER);
    CHECK(ft_canvas_at(c, 6, 1)->bg != FT_COLOR_AMBER);
    ft_canvas_destroy(c);
}

static void test_bar_widths(void)
{
    const struct ft_bar_part thirds[] = {
        {1, {.fg = FT_COLOR_GREEN}},
        {1, {.fg = FT_COLOR_AMBER}},
        {1, {.fg = FT_COLOR_BLUE}},
    };
    const struct ft_bar_part partial[] = {
        {0.5, {.fg = FT_COLOR_GREEN}},
        {0.25, {.fg = FT_COLOR_AMBER}},
    };
    struct ft_canvas *c = ft_canvas_create(100, 3);

    for (int width = 1; width <= 100; width++) {
        ft_canvas_clear(c, TEXT);
        int filled = ft_canvas_bar(c, 0, 0, width, &(struct ft_bar){.parts = thirds, .count = 3});
        int green = count_fg(c, 0, FT_COLOR_GREEN);
        int amber = count_fg(c, 0, FT_COLOR_AMBER);
        int blue = count_fg(c, 0, FT_COLOR_BLUE);
        CHECK(filled == width && green + amber + blue == width);
        CHECK(green >= width / 3 && green <= width / 3 + 1 && blue <= width / 3 + 1);
    }

    struct ft_bar bar = {
        .parts = partial,
        .count = 2,
        .total = 1,
        .rune = '|',
        .empty_rune = U'░',
        .empty = {.fg = FT_COLOR_TRACK},
    };
    CHECK_U64(ft_canvas_bar(c, 0, 1, 7, &bar), 5);
    CHECK_STR(row_trim(c, 1), "|||||░░");
    CHECK_U64(count_fg(c, 1, FT_COLOR_GREEN), 4);
    CHECK_U64(count_fg(c, 1, FT_COLOR_AMBER), 1);
    ft_canvas_destroy(c);
}

static bool term_color(struct ft_term_color c, enum ft_term_color_kind kind, uint32_t value)
{
    return c.kind == kind && (kind == FT_TERM_DEFAULT || c.value == value);
}

static void test_theme_roles(void)
{
    struct ft_term_style t;

    t = ft_theme_resolve(FT_DEPTH_TRUECOLOR, FT_COLOR_DIM, FT_COLOR_BG, 0);
    CHECK(term_color(t.fg, FT_TERM_RGB, 0x7d8590));
    CHECK(term_color(t.bg, FT_TERM_RGB, 0x0b0e14));
    t = ft_theme_resolve(FT_DEPTH_256, FT_COLOR_DIM, FT_COLOR_BG, 0);
    CHECK(term_color(t.fg, FT_TERM_INDEX, 244));
    CHECK(term_color(t.bg, FT_TERM_DEFAULT, 0));
    t = ft_theme_resolve(FT_DEPTH_16, FT_COLOR_DIM, FT_COLOR_BG, 0);
    CHECK(term_color(t.fg, FT_TERM_INDEX, 8));
    CHECK(term_color(t.bg, FT_TERM_DEFAULT, 0));
    t = ft_theme_resolve(FT_DEPTH_NONE, FT_COLOR_DIM, FT_COLOR_BG, 0);
    CHECK(term_color(t.fg, FT_TERM_DEFAULT, 0) && term_color(t.bg, FT_TERM_DEFAULT, 0));
    CHECK_U64(t.attrs, FT_TERM_DIM);

    /* Dark text on the selection bar. */
    t = ft_theme_resolve(FT_DEPTH_256, FT_COLOR_BG, FT_COLOR_CYAN, FT_ATTR_BOLD);
    CHECK(term_color(t.fg, FT_TERM_INDEX, 0) && term_color(t.bg, FT_TERM_INDEX, 80));
    CHECK_U64(t.attrs, FT_ATTR_BOLD);
    t = ft_theme_resolve(FT_DEPTH_16, FT_COLOR_BG, FT_COLOR_CYAN, 0);
    CHECK(term_color(t.fg, FT_TERM_INDEX, 0) && term_color(t.bg, FT_TERM_INDEX, 6));
    t = ft_theme_resolve(FT_DEPTH_NONE, FT_COLOR_BG, FT_COLOR_CYAN, 0);
    CHECK_U64(t.attrs, FT_ATTR_REVERSE);

    t = ft_theme_resolve(FT_DEPTH_16, FT_COLOR_BRIGHT, FT_COLOR_DEFAULT, 0);
    CHECK(term_color(t.fg, FT_TERM_INDEX, 15));
    CHECK_U64(t.attrs, FT_ATTR_BOLD);
    t = ft_theme_resolve(FT_DEPTH_TRUECOLOR, FT_COLOR_TEXT, FT_COLOR_DEFAULT, 0);
    CHECK(term_color(t.fg, FT_TERM_RGB, 0xc9d1d9) && term_color(t.bg, FT_TERM_DEFAULT, 0));
}

static void test_theme_detect(void)
{
    CHECK(ft_color_depth_for(FT_COLOR_MODE_AUTO, "xterm-256color", "truecolor", "1") ==
          FT_DEPTH_NONE);
    CHECK(ft_color_depth_for(FT_COLOR_MODE_AUTO, "dumb", nullptr, nullptr) == FT_DEPTH_NONE);
    CHECK(ft_color_depth_for(FT_COLOR_MODE_NEVER, "xterm-256color", "truecolor", nullptr) ==
          FT_DEPTH_NONE);
    CHECK(ft_color_depth_for(FT_COLOR_MODE_ALWAYS, "xterm-256color", nullptr, "1") == FT_DEPTH_256);
    CHECK(ft_color_depth_for(FT_COLOR_MODE_ALWAYS, "dumb", nullptr, "1") == FT_DEPTH_16);
    CHECK(ft_color_depth_for(FT_COLOR_MODE_AUTO, "xterm-256color", "24bit", "") ==
          FT_DEPTH_TRUECOLOR);
    CHECK(ft_color_depth_for(FT_COLOR_MODE_AUTO, "xterm-kitty", nullptr, nullptr) ==
          FT_DEPTH_TRUECOLOR);
    CHECK(ft_color_depth_for(FT_COLOR_MODE_AUTO, "tmux-256color", nullptr, nullptr) ==
          FT_DEPTH_256);
    CHECK(ft_color_depth_for(FT_COLOR_MODE_AUTO, "xterm", nullptr, nullptr) == FT_DEPTH_16);
}

static bool press(struct ft_lineedit *e, enum ft_key key, uint32_t rune)
{
    struct ft_input in = {.kind = FT_INPUT_KEY, .key = key, .rune = rune};

    return ft_lineedit_key(e, &in);
}

static void test_lineedit_utf8(void)
{
    struct ft_lineedit e = {0};

    CHECK(press(&e, FT_KEY_CHAR, 'a'));
    CHECK(press(&e, FT_KEY_CHAR, U'é'));
    CHECK(press(&e, FT_KEY_CHAR, 'b'));
    CHECK_STR(e.text, "aéb");
    CHECK_U64(e.cursor, 4);

    CHECK(!press(&e, FT_KEY_LEFT, 0));
    CHECK_U64(e.cursor, 3);
    press(&e, FT_KEY_LEFT, 0);
    CHECK_U64(e.cursor, 1);
    press(&e, FT_KEY_RIGHT, 0);
    CHECK_U64(e.cursor, 3);

    CHECK(press(&e, FT_KEY_BACKSPACE, 0));
    CHECK_STR(e.text, "ab");
    CHECK_U64(e.cursor, 1);
    CHECK(press(&e, FT_KEY_CHAR, U'漢'));
    CHECK_STR(e.text, "a漢b");
    CHECK_U64(e.cursor, 4);
    press(&e, FT_KEY_LEFT, 0);
    CHECK_U64(e.cursor, 1);
    CHECK(press(&e, FT_KEY_DELETE, 0));
    CHECK_STR(e.text, "ab");
    CHECK_U64(e.len, 2);

    press(&e, FT_KEY_HOME, 0);
    CHECK(!press(&e, FT_KEY_BACKSPACE, 0));
    CHECK(!press(&e, FT_KEY_CHAR, 0x1b));
    CHECK_STR(e.text, "ab");

    ft_lineedit_set(&e, "abcdefghij");
    struct ft_canvas *c = ft_canvas_create(6, 1);
    CHECK_U64(ft_lineedit_draw(&e, c, 1, 0, 5, TEXT), 5);
    CHECK_STR(row(c, 0), " ghij ");
    ft_canvas_destroy(c);
}

static void test_lineedit_words(void)
{
    struct ft_lineedit e = {0};

    ft_lineedit_set(&e, "file:/srv/app/** dest:public  ");
    CHECK(press(&e, FT_KEY_CTRL_W, 0));
    CHECK_STR(e.text, "file:/srv/app/** ");
    CHECK(press(&e, FT_KEY_CTRL_W, 0));
    CHECK_STR(e.text, "");
    CHECK(!press(&e, FT_KEY_CTRL_W, 0));

    ft_lineedit_set(&e, "foo bär baz");
    for (int i = 0; i < 4; i++)
        press(&e, FT_KEY_LEFT, 0);
    CHECK(press(&e, FT_KEY_CTRL_W, 0));
    CHECK_STR(e.text, "foo  baz");
    CHECK_U64(e.cursor, 4);
    CHECK(press(&e, FT_KEY_CTRL_K, 0));
    CHECK_STR(e.text, "foo ");
    CHECK(press(&e, FT_KEY_CTRL_U, 0));
    CHECK_STR(e.text, "");
}

static const struct ft_column_spec FIT_COLUMNS[] = {
    {"NAME", false},
    {"PATH", false},
    {"RATE", true},
    {"NOTE", false},
};
static const struct ft_column_fit FIT[] = {
    {.cut = 2, .least = 8},
    {.cut = 1, .least = 16, .keep_end = true},
    {0},
    {.leave = 1},
};
/* NAME cut to 12 before PATH is cut, and to 8 after it. */
static const struct ft_column_fit TWO_TURNS[] = {
    {.cut = 3, .least = 8, .early_cut = 1, .early_least = 12},
    {.cut = 2, .least = 16, .keep_end = true},
    {0},
    {.leave = 1},
};
/* Letters beyond ASCII both in what a cut takes and in what it keeps. */
static const char *const FIT_CELLS[][4] = {
    {"alpha", "/vär/log/nginx/access.log", "12.5 MB/s", "EXACT"},
    {"clickhoüse-serv", "/srv/a.bin", "0 B/s", "INFERRED"},
};

static const char *fit_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    (void)ctx;
    snprintf(buf, size, "%s", FIT_CELLS[r][c]);
    return buf;
}

/* The table fitted to width, or as ft_table_print prints it for 0; the caller frees it. */
static char *fitted(const struct ft_column_fit *fit, size_t width, bool *fits)
{
    char *text = nullptr;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);

    CHECK(out != nullptr);
    if (!out)
        return strdup("");
    if (width)
        *fits = ft_table_print_fit(out, FIT_COLUMNS, fit, 4, 2, fit_cell, nullptr, false, width);
    else
        ft_table_print(out, FIT_COLUMNS, 4, 2, fit_cell, nullptr, false);
    fclose(out);
    return text;
}

static void check_fitted(const struct ft_column_fit *fit, size_t width, bool fits,
                         const char *expected)
{
    bool did = !fits;
    char *text = fitted(fit, width, &did);

    CHECK(did == fits);
    CHECK_STR(text, expected);
    free(text);
}

static void test_table_fit_untouched(void)
{
    const char *table = "NAME             PATH                            RATE  NOTE\n"
                        "alpha            /vär/log/nginx/access.log  12.5 MB/s  EXACT\n"
                        "clickhoüse-serv  /srv/a.bin                     0 B/s  INFERRED\n";
    bool fits = false;
    char *printed = fitted(FIT, 0, &fits);

    CHECK_STR(printed, table);
    free(printed);
    check_fitted(FIT, 63, true, table);
    check_fitted(FIT, SIZE_MAX, true, table);
}

static void test_table_fit_cuts_cells(void)
{
    check_fitted(FIT, 60, true,
                 "NAME             PATH                         RATE  NOTE\n"
                 "alpha            ...og/nginx/access.log  12.5 MB/s  EXACT\n"
                 "clickhoüse-serv  /srv/a.bin                  0 B/s  INFERRED\n");
    check_fitted(FIT, 54, true,
                 "NAME             PATH                   RATE  NOTE\n"
                 "alpha            ...nx/access.log  12.5 MB/s  EXACT\n"
                 "clickhoüse-serv  /srv/a.bin            0 B/s  INFERRED\n");
    check_fitted(FIT, 50, true,
                 "NAME         PATH                   RATE  NOTE\n"
                 "alpha        ...nx/access.log  12.5 MB/s  EXACT\n"
                 "clickhoü...  /srv/a.bin            0 B/s  INFERRED\n");
    check_fitted(FIT, 47, true,
                 "NAME      PATH                   RATE  NOTE\n"
                 "alpha     ...nx/access.log  12.5 MB/s  EXACT\n"
                 "click...  /srv/a.bin            0 B/s  INFERRED\n");
}

/* PATH, with one cut, gives way in its turn as it does in FIT. */
static void test_table_fit_cuts_in_two_turns(void)
{
    check_fitted(TWO_TURNS, 60, true,
                 "NAME          PATH                            RATE  NOTE\n"
                 "alpha         /vär/log/nginx/access.log  12.5 MB/s  EXACT\n"
                 "clickhoüs...  /srv/a.bin                     0 B/s  INFERRED\n");
    check_fitted(TWO_TURNS, 54, true,
                 "NAME          PATH                      RATE  NOTE\n"
                 "alpha         ...nginx/access.log  12.5 MB/s  EXACT\n"
                 "clickhoüs...  /srv/a.bin               0 B/s  INFERRED\n");
    check_fitted(TWO_TURNS, 48, true,
                 "NAME       PATH                   RATE  NOTE\n"
                 "alpha      ...nx/access.log  12.5 MB/s  EXACT\n"
                 "clickh...  /srv/a.bin            0 B/s  INFERRED\n");
}

static void test_table_fit_leaves_columns(void)
{
    check_fitted(FIT, 46, true,
                 "NAME             PATH                     RATE\n"
                 "alpha            ...ginx/access.log  12.5 MB/s\n"
                 "clickhoüse-serv  /srv/a.bin              0 B/s\n");
    check_fitted(FIT, 37, true,
                 "NAME      PATH                   RATE\n"
                 "alpha     ...nx/access.log  12.5 MB/s\n"
                 "click...  /srv/a.bin            0 B/s\n");
    check_fitted(FIT, 36, false,
                 "NAME      PATH                   RATE\n"
                 "alpha     ...nx/access.log  12.5 MB/s\n"
                 "click...  /srv/a.bin            0 B/s\n");
}

/* Every line within the width, and the rates ending where their title does. */
static void test_table_fit_bounds(void)
{
    const char *const rates[] = {"RATE", FIT_CELLS[0][2], FIT_CELLS[1][2]};

    for (size_t width = 37; width <= 70; width++) {
        bool fits = false;
        char *text = fitted(FIT, width, &fits);
        size_t ends[3] = {0};
        char *line = text;

        CHECK(fits);
        for (size_t i = 0; i < 3 && line; i++) {
            char *next = strchr(line, '\n');
            if (next)
                *next = '\0';
            const char *rate = strstr(line, rates[i]);
            ends[i] = rate ? ft_text_width(line) - ft_text_width(rate) + strlen(rates[i]) : 0;
            CHECK(ft_text_width(line) <= width);
            line = next ? next + 1 : nullptr;
        }
        CHECK(ends[0] > 0 && ends[1] == ends[0] && ends[2] == ends[0]);
        free(text);
    }
}

/* The network view of watch asks for what every filter of the screen selects of connections. */
static void test_watch_network_filters(void)
{
    struct ft_watch_options opt = {.direction = FT_WATCH_INBOUND};
    uint8_t network[16] = {203, 0, 113, 0};
    struct ft_query q;

    ft_query_init(&opt.filter, FT_Q_TRANSFERS);
    opt.filter.pid = 2210;
    opt.filter.proto = FT_PROTO_TCP;
    ft_endpoint_set(&opt.filter.remote, false, network, 0);
    opt.filter.remote_host_bits = 8;
    CHECK(ft_name_pattern("*.Example.com", opt.filter.remote_name));
    ft_strlcpy(opt.filter.path, "/data/*", sizeof(opt.filter.path));

    ft_watch_connections_query(&opt, 25, &q);
    CHECK_U64(q.kind, FT_Q_CONNECTIONS);
    CHECK(q.flags & FT_QF_ACTIVE);
    CHECK_U64(q.pid, 2210);
    CHECK_U64(q.proto, FT_PROTO_TCP);
    CHECK(ft_addr_equal(&q.remote, &opt.filter.remote));
    CHECK_U64(q.remote_host_bits, 8);
    CHECK_STR(q.remote_name, "*.example.com");
    CHECK_U64(q.sort, FT_SORT_INBOUND);
    CHECK_U64(q.limit, 25);
    /* A file filter says nothing of a connection. */
    CHECK_STR(q.path, "");
}

struct watch_transfer {
    const char *comm;
    uint32_t pid;
    const char *path;
    const char *remote;
    const struct ft_remote_names *names; /* nullptr: none */
    uint8_t method;
    uint64_t rate;
};

static const struct ft_remote_names BUCKET = {.tls = "pg-backups.s3.example.com",
                                              .resolved = {"pg-backups.s3.example.com"},
                                              .listed = 1,
                                              .count = 1};
static const struct ft_remote_names MIRROR = {
    .tls = "", .resolved = {"mirror-2.internal"}, .listed = 1, .count = 1};
static const struct ft_remote_names REGISTRY = {
    .tls = "registry.ml.example.com", .resolved = {"proxy.corp.internal"}, .listed = 1, .count = 1};

/* The rclone address, behind a name, is wider than the least a name is cut to. */
static const struct watch_transfer WATCH_TRANSFERS[] = {
    {"java", 12044, "/var/lib/kafka/data/events-7/00000000000191560343.log", "10.0.5.22", nullptr,
     FT_METHOD_SENDFILE, 67'400'000},
    {"rclone", 40112, "/srv/backups/pg/base-2026-11-12.tar.zst", "2001:db8:8a2e:370:7334::15",
     &BUCKET, FT_METHOD_READ_SEND, 57'900'000},
    {"nginx", 2218, "/var/www/cdn/video/launch-2026-hd.mp4", "203.0.113.61", nullptr,
     FT_METHOD_SENDFILE, 42'900'000},
    {"rsync", 5120, "/srv/releases/api-v4.18.2.tar.gz", "10.0.7.32", &MIRROR, FT_METHOD_READ_SEND,
     40'400'000},
    {"python3", 24410, "/srv/ml/models/brand-ner-v3.safetensors", "10.0.8.40", &REGISTRY,
     FT_METHOD_READ_SEND, 28'600'000},
};

static void watch_rows(struct ft_rows *rows)
{
    static const struct ft_remote_names nameless = {.tls = ""};
    struct ft_row_transfer *row = malloc(sizeof(*row));

    ft_rows_init(rows, FT_MSG_ROW_TRANSFER);
    for (size_t i = 0; row && i < FT_ARRAY_LEN(WATCH_TRANSFERS); i++) {
        const struct watch_transfer *w = &WATCH_TRANSFERS[i];
        memset(row, 0, sizeof(*row));
        row->pid = w->pid;
        row->rate = w->rate;
        row->method = w->method;
        row->confidence = w->method == FT_METHOD_SENDFILE ? FT_CONF_EXACT : FT_CONF_INFERRED;
        row->flags = FT_XFER_ACTIVE | FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN;
        CHECK(ft_addr_parse(w->remote, &row->remote));
        ft_strlcpy(row->comm, w->comm, sizeof(row->comm));
        ft_strlcpy(row->path, w->path, FT_PATH_MAX);
        size_t lead = strlen(row->path) + 1;
        ft_remote_names_pack(w->names ? w->names : &nameless, &row->names, row->path + lead,
                             sizeof(row->path) - lead);
        CHECK(ft_rows_append(rows, row, ft_row_transfer_size(row)));
    }
    free(row);
}

static void check_watch_files(size_t width, bool names, const char *expected)
{
    struct ft_rows rows;
    char *text = nullptr;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);

    CHECK(out != nullptr);
    if (!out)
        return;
    watch_rows(&rows);
    ft_watch_transfers_table(out, &rows, width, false, names);
    fclose(out);
    CHECK_STR(text, expected);
    free(text);
    ft_rows_free(&rows);
}

/* A long name gives way down to 24 columns before any path does. */
static void test_watch_files_by_name(void)
{
    check_watch_files(
        120, true,
        "PROCESS        FILE                                          DESTINATION               "
        "METHOD           RATE  CONFIDENCE\n"
        "java 12044     ...ka/data/events-7/00000000000191560343.log  10.0.5.22                 "
        "sendfile    64.3 MB/s  EXACT\n"
        "rclone 40112   /srv/backups/pg/base-2026-11-12.tar.zst       pg-backups.s3.example...  "
        "read-write  55.2 MB/s  INFERRED\n"
        "nginx 2218     /var/www/cdn/video/launch-2026-hd.mp4         203.0.113.61              "
        "sendfile    40.9 MB/s  EXACT\n"
        "rsync 5120     /srv/releases/api-v4.18.2.tar.gz              mirror-2.internal         "
        "read-write  38.5 MB/s  INFERRED\n"
        "python3 24410  /srv/ml/models/brand-ner-v3.safetensors       registry.ml.example.c...  "
        "read-write  27.3 MB/s  INFERRED\n");
    check_watch_files(100, true,
                      "PROCESS        FILE                      DESTINATION               METHOD "
                      "          RATE  CONFIDENCE\n"
                      "java 12044     ...00000000191560343.log  10.0.5.22                 sendfile "
                      "   64.3 MB/s  EXACT\n"
                      "rclone 40112   ...se-2026-11-12.tar.zst  pg-backups.s3.example...  "
                      "read-write  55.2 MB/s  INFERRED\n"
                      "nginx 2218     ...eo/launch-2026-hd.mp4  203.0.113.61              sendfile "
                      "   40.9 MB/s  EXACT\n"
                      "rsync 5120     ...es/api-v4.18.2.tar.gz  mirror-2.internal         "
                      "read-write  38.5 MB/s  INFERRED\n"
                      "python3 24410  ...nd-ner-v3.safetensors  registry.ml.example.c...  "
                      "read-write  27.3 MB/s  INFERRED\n");
    check_watch_files(57, true,
                      "PROCESS      FILE              DESTINATION           RATE\n"
                      "java 12044   ...191560343.log  10.0.5.22        64.3 MB/s\n"
                      "rclone 4...  ...11-12.tar.zst  pg-backups.s...  55.2 MB/s\n"
                      "nginx 2218   ...h-2026-hd.mp4  203.0.113.61     40.9 MB/s\n"
                      "rsync 5120   ...4.18.2.tar.gz  mirror-2.int...  38.5 MB/s\n"
                      "python3 ...  ...3.safetensors  registry.ml....  27.3 MB/s\n");
}

/* By address the paths give way first: no address is cut before a path is. */
static void test_watch_files_by_address(void)
{
    check_watch_files(
        120, false,
        "PROCESS        FILE                                        DESTINATION                 "
        "METHOD           RATE  CONFIDENCE\n"
        "java 12044     .../data/events-7/00000000000191560343.log  10.0.5.22                   "
        "sendfile    64.3 MB/s  EXACT\n"
        "rclone 40112   /srv/backups/pg/base-2026-11-12.tar.zst     2001:db8:8a2e:370:7334::15  "
        "read-write  55.2 MB/s  INFERRED\n"
        "nginx 2218     /var/www/cdn/video/launch-2026-hd.mp4       203.0.113.61                "
        "sendfile    40.9 MB/s  EXACT\n"
        "rsync 5120     /srv/releases/api-v4.18.2.tar.gz            10.0.7.32                   "
        "read-write  38.5 MB/s  INFERRED\n"
        "python3 24410  /srv/ml/models/brand-ner-v3.safetensors     10.0.8.40                   "
        "read-write  27.3 MB/s  INFERRED\n");
    check_watch_files(100, false,
                      "PROCESS        FILE                    DESTINATION                 METHOD   "
                      "        RATE  CONFIDENCE\n"
                      "java 12044     ...000000191560343.log  10.0.5.22                   sendfile "
                      "   64.3 MB/s  EXACT\n"
                      "rclone 40112   ...-2026-11-12.tar.zst  2001:db8:8a2e:370:7334::15  "
                      "read-write  55.2 MB/s  INFERRED\n"
                      "nginx 2218     .../launch-2026-hd.mp4  203.0.113.61                sendfile "
                      "   40.9 MB/s  EXACT\n"
                      "rsync 5120     .../api-v4.18.2.tar.gz  10.0.7.32                   "
                      "read-write  38.5 MB/s  INFERRED\n"
                      "python3 24410  ...-ner-v3.safetensors  10.0.8.40                   "
                      "read-write  27.3 MB/s  INFERRED\n");
    check_watch_files(57, false,
                      "PROCESS      FILE              DESTINATION           RATE\n"
                      "java 12044   ...191560343.log  10.0.5.22        64.3 MB/s\n"
                      "rclone 4...  ...11-12.tar.zst  2001:db8:8a2...  55.2 MB/s\n"
                      "nginx 2218   ...h-2026-hd.mp4  203.0.113.61     40.9 MB/s\n"
                      "rsync 5120   ...4.18.2.tar.gz  10.0.7.32        38.5 MB/s\n"
                      "python3 ...  ...3.safetensors  10.0.8.40        27.3 MB/s\n");
}

void test_tui(void)
{
    test_watch_network_filters();
    test_text_clipping();
    test_text_wide();
    test_text_sanitized();
    test_text_cut();
    test_text_right();
    test_text_keeps_background();
    test_path();
    test_mark();
    test_bar_widths();
    test_theme_roles();
    test_theme_detect();
    test_lineedit_utf8();
    test_lineedit_words();
    test_table_fit_untouched();
    test_table_fit_cuts_cells();
    test_table_fit_cuts_in_two_turns();
    test_table_fit_leaves_columns();
    test_table_fit_bounds();
    test_watch_files_by_name();
    test_watch_files_by_address();
}
