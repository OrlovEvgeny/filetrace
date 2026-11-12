#include "unit/test.h"

#include "ui/tui/canvas.h"
#include "ui/tui/theme.h"

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

void test_tui(void)
{
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
}
