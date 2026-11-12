#include "ui/tui/theme.h"

#include <stdlib.h>
#include <string.h>

constexpr int16_t OWN = -1; /* the terminal's own color */

struct role {
    uint32_t rgb;
    int16_t c256;
    int16_t c16; /* 8-15 are the bright colors */
};

/* FT_COLOR_BG as a background is the terminal's own below truecolor, and black as text. */
static const struct role roles[FT_COLOR_COUNT] = {
    [FT_COLOR_BG] = {.rgb = 0x0b'0e'14, .c256 = 0, .c16 = 0},
    [FT_COLOR_TEXT] = {.rgb = 0xc9'd1'd9, .c256 = OWN, .c16 = OWN},
    [FT_COLOR_BRIGHT] = {.rgb = 0xf0'f6'fc, .c256 = 15, .c16 = 15},
    [FT_COLOR_DIM] = {.rgb = 0x7d'85'90, .c256 = 244, .c16 = 8},
    [FT_COLOR_CYAN] = {.rgb = 0x39'c5'cf, .c256 = 80, .c16 = 6},
    [FT_COLOR_GREEN] = {.rgb = 0x3f'b9'50, .c256 = 71, .c16 = 2},
    [FT_COLOR_AMBER] = {.rgb = 0xd2'99'22, .c256 = 178, .c16 = 3},
    [FT_COLOR_RED] = {.rgb = 0xff'7b'72, .c256 = 210, .c16 = 1},
    [FT_COLOR_PURPLE] = {.rgb = 0xd2'a8'ff, .c256 = 183, .c16 = 5},
    [FT_COLOR_BLUE] = {.rgb = 0x58'a6'ff, .c256 = 75, .c16 = 4},
    [FT_COLOR_TRACK] = {.rgb = 0x30'36'3d, .c256 = 237, .c16 = 8},
    [FT_COLOR_PANEL] = {.rgb = 0x16'1b'22, .c256 = 235, .c16 = OWN},
    [FT_COLOR_RULE] = {.rgb = 0x21'26'2d, .c256 = 236, .c16 = 8},
};

enum ft_color_depth ft_color_depth_for(enum ft_color_mode mode, const char *term,
                                       const char *colorterm, const char *no_color)
{
    static const char *const truecolor_terms[] = {
        "xterm-kitty", "alacritty", "wezterm", "foot", "xterm-ghostty",
    };

    if (mode == FT_COLOR_MODE_NEVER)
        return FT_DEPTH_NONE;
    if (mode == FT_COLOR_MODE_AUTO &&
        ((no_color && no_color[0]) || (term && strcmp(term, "dumb") == 0)))
        return FT_DEPTH_NONE;
    if (colorterm && (strcmp(colorterm, "truecolor") == 0 || strcmp(colorterm, "24bit") == 0))
        return FT_DEPTH_TRUECOLOR;
    if (!term)
        return FT_DEPTH_16;
    for (size_t i = 0; i < FT_ARRAY_LEN(truecolor_terms); i++) {
        if (strcmp(term, truecolor_terms[i]) == 0)
            return FT_DEPTH_TRUECOLOR;
    }
    return strstr(term, "256color") ? FT_DEPTH_256 : FT_DEPTH_16;
}

enum ft_color_depth ft_color_depth_detect(enum ft_color_mode mode)
{
    return ft_color_depth_for(mode, getenv("TERM"), getenv("COLORTERM"), getenv("NO_COLOR"));
}

static struct ft_term_color palette(int16_t index)
{
    if (index == OWN)
        return (struct ft_term_color){.kind = FT_TERM_DEFAULT};
    return (struct ft_term_color){.kind = FT_TERM_INDEX, .value = (uint32_t)index};
}

static struct ft_term_color indexed(enum ft_color_depth depth, enum ft_color color, bool bg)
{
    if (color == FT_COLOR_DEFAULT || (bg && color == FT_COLOR_BG))
        return palette(OWN);
    return palette(depth == FT_DEPTH_256 ? roles[color].c256 : roles[color].c16);
}

static struct ft_term_color rgb(enum ft_color color)
{
    if (color == FT_COLOR_DEFAULT)
        return (struct ft_term_color){.kind = FT_TERM_DEFAULT};
    return (struct ft_term_color){.kind = FT_TERM_RGB, .value = roles[color].rgb};
}

struct ft_term_style ft_theme_resolve(enum ft_color_depth depth, enum ft_color fg, enum ft_color bg,
                                      uint8_t attrs)
{
    struct ft_term_style out = {
        .attrs = attrs & (FT_ATTR_BOLD | FT_ATTR_UNDERLINE | FT_ATTR_REVERSE),
    };

    if (fg >= FT_COLOR_COUNT)
        fg = FT_COLOR_DEFAULT;
    if (bg >= FT_COLOR_COUNT)
        bg = FT_COLOR_DEFAULT;

    switch (depth) {
    case FT_DEPTH_NONE:
        if (fg == FT_COLOR_BRIGHT)
            out.attrs |= FT_ATTR_BOLD;
        if (fg == FT_COLOR_DIM)
            out.attrs |= FT_TERM_DIM;
        if (bg == FT_COLOR_CYAN || bg == FT_COLOR_GREEN || bg == FT_COLOR_AMBER)
            out.attrs |= FT_ATTR_REVERSE;
        break;
    case FT_DEPTH_16:
    case FT_DEPTH_256:
        out.fg = indexed(depth, fg, false);
        out.bg = indexed(depth, bg, true);
        if (fg == FT_COLOR_BRIGHT)
            out.attrs |= FT_ATTR_BOLD;
        break;
    case FT_DEPTH_TRUECOLOR:
        out.fg = rgb(fg);
        out.bg = rgb(bg);
        break;
    }
    return out;
}
