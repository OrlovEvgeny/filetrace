#ifndef FILETRACE_TUI_THEME_H
#define FILETRACE_TUI_THEME_H

#include "ui/tui/canvas.h"

enum ft_color_depth : uint8_t {
    FT_DEPTH_NONE,
    FT_DEPTH_16,
    FT_DEPTH_256,
    FT_DEPTH_TRUECOLOR,
};

enum ft_color_mode : uint8_t {
    FT_COLOR_MODE_AUTO,
    FT_COLOR_MODE_ALWAYS, /* as auto, but never without color */
    FT_COLOR_MODE_NEVER,
};

/* The depth TERM, COLORTERM and NO_COLOR call for. */
enum ft_color_depth ft_color_depth_detect(enum ft_color_mode mode);
enum ft_color_depth ft_color_depth_for(enum ft_color_mode mode, const char *term,
                                       const char *colorterm, const char *no_color);

enum ft_term_color_kind : uint8_t {
    FT_TERM_DEFAULT, /* the terminal's own color */
    FT_TERM_INDEX,   /* a palette entry: 0-15 at 16 colors, 0-255 at 256 */
    FT_TERM_RGB,     /* 0xRRGGBB */
};

struct ft_term_color {
    enum ft_term_color_kind kind;
    uint32_t value;
};

/* The dim attribute, beside the enum ft_attr bits. */
constexpr uint8_t FT_TERM_DIM = 8;

struct ft_term_style {
    struct ft_term_color fg;
    struct ft_term_color bg;
    uint8_t attrs;
};

/* How a cell with these roles and attributes looks at the given depth. */
struct ft_term_style ft_theme_resolve(enum ft_color_depth depth, enum ft_color fg, enum ft_color bg,
                                      uint8_t attrs);

#endif
