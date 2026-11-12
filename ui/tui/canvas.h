#ifndef FILETRACE_TUI_CANVAS_H
#define FILETRACE_TUI_CANVAS_H

#include "filetrace/base.h"

/* Color roles; the theme decides how each one looks on the terminal. */
enum ft_color : uint8_t {
    FT_COLOR_DEFAULT, /* in a style: keep the cell's color; in a cell: the terminal's own */
    FT_COLOR_BG,      /* the screen background; as a foreground, dark text on a bar */
    FT_COLOR_TEXT,
    FT_COLOR_BRIGHT,
    FT_COLOR_DIM,
    FT_COLOR_CYAN,
    FT_COLOR_GREEN,
    FT_COLOR_AMBER,
    FT_COLOR_RED,
    FT_COLOR_PURPLE,
    FT_COLOR_BLUE,
    FT_COLOR_TRACK, /* the empty part of a bar */
    FT_COLOR_PANEL, /* the background of an inactive tab */
    FT_COLOR_RULE,  /* separator lines */
    FT_COLOR_COUNT,
};

enum ft_attr : uint8_t {
    FT_ATTR_BOLD = 1,
    FT_ATTR_UNDERLINE = 2,
    FT_ATTR_REVERSE = 4,
};

/* FT_COLOR_DEFAULT keeps the color a cell has; any other role, FT_COLOR_BG too, replaces it. */
struct ft_style {
    enum ft_color fg;
    enum ft_color bg;
    uint8_t attrs; /* enum ft_attr bits */
};

struct ft_rect {
    int x, y, w, h;
};

struct ft_cell {
    uint32_t rune; /* 0 in the right half of a wide character */
    enum ft_color fg;
    enum ft_color bg;
    uint8_t attrs;
};

struct ft_canvas;

/* A canvas of spaces in the terminal's own colors; nullptr when out of memory. */
struct ft_canvas *ft_canvas_create(int cols, int rows);
void ft_canvas_destroy(struct ft_canvas *c);
/* Clears to cols by rows; false when out of memory, leaving the canvas as it was. */
bool ft_canvas_resize(struct ft_canvas *c, int cols, int rows);
int ft_canvas_cols(const struct ft_canvas *c);
int ft_canvas_rows(const struct ft_canvas *c);

/* Every cell becomes a space in exactly this style, and the clip the whole canvas. */
void ft_canvas_clear(struct ft_canvas *c, struct ft_style s);

/* Limits all drawing to r within the canvas; returns the previous clip, to restore it. */
struct ft_rect ft_canvas_clip(struct ft_canvas *c, struct ft_rect r);

/* The cell at (x, y), or nullptr outside the canvas. */
const struct ft_cell *ft_canvas_at(const struct ft_canvas *c, int x, int y);

/*
 * Text is UTF-8: a wide character takes two columns, "?" stands for an invalid byte or a
 * control character, and zero-width characters are left out. A wide character that does
 * not fit the width, the clip or the canvas leaves a space. Each call returns the columns
 * the text takes within the width, whether the clip shows them or not.
 */

enum ft_cut : uint8_t {
    FT_CUT_CLIP,  /* text stops at the width */
    FT_CUT_END,   /* text that does not fit keeps its start and ends in "…" */
    FT_CUT_START, /* text that does not fit keeps its end and starts with "…" */
};

int ft_canvas_text(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                   const char *text);
int ft_canvas_text_cut(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                       const char *text, enum ft_cut cut);
/* Spaces fill the width before the text; text that does not fit loses its end to "…". */
int ft_canvas_text_right(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                         const char *text);

/* Output past 1023 bytes is dropped. */
[[gnu::format(printf, 6, 7)]]
int ft_canvas_textf(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                    const char *fmt, ...);
[[gnu::format(printf, 6, 7)]]
int ft_canvas_textf_right(struct ft_canvas *c, int x, int y, int width, struct ft_style s,
                          const char *fmt, ...);

/* A path cut from its start, everything up to the last '/' in dir and the rest in name. */
int ft_canvas_path(struct ft_canvas *c, int x, int y, int width, struct ft_style dir,
                   struct ft_style name, const char *path);

/*
 * Restyles, as ft_canvas_restyle does, the cells that show bytes [start, end) of text drawn
 * at (x, y) with this width and cut; "…" counts as the bytes it hides. For text drawn by
 * ft_canvas_text_right, pass x + width - n and width n, n being what it returned.
 */
void ft_canvas_mark(struct ft_canvas *c, int x, int y, int width, const char *text, enum ft_cut cut,
                    size_t start, size_t end, struct ft_style s);

int ft_text_columns(const char *text);

/* The bytes of the character at the start of text (len > 0) and the columns it takes. */
size_t ft_text_next(const char *text, size_t len, int *columns);

void ft_canvas_fill(struct ft_canvas *c, struct ft_rect r, uint32_t rune, struct ft_style s);
void ft_canvas_repeat(struct ft_canvas *c, int x, int y, int count, uint32_t rune,
                      struct ft_style s);

/* Recolors cells keeping their characters and attributes, and adds s.attrs to them. */
void ft_canvas_restyle(struct ft_canvas *c, struct ft_rect r, struct ft_style s);

/* A frame of box-drawing characters on the edges of r; the inside stays as it is. */
void ft_canvas_box(struct ft_canvas *c, struct ft_rect r, struct ft_style s);

struct ft_bar_part {
    double value;
    struct ft_style style;
};

struct ft_bar {
    const struct ft_bar_part *parts;
    size_t count;
    double total;        /* the value of the whole width; 0 takes the sum of the parts */
    uint32_t rune;       /* drawn for the parts; 0 is U'█' */
    uint32_t empty_rune; /* drawn after the parts; 0 leaves those cells as they are */
    struct ft_style empty;
};

/* The parts side by side, each as wide as its share of the total; returns the cells filled. */
int ft_canvas_bar(struct ft_canvas *c, int x, int y, int width, const struct ft_bar *bar);

/* An htop meter: "[", the bar, text right-aligned over the end of the bar, "]". */
void ft_canvas_meter(struct ft_canvas *c, int x, int y, int width, const struct ft_bar *bar,
                     struct ft_style frame, struct ft_style text_style, const char *text);

/* One "▁▂▃▄▅▆▇█" cell per value, the last value at the right edge; max 0 takes the largest. */
void ft_canvas_spark(struct ft_canvas *c, int x, int y, int width, const double *values,
                     size_t count, double max, struct ft_style s);

#endif
