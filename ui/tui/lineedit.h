#ifndef FILETRACE_TUI_LINEEDIT_H
#define FILETRACE_TUI_LINEEDIT_H

#include "filetrace/base.h"
#include "ui/tui/canvas.h"
#include "ui/tui/screen.h"

/* A line of UTF-8 text being typed; zero-initialized it is empty. */
struct ft_lineedit {
    char text[512];
    size_t len;
    size_t cursor; /* byte offset, always at the start of a character */
};

/* Text longer than the buffer is cut at a character boundary; the cursor goes to the end. */
void ft_lineedit_set(struct ft_lineedit *e, const char *text);

/* Applies a key; returns whether the text changed. */
bool ft_lineedit_key(struct ft_lineedit *e, const struct ft_input *in);

/* Draws the text in width columns with the cursor kept in view; returns the cursor's x. */
int ft_lineedit_draw(const struct ft_lineedit *e, struct ft_canvas *c, int x, int y, int width,
                     struct ft_style s);

#endif
