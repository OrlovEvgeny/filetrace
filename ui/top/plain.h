#ifndef FILETRACE_TOP_PLAIN_H
#define FILETRACE_TOP_PLAIN_H

#include "ui/top/views.h"

#include <stdio.h>

/*
 * Writes the canvas as lines of text without their trailing blanks. Unless the depth is
 * FT_DEPTH_NONE, the cells keep their colors as escape sequences, reset at the end of each line.
 */
void ft_top_print_canvas(const struct ft_canvas *canvas, enum ft_color_depth depth, FILE *out);

/*
 * Prints the table of ui->mode as the screen draws it, at the given width and with every row. For
 * Leaders the table follows lines that tell what the ranking covers. False when memory ran out.
 */
bool ft_top_print_table(const struct ft_top_model *m, const struct ft_top_ui *ui, int cols,
                        enum ft_color_depth depth, FILE *out);

#endif
