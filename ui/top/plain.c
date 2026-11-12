#include "ui/top/plain.h"

void ft_top_print_canvas(const struct ft_canvas *canvas, enum ft_color_depth depth, FILE *out)
{
    (void)canvas;
    (void)depth;
    (void)out;
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
