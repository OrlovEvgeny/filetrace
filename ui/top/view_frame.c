#include "ui/top/views.h"

void ft_top_layout(const struct ft_top_ui *ui, int cols, int rows, struct ft_top_layout *out)
{
    (void)ui;
    *out = (struct ft_top_layout){.cols = cols, .rows = rows};
}

void ft_top_draw(struct ft_top_draw *d)
{
    (void)d;
}
