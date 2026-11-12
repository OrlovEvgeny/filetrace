#include "ui/top/views.h"

void ft_top_draw_panel(struct ft_top_draw *d, struct ft_rect r)
{
    (void)d;
    (void)r;
}

void ft_top_draw_inspect(struct ft_top_draw *d, struct ft_rect r)
{
    (void)d;
    (void)r;
}

void ft_top_draw_overlay(struct ft_top_draw *d, struct ft_rect r)
{
    (void)d;
    (void)r;
}

void ft_top_draw_help(struct ft_top_draw *d)
{
    (void)d;
}

const enum ft_top_group *ft_top_mode_groups(enum ft_top_mode mode, size_t *count)
{
    static const enum ft_top_group none[] = {FT_TOP_GROUP_NONE};

    (void)mode;
    *count = FT_ARRAY_LEN(none);
    return none;
}
