#include "ui/top/once.h"

int ft_top_once(struct ft_session *s, const struct ft_cli *cli, const struct ft_top_options *opt)
{
    (void)s;
    (void)cli;
    (void)opt;
    return FT_EXIT_UNSUPPORTED;
}

bool ft_top_export(const struct ft_top_model *m, enum ft_top_mode mode, const char *path,
                   size_t *rows, struct ft_error *err)
{
    (void)m;
    (void)mode;
    (void)path;
    *rows = 0;
    ft_error_set(err, FT_EXIT_UNSUPPORTED, "Export is not available");
    return false;
}

void ft_top_row_json(const struct ft_top_model *m, enum ft_top_mode mode, size_t index, FILE *out)
{
    (void)m;
    (void)mode;
    (void)index;
    (void)out;
}
