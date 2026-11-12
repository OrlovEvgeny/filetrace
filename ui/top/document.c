#include "ui/top/document.h"

#include "ui/top/once.h"

size_t ft_top_write_document(const struct ft_top_model *m, enum ft_top_mode mode, bool indent,
                             FILE *out)
{
    (void)m;
    (void)mode;
    (void)indent;
    (void)out;
    return 0;
}

size_t ft_top_write_csv(const struct ft_top_model *m, enum ft_top_mode mode, FILE *out)
{
    (void)m;
    (void)mode;
    (void)out;
    return 0;
}

void ft_top_row_json(const struct ft_top_model *m, enum ft_top_mode mode, size_t index, FILE *out)
{
    (void)m;
    (void)mode;
    (void)index;
    (void)out;
}
