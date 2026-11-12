#ifndef FILETRACE_TOP_ONCE_H
#define FILETRACE_TOP_ONCE_H

#include "ui/top/model.h"

#include <stdio.h>

/* The view without a screen: one snapshot, or with json and without once one per refresh. */
int ft_top_once(struct ft_session *s, const struct ft_cli *cli, const struct ft_top_options *opt);

/* Writes the mode's rows as they are shown: CSV to a path ending in ".csv", else JSON. */
bool ft_top_export(const struct ft_top_model *m, enum ft_top_mode mode, const char *path,
                   size_t *rows, struct ft_error *err);

/* One row as an indented JSON object. */
void ft_top_row_json(const struct ft_top_model *m, enum ft_top_mode mode, size_t index, FILE *out);

#endif
