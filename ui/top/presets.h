#ifndef FILETRACE_TOP_PRESETS_H
#define FILETRACE_TOP_PRESETS_H

#include "filetrace/base.h"

/*
 * Filter expressions saved under a name, one "name<TAB>expression" line each, in
 * $XDG_CONFIG_HOME/filetrace/top-presets or else ~/.config/filetrace/top-presets.
 */
struct ft_top_preset {
    char *name;
    char *expression;
};

struct ft_top_presets {
    struct ft_top_preset *items; /* in the order of the file */
    size_t count;
};

bool ft_top_presets_path(char *buf, size_t size, struct ft_error *err);

/* A missing file holds no presets. */
bool ft_top_presets_load(struct ft_top_presets *out, struct ft_error *err);
void ft_top_presets_free(struct ft_top_presets *presets);

/* Replaces the file at once, keeping its other lines; a preset of the same name is replaced. */
bool ft_top_presets_save(const char *name, const char *expression, struct ft_error *err);

/* Fails with FT_EXIT_USAGE, listing the names there are, when no preset has the name. */
bool ft_top_presets_find(const char *name, char *expression, size_t size, struct ft_error *err);

#endif
