#include "backends/backend.h"

#include <stdarg.h>
#include <stdio.h>

void ft_backend_config_defaults(struct ft_backend_config *cfg)
{
    *cfg = (struct ft_backend_config){
        .mode = FT_MODE_STANDARD,
        .queue_bytes = 4u * 1024u * 1024u,
        .agg_entries = 16384,
        .known_files = 16384,
        .corr_window_ns = 2 * FT_NS_PER_SEC,
    };
}

void ft_diagnosis_add(struct ft_diagnosis *d, enum ft_check_level level, bool optional,
                      const char *text, const char *detail_fmt, ...)
{
    if (d->count >= FT_MAX_CHECKS)
        return;

    struct ft_check *c = &d->checks[d->count++];
    va_list ap;

    c->level = level;
    c->optional = optional;
    ft_strlcpy(c->text, text, sizeof(c->text));
    va_start(ap, detail_fmt);
    vsnprintf(c->detail, sizeof(c->detail), detail_fmt, ap);
    va_end(ap);
}
