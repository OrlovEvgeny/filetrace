#include "backends/backend.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void ft_backend_config_defaults(struct ft_backend_config *cfg)
{
    *cfg = (struct ft_backend_config){
        .mode = FT_MODE_STANDARD,
        .track_read = true,
        .track_sendfile = true,
        .queue_bytes = 4u * 1024u * 1024u,
        .agg_entries = 16384,
        .known_files = 16384,
        .drain_batch = 512,
        .corr_window_ns = 2 * FT_NS_PER_SEC,
        .php_scripts = true,
    };
}

const char *ft_probes_name(enum ft_probes p)
{
    switch (p) {
    case FT_PROBES_TRAMPOLINE:
        return "trampoline";
    case FT_PROBES_KPROBE:
        return "kprobe";
    default:
        return "auto";
    }
}

bool ft_probes_parse(const char *text, enum ft_probes *p)
{
    for (int i = FT_PROBES_AUTO; i <= FT_PROBES_KPROBE; i++) {
        if (strcmp(text, ft_probes_name((enum ft_probes)i)) == 0) {
            *p = (enum ft_probes)i;
            return true;
        }
    }
    return false;
}

[[gnu::format(printf, 6, 0)]]
static void add_check(struct ft_diagnosis *d, enum ft_check_level level, bool optional, bool probe,
                      const char *text, const char *detail_fmt, va_list ap)
{
    if (d->count >= FT_MAX_CHECKS)
        return;

    struct ft_check *c = &d->checks[d->count++];
    c->level = level;
    c->optional = optional;
    c->probe = probe;
    ft_strlcpy(c->text, text, sizeof(c->text));
    vsnprintf(c->detail, sizeof(c->detail), detail_fmt, ap);
}

void ft_diagnosis_add(struct ft_diagnosis *d, enum ft_check_level level, bool optional,
                      const char *text, const char *detail_fmt, ...)
{
    va_list ap;
    va_start(ap, detail_fmt);
    add_check(d, level, optional, false, text, detail_fmt, ap);
    va_end(ap);
}

void ft_diagnosis_add_probe(struct ft_diagnosis *d, enum ft_check_level level, bool optional,
                            const char *text, const char *detail_fmt, ...)
{
    va_list ap;
    va_start(ap, detail_fmt);
    add_check(d, level, optional, true, text, detail_fmt, ap);
    va_end(ap);
}
