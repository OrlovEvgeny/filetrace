#include "exporters/exporters.h"

#include "filetrace/format.h"

#include <ctype.h>
#include <inttypes.h>
#include <string.h>

/* Dots separate OpenTelemetry name parts; Prometheus names have none. */
static void put_name(FILE *out, const char *name)
{
    for (const char *p = name; *p; p++)
        fputc(isalnum((unsigned char)*p) || *p == '_' ? *p : '_', out);
}

static void put_metric_name(FILE *out, const struct ft_metric *m)
{
    put_name(out, m->name);
    if (strcmp(m->unit, "By") == 0)
        fputs("_bytes", out);
    else if (strcmp(m->unit, "s") == 0)
        fputs("_seconds", out);
    if (m->monotonic)
        fputs("_total", out);
}

static void put_label_value(FILE *out, const char *value)
{
    char text[256];

    ft_utf8_copy(text, value, sizeof(text));
    fputc('"', out);
    for (const char *p = text; *p; p++) {
        if (*p == '\n') {
            fputs("\\n", out);
            continue;
        }
        if (*p == '"' || *p == '\\')
            fputc('\\', out);
        fputc(*p, out);
    }
    fputc('"', out);
}

static void put_labels(FILE *out, const struct ft_metric_attr *attrs, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        fputc(i ? ',' : '{', out);
        put_name(out, attrs[i].key);
        fputc('=', out);
        put_label_value(out, attrs[i].value);
    }
    if (count)
        fputc('}', out);
}

void ft_prometheus_begin(struct ft_prometheus *w, FILE *out, const struct ft_metric_attr *resource,
                         size_t count)
{
    *w = (struct ft_prometheus){.out = out};
    fputs("# HELP target_info Target metadata\n# TYPE target_info gauge\ntarget_info", out);
    put_labels(out, resource, count);
    fputs(" 1\n", out);
}

void ft_prometheus_point(void *ctx, const struct ft_metric_point *pt)
{
    struct ft_prometheus *w = ctx;
    const struct ft_metric *m = pt->metric;
    FILE *out = w->out;

    if (m != w->metric) {
        w->metric = m;
        fputs("# HELP ", out);
        put_metric_name(out, m);
        fprintf(out, " %s\n# TYPE ", m->description);
        put_metric_name(out, m);
        fprintf(out, " %s\n", m->monotonic ? "counter" : "gauge");
    }
    put_metric_name(out, m);
    put_labels(out, pt->attrs, pt->attr_count);
    if (m->real)
        fprintf(out, " %.6f\n", pt->real);
    else
        fprintf(out, " %" PRIu64 "\n", pt->value);
}
