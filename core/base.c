#include "filetrace/base.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static enum ft_log_level log_level = FT_LOG_WARN;

int ft_error_set(struct ft_error *err, int code, const char *fmt, ...)
{
    if (err) {
        va_list ap;
        va_start(ap, fmt);
        err->code = code;
        vsnprintf(err->msg, sizeof(err->msg), fmt, ap);
        va_end(ap);
    }
    return code;
}

void ft_log_set_level(enum ft_log_level level)
{
    log_level = level;
}

bool ft_log_level_parse(const char *text, enum ft_log_level *level)
{
    static const char *const names[] = {"error", "warn", "info", "debug"};
    for (size_t i = 0; i < FT_ARRAY_LEN(names); i++) {
        if (strcmp(text, names[i]) == 0) {
            *level = (enum ft_log_level)i;
            return true;
        }
    }
    return false;
}

void ft_log(enum ft_log_level level, const char *fmt, ...)
{
    static const char *const tags[] = {"error", "warn", "info", "debug"};
    if (level > log_level)
        return;

    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    fprintf(stderr, "filetrace: %s: %s\n", tags[level], line);
}

void ft_strlcpy(char *dst, const char *src, size_t size)
{
    if (size == 0)
        return;
    size_t n = strnlen(src, size - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}
