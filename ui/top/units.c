#include "ui/top/model.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

void ft_top_format_size(uint64_t bytes, char *buf, size_t size)
{
    static const struct {
        char unit;
        int decimals;
        double limit; /* the value that would print as 1024 */
    } units[] = {
        {'K', 0, 1023.5},
        {'M', 1, 1023.95},
        {'G', 1, 1023.95},
        {'T', 2, 0.0},
    };
    double value = (double)bytes;

    if (bytes < 1024) {
        snprintf(buf, size, "%" PRIu64 "B", bytes);
        return;
    }
    for (size_t i = 0; i < FT_ARRAY_LEN(units); i++) {
        value /= 1024.0;
        if (value < units[i].limit || i + 1 == FT_ARRAY_LEN(units)) {
            snprintf(buf, size, "%.*f%c", units[i].decimals, value, units[i].unit);
            return;
        }
    }
}

void ft_top_format_rate(uint64_t bytes_per_second, char *buf, size_t size)
{
    ft_top_format_size(bytes_per_second, buf, size);
    size_t len = strlen(buf);
    if (len < size)
        snprintf(buf + len, size - len, "/s");
}

void ft_top_format_age(uint64_t ns, char *buf, size_t size)
{
    uint64_t s = ns / FT_NS_PER_SEC;

    if (s < 10)
        snprintf(buf, size, "%" PRIu64 ".%" PRIu64 "s", s, ns / (FT_NS_PER_SEC / 10) % 10);
    else if (s < 60)
        snprintf(buf, size, "%" PRIu64 "s", s);
    else if (s < 3600)
        snprintf(buf, size, "%" PRIu64 ":%02" PRIu64, s / 60, s % 60);
    else if (s < 86400)
        snprintf(buf, size, "%" PRIu64 "h%02" PRIu64, s / 3600, s % 3600 / 60);
    else
        snprintf(buf, size, "%" PRIu64 "d%02" PRIu64, s / 86400, s % 86400 / 3600);
}

void ft_top_format_percent(double share, char *buf, size_t size)
{
    unsigned percent = 0;

    if (share >= 1.0)
        percent = 100;
    else if (share > 0.0)
        percent = (unsigned)(share * 100.0 + 0.5);
    /* Rounding up must not claim a whole that is not there. */
    if (percent == 100 && share < 1.0)
        percent = 99;
    snprintf(buf, size, "%3u%%", percent);
}
