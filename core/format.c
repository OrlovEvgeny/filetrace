#include "filetrace/format.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdckdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

void ft_format_bytes(uint64_t bytes, char *buf, size_t size)
{
    static const char *const units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
    double value = (double)bytes;
    size_t unit = 0;

    while (value >= 1024.0 && unit + 1 < FT_ARRAY_LEN(units)) {
        value /= 1024.0;
        unit++;
    }
    if (unit == 0)
        snprintf(buf, size, "%" PRIu64 " B", bytes);
    else if (value < 10.0)
        snprintf(buf, size, "%.2f %s", value, units[unit]);
    else if (value < 100.0)
        snprintf(buf, size, "%.1f %s", value, units[unit]);
    else
        snprintf(buf, size, "%.0f %s", value, units[unit]);
}

void ft_format_rate(uint64_t bytes_per_second, char *buf, size_t size)
{
    ft_format_bytes(bytes_per_second, buf, size);
    size_t len = strlen(buf);
    snprintf(buf + len, size - len, "/s");
}

void ft_format_duration(uint64_t ns, char *buf, size_t size)
{
    uint64_t s = ns / FT_NS_PER_SEC;
    uint64_t days = s / 86400;
    uint64_t hours = (s % 86400) / 3600;
    uint64_t minutes = (s % 3600) / 60;

    if (days)
        snprintf(buf, size, "%" PRIu64 "d %" PRIu64 "h", days, hours);
    else if (hours)
        snprintf(buf, size, "%" PRIu64 "h %" PRIu64 "m", hours, minutes);
    else if (minutes)
        snprintf(buf, size, "%" PRIu64 "m %" PRIu64 "s", minutes, s % 60);
    else
        snprintf(buf, size, "%" PRIu64 "s", s);
}

void ft_format_count(uint64_t value, char *buf, size_t size)
{
    char digits[32];
    int len = snprintf(digits, sizeof(digits), "%" PRIu64, value);
    size_t out = 0;

    for (int i = 0; i < len && out + 2 < size; i++) {
        if (i && (len - i) % 3 == 0)
            buf[out++] = ',';
        buf[out++] = digits[i];
    }
    if (size)
        buf[out] = '\0';
}

static void format_tm(uint64_t wall_ns, bool utc, const char *fmt, char *buf, size_t size)
{
    time_t secs = (time_t)(wall_ns / FT_NS_PER_SEC);
    struct tm tm;

    if (wall_ns == 0 || !(utc ? gmtime_r(&secs, &tm) : localtime_r(&secs, &tm)) ||
        strftime(buf, size, fmt, &tm) == 0)
        ft_strlcpy(buf, "-", size);
}

void ft_format_time_local(uint64_t wall_ns, char *buf, size_t size)
{
    format_tm(wall_ns, false, "%Y-%m-%d %H:%M:%S", buf, size);
}

void ft_format_clock_local(uint64_t wall_ns, char *buf, size_t size)
{
    format_tm(wall_ns, false, "%H:%M:%S", buf, size);
}

void ft_format_time_rfc3339(uint64_t wall_ns, char *buf, size_t size)
{
    char date[32];
    format_tm(wall_ns, true, "%Y-%m-%dT%H:%M:%S", date, sizeof(date));
    snprintf(buf, size, "%s.%03uZ", date, (unsigned)((wall_ns % FT_NS_PER_SEC) / FT_NS_PER_MS));
}

static bool parse_decimal(const char *text, double *value, const char **rest)
{
    char *end;
    errno = 0;
    double v = strtod(text, &end);
    if (end == text || errno || v < 0.0 || v != v)
        return false;
    *value = v;
    *rest = end;
    return true;
}

bool ft_parse_size(const char *text, uint64_t *bytes)
{
    static const struct {
        const char *suffix;
        double scale;
    } units[] = {
        {"", 1.0},
        {"B", 1.0},
        {"K", 1024.0},
        {"KB", 1024.0},
        {"M", 1048576.0},
        {"MB", 1048576.0},
        {"G", 1073741824.0},
        {"GB", 1073741824.0},
        {"T", 1099511627776.0},
        {"TB", 1099511627776.0},
    };
    double value;
    const char *rest;

    if (!isdigit((unsigned char)text[0]) || !parse_decimal(text, &value, &rest))
        return false;
    for (size_t i = 0; i < FT_ARRAY_LEN(units); i++) {
        if (strcasecmp(rest, units[i].suffix) == 0) {
            double scaled = value * units[i].scale;
            if (scaled >= 18446744073709551615.0)
                return false;
            *bytes = (uint64_t)scaled;
            return true;
        }
    }
    return false;
}

bool ft_parse_duration(const char *text, uint64_t *ns)
{
    static const struct {
        const char *suffix;
        double scale;
    } units[] = {
        {"ms", 1e6}, {"s", 1e9}, {"m", 60e9}, {"h", 3600e9}, {"d", 86400e9},
    };
    double value;
    const char *rest;

    if (!isdigit((unsigned char)text[0]) || !parse_decimal(text, &value, &rest))
        return false;
    for (size_t i = 0; i < FT_ARRAY_LEN(units); i++) {
        if (strcmp(rest, units[i].suffix) == 0) {
            double scaled = value * units[i].scale;
            if (scaled >= 9.2e18)
                return false;
            *ns = (uint64_t)scaled;
            return true;
        }
    }
    return false;
}

static int64_t days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    int64_t era = (y >= 0 ? y : y - 399) / 400;
    unsigned yoe = (unsigned)(y - era * 400);
    unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

bool ft_parse_time_rfc3339(const char *text, uint64_t *wall_ns)
{
    unsigned year, month, day, hour, minute, second;
    int consumed = 0;

    if (sscanf(text, "%4u-%2u-%2u%*1[Tt ]%2u:%2u:%2u%n", &year, &month, &day, &hour, &minute,
               &second, &consumed) != 6)
        return false;
    if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 60)
        return false;

    const char *p = text + consumed;
    uint64_t frac_ns = 0;
    if (*p == '.') {
        uint64_t scale = FT_NS_PER_SEC / 10;
        p++;
        if (!isdigit((unsigned char)*p))
            return false;
        for (; isdigit((unsigned char)*p); p++) {
            frac_ns += (uint64_t)(*p - '0') * scale;
            scale /= 10;
        }
    }

    int64_t offset_s = 0;
    if (*p == 'Z' || *p == 'z') {
        p++;
    } else if (*p == '+' || *p == '-') {
        unsigned oh, om;
        int n = 0;
        if (sscanf(p + 1, "%2u:%2u%n", &oh, &om, &n) != 2 || n != 5 || oh > 23 || om > 59)
            return false;
        offset_s = (int64_t)(oh * 3600 + om * 60) * (*p == '-' ? -1 : 1);
        p += 6;
    } else {
        return false;
    }
    if (*p != '\0')
        return false;

    int64_t secs = days_from_civil((int64_t)year, month, day) * 86400 + (int64_t)hour * 3600 +
                   (int64_t)minute * 60 + (int64_t)second - offset_s;
    if (secs < 0)
        return false;

    uint64_t ns;
    if (ckd_mul(&ns, (uint64_t)secs, FT_NS_PER_SEC) || ckd_add(&ns, ns, frac_ns))
        return false;
    *wall_ns = ns;
    return true;
}

bool ft_parse_u64(const char *text, uint64_t *value)
{
    char *end;
    if (!isdigit((unsigned char)text[0]))
        return false;
    errno = 0;
    unsigned long long v = strtoull(text, &end, 10);
    if (errno || *end != '\0')
        return false;
    *value = v;
    return true;
}

bool ft_parse_u32(const char *text, uint32_t *value)
{
    uint64_t v;
    if (!ft_parse_u64(text, &v) || v > UINT32_MAX)
        return false;
    *value = (uint32_t)v;
    return true;
}

bool ft_glob_match(const char *pattern, const char *text)
{
    const char *star = nullptr;
    const char *resume = nullptr;

    while (*text) {
        if (*pattern == '*') {
            star = pattern++;
            resume = text;
        } else if (*pattern == '?' || *pattern == *text) {
            pattern++;
            text++;
        } else if (star) {
            pattern = star + 1;
            text = ++resume;
        } else {
            return false;
        }
    }
    while (*pattern == '*')
        pattern++;
    return *pattern == '\0';
}

/* Length of the well-formed sequence at p, or 0. */
static size_t utf8_sequence(const unsigned char *p)
{
    unsigned char lead = p[0];
    size_t len = lead < 0x80   ? 1
                 : lead < 0xc2 ? 0
                 : lead < 0xe0 ? 2
                 : lead < 0xf0 ? 3
                 : lead < 0xf5 ? 4
                               : 0;

    for (size_t i = 1; i < len; i++) {
        if ((p[i] & 0xc0) != 0x80)
            return 0;
    }
    /* Overlong forms, surrogates and code points past U+10FFFF. */
    if ((lead == 0xe0 && p[1] < 0xa0) || (lead == 0xed && p[1] > 0x9f) ||
        (lead == 0xf0 && p[1] < 0x90) || (lead == 0xf4 && p[1] > 0x8f))
        return 0;
    return len;
}

void ft_utf8_copy(char *dst, const char *src, size_t size)
{
    const unsigned char *p = (const unsigned char *)src;
    size_t n = 0;

    if (size == 0)
        return;
    while (*p) {
        size_t len = utf8_sequence(p);
        size_t take = len ? len : 1;

        if (n + take >= size)
            break;
        if (len)
            memcpy(dst + n, p, len);
        else
            dst[n] = '?';
        n += take;
        p += take;
    }
    dst[n] = '\0';
}
