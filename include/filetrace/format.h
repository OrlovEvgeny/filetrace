#ifndef FILETRACE_FORMAT_H
#define FILETRACE_FORMAT_H

#include "filetrace/base.h"

/* "512 B", "12.0 KB", "1.42 GB"; units are powers of 1024. */
void ft_format_bytes(uint64_t bytes, char *buf, size_t size);

/* "512 B/s", "1.20 MB/s". */
void ft_format_rate(uint64_t bytes_per_second, char *buf, size_t size);

/* "42s", "3h 42m", "2d 4h". */
void ft_format_duration(uint64_t ns, char *buf, size_t size);

/* "1,284,920". */
void ft_format_count(uint64_t value, char *buf, size_t size);

/* "2026-11-10 21:42:11" in local time; "-" for zero. */
void ft_format_time_local(uint64_t wall_ns, char *buf, size_t size);

/* "21:42:11" in local time. */
void ft_format_clock_local(uint64_t wall_ns, char *buf, size_t size);

/* RFC 3339 in UTC with milliseconds: "2026-11-10T21:42:11.210Z". */
void ft_format_time_rfc3339(uint64_t wall_ns, char *buf, size_t size);

/* "100MB", "1.5GB", "4096"; units are powers of 1024, suffix B optional. */
bool ft_parse_size(const char *text, uint64_t *bytes);

/* "10s", "5m", "1h", "7d", "250ms". */
bool ft_parse_duration(const char *text, uint64_t *ns);

/* RFC 3339 timestamp, with "Z" or a numeric offset. */
bool ft_parse_time_rfc3339(const char *text, uint64_t *wall_ns);

bool ft_parse_u32(const char *text, uint32_t *value);
bool ft_parse_u64(const char *text, uint64_t *value);

/* Copies src with '?' in place of every byte that is not part of valid UTF-8. */
void ft_utf8_copy(char *dst, const char *src, size_t size);

/* Shell-style pattern match where '*' also crosses '/'. */
bool ft_glob_match(const char *pattern, const char *text);

#endif
