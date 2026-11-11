#ifndef FILETRACE_BASE_H
#define FILETRACE_BASE_H

#include <stddef.h>
#include <stdint.h>

#define FT_ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

#define FT_NS_PER_MS UINT64_C(1'000'000)
#define FT_NS_PER_SEC UINT64_C(1'000'000'000)

enum ft_exit : int {
    FT_EXIT_OK = 0,
    FT_EXIT_ERROR = 1,
    FT_EXIT_USAGE = 2,
    FT_EXIT_PERMISSION = 3,
    FT_EXIT_NO_AGENT = 4,
    FT_EXIT_UNSUPPORTED = 5,
    FT_EXIT_CONFIG = 6,
    FT_EXIT_STORAGE = 7,
    FT_EXIT_EXPORTER = 8,
    FT_EXIT_PARTIAL = 9,
};

struct ft_error {
    int code; /* enum ft_exit */
    char msg[512];
};

[[gnu::format(printf, 3, 4)]]
int ft_error_set(struct ft_error *err, int code, const char *fmt, ...);

enum ft_log_level : uint8_t {
    FT_LOG_ERROR,
    FT_LOG_WARN,
    FT_LOG_INFO,
    FT_LOG_DEBUG,
};

void ft_log_set_level(enum ft_log_level level);
bool ft_log_level_parse(const char *text, enum ft_log_level *level);

[[gnu::format(printf, 2, 3)]]
void ft_log(enum ft_log_level level, const char *fmt, ...);

/* Copies at most size - 1 bytes and always terminates dst. */
void ft_strlcpy(char *dst, const char *src, size_t size);

#endif
