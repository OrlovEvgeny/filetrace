#include "ui/top/top.h"

#include <string.h>

void ft_top_options_defaults(struct ft_top_options *opt)
{
    memset(opt, 0, sizeof(*opt));
    opt->mode = FT_TOP_TRANSFERS;
    opt->window = FT_WINDOW_1H;
    opt->by = FT_SORT_BYTES;
    opt->limit = 50;
    opt->delay_ns = FT_NS_PER_SEC;
}

const char *ft_top_mode_name(enum ft_top_mode mode)
{
    static const char *const names[FT_TOP_MODE_COUNT] = {
        [FT_TOP_TRANSFERS] = "transfers",       [FT_TOP_PROCESSES] = "processes",
        [FT_TOP_DESTINATIONS] = "destinations", [FT_TOP_FILES] = "files",
        [FT_TOP_LEADERS] = "leaders",
    };
    return mode < FT_TOP_MODE_COUNT ? names[mode] : "?";
}

/* The keys --sort takes keep their command-line spelling. */
const char *ft_top_sort_name(enum ft_top_sort sort)
{
    static const char *const names[FT_TOP_SORT_COUNT] = {
        [FT_TOP_SORT_DEFAULT] = "default",
        [FT_TOP_SORT_RATE] = "rate",
        [FT_TOP_SORT_BYTES] = "bytes",
        [FT_TOP_SORT_PROGRESS] = "progress",
        [FT_TOP_SORT_AGE] = "age",
        [FT_TOP_SORT_PID] = "pid",
        [FT_TOP_SORT_USER] = "user",
        [FT_TOP_SORT_PROCESS] = "proc",
        [FT_TOP_SORT_SCRIPT] = "script",
        [FT_TOP_SORT_FILE] = "file",
        [FT_TOP_SORT_SIZE] = "size",
        [FT_TOP_SORT_DESTINATION] = "dest",
        [FT_TOP_SORT_METHOD] = "method",
        [FT_TOP_SORT_CONFIDENCE] = "conf",
        [FT_TOP_SORT_TOTAL] = "total",
        [FT_TOP_SORT_FILES] = "files",
        [FT_TOP_SORT_DESTINATIONS] = "dests",
        [FT_TOP_SORT_PROCESSES] = "procs",
        [FT_TOP_SORT_TRANSFERS] = "transfers",
        [FT_TOP_SORT_KIND] = "kind",
        [FT_TOP_SORT_HOSTNAME] = "host",
    };
    return sort < FT_TOP_SORT_COUNT ? names[sort] : "?";
}

const char *ft_top_group_name(enum ft_top_group group)
{
    static const char *const names[FT_TOP_GROUP_COUNT] = {
        [FT_TOP_GROUP_NONE] = "none",     [FT_TOP_GROUP_PROCESS] = "process",
        [FT_TOP_GROUP_SCRIPT] = "script", [FT_TOP_GROUP_DESTINATION] = "dest",
        [FT_TOP_GROUP_DIRECTORY] = "dir", [FT_TOP_GROUP_SUBNET] = "subnet",
    };
    return group < FT_TOP_GROUP_COUNT ? names[group] : "?";
}

const char *ft_leader_window_name(enum ft_leader_window window)
{
    static const char *const names[FT_WINDOW_COUNT] = {
        [FT_WINDOW_LIFETIME] = "lifetime",
        [FT_WINDOW_1M] = "1m",
        [FT_WINDOW_5M] = "5m",
        [FT_WINDOW_15M] = "15m",
        [FT_WINDOW_1H] = "1h",
        [FT_WINDOW_24H] = "24h",
        [FT_WINDOW_7D] = "7d",
    };
    return window < FT_WINDOW_COUNT ? names[window] : "?";
}

uint64_t ft_leader_window_ns(enum ft_leader_window window)
{
    static const uint64_t seconds[FT_WINDOW_COUNT] = {
        [FT_WINDOW_LIFETIME] = 0,          [FT_WINDOW_1M] = 60,      [FT_WINDOW_5M] = 5 * 60,
        [FT_WINDOW_15M] = 15 * 60,         [FT_WINDOW_1H] = 60 * 60, [FT_WINDOW_24H] = 24 * 60 * 60,
        [FT_WINDOW_7D] = 7 * 24 * 60 * 60,
    };
    return window < FT_WINDOW_COUNT ? seconds[window] * FT_NS_PER_SEC : 0;
}
