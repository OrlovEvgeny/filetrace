#ifndef FILETRACE_TOP_H
#define FILETRACE_TOP_H

#include "cmd/cli.h"

enum ft_top_mode : uint8_t {
    FT_TOP_TRANSFERS,
    FT_TOP_PROCESSES,
    FT_TOP_DESTINATIONS,
    FT_TOP_FILES,
    FT_TOP_LEADERS,
    FT_TOP_MODE_COUNT,
};

enum ft_top_sort : uint8_t {
    FT_TOP_SORT_DEFAULT, /* the mode's own: rate, or bytes for leaders */
    FT_TOP_SORT_RATE,
    FT_TOP_SORT_BYTES,
    FT_TOP_SORT_PROGRESS,
    FT_TOP_SORT_AGE,
    FT_TOP_SORT_PID,
    FT_TOP_SORT_USER,
    FT_TOP_SORT_PROCESS,
    FT_TOP_SORT_SCRIPT,
    FT_TOP_SORT_FILE,
    FT_TOP_SORT_SIZE,
    FT_TOP_SORT_DESTINATION,
    FT_TOP_SORT_METHOD,
    FT_TOP_SORT_CONFIDENCE,
    FT_TOP_SORT_TOTAL,        /* bytes since the agent started */
    FT_TOP_SORT_FILES,        /* how many files */
    FT_TOP_SORT_DESTINATIONS, /* how many remote addresses */
    FT_TOP_SORT_PROCESSES,    /* how many processes */
    FT_TOP_SORT_TRANSFERS,    /* how many transfers */
    FT_TOP_SORT_KIND,         /* public or private */
    FT_TOP_SORT_HOSTNAME,
    FT_TOP_SORT_COUNT,
};

enum ft_top_group : uint8_t {
    FT_TOP_GROUP_NONE,
    FT_TOP_GROUP_PROCESS,
    FT_TOP_GROUP_SCRIPT,
    FT_TOP_GROUP_DESTINATION,
    FT_TOP_GROUP_DIRECTORY,
    FT_TOP_GROUP_SUBNET, /* IPv4 /24, IPv6 /64 */
    FT_TOP_GROUP_NAME,   /* of the remote end, as the table shows it */
    FT_TOP_GROUP_COUNT,
};

enum ft_top_color : uint8_t {
    FT_TOP_COLOR_AUTO,
    FT_TOP_COLOR_ALWAYS,
    FT_TOP_COLOR_NEVER,
};

constexpr uint64_t FT_TOP_DELAY_MIN_NS = 500 * FT_NS_PER_MS;
constexpr uint64_t FT_TOP_DELAY_MAX_NS = 10 * FT_NS_PER_SEC;

struct ft_top_options {
    enum ft_top_mode mode;
    enum ft_top_sort sort;
    enum ft_top_group group;
    enum ft_top_color color;
    enum ft_leader_window window; /* leaders */
    enum ft_sort by;              /* leaders: FT_SORT_BYTES, _TRANSFERS or _DESTINATIONS */
    uint32_t limit;               /* leaders: rows asked for */
    uint64_t delay_ns;
    const char *filter; /* an expression, or nullptr */
    bool tree;          /* processes as a tree */
    bool reverse;       /* invert the sort order */
    bool once;          /* one snapshot on stdout instead of the screen */
    bool json;          /* with once: JSON; without: one JSON line per refresh */
    bool resolve;       /* show remote addresses by host name */
    bool addresses;     /* start with destinations by address, as the key a */
};

void ft_top_options_defaults(struct ft_top_options *opt);

const char *ft_top_mode_name(enum ft_top_mode mode);
const char *ft_top_sort_name(enum ft_top_sort sort);
const char *ft_top_group_name(enum ft_top_group group);
const char *ft_leader_window_name(enum ft_leader_window window);
uint64_t ft_leader_window_ns(enum ft_leader_window window);

int ft_top_run(struct ft_session *s, const struct ft_cli *cli, const struct ft_top_options *opt);

#endif
