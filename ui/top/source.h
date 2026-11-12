#ifndef FILETRACE_TOP_SOURCE_H
#define FILETRACE_TOP_SOURCE_H

#include "ui/top/top.h"

/*
 * Asks the agent for fresh data from a thread of its own and hands complete frames to the
 * caller, so that a slow agent never delays the caller's loop. While a source runs, nothing
 * else may use the session's client.
 */
struct ft_top_source;

struct ft_top_request {
    uint64_t delay_ns; /* between the starts of two refreshes */
    /* The terms the agent applies: pid, uid, process, script, remote, method and confidence.
     * Kind 0 selects everything; ft_top_request_init() sets a scope that does too. */
    struct ft_query scope;
    bool live;    /* statistics, active transfers and processes */
    bool totals;  /* lifetime bytes per destination, on the first refresh and every fifth after */
    bool leaders; /* the ranking of the window, its top directories and its top destinations */
    enum ft_leader_window window;
    enum ft_leader_key key;
    enum ft_sort by;       /* FT_SORT_BYTES, FT_SORT_TRANSFERS or FT_SORT_DESTINATIONS */
    uint32_t limit;        /* rows of the ranking; 0 asks for the agent's default */
    char leader_path[256]; /* glob the ranked paths must match, or "" */
    /* The latest events of a process, a remote address or a file; fetched once per request. */
    bool events;
    uint32_t events_pid;              /* 0: any */
    struct ft_endpoint events_remote; /* any port; family 0: any */
    char events_path[FT_PATH_MAX];    /* glob, or "" */
};

/* How many of the latest events an events request asks for. */
constexpr uint32_t FT_TOP_EVENTS_LIMIT = 200;

/* Everything one refresh asked for, taken as close together as the agent allows. */
struct ft_top_frame {
    uint64_t serial;           /* counts frames from 1, those dropped unread included */
    uint64_t request_serial;   /* the ft_top_source_request() this frame answers */
    uint64_t wall_ns, mono_ns; /* when the refresh began */
    uint64_t took_ns;          /* from the start of the refresh to its last answer */
    int code;                  /* FT_EXIT_OK, or why the frame holds no data */
    char error[256];           /* the first line of the reason */
    struct ft_row_stats stats;
    struct ft_msg_end end; /* of the transfers query: lost events, observed since */
    struct ft_rows transfers, processes;
    /* Only some frames carry the totals; the caller keeps those of the last one that did. */
    bool has_totals;
    struct ft_rows destination_totals;
    /* False when the agent does not know the leaders queries. */
    bool has_leaders;
    struct ft_row_leader_summary leader_summary;
    struct ft_rows leaders, leader_directories, leader_destinations;
    /* Only on the frame that answers an events request; FT_MSG_ROW_EVENT rows, oldest first. */
    bool has_events;
    struct ft_rows events;
};

/* Fills the request with the defaults of the options, asking for nothing yet. */
void ft_top_request_init(struct ft_top_request *req);

/* The first request has serial 1. Returns nullptr with err set when the thread cannot start. */
struct ft_top_source *ft_top_source_start(struct ft_session *s, const struct ft_cli *cli,
                                          const struct ft_top_request *first, struct ft_error *err);

/*
 * Joins the thread. The session's client may then be nullptr, with the agent lost, or have been
 * interrupted in a query: close the session rather than use it.
 */
void ft_top_source_stop(struct ft_top_source *src);

/* Readable while a frame is waiting; for poll(2). */
int ft_top_source_fd(const struct ft_top_source *src);

/* Swaps the waiting frame into *frame, which ft_top_frame_init() set up; false when none waits. */
bool ft_top_source_take(struct ft_top_source *src, struct ft_top_frame *frame);

/* Replaces the request and refreshes at once. Returns its serial. */
uint64_t ft_top_source_request(struct ft_top_source *src, const struct ft_top_request *req);

void ft_top_frame_init(struct ft_top_frame *frame);
void ft_top_frame_free(struct ft_top_frame *frame);

#endif
