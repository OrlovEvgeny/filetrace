#ifndef FILETRACE_STATE_H
#define FILETRACE_STATE_H

#include "filetrace/event.h"
#include "filetrace/metrics.h"
#include "filetrace/process.h"
#include "filetrace/table.h"
#include "filetrace/wire.h"

/* Every table has a fixed capacity and forgets its least recently updated entry when full. */

struct ft_state_config {
    size_t max_processes;
    size_t max_sockets;
    size_t max_flows;
    size_t max_files;
    size_t max_transfers;
    size_t max_metric_series; /* label sets of the exported counters */
    size_t event_log_bytes;   /* 0: recent events are not kept */

    /* An inferred association is reported only at or above both thresholds. */
    uint64_t inferred_min_bytes;
    uint32_t inferred_min_permille; /* attributed bytes per 1000 bytes read */

    /* Associations below this level are not reported at all. */
    enum ft_confidence min_confidence;

    uint64_t active_window_ns;    /* updated this recently: still in progress */
    uint64_t idle_socket_ns;      /* connectionless socket silent this long: idle */
    uint64_t closed_retention_ns; /* closed sockets stay listed this long */

    /* Traffic of an ignored protocol or address family is not recorded. */
    bool ignore_tcp;
    bool ignore_udp;
    bool ignore_ipv4;
    bool ignore_ipv6;

    /* Borrowed patterns: a matching process name or file path leaves no record. */
    const char *const *exclude_processes;
    size_t exclude_process_count;
    const char *const *exclude_paths;
    size_t exclude_path_count;
    /* Borrowed patterns: a read-write transfer of a matching file is reported at any size. */
    const char *const *no_minimum_paths;
    size_t no_minimum_path_count;

    /* Describes a process that was running before observation started. */
    bool (*lookup_process)(uint32_t pid, struct ft_ev_process *out);

    /* Reads a process's arguments and working directory; without it they stay unknown. */
    bool (*read_process_text)(uint32_t pid, struct ft_process_text *out);
    bool command_line_arguments; /* false: a command line keeps only the program */
};

void ft_state_config_defaults(struct ft_state_config *cfg);

/* Bytes in the current and the previous second, for a rate over the last one to two. */
struct ft_rate {
    uint64_t second;
    uint64_t current;
    uint64_t previous;
};

void ft_rate_add(struct ft_rate *r, uint64_t now_ns, uint64_t bytes);
uint64_t ft_rate_per_second(const struct ft_rate *r, uint64_t now_ns);

struct ft_process {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pidns;
    uint32_t mntns;
    uint32_t netns;
    uint64_t cgroup_id;
    uint64_t start_ns;
    uint64_t exit_ns;
    uint64_t last_ns;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    struct ft_rate tx_rate;
    struct ft_rate rx_rate;
    int32_t exit_status;
    bool exited;
    bool excluded;
    char comm[FT_COMM_MAX];
    char exe[FT_EXE_MAX];
    char *command_line; /* nullptr while unknown, as are cwd and script */
    char *cwd;
    char *script;
    uint64_t text_ns;   /* when they were read during traffic; 0: not since the last exec or fork */
    uint64_t args_hash; /* of the arguments they were made from */

    /* Per-query working values. */
    uint64_t q_tx;
    uint64_t q_rx;
    uint64_t q_tx_rate;
    uint64_t q_rx_rate;
    uint32_t q_connections;
    uint32_t q_files;
    uint32_t q_transfers;
    uint32_t q_active_transfers;
    uint32_t q_own_connections;
    uint32_t q_own_files;
    uint32_t q_own_transfers;
    uint32_t q_own_active_transfers;
};

struct ft_socket {
    uint64_t id;
    uint32_t pid;
    uint16_t proto;
    enum ft_sock_state state;
    struct ft_endpoint local;
    struct ft_endpoint remote;
    uint64_t first_ns;
    uint64_t last_ns;
    uint64_t closed_ns;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    struct ft_rate tx_rate;
    struct ft_rate rx_rate;
    bool many_remotes;
    char comm[FT_COMM_MAX];

    uint64_t q_attributed;
};

struct ft_flow_key {
    uint64_t sock_id;
    uint32_t pid;
    struct ft_endpoint remote;
};

struct ft_flow {
    uint64_t id;
    uint64_t sock_id;
    uint32_t pid;
    uint16_t proto;
    struct ft_endpoint local;
    struct ft_endpoint remote;
    uint64_t first_ns;
    uint64_t last_ns;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_ops;
    uint64_t rx_ops;
    struct ft_rate tx_rate;
    struct ft_rate rx_rate;
    char comm[FT_COMM_MAX];
};

struct ft_file {
    struct ft_file_id id;
    uint32_t generation;
    uint32_t mnt_id;
    uint32_t mntns;
    uint32_t uid;
    uint64_t size;
    uint64_t first_ns;
    char fs_type[FT_FS_TYPE_MAX];
    bool deleted;
    bool path_truncated;
    bool excluded;
    bool no_minimum;
    char *path;
};

struct ft_transfer_key {
    uint64_t sock_id;
    struct ft_file_id file;
    uint32_t pid;
    uint32_t method;
};

struct ft_transfer {
    uint64_t id;
    uint64_t sock_id;
    struct ft_file_id file;
    uint32_t pid;
    enum ft_method method;
    uint64_t first_ns;
    uint64_t last_ns;
    uint64_t bytes;
    uint64_t read_bytes;
    uint64_t ops;
    uint64_t alternations;
    uint64_t counted_bytes; /* already added to the exported counters */
    bool counted;
    bool no_minimum; /* the file matches [correlation] no_minimum_paths */
    bool background; /* bytes were charged to a file in [correlation] background_paths */
    struct ft_rate rate;
    char comm[FT_COMM_MAX];
};

struct ft_loss_window {
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t count;
};

#define FT_LOSS_WINDOWS 64

/* A flood of one kind of record does not push the others out of the log. */
enum ft_log_class : uint8_t {
    FT_LOG_TRANSFERS, /* files seen, file transfers, event loss */
    FT_LOG_NETWORK,   /* socket states and bytes */
    FT_LOG_PROCESSES,
    FT_LOG_CLASS_COUNT,
};

struct ft_evlog;

/* Receives each record as it is made; its time_ns is still monotonic. */
typedef void ft_record_fn(void *ctx, const struct ft_row_event *row);

struct ft_state {
    struct ft_state_config cfg;
    struct ft_table *processes; /* key: uint32_t pid */
    struct ft_table *sockets;   /* key: uint64_t socket id */
    struct ft_table *flows;     /* key: struct ft_flow_key */
    struct ft_table *files;     /* key: struct ft_file_id */
    struct ft_table *transfers; /* key: struct ft_transfer_key */
    struct ft_evlog *logs[FT_LOG_CLASS_COUNT];
    struct ft_series *series;
    struct ft_row_event *record;          /* the record being made */
    struct ft_process_text *process_text; /* what read_process_text last read */
    ft_record_fn *on_record;
    void *on_record_ctx;

    uint64_t start_ns;
    uint64_t next_transfer_id;
    uint64_t next_flow_id;
    uint64_t next_record_seq;
    uint64_t last_record_ns;
    uint64_t events;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    struct ft_rate tx_rate;
    struct ft_rate rx_rate;
    uint64_t loss[FT_LOSS_KIND_COUNT];
    uint64_t last_loss_ns;
    struct ft_loss_window loss_windows[FT_LOSS_WINDOWS];
    size_t loss_count; /* windows recorded so far; the ring keeps the latest */
};

struct ft_state *ft_state_create(const struct ft_state_config *cfg);
void ft_state_destroy(struct ft_state *st);

void ft_state_ingest(struct ft_state *st, const struct ft_event *ev);

/* Forgets processes that exited without ever touching the network. */
void ft_state_sweep(struct ft_state *st, uint64_t now_ns);

/* Reads a process's command line and working directory as it starts a program. */
void ft_process_text_exec(struct ft_state *st, struct ft_process *p);

/* Reads them again for a process with traffic: first after an exec or fork, then now and then. */
void ft_process_text_refresh(struct ft_state *st, struct ft_process *p, uint64_t now_ns);

/* A forked child has its parent's until its own are read. */
void ft_process_text_inherit(struct ft_process *child, const struct ft_process *parent);

void ft_process_text_clear(struct ft_process *p);

/* Returns false for an association that is not reported. */
bool ft_state_classify(const struct ft_state *st, const struct ft_transfer *t,
                       enum ft_confidence *confidence, uint32_t *evidence);

/* first_ns and last_ns, when given, receive the span of the affected windows. */
uint64_t ft_state_lost_between(const struct ft_state *st, uint64_t from_ns, uint64_t to_ns,
                               uint64_t *first_ns, uint64_t *last_ns);

enum ft_sock_state ft_state_socket_state(const struct ft_state *st, const struct ft_socket *s,
                                         uint64_t now_ns);

typedef void ft_row_fn(void *ctx, uint16_t type, const void *row, size_t size);

/* Returns false, with err set, for a query that cannot be evaluated. */
bool ft_state_query(struct ft_state *st, const struct ft_query *q, uint64_t now_ns, ft_row_fn *emit,
                    void *ctx, struct ft_msg_end *end, struct ft_error *err);

/* Whether a record passes the filters of an events query; times are monotonic. */
bool ft_state_record_matches(const struct ft_query *q, uint64_t from_ns, uint64_t to_ns,
                             const struct ft_row_event *row);

/* Fills the parts of the statistics row that the state owns. */
void ft_state_fill_stats(struct ft_state *st, uint64_t now_ns, struct ft_row_stats *row);

struct ft_evlog *ft_evlog_create(size_t bytes);
void ft_evlog_destroy(struct ft_evlog *log);

/* Stores the first size bytes of row, discarding the oldest records to make room. */
void ft_evlog_append(struct ft_evlog *log, const struct ft_row_event *row, size_t size);

size_t ft_evlog_capacity(const struct ft_evlog *log);
uint64_t ft_evlog_records(const struct ft_evlog *log);
uint64_t ft_evlog_discarded(const struct ft_evlog *log);

struct ft_evlog_cursor {
    size_t pos;
    size_t remaining;
};

void ft_evlog_rewind(const struct ft_evlog *log, struct ft_evlog_cursor *cur);

/* Copies the record under the cursor into out; false once the cursor is past the newest. */
bool ft_evlog_peek(const struct ft_evlog *log, const struct ft_evlog_cursor *cur,
                   struct ft_row_event *out);
void ft_evlog_advance(const struct ft_evlog *log, struct ft_evlog_cursor *cur);

#endif
