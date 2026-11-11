#ifndef FILETRACE_STATE_H
#define FILETRACE_STATE_H

#include "filetrace/event.h"
#include "filetrace/table.h"
#include "filetrace/wire.h"

/* Every table has a fixed capacity and forgets its least recently updated entry when full. */

struct ft_state_config {
    size_t max_processes;
    size_t max_sockets;
    size_t max_flows;
    size_t max_files;
    size_t max_transfers;

    /* An inferred association is reported only at or above both thresholds. */
    uint64_t inferred_min_bytes;
    uint32_t inferred_min_permille; /* attributed bytes per 1000 bytes read */

    uint64_t active_window_ns;    /* updated this recently: still in progress */
    uint64_t idle_socket_ns;      /* connectionless socket silent this long: idle */
    uint64_t closed_retention_ns; /* closed sockets stay listed this long */

    /* Describes a process that was running before observation started. */
    bool (*lookup_process)(uint32_t pid, struct ft_ev_process *out);
};

void ft_state_config_defaults(struct ft_state_config *cfg);

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
    int32_t exit_status;
    bool exited;
    char comm[FT_COMM_MAX];
    char exe[FT_EXE_MAX];

    /* Per-query working values. */
    uint64_t q_tx;
    uint64_t q_rx;
    uint32_t q_connections;
    uint32_t q_transfers;
    uint32_t q_own_connections;
    uint32_t q_own_transfers;
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
    char comm[FT_COMM_MAX];
};

struct ft_loss_window {
    uint64_t start_ns;
    uint64_t end_ns;
    uint64_t count;
};

#define FT_LOSS_WINDOWS 64

struct ft_state {
    struct ft_state_config cfg;
    struct ft_table *processes; /* key: uint32_t pid */
    struct ft_table *sockets;   /* key: uint64_t socket id */
    struct ft_table *flows;     /* key: struct ft_flow_key */
    struct ft_table *files;     /* key: struct ft_file_id */
    struct ft_table *transfers; /* key: struct ft_transfer_key */

    uint64_t start_ns;
    uint64_t next_transfer_id;
    uint64_t events;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
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

/* Returns false for an inferred association still below the configured thresholds. */
bool ft_state_classify(const struct ft_state *st, const struct ft_transfer *t,
                       enum ft_confidence *confidence, uint32_t *evidence);

/* first_ns and last_ns, when given, receive the span of the affected windows. */
uint64_t ft_state_lost_between(const struct ft_state *st, uint64_t from_ns, uint64_t to_ns,
                               uint64_t *first_ns, uint64_t *last_ns);

enum ft_sock_state ft_state_socket_state(const struct ft_state *st, const struct ft_socket *s,
                                         uint64_t now_ns);

typedef void ft_row_fn(void *ctx, uint16_t type, const void *row, size_t size);

void ft_state_query(struct ft_state *st, const struct ft_query *q, uint64_t now_ns, ft_row_fn *emit,
                    void *ctx, struct ft_msg_end *end);

/* Fills the parts of the statistics row that the state owns. */
void ft_state_fill_stats(struct ft_state *st, uint64_t now_ns, struct ft_row_stats *row);

#endif
