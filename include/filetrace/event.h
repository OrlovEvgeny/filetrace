#ifndef FILETRACE_EVENT_H
#define FILETRACE_EVENT_H

#include "filetrace/model.h"

/* Timestamps use ft_clock_mono_ns(); a field the platform cannot observe stays zero. */
enum ft_event_type : uint8_t {
    FT_EVENT_PROCESS_EXEC = 1,
    FT_EVENT_PROCESS_FORK,
    FT_EVENT_PROCESS_EXIT,
    FT_EVENT_SOCKET_STATE,
    FT_EVENT_FILE_SEEN,
    FT_EVENT_FLOW,     /* network bytes accumulated since the previous record */
    FT_EVENT_TRANSFER, /* file-to-socket bytes accumulated since the previous record */
    FT_EVENT_LOSS,
};

struct ft_ev_process {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint64_t start_ns;
    uint64_t cgroup_id;
    uint32_t pidns;
    uint32_t mntns;
    uint32_t netns;
    int32_t exit_status; /* wait(2) status encoding */
    char comm[FT_COMM_MAX];
    char exe[FT_EXE_MAX];
};

struct ft_ev_socket {
    uint64_t sock_id;
    uint32_t pid; /* 0 when the owner was not observable */
    uint16_t proto;
    enum ft_sock_state state;
    struct ft_endpoint local;
    struct ft_endpoint remote;
};

struct ft_ev_file {
    struct ft_file_id id;
    uint32_t generation;
    uint32_t mnt_id;
    uint32_t mntns;
    uint32_t uid;  /* owner */
    uint64_t size; /* when the file was first seen */
    char fs_type[FT_FS_TYPE_MAX];
    bool deleted;
    bool path_truncated;
    const char *path; /* valid only during the callback */
};

struct ft_ev_flow {
    uint64_t sock_id;
    uint32_t pid;
    uint16_t proto;
    struct ft_endpoint local;
    struct ft_endpoint remote;
    uint64_t first_ns;
    uint64_t tx_bytes; /* accepted by the local socket */
    uint64_t rx_bytes; /* delivered to the application */
    uint32_t tx_ops;
    uint32_t rx_ops;
};

struct ft_ev_transfer {
    uint64_t sock_id;
    uint32_t pid;
    enum ft_method method;
    struct ft_file_id file;
    uint64_t first_ns;
    uint64_t bytes;
    uint64_t read_bytes; /* READ_SEND: bytes read from the file */
    uint32_t ops;
    uint32_t alternations; /* READ_SEND: read-then-send sequences */
};

enum ft_loss_kind : uint8_t {
    FT_LOSS_EVENT_QUEUE,  /* the kernel-to-userspace queue overflowed */
    FT_LOSS_AGGREGATION,  /* the in-kernel counter table was full */
    FT_LOSS_SOCKET_IDENT, /* a transfer's socket had no usable identity */
    FT_LOSS_KIND_COUNT,
};

struct ft_ev_loss {
    enum ft_loss_kind kind;
    uint64_t count;
    uint64_t since_ns; /* start of the interval in which the loss happened */
};

struct ft_event {
    enum ft_event_type type;
    uint64_t ts_ns;
    union {
        struct ft_ev_process process;
        struct ft_ev_socket socket;
        struct ft_ev_file file;
        struct ft_ev_flow flow;
        struct ft_ev_transfer transfer;
        struct ft_ev_loss loss;
    };
};

struct ft_sink {
    void *ctx;
    void (*emit)(void *ctx, const struct ft_event *ev);
};

const char *ft_loss_kind_name(enum ft_loss_kind kind);

/* The kind as exported telemetry spells it: "event_queue". */
const char *ft_loss_kind_label(enum ft_loss_kind kind);

#endif
