#ifndef FILETRACE_WIRE_H
#define FILETRACE_WIRE_H

#include "filetrace/model.h"

/* Frames use host byte order: both ends of the socket run on the same host. */
#define FT_WIRE_MAGIC 0x43525446u /* "FTRC" */
#define FT_WIRE_VERSION 2
#define FT_WIRE_MAX_PAYLOAD (64u * 1024u)

enum ft_msg_type : uint16_t {
    FT_MSG_QUERY = 1,
    FT_MSG_SHUTDOWN = 2,

    FT_MSG_ROW_PROCESS = 16,
    FT_MSG_ROW_CONNECTION = 17,
    FT_MSG_ROW_FLOW = 18,
    FT_MSG_ROW_TRANSFER = 19,
    FT_MSG_ROW_STATS = 20,
    FT_MSG_ROW_CAPABILITY = 21,
    FT_MSG_ROW_EVENT = 22,

    FT_MSG_END = 64,
    FT_MSG_ERROR = 65,
};

struct ft_frame_hdr {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t length; /* payload bytes that follow */
    uint32_t reserved;
};

enum ft_query_kind : uint16_t {
    FT_Q_STATS = 1,
    FT_Q_CAPABILITIES,
    FT_Q_PROCESSES,
    FT_Q_CONNECTIONS,
    FT_Q_FLOWS,
    FT_Q_TRANSFERS,
    FT_Q_EVENTS,
};

enum ft_query_flag : uint32_t {
    FT_QF_ACTIVE = 1u << 0,
    FT_QF_COMPLETED = 1u << 1,
    FT_QF_INCLUDE_UNKNOWN = 1u << 2, /* transfers: bytes with no associated file */
    FT_QF_DELETED = 1u << 3,         /* transfers: only files with no remaining links */
    FT_QF_INCLUDE_CHILDREN = 1u << 4,
    FT_QF_HAS_UID = 1u << 5,
    FT_QF_PATH_REGEX = 1u << 6, /* path is a POSIX extended regular expression */
    FT_QF_FOLLOW = 1u << 7,     /* events: keep sending them as they are recorded */
};

enum ft_sort : uint16_t {
    FT_SORT_DEFAULT = 0,
    FT_SORT_OUTBOUND,
    FT_SORT_INBOUND,
    FT_SORT_CONNECTIONS,
    FT_SORT_BYTES,
    FT_SORT_TIME,
    FT_SORT_PID,
    FT_SORT_RATE,
    FT_SORT_DURATION,
    FT_SORT_PROCESS, /* by name, ascending */
    FT_SORT_FILE,    /* by path, ascending */
};

struct ft_query {
    uint16_t kind; /* enum ft_query_kind */
    uint16_t sort; /* enum ft_sort */
    uint32_t flags;
    uint32_t limit; /* 0: no limit */
    uint32_t pid;   /* 0: any */
    uint32_t uid;   /* with FT_QF_HAS_UID */
    uint32_t ns_inum;
    uint16_t proto;           /* 0: any */
    uint16_t port;            /* 0: any; matches either end */
    uint8_t family;           /* 0: any, 4 or 6 */
    uint8_t state;            /* enum ft_sock_state or FT_SOCK_ANY */
    uint8_t method;           /* enum ft_method or FT_METHOD_ANY */
    uint8_t confidence;       /* enum ft_confidence or FT_CONF_ANY */
    uint8_t remote_host_bits; /* low-order address bits left out of the comparison */
    uint8_t local_host_bits;
    uint8_t pad[2];
    uint32_t event_types;   /* events: bit per enum ft_record_type; 0: any */
    uint64_t since_wall_ns; /* 0: unbounded */
    uint64_t until_wall_ns; /* 0: unbounded */
    uint64_t min_bytes;
    uint64_t min_size;         /* transfers: smallest file size */
    uint64_t cgroup_id;        /* 0: any */
    uint64_t sock_id;          /* 0: any */
    uint64_t flow_id;          /* 0: any */
    struct ft_endpoint remote; /* family 0: any */
    struct ft_endpoint local;
    char process[64];
    char path[FT_PATH_MAX];
};

void ft_query_init(struct ft_query *q, enum ft_query_kind kind);

#define FT_PROC_EXITED 0x1u

struct ft_row_process {
    uint64_t start_wall_ns;
    uint64_t exit_wall_ns;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_rate; /* bytes per second over the last one to two seconds */
    uint64_t rx_rate;
    uint64_t cgroup_id;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint32_t pidns;
    uint32_t mntns;
    uint32_t netns;
    uint32_t connections;      /* sockets currently open or active */
    uint32_t files;            /* distinct files in attributed transfers */
    uint32_t transfers;        /* attributed transfers */
    uint32_t active_transfers; /* of those, still in progress */
    int32_t exit_status;
    uint32_t flags;
    char comm[FT_COMM_MAX];
    char exe[FT_EXE_MAX];
};

struct ft_row_connection {
    uint64_t sock_id;
    uint64_t first_wall_ns;
    uint64_t last_wall_ns;
    uint64_t closed_wall_ns;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_rate;
    uint64_t rx_rate;
    uint32_t pid;
    uint16_t proto;
    uint8_t state;
    uint8_t pad;
    struct ft_endpoint local;
    struct ft_endpoint remote;
    char comm[FT_COMM_MAX];
};

struct ft_row_flow {
    uint64_t id;
    uint64_t sock_id;
    uint64_t first_wall_ns;
    uint64_t last_wall_ns;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_rate;
    uint64_t rx_rate;
    uint32_t tx_ops;
    uint32_t rx_ops;
    uint32_t pid;
    uint16_t proto;
    uint16_t pad;
    struct ft_endpoint local;
    struct ft_endpoint remote;
    char comm[FT_COMM_MAX];
};

#define FT_XFER_ACTIVE 0x01u
#define FT_XFER_INCOMPLETE 0x02u /* events were lost while it was in progress */
#define FT_XFER_FILE_KNOWN 0x04u
#define FT_XFER_PATH_KNOWN 0x08u
#define FT_XFER_FILE_DELETED 0x10u
#define FT_XFER_PATH_TRUNCATED 0x20u

struct ft_row_transfer {
    uint64_t id;
    uint64_t sock_id;
    uint64_t first_wall_ns;
    uint64_t last_wall_ns;
    uint64_t bytes;
    uint64_t read_bytes;
    uint64_t rate;      /* bytes per second over the last one to two seconds */
    uint64_t file_size; /* when the file was first seen */
    uint64_t dev;
    uint64_t ino;
    uint32_t file_uid;
    uint32_t gen;
    uint32_t ops;
    uint32_t alternations;
    uint32_t pid;
    uint32_t ppid;
    uint32_t evidence; /* enum ft_evidence bits */
    uint16_t proto;
    uint8_t confidence;
    uint8_t method;
    uint32_t flags;
    struct ft_endpoint local;
    struct ft_endpoint remote;
    char comm[FT_COMM_MAX];
    char exe[FT_EXE_MAX];
    char fs_type[FT_FS_TYPE_MAX];
    char path[FT_PATH_MAX]; /* sent up to and including its terminator */
};

struct ft_table_usage {
    uint64_t count;
    uint64_t capacity;
    uint64_t evictions;
};

enum ft_health : uint32_t {
    FT_HEALTH_OK = 0,
    FT_HEALTH_DEGRADED = 1,
};

struct ft_row_stats {
    uint64_t start_wall_ns;
    uint64_t now_wall_ns;
    uint64_t events_received;
    uint64_t events_processed;
    uint64_t events_dropped;
    uint64_t events_per_sec_milli;
    uint64_t rss_bytes;
    uint64_t queue_bytes;      /* kernel-to-userspace queue capacity */
    uint64_t queue_peak_bytes; /* largest backlog seen at a flush */
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_rate;
    uint64_t rx_rate;
    uint64_t loss[4]; /* indexed by enum ft_loss_kind */
    uint64_t last_loss_wall_ns;
    uint64_t event_log_bytes; /* capacity of the recent-event log; 0 when it is off */
    uint64_t event_log_records;
    uint64_t event_log_discarded; /* records that made room for later ones */
    uint64_t candidates_rejected; /* inferred associations below the thresholds */
    struct ft_table_usage processes;
    struct ft_table_usage sockets;
    struct ft_table_usage flows;
    struct ft_table_usage files;
    struct ft_table_usage transfers;
    uint32_t cpu_milli_percent;
    uint32_t open_fds;
    uint32_t active_flows;
    uint32_t active_transfers;
    uint32_t open_sockets;
    uint32_t health;
    uint32_t pid;
    uint32_t pad;
    char backend[48];
    char mode[16];
    char version[16];
};

struct ft_row_capability {
    uint8_t feature;
    uint8_t status;
    uint8_t pad[2];
    char reason[188];
};

enum ft_record_type : uint8_t {
    FT_REC_PROCESS_EXEC = 1,
    FT_REC_PROCESS_FORK,
    FT_REC_PROCESS_EXIT,
    FT_REC_SOCKET_CONNECT,
    FT_REC_SOCKET_LISTEN,
    FT_REC_SOCKET_ESTABLISHED,
    FT_REC_SOCKET_CLOSE,
    FT_REC_FILE_SEEN,
    FT_REC_NETWORK_SEND,    /* bytes a socket accepted since its previous record */
    FT_REC_NETWORK_RECEIVE, /* bytes a socket delivered since its previous record */
    FT_REC_FILE_TRANSFER,   /* file bytes attributed to a socket since the previous record */
    FT_REC_EVENT_LOSS,
    FT_REC_TYPE_COUNT,
};

#define FT_EVENT_FILE_DELETED 0x1u
#define FT_EVENT_HAS_CONFIDENCE 0x2u

/* loss_kind of an EVENT_LOSS record made for a follower that read too slowly. */
#define FT_EVENT_LOSS_READER 0xffu

struct ft_row_event {
    uint64_t seq;
    uint64_t time_ns; /* wall clock on the wire */
    uint64_t sock_id;
    uint64_t bytes;      /* sent, received or attributed; EVENT_LOSS: events lost */
    uint64_t read_bytes; /* FILE_TRANSFER: read from the file */
    uint64_t file_size;
    uint64_t dev;
    uint64_t ino;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    int32_t exit_status;
    uint16_t proto;
    uint8_t type; /* enum ft_record_type */
    uint8_t confidence;
    uint8_t method;
    uint8_t loss_kind;
    uint8_t flags;
    uint8_t pad;
    struct ft_endpoint local;
    struct ft_endpoint remote;
    char comm[FT_COMM_MAX];
    char text[FT_PATH_MAX]; /* file path or executable; sent up to its terminator */
};

struct ft_msg_end {
    uint32_t rows;
    uint32_t health;
    uint64_t observed_since_wall_ns;
    uint64_t lost_events; /* lost inside the queried time range */
    uint64_t loss_first_wall_ns;
    uint64_t loss_last_wall_ns;
};

struct ft_msg_error {
    uint32_t code; /* enum ft_exit */
    char msg[508];
};

/* Payload size of the row: everything up to its path's terminator. */
size_t ft_row_transfer_size(const struct ft_row_transfer *row);
size_t ft_row_event_size(const struct ft_row_event *row);

const char *ft_record_type_name(enum ft_record_type type);
bool ft_record_type_parse(const char *text, enum ft_record_type *type);

const char *ft_default_socket_path(void);

#endif
