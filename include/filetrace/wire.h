#ifndef FILETRACE_WIRE_H
#define FILETRACE_WIRE_H

#include "filetrace/model.h"
#include "filetrace/names.h"

/* Frames use host byte order: both ends of the socket run on the same host. */
#define FT_WIRE_MAGIC 0x43525446u /* "FTRC" */
#define FT_WIRE_VERSION 7
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
    FT_MSG_ROW_LEADER_SUMMARY = 23,
    FT_MSG_ROW_LEADER = 24,

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
    FT_Q_LEADERS,
};

enum ft_query_flag : uint32_t {
    FT_QF_ACTIVE = 1u << 0,
    FT_QF_COMPLETED = 1u << 1,
    FT_QF_INCLUDE_UNKNOWN = 1u << 2, /* transfers: bytes with no associated file */
    FT_QF_DELETED = 1u << 3,         /* transfers: only files with no remaining links */
    FT_QF_INCLUDE_CHILDREN = 1u << 4,
    FT_QF_HAS_UID = 1u << 5,
    FT_QF_PATH_REGEX = 1u << 6,   /* path is a POSIX extended regular expression */
    FT_QF_FOLLOW = 1u << 7,       /* events: keep sending them as they are recorded */
    FT_QF_INCLUDE_IDLE = 1u << 8, /* processes: also those that never used the network */
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
    FT_SORT_PROCESS,      /* by name, ascending */
    FT_SORT_FILE,         /* by path, ascending */
    FT_SORT_TRANSFERS,    /* leaders: by transfers started */
    FT_SORT_DESTINATIONS, /* leaders: by distinct remote addresses */
};

/* The span a ranking covers. Each window but the lifetime one is kept as slots of equal length. */
enum ft_leader_window : uint8_t {
    FT_WINDOW_LIFETIME = 0, /* since the agent started */
    FT_WINDOW_1M,
    FT_WINDOW_5M,
    FT_WINDOW_15M,
    FT_WINDOW_1H,
    FT_WINDOW_24H,
    FT_WINDOW_7D,
    FT_WINDOW_COUNT,
};

/* What one row of a ranking stands for. */
enum ft_leader_key : uint8_t {
    FT_LEADER_FILE = 0,
    FT_LEADER_DIRECTORY,   /* files merged by their parent directory */
    FT_LEADER_EXTENSION,   /* files merged by the extension of their name */
    FT_LEADER_DESTINATION, /* remote addresses, whatever the port */
    FT_LEADER_KEY_COUNT,
};

struct ft_query {
    uint16_t kind; /* enum ft_query_kind */
    uint16_t sort; /* enum ft_sort */
    uint32_t flags;
    uint32_t limit; /* 0: no limit; for FT_Q_LEADERS, 0: the first 50 */
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
    uint8_t window;         /* leaders: enum ft_leader_window */
    uint8_t leader_key;     /* leaders: enum ft_leader_key */
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
    char script[1024]; /* of the process; matched as process is */
    /* A pattern for the names of the remote end, as ft_name_pattern writes one; "": any. */
    char remote_name[256];
    char path[FT_PATH_MAX];
};

void ft_query_init(struct ft_query *q, enum ft_query_kind kind);

#define FT_PROC_EXITED 0x1u

/* A process's command line, working directory and script, each followed by its terminator. */
#define FT_PROCESS_TEXT_MAX (FT_CMDLINE_MAX + 2 * FT_PATH_MAX)

/* Each one is "" when it is not known. */
struct ft_process_strings {
    const char *command_line;
    const char *cwd;
    const char *script;
};

struct ft_row_process {
    uint64_t start_wall_ns;
    uint64_t exit_wall_ns;
    uint64_t tx_bytes;
    uint64_t rx_bytes;
    uint64_t tx_rate; /* bytes per second over the last one to two seconds */
    uint64_t rx_rate;
    uint64_t file_bytes; /* of tx_bytes, attributed to files */
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
    char text[FT_PROCESS_TEXT_MAX]; /* sent up to its last terminator */
};

/* A TLS server name and the looked-up names, each followed by its terminator. */
#define FT_NAMES_TEXT_MAX ((FT_RESOLVED_NAMES + 1) * FT_NAME_MAX)

/* Which names of the remote end follow a row's other strings. */
struct ft_row_names {
    uint16_t count; /* names the process looked up to the remote address: listed or more */
    uint8_t listed; /* of them, in the row: the connecting thread's latest first */
    uint8_t tls;    /* 1: the TLS server name precedes them */
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
    struct ft_row_names names;
    char text[FT_NAMES_TEXT_MAX]; /* the names; sent up to the last one's terminator */
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
    struct ft_row_names names;
    char text[FT_NAMES_TEXT_MAX]; /* the names; sent up to the last one's terminator */
};

#define FT_XFER_ACTIVE 0x01u
#define FT_XFER_INCOMPLETE 0x02u /* events were lost while it was in progress */
#define FT_XFER_FILE_KNOWN 0x04u
#define FT_XFER_PATH_KNOWN 0x08u
#define FT_XFER_FILE_DELETED 0x10u
#define FT_XFER_PATH_TRUNCATED 0x20u
#define FT_XFER_PROCESS_TEXT 0x40u /* the process's strings follow the path */

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
    struct ft_row_names names;
    char comm[FT_COMM_MAX];
    char exe[FT_EXE_MAX];
    char fs_type[FT_FS_TYPE_MAX];
    /* The path, any process strings, then any names; sent up to its last terminator. */
    char path[FT_PATH_MAX + FT_PROCESS_TEXT_MAX + FT_NAMES_TEXT_MAX];
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
    uint32_t active_by_confidence[4]; /* the active transfers, by enum ft_confidence */
    uint32_t active_processes;        /* processes with traffic in the last few seconds */
    uint32_t open_sockets;
    uint32_t health;
    uint32_t pid;
    char backend[48];
    char mode[16];
    char version[48];
    uint64_t leaders_bytes; /* memory of the rankings of the most sent files; 0 when off */
    struct ft_table_usage listed_files;   /* the kernel's table of listed files; capacity 0: none */
    struct ft_table_usage names;          /* names of remote ends; capacity 0: they are off */
    struct ft_table_usage name_lookups;   /* what processes looked up, per process and address */
    struct ft_table_usage name_libraries; /* library files probed for names; capacity 0: none */
    uint64_t names_invalid;               /* names refused: not host names */
    uint64_t names_refused; /* names refused: listed connections held every kept name */
    /* [limits] name_libraries, more than name_libraries.capacity when open files cut it */
    uint64_t name_libraries_configured;
    uint64_t tls_libraries; /* TLS library files probed for server names; 0: none or TLS off */
    uint64_t tls_library_capacity; /* TLS library files that may be probed */
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
#define FT_EVENT_PROCESS_TEXT 0x4u /* the process's strings follow the text */

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
    uint8_t name_source; /* enum ft_name_source; unless none, the remote end's name is last */
    struct ft_endpoint local;
    struct ft_endpoint remote;
    char comm[FT_COMM_MAX];
    /*
     * A file path or an executable, then any process strings, then the name the remote end had
     * when the record was made; sent up to its last terminator.
     */
    char text[FT_PATH_MAX + FT_PROCESS_TEXT_MAX + FT_NAME_MAX];
};

#define FT_LEADER_SLOTS 12  /* trend points of a window */
#define FT_LEADER_SENDERS 3 /* sender names listed per row */

/* Above this many, a row's count of remote addresses is an estimate. */
#define FT_LEADER_EXACT_DESTINATIONS 15

#define FT_LEADERS_SHORT_HISTORY 0x1u /* the agent has run for less than the window */
#define FT_LEADERS_CAPPED 0x2u        /* entries were replaced to keep memory bounded */
#define FT_LEADERS_OFF 0x4u           /* the agent keeps no rankings; every figure is zero */

/* Precedes the rows of a leaders query. */
struct ft_row_leader_summary {
    uint64_t window_ns; /* 0: lifetime */
    uint64_t slot_ns;   /* length of one trend slot; 0: lifetime */
    uint64_t from_wall_ns;
    uint64_t to_wall_ns;
    uint64_t previous_from_wall_ns; /* start of the span ranks are compared with; 0: none */
    uint64_t bytes;                 /* file bytes sent in the span, ranked or not */
    uint64_t bytes_exact;           /* of them, moved by the kernel itself */
    uint64_t transfers;
    uint64_t top_bytes; /* sent by the ten largest files */
    uint64_t files;     /* distinct files; an estimate when large */
    uint64_t destinations_public;
    uint64_t destinations_private;
    uint32_t processes; /* distinct sender names */
    uint32_t scripts;
    uint32_t flags;
    uint32_t pad;
};

struct ft_leader_sender {
    uint64_t bytes;
    uint64_t transfers;
    char name[FT_COMM_MAX];
};

#define FT_LEADER_DELETED 0x1u      /* the file has no remaining links */
#define FT_LEADER_MORE_SENDERS 0x2u /* more names sent it than are listed */

struct ft_row_leader {
    uint64_t bytes;       /* counted for this entry itself, so never more than the truth */
    uint64_t bytes_error; /* how much more the truth may be */
    uint64_t bytes_exact; /* of bytes, moved by the kernel itself */
    uint64_t transfers;
    uint64_t transfers_error;
    uint64_t destinations; /* distinct remote addresses */
    uint64_t files;        /* distinct files behind a directory, extension or destination */
    uint64_t file_size;
    uint64_t dev;
    uint64_t ino;
    uint64_t first_wall_ns;
    uint64_t last_wall_ns;
    uint64_t trend[FT_LEADER_SLOTS]; /* bytes per slot, oldest first; zero for lifetime */
    uint32_t rank;                   /* from 1, in the order asked for */
    uint32_t previous_rank;          /* in the span before; 0: not among its first fifty */
    uint32_t flags;
    uint8_t confidence; /* the lowest among its transfers */
    uint8_t method;     /* the one that carried the most bytes */
    uint8_t pad[2];
    struct ft_endpoint remote; /* FT_LEADER_DESTINATION: the address, with port 0 */
    struct ft_leader_sender senders[FT_LEADER_SENDERS]; /* largest first; unused ones zero */
    char text[FT_PATH_MAX]; /* path, directory or ".ext"; sent up to its terminator */
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

/* Payload size of the row: everything up to its last string's terminator. */
size_t ft_row_process_size(const struct ft_row_process *row);
size_t ft_row_connection_size(const struct ft_row_connection *row);
size_t ft_row_flow_size(const struct ft_row_flow *row);
size_t ft_row_transfer_size(const struct ft_row_transfer *row);
size_t ft_row_event_size(const struct ft_row_event *row);
size_t ft_row_leader_size(const struct ft_row_leader *row);

/* Writes the three strings one after another, each cut to its size; returns the bytes used. */
size_t ft_process_strings_pack(char *buf, size_t size, const struct ft_process_strings *s);

void ft_row_process_strings(const struct ft_row_process *row, struct ft_process_strings *out);
void ft_row_transfer_strings(const struct ft_row_transfer *row, struct ft_process_strings *out);
void ft_row_event_strings(const struct ft_row_event *row, struct ft_process_strings *out);

/* Writes the names one after another and says in fixed which they are; returns the bytes used. */
size_t ft_remote_names_pack(const struct ft_remote_names *names, struct ft_row_names *fixed,
                            char *buf, size_t size);

/* A row without names gives "" for the TLS name and lists none. */
void ft_row_connection_names(const struct ft_row_connection *row, struct ft_remote_names *out);
void ft_row_flow_names(const struct ft_row_flow *row, struct ft_remote_names *out);
void ft_row_transfer_names(const struct ft_row_transfer *row, struct ft_remote_names *out);

/* Puts the name after the record's other strings; none leaves the record without one. */
void ft_row_event_set_name(struct ft_row_event *row, enum ft_name_source source, const char *name);

/* "" when the record has no name. */
const char *ft_row_event_name(const struct ft_row_event *row);

const char *ft_record_type_name(enum ft_record_type type);
bool ft_record_type_parse(const char *text, enum ft_record_type *type);

const char *ft_default_socket_path(void);

#endif
