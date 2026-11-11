#ifndef FILETRACE_CLI_H
#define FILETRACE_CLI_H

#include "filetrace/client.h"

#include <stdio.h>
#include <sys/types.h>

enum ft_format : uint8_t {
    FT_FMT_TABLE,
    FT_FMT_JSON,
    FT_FMT_JSONL,
    FT_FMT_CSV,
    FT_FMT_QUIET,
};

constexpr size_t FT_FMT_COUNT = FT_FMT_QUIET + 1;

#define FT_FMT_BIT(format) (1u << (format))

constexpr uint32_t FT_FORMATS_ALL = FT_FMT_BIT(FT_FMT_COUNT) - 1;
constexpr uint32_t FT_FORMATS_REPORT = FT_FMT_BIT(FT_FMT_TABLE) | FT_FMT_BIT(FT_FMT_JSON);

struct ft_config;
struct ft_agent_config;

struct ft_cli {
    const char *socket_path;
    bool socket_given;              /* by --socket or $FILETRACE_SOCKET, not by the file */
    const char *config_path;        /* --config; nullptr for the default file */
    const struct ft_config *config; /* nullptr for the commands that run without one */
};

/* Reports an unusable configuration file itself and returns FT_EXIT_CONFIG. */
int ft_cli_load_config(struct ft_cli *cli);
void ft_cli_free_config(struct ft_cli *cli);
const char *ft_config_default_path_text(void);

/* The configured default output format when the command can print it, else table. */
enum ft_format ft_cli_format(const struct ft_cli *cli, uint32_t accepted);
bool ft_cli_timestamps(const struct ft_cli *cli);

/* Settings for a collector started by a command, or nullptr for the built-in ones. */
const struct ft_agent_config *ft_cli_collector_config(const struct ft_cli *cli);

struct ft_args {
    int argc;
    char **argv;
    int pos;
};

bool ft_args_done(const struct ft_args *a);
const char *ft_args_peek(const struct ft_args *a);
const char *ft_args_take(struct ft_args *a);

bool ft_args_flag(struct ft_args *a, const char *name);

/* Returns 1 with *value set, 0 for a different argument, -1 after reporting a missing value. */
int ft_args_value(struct ft_args *a, const char *name, const char **value);

[[gnu::format(printf, 2, 3)]]
int ft_usage_error(const char *command, const char *fmt, ...);

/* Returns 1 with *format set, 0 for another argument, -1 after reporting a bad value. */
int ft_args_format(struct ft_args *a, const char *command, uint32_t accepted,
                   enum ft_format *format);

struct ft_output {
    enum ft_format format;
    FILE *stream;
    bool tty;
    bool format_given;
};

void ft_output_init(struct ft_output *out);
int ft_output_open(struct ft_output *out, const char *path);
void ft_output_close(struct ft_output *out);

enum ft_query_opt : uint32_t {
    FT_QO_PID = 1u << 0,
    FT_QO_PROCESS = 1u << 1,
    FT_QO_FILE = 1u << 2,
    FT_QO_REMOTE = 1u << 3,
    FT_QO_LOCAL = 1u << 4,
    FT_QO_PROTOCOL = 1u << 5,
    FT_QO_TIME = 1u << 6,
    FT_QO_CONFIDENCE = 1u << 7,
    FT_QO_MIN_BYTES = 1u << 8,
    FT_QO_PORT = 1u << 9,
    FT_QO_FAMILY = 1u << 10,
    FT_QO_STATE = 1u << 11,
    FT_QO_METHOD = 1u << 12,
    FT_QO_ACTIVITY = 1u << 13, /* --active, --completed */
    FT_QO_USER = 1u << 14,
    FT_QO_SCOPE = 1u << 15, /* --cgroup, --namespace */
    FT_QO_SORT = 1u << 16,
    FT_QO_LIMIT = 1u << 17,
    FT_QO_OUTPUT = 1u << 18,     /* --format, --output */
    FT_QO_FILE_MATCH = 1u << 19, /* --path-regex, --min-size */
    FT_QO_RESOLVE = 1u << 20,    /* --resolve-hostnames */
    FT_QO_SCRIPT = 1u << 21,
};

#define FT_SORT_BIT(sort) (1u << (sort))

constexpr uint32_t FT_OPTS_PROCESSES = FT_QO_PID | FT_QO_PROCESS | FT_QO_SCRIPT | FT_QO_USER |
                                       FT_QO_SCOPE | FT_QO_TIME | FT_QO_SORT | FT_QO_LIMIT |
                                       FT_QO_OUTPUT;
constexpr uint32_t FT_SORTS_PROCESSES =
    FT_SORT_BIT(FT_SORT_OUTBOUND) | FT_SORT_BIT(FT_SORT_INBOUND) | FT_SORT_BIT(FT_SORT_BYTES) |
    FT_SORT_BIT(FT_SORT_CONNECTIONS) | FT_SORT_BIT(FT_SORT_TIME) | FT_SORT_BIT(FT_SORT_PID) |
    FT_SORT_BIT(FT_SORT_PROCESS);

constexpr uint32_t FT_OPTS_NETWORK = FT_QO_PID | FT_QO_PROCESS | FT_QO_USER | FT_QO_SCOPE |
                                     FT_QO_REMOTE | FT_QO_LOCAL | FT_QO_PORT | FT_QO_PROTOCOL |
                                     FT_QO_FAMILY | FT_QO_TIME | FT_QO_SORT | FT_QO_LIMIT |
                                     FT_QO_OUTPUT | FT_QO_RESOLVE;
constexpr uint32_t FT_OPTS_CONNECTIONS = FT_OPTS_NETWORK | FT_QO_STATE;
constexpr uint32_t FT_SORTS_CONNECTIONS =
    FT_SORT_BIT(FT_SORT_TIME) | FT_SORT_BIT(FT_SORT_BYTES) | FT_SORT_BIT(FT_SORT_OUTBOUND) |
    FT_SORT_BIT(FT_SORT_INBOUND) | FT_SORT_BIT(FT_SORT_RATE) | FT_SORT_BIT(FT_SORT_DURATION) |
    FT_SORT_BIT(FT_SORT_PID) | FT_SORT_BIT(FT_SORT_PROCESS);
constexpr uint32_t FT_OPTS_FLOWS = FT_OPTS_NETWORK | FT_QO_MIN_BYTES;
constexpr uint32_t FT_SORTS_FLOWS = FT_SORT_BIT(FT_SORT_OUTBOUND) | FT_SORT_BIT(FT_SORT_INBOUND) |
                                    FT_SORT_BIT(FT_SORT_BYTES) | FT_SORT_BIT(FT_SORT_RATE) |
                                    FT_SORT_BIT(FT_SORT_DURATION) | FT_SORT_BIT(FT_SORT_TIME) |
                                    FT_SORT_BIT(FT_SORT_PID) | FT_SORT_BIT(FT_SORT_PROCESS);

constexpr uint32_t FT_OPTS_TRANSFERS =
    FT_QO_PID | FT_QO_PROCESS | FT_QO_SCRIPT | FT_QO_USER | FT_QO_SCOPE | FT_QO_FILE |
    FT_QO_FILE_MATCH | FT_QO_REMOTE | FT_QO_LOCAL | FT_QO_PORT | FT_QO_PROTOCOL | FT_QO_CONFIDENCE |
    FT_QO_METHOD | FT_QO_MIN_BYTES | FT_QO_ACTIVITY | FT_QO_TIME | FT_QO_SORT | FT_QO_LIMIT |
    FT_QO_OUTPUT | FT_QO_RESOLVE;

constexpr uint32_t FT_OPTS_WATCH = FT_QO_PID | FT_QO_PROCESS | FT_QO_USER | FT_QO_SCOPE |
                                   FT_QO_FILE | FT_QO_REMOTE | FT_QO_PROTOCOL | FT_QO_CONFIDENCE |
                                   FT_QO_MIN_BYTES | FT_QO_SORT | FT_QO_LIMIT | FT_QO_RESOLVE;
constexpr uint32_t FT_SORTS_WATCH = FT_SORT_BIT(FT_SORT_RATE) | FT_SORT_BIT(FT_SORT_BYTES) |
                                    FT_SORT_BIT(FT_SORT_PROCESS) | FT_SORT_BIT(FT_SORT_FILE);

constexpr uint32_t FT_OPTS_EVENTS = FT_QO_PID | FT_QO_PROCESS | FT_QO_SCRIPT | FT_QO_FILE |
                                    FT_QO_REMOTE | FT_QO_LOCAL | FT_QO_PORT | FT_QO_PROTOCOL |
                                    FT_QO_FAMILY | FT_QO_TIME | FT_QO_LIMIT | FT_QO_OUTPUT;
constexpr uint32_t FT_FORMATS_EVENTS =
    FT_FMT_BIT(FT_FMT_TABLE) | FT_FMT_BIT(FT_FMT_JSON) | FT_FMT_BIT(FT_FMT_JSONL);
constexpr uint32_t FT_SORTS_TRANSFERS = FT_SORT_BIT(FT_SORT_TIME) | FT_SORT_BIT(FT_SORT_BYTES) |
                                        FT_SORT_BIT(FT_SORT_RATE) | FT_SORT_BIT(FT_SORT_DURATION) |
                                        FT_SORT_BIT(FT_SORT_PID) | FT_SORT_BIT(FT_SORT_PROCESS) |
                                        FT_SORT_BIT(FT_SORT_FILE);

struct ft_query_args {
    struct ft_query query;
    struct ft_output out;
    const char *output_path;
    const char *command;
    const char *subject; /* what messages call it, such as "top processes" */
    const char *masked;  /* the option the last argument named that this command lacks */
    uint32_t allowed;
    uint32_t sorts;   /* bit per enum ft_sort value the command accepts */
    uint32_t formats; /* bit per enum ft_format value the command can print */
    bool resolve;     /* show host names for remote addresses */
};

void ft_query_args_init(struct ft_query_args *qa, const char *command, enum ft_query_kind kind,
                        uint32_t allowed, uint32_t sorts);

/* Returns 1 for a consumed option, 0 for an unknown argument, -1 after reporting a bad value. */
int ft_query_args_parse(struct ft_query_args *qa, struct ft_args *a);

/* Once the arguments are parsed: the configured format, unless one was given. */
void ft_query_args_finish(struct ft_query_args *qa, const struct ft_cli *cli);

/* The usage error for an argument no option took, naming a query option this command lacks. */
int ft_query_args_refuse(const struct ft_query_args *qa, const struct ft_args *a);

void ft_query_args_help(FILE *out, uint32_t allowed, uint32_t sorts, uint32_t formats);
void ft_query_args_help_note(FILE *out);

struct ft_session {
    struct ft_client *client;
    pid_t collector; /* a collector started for this session, or 0 */
};

/* With allow_foreground, starts a collector for the session when no agent is reachable. */
int ft_session_open(const struct ft_cli *cli, bool allow_foreground, struct ft_session *s);
void ft_session_close(struct ft_session *s);

enum ft_agent_state : uint8_t {
    FT_AGENT_RUNNING,
    FT_AGENT_STOPPED,
    FT_AGENT_UNREACHABLE, /* serving a socket this user may not open */
};

/* Asks the running agent for its statistics, without reporting a failure to do so. */
enum ft_agent_state ft_agent_ask(const struct ft_cli *cli, struct ft_row_stats *stats);

struct ft_rows {
    unsigned char *data;
    size_t *offsets;
    size_t *sizes;
    size_t count;
    size_t capacity;
    size_t used;
    size_t reserved;
    uint16_t type;
};

void ft_rows_init(struct ft_rows *rows, uint16_t type);
void ft_rows_free(struct ft_rows *rows);
void ft_rows_clear(struct ft_rows *rows);
bool ft_rows_append(struct ft_rows *rows, const void *payload, size_t size);

/* Copies row i into out, zero-filling whatever the agent did not send. */
void ft_rows_get(const struct ft_rows *rows, size_t i, void *out, size_t out_size);

void ft_rows_collect(void *ctx, uint16_t type, const void *payload, size_t size);

enum ft_view_id : uint8_t {
    FT_VIEW_PROCESSES,
    FT_VIEW_CONNECTIONS,
    FT_VIEW_FLOWS,
    FT_VIEW_FILES,
    FT_VIEW_TRANSFERS,
};

void ft_view_render(enum ft_view_id view, const struct ft_rows *rows, const struct ft_output *out,
                    bool rank);

struct ft_view_column {
    const char *title;
    const char *key; /* a field of the view, as in its JSON output; '@' marks table-only ones */
    bool right;
};

/* A table of the first limit rows (all of them when 0) with the given columns. */
void ft_view_table(enum ft_view_id view, const struct ft_rows *rows, size_t limit,
                   const struct ft_view_column *columns, size_t ncolumns, FILE *out);

void ft_view_resolve_hosts(bool on);

/* Starts the lookups for the remote addresses of the rows and gives them a moment. */
void ft_view_prefetch_hosts(enum ft_view_id view, const struct ft_rows *rows);

/* nullptr while no name is known; the first call for an address starts its lookup. */
const char *ft_resolver_name(const struct ft_endpoint *addr);

/* Returns once every lookup started so far has finished, or after the timeout. */
void ft_resolver_wait(uint64_t timeout_ns);

/* The rows, or one of them, as the JSON objects that ft_view_render prints. */
void ft_view_json_array(enum ft_view_id view, const struct ft_rows *rows, FILE *out);
void ft_view_json_object(enum ft_view_id view, const struct ft_rows *rows, size_t index, FILE *out);

void ft_transfer_id_format(const struct ft_row_transfer *row, char *buf, size_t size);

int ft_cmd_watch(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_top(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_files(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_transfers(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_processes(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_connections(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_flows(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_events(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_inspect(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_stats(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_doctor(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_capabilities(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_version(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_agent(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_config(const struct ft_cli *cli, struct ft_args *a);

/* Returns false when the command is unknown. */
bool ft_help_command(FILE *out, const char *command);
void ft_help_overview(FILE *out);

/* What 'filetrace' alone prints: whether the agent is running, and the commands. */
void ft_status_overview(const struct ft_cli *cli, FILE *out);

/* Reports a failed query or lost events and returns the command's exit code. */
int ft_finish_query(int code, const struct ft_error *err, const struct ft_msg_end *end,
                    const struct ft_output *out);

#endif
