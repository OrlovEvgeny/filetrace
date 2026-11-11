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

struct ft_cli {
    const char *socket_path;
};

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
    FT_QO_OUTPUT = 1u << 18, /* --format, --output */
};

#define FT_SORT_BIT(sort) (1u << (sort))

constexpr uint32_t FT_OPTS_PROCESSES = FT_QO_PID | FT_QO_PROCESS | FT_QO_USER | FT_QO_SCOPE |
                                       FT_QO_TIME | FT_QO_SORT | FT_QO_LIMIT | FT_QO_OUTPUT;
constexpr uint32_t FT_SORTS_PROCESSES =
    FT_SORT_BIT(FT_SORT_OUTBOUND) | FT_SORT_BIT(FT_SORT_INBOUND) | FT_SORT_BIT(FT_SORT_RATE) |
    FT_SORT_BIT(FT_SORT_CONNECTIONS) | FT_SORT_BIT(FT_SORT_TIME) | FT_SORT_BIT(FT_SORT_PID) |
    FT_SORT_BIT(FT_SORT_PROCESS);

constexpr uint32_t FT_OPTS_NETWORK = FT_QO_PID | FT_QO_PROCESS | FT_QO_REMOTE | FT_QO_LOCAL |
                                     FT_QO_PORT | FT_QO_PROTOCOL | FT_QO_FAMILY | FT_QO_TIME |
                                     FT_QO_SORT | FT_QO_LIMIT | FT_QO_OUTPUT;
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
    FT_QO_PID | FT_QO_PROCESS | FT_QO_FILE | FT_QO_REMOTE | FT_QO_LOCAL | FT_QO_PORT |
    FT_QO_PROTOCOL | FT_QO_CONFIDENCE | FT_QO_METHOD | FT_QO_MIN_BYTES | FT_QO_ACTIVITY |
    FT_QO_TIME | FT_QO_SORT | FT_QO_LIMIT | FT_QO_OUTPUT;
constexpr uint32_t FT_SORTS_TRANSFERS = FT_SORT_BIT(FT_SORT_TIME) | FT_SORT_BIT(FT_SORT_BYTES) |
                                        FT_SORT_BIT(FT_SORT_RATE) | FT_SORT_BIT(FT_SORT_DURATION) |
                                        FT_SORT_BIT(FT_SORT_PID) | FT_SORT_BIT(FT_SORT_PROCESS) |
                                        FT_SORT_BIT(FT_SORT_FILE);

struct ft_query_args {
    struct ft_query query;
    struct ft_output out;
    const char *output_path;
    const char *command;
    uint32_t allowed;
    uint32_t sorts; /* bit per enum ft_sort value the command accepts */
};

void ft_query_args_init(struct ft_query_args *qa, const char *command, enum ft_query_kind kind,
                        uint32_t allowed, uint32_t sorts);

/* Returns 1 for a consumed option, 0 for an unknown argument, -1 after reporting a bad value. */
int ft_query_args_parse(struct ft_query_args *qa, struct ft_args *a);

void ft_query_args_help(FILE *out, uint32_t allowed, uint32_t sorts);

struct ft_session {
    struct ft_client *client;
    pid_t collector; /* a collector started for this session, or 0 */
};

/* With allow_foreground, starts a collector for the session when no daemon is reachable. */
int ft_session_open(const struct ft_cli *cli, bool allow_foreground, struct ft_session *s);
void ft_session_close(struct ft_session *s);

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

/* Copies row i into out, zero-filling whatever the daemon did not send. */
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

void ft_transfer_id_format(const struct ft_row_transfer *row, char *buf, size_t size);

int ft_cmd_watch(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_top(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_files(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_transfers(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_processes(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_connections(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_flows(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_stats(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_doctor(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_capabilities(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_version(const struct ft_cli *cli, struct ft_args *a);
int ft_cmd_daemon(const struct ft_cli *cli, struct ft_args *a);

/* Returns false when the command is unknown. */
bool ft_help_command(FILE *out, const char *command);
void ft_help_overview(FILE *out);

/* Reports a failed query or lost events and returns the command's exit code. */
int ft_finish_query(int code, const struct ft_error *err, const struct ft_msg_end *end,
                    const struct ft_output *out);

#endif
