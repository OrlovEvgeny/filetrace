#include "cmd/cli.h"

#include "filetrace/clock.h"
#include "filetrace/format.h"

#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

bool ft_args_done(const struct ft_args *a)
{
    return a->pos >= a->argc;
}

const char *ft_args_peek(const struct ft_args *a)
{
    return ft_args_done(a) ? nullptr : a->argv[a->pos];
}

const char *ft_args_take(struct ft_args *a)
{
    return ft_args_done(a) ? nullptr : a->argv[a->pos++];
}

bool ft_args_flag(struct ft_args *a, const char *name)
{
    const char *arg = ft_args_peek(a);
    if (!arg || strcmp(arg, name) != 0)
        return false;
    a->pos++;
    return true;
}

int ft_args_value(struct ft_args *a, const char *name, const char **value)
{
    const char *arg = ft_args_peek(a);
    size_t len = strlen(name);

    if (!arg || strncmp(arg, name, len) != 0)
        return 0;
    if (arg[len] == '=') {
        *value = arg + len + 1;
        a->pos++;
        return 1;
    }
    if (arg[len] != '\0')
        return 0;
    if (a->pos + 1 >= a->argc) {
        fprintf(stderr, "filetrace: option '%s' needs a value\n", name);
        return -1;
    }
    *value = a->argv[a->pos + 1];
    a->pos += 2;
    return 1;
}

int ft_usage_error(const char *command, const char *fmt, ...)
{
    va_list ap;

    fputs("filetrace: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n\nSee 'filetrace help%s%s' for usage.\n", command ? " " : "",
            command ? command : "");
    return FT_EXIT_USAGE;
}

void ft_output_init(struct ft_output *out)
{
    out->format = FT_FMT_TABLE;
    out->stream = stdout;
    out->tty = isatty(STDOUT_FILENO) != 0;
    out->format_given = false;
}

int ft_output_open(struct ft_output *out, const char *path)
{
    if (!path)
        return FT_EXIT_OK;
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "filetrace: cannot write %s: %s\n", path, strerror(errno));
        return FT_EXIT_ERROR;
    }
    out->stream = f;
    out->tty = false;
    return FT_EXIT_OK;
}

void ft_output_close(struct ft_output *out)
{
    if (out->stream && out->stream != stdout)
        fclose(out->stream);
    out->stream = stdout;
}

static const char *const format_names[FT_FMT_COUNT] = {"table", "json", "jsonl", "csv", "quiet"};

int ft_args_format(struct ft_args *a, const char *command, uint32_t accepted,
                   enum ft_format *format)
{
    size_t found = FT_FMT_COUNT;
    const char *given = ft_args_peek(a);
    const char *v = nullptr;
    int r;

    if (ft_args_flag(a, "--json")) {
        found = FT_FMT_JSON;
    } else if (ft_args_flag(a, "--jsonl")) {
        found = FT_FMT_JSONL;
    } else if ((r = ft_args_value(a, "--format", &v)) != 0) {
        if (r < 0)
            return -1;
        for (size_t i = 0; i < FT_FMT_COUNT; i++) {
            if (strcmp(v, format_names[i]) == 0)
                found = i;
        }
    } else {
        return 0;
    }

    if (found != FT_FMT_COUNT && (accepted & FT_FMT_BIT(found))) {
        *format = (enum ft_format)found;
        return 1;
    }

    char expected[64] = "";
    size_t len = 0;
    for (size_t i = 0; i < FT_FMT_COUNT; i++) {
        if (!(accepted & FT_FMT_BIT(i)))
            continue;
        bool last = (accepted >> (i + 1)) == 0;
        int n = snprintf(expected + len, sizeof(expected) - len, "%s%s",
                         len == 0 ? ""
                         : last   ? " or "
                                  : ", ",
                         format_names[i]);
        if (n > 0)
            len += (size_t)n;
    }
    if (v)
        ft_usage_error(command, "invalid value '%s' for --format (expected %s)", v, expected);
    else
        ft_usage_error(command, "'%s' is not available here (expected --format %s)", given,
                       expected);
    return -1;
}

static const struct {
    const char *name;
    enum ft_sort sort;
} sort_names[] = {
    {"outbound", FT_SORT_OUTBOUND},
    {"inbound", FT_SORT_INBOUND},
    {"connections", FT_SORT_CONNECTIONS},
    {"bytes", FT_SORT_BYTES},
    {"time", FT_SORT_TIME},
    {"pid", FT_SORT_PID},
    {"rate", FT_SORT_RATE},
    {"duration", FT_SORT_DURATION},
    {"process", FT_SORT_PROCESS},
    {"file", FT_SORT_FILE},
};

void ft_query_args_init(struct ft_query_args *qa, const char *command, enum ft_query_kind kind,
                        uint32_t allowed, uint32_t sorts)
{
    memset(qa, 0, sizeof(*qa));
    ft_query_init(&qa->query, kind);
    ft_output_init(&qa->out);
    qa->command = command;
    qa->allowed = allowed;
    qa->sorts = sorts;
    qa->formats = FT_FORMATS_ALL;
}

void ft_query_args_finish(struct ft_query_args *qa, const struct ft_cli *cli)
{
    if (!qa->out.format_given)
        qa->out.format = ft_cli_format(cli, qa->formats);
}

static int bad_value(const struct ft_query_args *qa, const char *option, const char *value,
                     const char *expected)
{
    ft_usage_error(qa->command, "invalid value '%s' for %s (expected %s)", value, option, expected);
    return -1;
}

static bool parse_user(const char *text, uint32_t *uid)
{
    if (ft_parse_u32(text, uid))
        return true;
    const struct passwd *pw = getpwnam(text);
    if (!pw)
        return false;
    *uid = (uint32_t)pw->pw_uid;
    return true;
}

/* A cgroup is named by its numeric id or by its directory in the cgroup tree. */
static bool parse_cgroup(const char *text, uint64_t *id)
{
    struct stat st;
    if (ft_parse_u64(text, id))
        return true;
    if (stat(text, &st) != 0)
        return false;
    *id = (uint64_t)st.st_ino;
    return true;
}

static bool parse_network(const char *text, struct ft_endpoint *net, uint8_t *host_bits)
{
    uint8_t bits;
    if (!ft_prefix_parse(text, net, &bits))
        return false;
    *host_bits = (uint8_t)((net->family == 6 ? 128 : 32) - bits);
    return true;
}

static bool parse_when(const char *text, uint64_t *wall_ns)
{
    uint64_t ago;
    if (ft_parse_duration(text, &ago)) {
        uint64_t now = ft_clock_wall_ns();
        *wall_ns = ago >= now ? 1 : now - ago;
        return true;
    }
    return ft_parse_time_rfc3339(text, wall_ns);
}

int ft_query_args_parse(struct ft_query_args *qa, struct ft_args *a)
{
    struct ft_query *q = &qa->query;
    const char *v = nullptr;
    int r;

#define OPTION(group, name) ((qa->allowed & (group)) && (r = ft_args_value(a, name, &v)) != 0)

    if (OPTION(FT_QO_PID, "--pid")) {
        if (r < 0)
            return -1;
        return ft_parse_u32(v, &q->pid) && q->pid ? 1 : bad_value(qa, "--pid", v, "a process ID");
    }
    if (OPTION(FT_QO_PROCESS, "--process") || OPTION(FT_QO_PROCESS, "--name")) {
        if (r < 0)
            return -1;
        if (strlen(v) >= sizeof(q->process))
            return bad_value(qa, "--process", v, "a shorter name");
        ft_strlcpy(q->process, v, sizeof(q->process));
        return 1;
    }
    if (OPTION(FT_QO_FILE, "--file") || OPTION(FT_QO_FILE, "--path")) {
        if (r < 0)
            return -1;
        if (strlen(v) >= sizeof(q->path))
            return bad_value(qa, "--path", v, "a shorter path");
        ft_strlcpy(q->path, v, sizeof(q->path));
        q->flags &= ~(uint32_t)FT_QF_PATH_REGEX;
        return 1;
    }
    if (OPTION(FT_QO_FILE_MATCH, "--path-regex")) {
        if (r < 0)
            return -1;
        if (strlen(v) >= sizeof(q->path))
            return bad_value(qa, "--path-regex", v, "a shorter expression");
        ft_strlcpy(q->path, v, sizeof(q->path));
        q->flags |= FT_QF_PATH_REGEX;
        return 1;
    }
    if (OPTION(FT_QO_FILE_MATCH, "--min-size")) {
        if (r < 0)
            return -1;
        return ft_parse_size(v, &q->min_size)
                   ? 1
                   : bad_value(qa, "--min-size", v, "a size such as 100MB");
    }
    if (OPTION(FT_QO_REMOTE, "--remote")) {
        if (r < 0)
            return -1;
        return parse_network(v, &q->remote, &q->remote_host_bits)
                   ? 1
                   : bad_value(qa, "--remote", v, "an IP address or CIDR network");
    }
    if (OPTION(FT_QO_LOCAL, "--local")) {
        if (r < 0)
            return -1;
        return parse_network(v, &q->local, &q->local_host_bits)
                   ? 1
                   : bad_value(qa, "--local", v, "an IP address or CIDR network");
    }
    if (OPTION(FT_QO_PROTOCOL, "--protocol")) {
        if (r < 0)
            return -1;
        if (strcmp(v, "all") == 0) {
            q->proto = 0;
            return 1;
        }
        return ft_proto_parse(v, &q->proto) ? 1 : bad_value(qa, "--protocol", v, "tcp, udp or all");
    }
    if (OPTION(FT_QO_TIME, "--since")) {
        if (r < 0)
            return -1;
        return parse_when(v, &q->since_wall_ns)
                   ? 1
                   : bad_value(qa, "--since", v, "a duration such as 10m or an RFC 3339 time");
    }
    if (OPTION(FT_QO_TIME, "--until")) {
        if (r < 0)
            return -1;
        return parse_when(v, &q->until_wall_ns)
                   ? 1
                   : bad_value(qa, "--until", v, "a duration such as 10m or an RFC 3339 time");
    }
    if (OPTION(FT_QO_CONFIDENCE, "--confidence")) {
        enum ft_confidence c;
        if (r < 0)
            return -1;
        if (strcmp(v, "all") == 0) {
            q->confidence = FT_CONF_ANY;
            return 1;
        }
        if (!ft_confidence_parse(v, &c))
            return bad_value(qa, "--confidence", v, "exact, strong, inferred, unknown or all");
        q->confidence = c;
        if (c == FT_CONF_UNKNOWN)
            q->flags |= FT_QF_INCLUDE_UNKNOWN;
        return 1;
    }
    if (OPTION(FT_QO_MIN_BYTES, "--min-bytes")) {
        if (r < 0)
            return -1;
        return ft_parse_size(v, &q->min_bytes)
                   ? 1
                   : bad_value(qa, "--min-bytes", v, "a size such as 100MB");
    }
    if (OPTION(FT_QO_PORT, "--port")) {
        uint32_t port;
        if (r < 0)
            return -1;
        if (!ft_parse_u32(v, &port) || port == 0 || port > 65535)
            return bad_value(qa, "--port", v, "a port number");
        q->port = (uint16_t)port;
        return 1;
    }
    if (OPTION(FT_QO_FAMILY, "--family")) {
        if (r < 0)
            return -1;
        if (strcmp(v, "ipv4") == 0)
            q->family = 4;
        else if (strcmp(v, "ipv6") == 0)
            q->family = 6;
        else
            return bad_value(qa, "--family", v, "ipv4 or ipv6");
        return 1;
    }
    if (OPTION(FT_QO_STATE, "--state")) {
        enum ft_sock_state s;
        if (r < 0)
            return -1;
        if (!ft_sock_state_parse(v, &s))
            return bad_value(qa, "--state", v,
                             "connecting, established, listening, closed, active or idle");
        q->state = s;
        return 1;
    }
    if (OPTION(FT_QO_METHOD, "--method")) {
        enum ft_method m;
        if (r < 0)
            return -1;
        if (!ft_method_parse(v, &m))
            return bad_value(qa, "--method", v, "sendfile, read-write, splice, mmap or io_uring");
        q->method = m;
        return 1;
    }
    if (OPTION(FT_QO_USER, "--user")) {
        if (r < 0)
            return -1;
        if (!parse_user(v, &q->uid))
            return bad_value(qa, "--user", v, "a user name or numeric ID");
        q->flags |= FT_QF_HAS_UID;
        return 1;
    }
    if (OPTION(FT_QO_SCOPE, "--cgroup")) {
        if (r < 0)
            return -1;
        return parse_cgroup(v, &q->cgroup_id)
                   ? 1
                   : bad_value(qa, "--cgroup", v, "a cgroup ID or cgroup directory");
    }
    if (OPTION(FT_QO_SCOPE, "--namespace")) {
        if (r < 0)
            return -1;
        return ft_parse_u32(v, &q->ns_inum) && q->ns_inum
                   ? 1
                   : bad_value(qa, "--namespace", v, "a namespace inode number");
    }
    if (OPTION(FT_QO_SORT, "--sort")) {
        if (r < 0)
            return -1;
        for (size_t i = 0; i < FT_ARRAY_LEN(sort_names); i++) {
            if (strcmp(v, sort_names[i].name) == 0 && (qa->sorts & (1u << sort_names[i].sort))) {
                q->sort = sort_names[i].sort;
                return 1;
            }
        }
        return bad_value(qa, "--sort", v, "one of the keys listed in the command's help");
    }
    if (OPTION(FT_QO_LIMIT, "--limit")) {
        if (r < 0)
            return -1;
        return ft_parse_u32(v, &q->limit) && q->limit
                   ? 1
                   : bad_value(qa, "--limit", v, "a positive number");
    }
    if (OPTION(FT_QO_OUTPUT, "--output")) {
        if (r < 0)
            return -1;
        qa->output_path = v;
        return 1;
    }
#undef OPTION

    if (qa->allowed & FT_QO_OUTPUT) {
        r = ft_args_format(a, qa->command, qa->formats, &qa->out.format);
        if (r != 0) {
            qa->out.format_given = r > 0;
            return r;
        }
    }

    if ((qa->allowed & FT_QO_RESOLVE) && ft_args_flag(a, "--resolve-hostnames")) {
        qa->resolve = true;
        return 1;
    }
    if (qa->allowed & FT_QO_ACTIVITY) {
        if (ft_args_flag(a, "--active")) {
            q->flags |= FT_QF_ACTIVE;
            return 1;
        }
        if (ft_args_flag(a, "--completed")) {
            q->flags |= FT_QF_COMPLETED;
            return 1;
        }
    }
    return 0;
}

void ft_query_args_help(FILE *out, uint32_t allowed, uint32_t sorts, uint32_t formats)
{
    static const struct {
        uint32_t group;
        const char *text;
    } lines[] = {
        {FT_QO_PID, "  --pid <pid>             Only this process\n"},
        {FT_QO_PROCESS,
         "  --process <name>        Only processes with this name ('*' wildcards)\n"},
        {FT_QO_USER, "  --user <user>           Only processes of this user\n"},
        {FT_QO_SCOPE, "  --cgroup <id|dir>       Only processes in this cgroup\n"
                      "  --namespace <inode>     Only processes in this network, PID or mount\n"
                      "                          namespace (the number 'ls -Li /proc/<pid>/ns'\n"
                      "                          shows)\n"},
        {FT_QO_FILE, "  --path <path>           Only this file ('*' wildcards; alias: --file)\n"},
        {FT_QO_FILE_MATCH, "  --path-regex <regex>    Only files whose path matches this POSIX\n"
                           "                          extended regular expression\n"
                           "  --min-size <size>       Only files at least this large\n"},
        {FT_QO_REMOTE, "  --remote <ip|cidr>      Only this remote address or network\n"},
        {FT_QO_LOCAL, "  --local <ip|cidr>       Only this local address or network\n"},
        {FT_QO_PORT, "  --port <port>           Only this local or remote port\n"},
        {FT_QO_PROTOCOL, "  --protocol tcp|udp|all  Only this protocol (default: all)\n"},
        {FT_QO_FAMILY, "  --family ipv4|ipv6      Only this address family\n"},
        {FT_QO_STATE, "  --state <state>         connecting, established, listening, closed,\n"
                      "                          active or idle\n"},
        {FT_QO_METHOD,
         "  --method <method>       sendfile or read-write; splice, mmap and io_uring\n"
         "                          are accepted but not observed by this build\n"},
        {FT_QO_CONFIDENCE, "  --confidence <level>    exact, strong, inferred, unknown or all\n"},
        {FT_QO_MIN_BYTES, "  --min-bytes <size>      At least this many bytes (1KB, 100MB, 1GB)\n"},
        {FT_QO_ACTIVITY, "  --active                Only records still in progress\n"
                         "  --completed             Only records that are no longer in progress\n"},
        {FT_QO_TIME, "  --since <when>          Active at or after this time (10m, 1h, 7d or\n"
                     "                          an RFC 3339 timestamp)\n"
                     "  --until <when>          Started at or before this time\n"},
    };

    for (size_t i = 0; i < FT_ARRAY_LEN(lines); i++) {
        if (allowed & lines[i].group)
            fputs(lines[i].text, out);
    }
    if (allowed & FT_QO_SORT) {
        size_t column = 0;
        fputs("  --sort <key>            ", out);
        for (size_t i = 0; i < FT_ARRAY_LEN(sort_names); i++) {
            if (!(sorts & (1u << sort_names[i].sort)))
                continue;
            size_t width = strlen(sort_names[i].name) + 2;
            if (column && column + width > 50) {
                fputs(",\n                          ", out);
                column = 0;
            } else if (column) {
                fputs(", ", out);
            }
            fputs(sort_names[i].name, out);
            column += width;
        }
        fputc('\n', out);
    }
    if (allowed & FT_QO_RESOLVE)
        fputs("  --resolve-hostnames     Show remote addresses by host name where a reverse\n"
              "                          DNS lookup finds one; the lookups tell the DNS\n"
              "                          resolver which addresses are being looked at\n",
              out);
    if (allowed & FT_QO_LIMIT)
        fputs("  --limit <n>             Show at most n rows\n", out);
    if (allowed & FT_QO_OUTPUT) {
        fputs("  --format <format>       table (default)", out);
        for (size_t i = FT_FMT_TABLE + 1; i < FT_FMT_COUNT; i++) {
            if (formats & FT_FMT_BIT(i))
                fprintf(out, "%s%s", (formats >> (i + 1)) ? ", " : " or ", format_names[i]);
        }
        fputs("\n"
              "  --json, --jsonl         Short for --format json and --format jsonl\n"
              "  --output <file>         Write to a file instead of standard output\n",
              out);
    }
    if (allowed & FT_QO_TIME)
        fputs("\nByte counts cover a record's whole observed lifetime; --since and --until\n"
              "select which records are listed.\n",
              out);
}

void ft_rows_init(struct ft_rows *rows, uint16_t type)
{
    memset(rows, 0, sizeof(*rows));
    rows->type = type;
}

void ft_rows_free(struct ft_rows *rows)
{
    free(rows->data);
    free(rows->offsets);
    free(rows->sizes);
    memset(rows, 0, sizeof(*rows));
}

void ft_rows_clear(struct ft_rows *rows)
{
    rows->count = 0;
    rows->used = 0;
}

bool ft_rows_append(struct ft_rows *rows, const void *payload, size_t size)
{
    if (rows->count == rows->capacity) {
        size_t cap = rows->capacity ? rows->capacity * 2 : 64;
        size_t *offsets = realloc(rows->offsets, cap * sizeof(size_t));
        if (!offsets)
            return false;
        rows->offsets = offsets;
        size_t *sizes = realloc(rows->sizes, cap * sizeof(size_t));
        if (!sizes)
            return false;
        rows->sizes = sizes;
        rows->capacity = cap;
    }
    if (rows->used + size > rows->reserved) {
        size_t reserved = rows->reserved ? rows->reserved * 2 : 16384;
        while (reserved < rows->used + size)
            reserved *= 2;
        unsigned char *data = realloc(rows->data, reserved);
        if (!data)
            return false;
        rows->data = data;
        rows->reserved = reserved;
    }
    memcpy(rows->data + rows->used, payload, size);
    rows->offsets[rows->count] = rows->used;
    rows->sizes[rows->count] = size;
    rows->used += size;
    rows->count++;
    return true;
}

void ft_rows_get(const struct ft_rows *rows, size_t i, void *out, size_t out_size)
{
    size_t size = rows->sizes[i] < out_size ? rows->sizes[i] : out_size;
    memcpy(out, rows->data + rows->offsets[i], size);
    memset((unsigned char *)out + size, 0, out_size - size);
}

void ft_rows_collect(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct ft_rows *rows = ctx;
    if (type == rows->type)
        ft_rows_append(rows, payload, size);
}

int ft_finish_query(int code, const struct ft_error *err, const struct ft_msg_end *end,
                    const struct ft_output *out)
{
    if (code != FT_EXIT_OK) {
        fprintf(stderr, "%s\n", err->msg);
        return code;
    }
    if (end->lost_events == 0)
        return FT_EXIT_OK;

    char first[32];
    char last[32];
    ft_format_clock_local(end->loss_first_wall_ns, first, sizeof(first));
    ft_format_clock_local(end->loss_last_wall_ns, last, sizeof(last));
    fprintf(stderr,
            "%sWARNING: %llu events lost.\n\n"
            "Affected monitoring window:\n"
            "%s - %s\n\n"
            "Attribution reliability:\n"
            "DEGRADED\n",
            out->format == FT_FMT_TABLE ? "\n" : "", (unsigned long long)end->lost_events, first,
            last);
    return FT_EXIT_PARTIAL;
}
