#include "ui/ui.h"

#include "filetrace/format.h"
#include "filetrace/names.h"
#include "filetrace/sysinfo.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Style marks inside composed text; none of them takes a column. */
constexpr char HEADING = '\x01'; /* first byte of a line drawn emphasised */
constexpr char BOLD = '\x02';
constexpr char PLAIN = '\x03';
constexpr char GREEN = '\x04';
constexpr char YELLOW = '\x05';
constexpr char RED = '\x06';
constexpr char DIM = '\x07';

static bool is_style_mark(char c)
{
    return c >= HEADING && c <= DIM;
}

static const char *style_sequence(char mark)
{
    switch (mark) {
    case BOLD:
        return FT_STYLE_BOLD;
    case GREEN:
        return "\033[32m";
    case YELLOW:
        return "\033[33m";
    case RED:
        return "\033[31m";
    case DIM:
        return FT_STYLE_DIM;
    default:
        return FT_STYLE_RESET;
    }
}

static volatile sig_atomic_t quit_requested;
static volatile sig_atomic_t resized;

static void on_quit(int signo)
{
    (void)signo;
    quit_requested = 1;
}

static void on_resize(int signo)
{
    (void)signo;
    resized = 1;
}

enum view : uint8_t {
    VIEW_FILES,
    VIEW_PROCESSES,
    VIEW_NETWORK,
};

struct snapshot {
    struct ft_row_stats stats;
    struct ft_rows transfers;
    struct ft_rows processes;
    struct ft_rows connections;
};

struct frame {
    char **lines;
    size_t count;
};

static void stats_collect(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct ft_row_stats *row = ctx;
    if (type == FT_MSG_ROW_STATS)
        memcpy(row, payload, size < sizeof(*row) ? size : sizeof(*row));
}

static void scope_from(struct ft_query *q, const struct ft_query *filter)
{
    q->pid = filter->pid;
    q->uid = filter->uid;
    q->flags |= filter->flags & FT_QF_HAS_UID;
    q->cgroup_id = filter->cgroup_id;
    q->ns_inum = filter->ns_inum;
    ft_strlcpy(q->process, filter->process, sizeof(q->process));
}

void ft_watch_connections_query(const struct ft_watch_options *opt, uint32_t limit,
                                struct ft_query *q)
{
    const struct ft_query *filter = &opt->filter;

    ft_query_init(q, FT_Q_CONNECTIONS);
    scope_from(q, filter);
    q->flags |= FT_QF_ACTIVE;
    q->proto = filter->proto;
    q->remote = filter->remote;
    q->remote_host_bits = filter->remote_host_bits;
    ft_strlcpy(q->remote_name, filter->remote_name, sizeof(q->remote_name));
    q->sort = opt->direction == FT_WATCH_OUTBOUND  ? FT_SORT_OUTBOUND
              : opt->direction == FT_WATCH_INBOUND ? FT_SORT_INBOUND
                                                   : FT_SORT_RATE;
    q->limit = limit;
}

static int take_snapshot(struct ft_session *s, const struct ft_watch_options *opt, enum view view,
                         bool every_view, uint32_t limit, struct snapshot *snap,
                         struct ft_error *err)
{
    const struct ft_query *filter = &opt->filter;
    struct ft_query *q = malloc(sizeof(*q));
    int code;

    if (!q)
        return ft_error_set(err, FT_EXIT_ERROR, "Out of memory");

    ft_query_init(q, FT_Q_STATS);
    memset(&snap->stats, 0, sizeof(snap->stats));
    code = ft_client_query(s->client, q, stats_collect, &snap->stats, nullptr, err);

    if (code == FT_EXIT_OK && (every_view || view == VIEW_FILES)) {
        *q = *filter;
        q->kind = FT_Q_TRANSFERS;
        q->flags |= FT_QF_ACTIVE;
        q->sort = filter->sort ? filter->sort : FT_SORT_RATE;
        q->limit = limit;
        ft_rows_clear(&snap->transfers);
        code = ft_client_query(s->client, q, ft_rows_collect, &snap->transfers, nullptr, err);
    }
    if (code == FT_EXIT_OK && (every_view || view == VIEW_PROCESSES)) {
        ft_query_init(q, FT_Q_PROCESSES);
        scope_from(q, filter);
        q->sort = opt->direction == FT_WATCH_INBOUND ? FT_SORT_INBOUND : FT_SORT_OUTBOUND;
        q->min_bytes = filter->min_bytes;
        q->limit = limit;
        ft_rows_clear(&snap->processes);
        code = ft_client_query(s->client, q, ft_rows_collect, &snap->processes, nullptr, err);
    }
    if (code == FT_EXIT_OK && view == VIEW_NETWORK && !every_view) {
        ft_watch_connections_query(opt, limit, q);
        ft_rows_clear(&snap->connections);
        code = ft_client_query(s->client, q, ft_rows_collect, &snap->connections, nullptr, err);
    }
    free(q);
    return code;
}

constexpr size_t PROCESS_LEAST = 10;
constexpr size_t PATH_LEAST = 16;
constexpr size_t ADDRESS_LEAST = sizeof("255.255.255.255") - 1;
constexpr size_t ADDRESS_PORT_LEAST = sizeof("255.255.255.255:65535") - 1;
constexpr size_t RATE_WIDEST = sizeof("100.0 MB/s") - 1;

/* The files table at its narrowest, the widest of the views at theirs: four columns, three gaps. */
constexpr size_t LEAST_COLUMNS = PROCESS_LEAST + PATH_LEAST + ADDRESS_LEAST + RATE_WIDEST + 3 * 2;

/* Snapshots appended to a pipe or file have no width to fit; their paths keep this many bytes. */
constexpr size_t PLAIN_PATH_WIDTH = 128;

struct transfer_table {
    const struct ft_rows *rows;
    struct ft_row_transfer *row;
    size_t loaded;
    size_t path_width;
    bool resolve;
    bool names;
};

/* A name appears on the refresh after its lookup finishes; until then the address shows. */
static const char *host_name(bool resolve, const struct ft_endpoint *ep)
{
    return resolve ? ft_resolver_name(ep) : nullptr;
}

static const char *transfer_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    struct transfer_table *t = ctx;
    const struct ft_row_transfer *row = t->row;

    if (t->loaded != r) {
        ft_rows_get(t->rows, r, t->row, sizeof(*t->row));
        t->loaded = r;
    }
    switch (c) {
    case 0:
        snprintf(buf, size, "%s %" PRIu32, row->comm[0] ? row->comm : "-", row->pid);
        break;
    case 1: {
        const char *deleted = (row->flags & FT_XFER_FILE_DELETED) ? " (deleted)" : "";
        if (row->flags & FT_XFER_PATH_KNOWN)
            snprintf(buf, size, "%s%s", row->path, deleted);
        else if (row->flags & FT_XFER_FILE_KNOWN)
            snprintf(buf, size, "(device %" PRIu64 " inode %" PRIu64 ")%s", row->dev, row->ino,
                     deleted);
        else
            snprintf(buf, size, "unknown");
        /* Keep the end of a long path: the file name matters most. */
        size_t len = strlen(buf);
        if (len > t->path_width && t->path_width > 3) {
            const char *tail = buf + len - (t->path_width - 3);
            while (((unsigned char)*tail & 0xc0) == 0x80)
                tail++;
            memmove(buf + 3, tail, strlen(tail) + 1);
            memcpy(buf, "...", 3);
        }
        break;
    }
    case 2: {
        struct ft_remote_names names;
        ft_row_transfer_names(row, &names);
        ft_remote_name_cell(&names, 0, buf, size);
        if (t->names && buf[0])
            break;
        const char *host = host_name(t->resolve, &row->remote);
        if (host)
            snprintf(buf, size, "%s", host);
        else
            ft_addr_format(&row->remote, buf, size);
        break;
    }
    case 3:
        snprintf(buf, size, "%s",
                 row->method == FT_METHOD_NONE ? "-" : ft_method_name((enum ft_method)row->method));
        break;
    case 4:
        ft_format_rate(row->rate, buf, size);
        break;
    default: {
        const char *name = ft_confidence_name((enum ft_confidence)row->confidence);
        size_t i = 0;
        for (; name[i] && i + 2 < size; i++)
            buf[i] = (char)(name[i] - ('a' <= name[i] && name[i] <= 'z' ? 32 : 0));
        if (row->flags & FT_XFER_INCOMPLETE)
            buf[i++] = '*';
        buf[i] = '\0';
        break;
    }
    }
    return buf;
}

static void transfers_table(FILE *o, const struct ft_rows *rows, size_t width, bool resolve,
                            bool names)
{
    static const struct ft_column_spec columns[] = {
        {"PROCESS", false}, {"FILE", false}, {"DESTINATION", false},
        {"METHOD", false},  {"RATE", true},  {"CONFIDENCE", false},
    };
    static const struct ft_column_fit fit[] = {
        {.cut = 3, .least = PROCESS_LEAST},
        {.cut = 1, .least = PATH_LEAST, .keep_end = true},
        {.cut = 2, .least = ADDRESS_LEAST},
        {.leave = 2},
        {0},
        {.leave = 1},
    };
    struct ft_row_transfer *row = malloc(sizeof(*row));
    struct transfer_table table = {
        .rows = rows,
        .row = row,
        .loaded = SIZE_MAX,
        .path_width = width == SIZE_MAX ? PLAIN_PATH_WIDTH : SIZE_MAX,
        .resolve = resolve,
        .names = names,
    };

    if (row && rows->count)
        ft_table_print_fit(o, columns, fit, FT_ARRAY_LEN(columns), rows->count, transfer_cell,
                           &table, false, width);
    else
        fputs("No file transfers in progress.\n", o);
    free(row);
}

struct process_table {
    const struct ft_rows *rows;
    enum ft_watch_direction direction;
};

static const char *process_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    const struct process_table *t = ctx;
    struct ft_row_process row;
    bool inbound = t->direction == FT_WATCH_INBOUND;

    ft_rows_get(t->rows, r, &row, sizeof(row));
    switch (c) {
    case 0:
        snprintf(buf, size, "%" PRIu32, row.pid);
        break;
    case 1:
        snprintf(buf, size, "%s", row.comm[0] ? row.comm : "-");
        break;
    case 2:
        ft_format_rate(inbound ? row.rx_rate : row.tx_rate, buf, size);
        break;
    case 3:
        snprintf(buf, size, "%" PRIu32, row.files);
        break;
    case 4:
        snprintf(buf, size, "%" PRIu32, row.connections);
        break;
    case 5:
        if (t->direction == FT_WATCH_BOTH)
            ft_format_rate(row.rx_rate, buf, size);
        else
            ft_format_bytes(inbound ? row.rx_bytes : row.tx_bytes, buf, size);
        break;
    default:
        ft_format_bytes(row.tx_bytes + row.rx_bytes, buf, size);
        break;
    }
    return buf;
}

static void processes_table(FILE *o, const struct ft_rows *rows, enum ft_watch_direction direction,
                            size_t width)
{
    static const struct ft_column_spec outbound[] = {
        {"PID", false},  {"PROCESS", false},    {"OUTBOUND", true},
        {"FILES", true}, {"CONNECTIONS", true}, {"SENT", true},
    };
    static const struct ft_column_spec inbound[] = {
        {"PID", false},  {"PROCESS", false},    {"INBOUND", true},
        {"FILES", true}, {"CONNECTIONS", true}, {"RECEIVED", true},
    };
    static const struct ft_column_spec both[] = {
        {"PID", false},        {"PROCESS", false}, {"OUTBOUND", true}, {"FILES", true},
        {"CONNECTIONS", true}, {"INBOUND", true},  {"TOTAL", true},
    };
    static const struct ft_column_fit one_way_fit[] = {
        {0}, {.cut = 1, .least = PROCESS_LEAST}, {0}, {.leave = 3}, {.leave = 2}, {.leave = 1},
    };
    static const struct ft_column_fit both_fit[] = {
        {0}, {.cut = 1, .least = PROCESS_LEAST}, {0}, {.leave = 3}, {.leave = 2}, {0}, {.leave = 1},
    };
    struct process_table table = {rows, direction};

    if (rows->count == 0)
        fputs("No network activity observed yet.\n", o);
    else if (direction == FT_WATCH_BOTH)
        ft_table_print_fit(o, both, both_fit, FT_ARRAY_LEN(both), rows->count, process_cell, &table,
                           false, width);
    else
        ft_table_print_fit(o, direction == FT_WATCH_INBOUND ? inbound : outbound, one_way_fit,
                           FT_ARRAY_LEN(outbound), rows->count, process_cell, &table, false, width);
}

struct connection_table {
    const struct ft_rows *rows;
    bool names;
};

static const char *connection_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    const struct connection_table *t = ctx;
    struct ft_row_connection row;
    char scratch[8];

    ft_rows_get(t->rows, r, &row, sizeof(row));
    switch (c) {
    case 0:
        if (row.pid)
            snprintf(buf, size, "%" PRIu32, row.pid);
        else
            snprintf(buf, size, "-");
        break;
    case 1:
        snprintf(buf, size, "%s", row.comm[0] ? row.comm : "-");
        break;
    case 2: {
        size_t i = 0;
        for (const char *p = ft_proto_name(row.proto, scratch); *p && i + 1 < size; p++)
            buf[i++] = (char)(*p - ('a' <= *p && *p <= 'z' ? 32 : 0));
        buf[i] = '\0';
        break;
    }
    case 3:
    case 4: {
        const struct ft_endpoint *ep = c == 3 ? &row.local : &row.remote;
        struct ft_remote_names names;
        ft_row_connection_names(&row, &names);
        ft_remote_name_cell(&names, row.remote.port, buf, size);
        if (c == 4 && t->names && buf[0])
            break;
        if (ep->family == 0 && ep->port == 0)
            snprintf(buf, size, "*");
        else
            ft_endpoint_format(ep, buf, size);
        break;
    }
    case 5:
        ft_format_rate(row.tx_rate, buf, size);
        break;
    default:
        ft_format_rate(row.rx_rate, buf, size);
        break;
    }
    return buf;
}

static void connections_table(FILE *o, const struct ft_rows *rows, size_t width, bool names)
{
    static const struct ft_column_spec columns[] = {
        {"PID", false},    {"PROCESS", false}, {"PROTOCOL", false}, {"LOCAL", false},
        {"REMOTE", false}, {"OUTBOUND", true}, {"INBOUND", true},
    };
    static const struct ft_column_fit fit[] = {
        {0},          {.cut = 2, .least = PROCESS_LEAST},      {.leave = 1},
        {.leave = 3}, {.cut = 1, .least = ADDRESS_PORT_LEAST}, {0},
        {.leave = 2},
    };

    struct connection_table table = {rows, names};

    if (rows->count)
        ft_table_print_fit(o, columns, fit, FT_ARRAY_LEN(columns), rows->count, connection_cell,
                           &table, false, width);
    else
        fputs("No open connections.\n", o);
}

static void counters(FILE *o, const struct ft_row_stats *st, enum ft_watch_direction direction)
{
    const char *labels[4] = {"Transfers", "Processes"};
    char values[4][32];
    size_t n = 2;

    snprintf(values[0], sizeof(values[0]), "%u", st->active_transfers);
    snprintf(values[1], sizeof(values[1]), "%u", st->active_processes);
    if (direction != FT_WATCH_INBOUND) {
        ft_format_rate(st->tx_rate, values[n], sizeof(values[n]));
        labels[n++] = "Outbound";
    }
    if (direction != FT_WATCH_OUTBOUND) {
        ft_format_rate(st->rx_rate, values[n], sizeof(values[n]));
        labels[n++] = "Inbound";
    }

    fprintf(o, "\n%c", BOLD);
    for (size_t i = 0; i < n; i++)
        fprintf(o, i + 1 < n ? "%-14s" : "%s", values[i]);
    fprintf(o, "%c\n%c", PLAIN, DIM);
    for (size_t i = 0; i < n; i++)
        fprintf(o, i + 1 < n ? "%-14s" : "%s", labels[i]);
    fprintf(o, "%c\n", PLAIN);
}

static void confidence_line(FILE *o, const struct ft_row_stats *st)
{
    char lost[32];

    ft_format_count(st->events_dropped, lost, sizeof(lost));
    fprintf(o, "\n%c●%c EXACT: %u   %c●%c INFERRED: %u   ", GREEN, PLAIN,
            st->active_by_confidence[FT_CONF_EXACT], YELLOW, PLAIN,
            st->active_by_confidence[FT_CONF_INFERRED]);
    if (st->active_by_confidence[FT_CONF_STRONG])
        fprintf(o, "STRONG: %u   ", st->active_by_confidence[FT_CONF_STRONG]);
    if (st->events_dropped)
        fprintf(o, "%cLOST: %s%c\n", RED, lost, PLAIN);
    else
        fprintf(o, "LOST: %s\n", lost);
}

struct key_hint {
    const char *label;
    const char *name;
    bool current;
};

static size_t hint_width(const struct key_hint *k)
{
    return strlen(k->label) + strlen(k->name) + 3;
}

static void key(FILE *o, const struct key_hint *k)
{
    if (k->current)
        fprintf(o, "%c[%s] %s%c", BOLD, k->label, k->name, PLAIN);
    else
        fprintf(o, "[%s] %s", k->label, k->name);
}

/* Hints that do not fit are left out, the least needed first. */
static void key_row(FILE *o, enum view view, bool paused, bool names, size_t width)
{
    const struct key_hint hints[] = {
        {"F", "Files", view == VIEW_FILES},
        {"P", "Processes", view == VIEW_PROCESSES},
        {"N", "Network", view == VIEW_NETWORK},
        {"A", "Addresses", !names},
        {"Space", "Pause", paused},
        {"?", "Help", false},
        {"Q", "Quit", false},
    };
    static const size_t leave[] = {3, 4, 2, 1, 0};
    bool shown[FT_ARRAY_LEN(hints)];
    size_t total = 0;

    for (size_t i = 0; i < FT_ARRAY_LEN(hints); i++) {
        shown[i] = true;
        total += hint_width(&hints[i]) + (i ? 2 : 0);
    }
    for (size_t i = 0; i < FT_ARRAY_LEN(leave) && total > width; i++) {
        shown[leave[i]] = false;
        total -= hint_width(&hints[leave[i]]) + 2;
    }
    const char *gap = "";
    for (size_t i = 0; i < FT_ARRAY_LEN(hints); i++) {
        if (shown[i]) {
            fputs(gap, o);
            key(o, &hints[i]);
            gap = "  ";
        }
    }
    fputc('\n', o);
}

/* Whole on the least terminal: no line wider than LEAST_COLUMNS, 23 lines for 24 rows. */
static void help_screen(FILE *o)
{
    fprintf(o,
            "%cKEYS\n"
            "f      File transfers in progress\n"
            "p      Processes, by the rate they send at\n"
            "n      Network: open connections\n"
            "a      Show remote ends by name or by address\n"
            "space  Pause or resume refreshing\n"
            "?      Show or hide this help\n"
            "q      Quit\n"
            "\n%cCOLUMNS\n"
            "RATE, OUTBOUND, INBOUND\n"
            "            Bytes per second over the last one to two\n"
            "            seconds, counted where the local socket\n"
            "            accepts or delivers them.\n"
            "METHOD      sendfile: the kernel moved the file to the\n"
            "            socket itself.\n"
            "            read-write: a thread read the file then sent.\n"
            "CONFIDENCE  EXACT for sendfile. INFERRED for read-write:\n"
            "            the payload cannot be proven to come only\n"
            "            from that file.\n"
            "            A '*' marks a transfer with lost events.\n"
            "LOST        Events the collector could not record since\n"
            "            it started.\n",
            HEADING, HEADING);
}

static void compose(FILE *o, const struct snapshot *snap, const struct ft_watch_options *opt,
                    const struct ft_host_info *host, enum view view, bool every_view, size_t width,
                    bool paused, bool help, bool names)
{
    const struct ft_row_stats *st = &snap->stats;
    unsigned major = 0;
    unsigned minor = 0;

    if (width < LEAST_COLUMNS) {
        fprintf(o, "Terminal too narrow: needs %zu columns\n", LEAST_COLUMNS);
        return;
    }
    if (help) {
        help_screen(o);
        return;
    }
    sscanf(host->release, "%u.%u", &major, &minor);
    fprintf(o, "%cFILETRACE%c  %s · %s %u.%u  ", BOLD, PLAIN, host->hostname,
            strcmp(host->system, "Darwin") == 0 ? "macOS" : host->system, major, minor);
    if (paused)
        fprintf(o, "%cPAUSED%c\n", YELLOW, PLAIN);
    else if (st->health != FT_HEALTH_OK)
        fprintf(o, "%cDEGRADED%c\n", RED, PLAIN);
    else
        fprintf(o, "%cLIVE%c\n", GREEN, PLAIN);

    counters(o, st, opt->direction);

    if (every_view || view == VIEW_FILES) {
        fprintf(o, "\n%cACTIVE FILE TRANSFERS\n", HEADING);
        transfers_table(o, &snap->transfers, width, opt->resolve, names);
    }
    if (every_view || view == VIEW_PROCESSES) {
        fprintf(o, "\n%cPROCESSES\n", HEADING);
        processes_table(o, &snap->processes, opt->direction, width);
    }
    if (!every_view && view == VIEW_NETWORK) {
        fprintf(o, "\n%cCONNECTIONS\n", HEADING);
        connections_table(o, &snap->connections, width, names);
    }

    confidence_line(o, st);
    if (every_view)
        return;
    key_row(o, view, paused, names, width);
}

static void frame_free(struct frame *f)
{
    for (size_t i = 0; i < f->count; i++)
        free(f->lines[i]);
    free(f->lines);
    f->lines = nullptr;
    f->count = 0;
}

static bool frame_build(struct frame *f, char *text, int rows, int cols)
{
    size_t max = rows > 1 ? (size_t)rows - 1 : 1;

    f->lines = calloc(max, sizeof(char *));
    f->count = 0;
    if (!f->lines)
        return false;

    for (char *line = text; line && *line && f->count < max;) {
        char *end = strchr(line, '\n');
        if (end)
            *end = '\0';

        size_t width = 0;
        char *cut = line;
        for (; *cut; cut++) {
            if (is_style_mark(*cut) || ((unsigned char)*cut & 0xc0) == 0x80)
                continue;
            if (++width > (size_t)cols)
                break;
        }
        *cut = '\0';

        f->lines[f->count] = strdup(line);
        if (!f->lines[f->count])
            return false;
        f->count++;
        line = end ? end + 1 : nullptr;
    }
    return true;
}

static void write_line(const char *line, bool styled)
{
    bool heading = line[0] == HEADING;

    if (heading && styled)
        fputs(FT_STYLE_BOLD, stdout);
    for (const char *p = line + (heading ? 1 : 0); *p; p++) {
        if (!is_style_mark(*p))
            fputc(*p, stdout);
        else if (styled)
            fputs(style_sequence(*p), stdout);
    }
    if (styled)
        fputs(FT_STYLE_RESET, stdout);
}

/* Rewrites only the lines that differ from the frame on screen. */
static void frame_draw(const struct frame *next, const struct frame *shown, bool styled)
{
    for (size_t i = 0; i < next->count; i++) {
        const char *line = next->lines[i];
        if (i < shown->count && strcmp(line, shown->lines[i]) == 0)
            continue;
        /* Erased first: after a line as wide as the terminal the erase would take its last cell. */
        printf("\033[%zu;1H\033[K", i + 1);
        write_line(line, styled);
    }
    for (size_t i = next->count; i < shown->count; i++)
        printf("\033[%zu;1H\033[K", i + 1);
    fflush(stdout);
}

static void print_plain(char *text)
{
    for (char *line = text; line && *line;) {
        char *end = strchr(line, '\n');
        if (end)
            *end = '\0';
        write_line(line, false);
        fputc('\n', stdout);
        line = end ? end + 1 : nullptr;
    }
    fputc('\n', stdout);
    fflush(stdout);
}

/* Rows left for a table once the lines around it are drawn. */
static uint32_t table_rows(const struct ft_watch_options *opt, int rows)
{
    constexpr int SURROUNDING_LINES = 12;
    constexpr uint32_t PLAIN_ROWS = 10;
    int room = rows - SURROUNDING_LINES;
    uint32_t fit = room > 1 ? (uint32_t)room : 1;

    if (opt->plain)
        return opt->filter.limit ? opt->filter.limit : PLAIN_ROWS;
    return opt->filter.limit && opt->filter.limit < fit ? opt->filter.limit : fit;
}

int ft_watch_run(struct ft_session *s, const struct ft_watch_options *given)
{
    struct ft_watch_options opt = *given;
    struct snapshot snap = {0};
    struct frame shown = {0};
    struct ft_host_info host;
    struct ft_error err = {0};
    bool dashboard = !opt.plain && isatty(STDOUT_FILENO) && isatty(STDIN_FILENO);
    bool styled = ft_term_styled(stdout);
    enum view view = VIEW_FILES;
    bool paused = false;
    bool help = false;
    bool names = true;
    int code = FT_EXIT_OK;

    opt.plain = !dashboard;
    ft_sysinfo_host(&host);
    ft_rows_init(&snap.transfers, FT_MSG_ROW_TRANSFER);
    ft_rows_init(&snap.processes, FT_MSG_ROW_PROCESS);
    ft_rows_init(&snap.connections, FT_MSG_ROW_CONNECTION);

    struct sigaction quit = {.sa_handler = on_quit};
    struct sigaction winch = {.sa_handler = on_resize};
    sigemptyset(&quit.sa_mask);
    sigemptyset(&winch.sa_mask);
    quit_requested = 0;
    sigaction(SIGINT, &quit, nullptr);
    sigaction(SIGTERM, &quit, nullptr);
    sigaction(SIGWINCH, &winch, nullptr);

    if (dashboard) {
        ft_term_raw_enter();
        /* Alternate screen, cursor hidden. */
        fputs("\033[?1049h\033[?25l\033[2J", stdout);
    }

    while (!quit_requested) {
        int rows = 24;
        int cols = 200;

        if (dashboard)
            ft_term_size(&rows, &cols);
        if (!paused) {
            code = take_snapshot(s, &opt, view, !dashboard, table_rows(&opt, rows), &snap, &err);
            if (code != FT_EXIT_OK)
                break;
        }

        char *text = nullptr;
        size_t text_size = 0;
        FILE *mem = open_memstream(&text, &text_size);
        if (!mem) {
            code = FT_EXIT_ERROR;
            break;
        }
        compose(mem, &snap, &opt, &host, view, !dashboard, dashboard ? (size_t)cols : SIZE_MAX,
                paused, help, names);
        fclose(mem);

        if (dashboard) {
            struct frame next = {0};
            if (resized) {
                resized = 0;
                fputs("\033[2J", stdout);
                frame_free(&shown);
            }
            if (frame_build(&next, text, rows, cols)) {
                frame_draw(&next, &shown, styled);
                frame_free(&shown);
                shown = next;
            } else {
                frame_free(&next);
            }
        } else {
            char stamp[32];
            ft_format_time_local(snap.stats.now_wall_ns, stamp, sizeof(stamp));
            if (opt.timestamps)
                printf("--- %s ---\n", stamp);
            print_plain(text);
        }
        free(text);

        if (dashboard) {
            struct pollfd pfd = {.fd = STDIN_FILENO, .events = POLLIN};
            int ready = poll(&pfd, 1, (int)(opt.interval_ns / FT_NS_PER_MS));
            char pressed;
            if (ready > 0 && read(STDIN_FILENO, &pressed, 1) == 1) {
                switch (pressed) {
                case 'q':
                case 'Q':
                case 3:
                    quit_requested = 1;
                    break;
                case 'f':
                case 'F':
                    view = VIEW_FILES;
                    help = false;
                    break;
                case 'p':
                case 'P':
                    view = VIEW_PROCESSES;
                    help = false;
                    break;
                case 'n':
                case 'N':
                    view = VIEW_NETWORK;
                    help = false;
                    break;
                case 'a':
                case 'A':
                    names = !names;
                    break;
                case ' ':
                    paused = !paused;
                    break;
                case '?':
                case 'h':
                    help = !help;
                    break;
                default:
                    break;
                }
            }
        } else {
            struct timespec ts = {(time_t)(opt.interval_ns / FT_NS_PER_SEC),
                                  (long)(opt.interval_ns % FT_NS_PER_SEC)};
            nanosleep(&ts, nullptr);
        }
    }

    if (dashboard) {
        fputs("\033[?25h\033[?1049l", stdout);
        fflush(stdout);
        ft_term_raw_leave();
    }
    if (code != FT_EXIT_OK)
        fprintf(stderr, "%s\n", err.msg);
    else if (snap.stats.events_dropped)
        code = FT_EXIT_PARTIAL;

    frame_free(&shown);
    ft_rows_free(&snap.transfers);
    ft_rows_free(&snap.processes);
    ft_rows_free(&snap.connections);
    return code;
}
