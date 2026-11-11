#include "ui/ui.h"

#include "filetrace/format.h"
#include "filetrace/sysinfo.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

constexpr char HEADING = '\x01'; /* first byte of a line drawn emphasised */

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

struct snapshot {
    struct ft_row_stats stats;
    struct ft_rows processes;
    struct ft_rows transfers;
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

static int take_snapshot(struct ft_session *s, const struct ft_watch_options *opt,
                         struct snapshot *snap, struct ft_error *err)
{
    struct ft_query q;

    ft_query_init(&q, FT_Q_STATS);
    memset(&snap->stats, 0, sizeof(snap->stats));
    int code = ft_client_query(s->client, &q, stats_collect, &snap->stats, nullptr, err);
    if (code != FT_EXIT_OK)
        return code;

    ft_query_init(&q, FT_Q_PROCESSES);
    q.sort = opt->inbound ? FT_SORT_INBOUND : FT_SORT_OUTBOUND;
    q.limit = opt->limit;
    q.pid = opt->pid;
    ft_strlcpy(q.process, opt->process, sizeof(q.process));
    ft_rows_clear(&snap->processes);
    code = ft_client_query(s->client, &q, ft_rows_collect, &snap->processes, nullptr, err);
    if (code != FT_EXIT_OK)
        return code;

    ft_query_init(&q, FT_Q_TRANSFERS);
    q.sort = FT_SORT_BYTES;
    q.flags = FT_QF_ACTIVE;
    q.limit = opt->limit;
    q.pid = opt->pid;
    q.proto = opt->proto;
    ft_strlcpy(q.process, opt->process, sizeof(q.process));
    ft_rows_clear(&snap->transfers);
    return ft_client_query(s->client, &q, ft_rows_collect, &snap->transfers, nullptr, err);
}

struct process_table {
    const struct ft_rows *rows;
    bool inbound;
};

static const char *process_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    const struct process_table *t = ctx;
    struct ft_row_process row;

    ft_rows_get(t->rows, r, &row, sizeof(row));
    switch (c) {
    case 0:
        snprintf(buf, size, "%" PRIu32, row.pid);
        break;
    case 1:
        snprintf(buf, size, "%s", row.comm[0] ? row.comm : "-");
        break;
    case 2:
        ft_format_bytes(t->inbound ? row.rx_bytes : row.tx_bytes, buf, size);
        break;
    default:
        snprintf(buf, size, "%" PRIu32, row.connections);
        break;
    }
    return buf;
}

struct transfer_table {
    const struct ft_rows *rows;
    struct ft_row_transfer *row;
    size_t loaded;
    size_t path_width;
};

static const char *transfer_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    struct transfer_table *t = ctx;
    const struct ft_row_transfer *row = t->row;

    if (t->loaded != r) {
        ft_rows_get(t->rows, r, t->row, sizeof(*t->row));
        t->loaded = r;
    }
    switch (c) {
    case 0: {
        const char *deleted = (row->flags & FT_XFER_FILE_DELETED) ? " (deleted)" : "";
        if (row->flags & FT_XFER_PATH_KNOWN)
            snprintf(buf, size, "%s%s", row->path, deleted);
        else
            snprintf(buf, size, "(device %" PRIu64 " inode %" PRIu64 ")%s", row->dev, row->ino,
                     deleted);
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
    case 1:
        snprintf(buf, size, "%s", row->comm[0] ? row->comm : "-");
        break;
    case 2:
        if (row->remote.family == 0 && row->remote.port == 0)
            snprintf(buf, size, "*");
        else
            ft_endpoint_format(&row->remote, buf, size);
        break;
    case 3:
        ft_format_bytes(row->bytes, buf, size);
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

static void compose(FILE *o, const struct snapshot *snap, const struct ft_watch_options *opt,
                    const struct ft_host_info *host, int cols, bool paused, bool help)
{
    const struct ft_row_stats *st = &snap->stats;
    char a[32];
    char b[32];
    unsigned major = 0;
    unsigned minor = 0;

    sscanf(host->release, "%u.%u", &major, &minor);
    fprintf(o, "%cFILETRACE  |  %s  |  %s %u.%u  |  %s\n", HEADING, host->hostname,
            strcmp(host->system, "Darwin") == 0 ? "macOS" : host->system, major, minor,
            paused                       ? "Paused"
            : st->health == FT_HEALTH_OK ? "Monitoring"
                                         : "Degraded");
    if (st->events_dropped) {
        ft_format_count(st->events_dropped, a, sizeof(a));
        fprintf(o, "WARNING: %s events lost; attribution may be incomplete.\n", a);
    }

    ft_format_bytes(st->tx_bytes, a, sizeof(a));
    ft_format_bytes(st->rx_bytes, b, sizeof(b));
    fprintf(o, "\n%c%-16s%-16s%-19s%s\n", HEADING, "OUTBOUND", "INBOUND", "ACTIVE FLOWS",
            "EVENTS/S");
    fprintf(o, "%-16s%-16s%-19u%" PRIu64 "\n", a, b, st->active_flows,
            st->events_per_sec_milli / 1000);

    if (help) {
        fprintf(o,
                "\n%cKEYS\n"
                "q      Quit\n"
                "p      Pause or resume refreshing\n"
                "?      Show or hide this help\n"
                "\n%cCOLUMNS\n"
                "SENT        Bytes the local socket accepted, not bytes the remote\n"
                "            end acknowledged.\n"
                "CONFIDENCE  EXACT: the kernel moved the file to the socket itself.\n"
                "            INFERRED: a thread read the file, then sent; the payload\n"
                "            cannot be proven to come only from that file.\n"
                "            A '*' marks a transfer during which events were lost.\n",
                HEADING, HEADING);
        fprintf(o, "\nPress ? to return\n");
        return;
    }

    static const struct ft_column_spec out_cols[] = {
        {"PID", false}, {"PROCESS", false}, {"SENT", true}, {"CONNECTIONS", true}};
    static const struct ft_column_spec in_cols[] = {
        {"PID", false}, {"PROCESS", false}, {"RECEIVED", true}, {"CONNECTIONS", true}};
    struct process_table pt = {&snap->processes, opt->inbound};

    fprintf(o, "\n%cTOP %s PROCESSES\n", HEADING, opt->inbound ? "INBOUND" : "OUTBOUND");
    if (snap->processes.count)
        ft_table_print(o, opt->inbound ? in_cols : out_cols, 4, snap->processes.count, process_cell,
                       &pt, false);
    else
        fputs("No network activity observed yet.\n", o);

    static const struct ft_column_spec xfer_cols[] = {{"FILE", false},
                                                      {"PROCESS", false},
                                                      {"REMOTE", false},
                                                      {"SENT", true},
                                                      {"CONFIDENCE", false}};
    struct ft_row_transfer *row = malloc(sizeof(*row));
    struct transfer_table tt = {
        .rows = &snap->transfers,
        .row = row,
        .loaded = SIZE_MAX,
        .path_width = cols > 110 ? (size_t)cols - 70 : 40,
    };

    fprintf(o, "\n%cACTIVE FILE TRANSFERS\n", HEADING);
    if (row && snap->transfers.count)
        ft_table_print(o, xfer_cols, 5, snap->transfers.count, transfer_cell, &tt, false);
    else
        fputs("No file transfers in progress.\n", o);
    free(row);

    fprintf(o, "\nPress q to quit | ? for help\n");
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

        bool heading = line[0] == HEADING;
        size_t width = 0;
        char *cut = line + (heading ? 1 : 0);
        for (; *cut; cut++) {
            if (((unsigned char)*cut & 0xc0) != 0x80 && ++width > (size_t)cols)
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

/* Rewrites only the lines that differ from the frame on screen. */
static void frame_draw(const struct frame *next, const struct frame *shown, bool styled)
{
    for (size_t i = 0; i < next->count; i++) {
        const char *line = next->lines[i];
        if (i < shown->count && strcmp(line, shown->lines[i]) == 0)
            continue;
        printf("\033[%zu;1H", i + 1);
        if (line[0] == HEADING)
            printf("%s%s%s", styled ? FT_STYLE_BOLD : "", line + 1, styled ? FT_STYLE_RESET : "");
        else
            fputs(line, stdout);
        fputs("\033[K", stdout);
    }
    for (size_t i = next->count; i < shown->count; i++)
        printf("\033[%zu;1H\033[K", i + 1);
    fflush(stdout);
}

static void print_plain(char *text)
{
    for (char *p = text; *p; p++) {
        if (*p != HEADING)
            fputc(*p, stdout);
    }
    fputc('\n', stdout);
    fflush(stdout);
}

int ft_watch_run(struct ft_session *s, const struct ft_watch_options *opt)
{
    struct snapshot snap = {0};
    struct frame shown = {0};
    struct ft_host_info host;
    struct ft_error err = {0};
    bool dashboard = !opt->plain && isatty(STDOUT_FILENO) && isatty(STDIN_FILENO);
    bool styled = ft_term_styled(stdout);
    bool paused = false;
    bool help = false;
    int code = FT_EXIT_OK;

    ft_sysinfo_host(&host);
    ft_rows_init(&snap.processes, FT_MSG_ROW_PROCESS);
    ft_rows_init(&snap.transfers, FT_MSG_ROW_TRANSFER);

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

        if (!paused) {
            code = take_snapshot(s, opt, &snap, &err);
            if (code != FT_EXIT_OK)
                break;
        }
        if (dashboard)
            ft_term_size(&rows, &cols);

        char *text = nullptr;
        size_t text_size = 0;
        FILE *mem = open_memstream(&text, &text_size);
        if (!mem) {
            code = FT_EXIT_ERROR;
            break;
        }
        compose(mem, &snap, opt, &host, cols, paused, help);
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
            printf("--- %s ---\n", stamp);
            print_plain(text);
        }
        free(text);

        if (dashboard) {
            struct pollfd pfd = {.fd = STDIN_FILENO, .events = POLLIN};
            int ready = poll(&pfd, 1, (int)(opt->interval_ns / FT_NS_PER_MS));
            char key;
            if (ready > 0 && read(STDIN_FILENO, &key, 1) == 1) {
                if (key == 'q' || key == 'Q' || key == 3)
                    break;
                if (key == 'p' || key == 'P')
                    paused = !paused;
                if (key == '?' || key == 'h')
                    help = !help;
            }
        } else {
            struct timespec ts = {(time_t)(opt->interval_ns / FT_NS_PER_SEC),
                                  (long)(opt->interval_ns % FT_NS_PER_SEC)};
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
    ft_rows_free(&snap.processes);
    ft_rows_free(&snap.transfers);
    return code;
}
