#include "cmd/cli.h"

#include "exporters/exporters.h"
#include "filetrace/clock.h"
#include "filetrace/format.h"
#include "filetrace/sysinfo.h"
#include "ui/ui.h"

#include <inttypes.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#if defined(__linux__)
#include <sys/sysmacros.h>
#endif

struct inspect {
    struct ft_session *session;
    struct ft_output out;
    uint64_t since_wall_ns;
    uint32_t limit;
    bool resolve;
    struct ft_msg_end end; /* of the query that lost the most events */
    bool queried;
};

static int fetch(struct inspect *in, struct ft_query *q, uint16_t type, struct ft_rows *rows)
{
    struct ft_msg_end end = {0};
    struct ft_error err = {0};

    ft_rows_init(rows, type);
    q->since_wall_ns = in->since_wall_ns;
    int code = ft_client_query(in->session->client, q, ft_rows_collect, rows, &end, &err);
    if (code != FT_EXIT_OK) {
        fprintf(stderr, "%s\n", err.msg);
        return code;
    }
    if (!in->queried || end.lost_events > in->end.lost_events)
        in->end = end;
    in->queried = true;
    if (type == FT_MSG_ROW_TRANSFER)
        ft_view_prefetch_hosts(FT_VIEW_FILES, rows);
    else if (type == FT_MSG_ROW_FLOW)
        ft_view_prefetch_hosts(FT_VIEW_FLOWS, rows);
    else if (type == FT_MSG_ROW_CONNECTION)
        ft_view_prefetch_hosts(FT_VIEW_CONNECTIONS, rows);
    return FT_EXIT_OK;
}

static void section(FILE *o, const char *title)
{
    bool styled = ft_term_styled(o);
    fprintf(o, "%s%s%s\n", styled ? FT_STYLE_BOLD : "", title, styled ? FT_STYLE_RESET : "");
    for (int i = 0; i < 36; i++)
        fputs("─", o);
    fputc('\n', o);
}

[[gnu::format(printf, 3, 4)]]
static void field(FILE *o, const char *label, const char *fmt, ...)
{
    va_list ap;

    fprintf(o, "%-18s", label);
    va_start(ap, fmt);
    vfprintf(o, fmt, ap);
    va_end(ap);
    fputc('\n', o);
}

static const char *user_name(uint32_t uid, char *buf, size_t size)
{
    const struct passwd *pw = getpwuid((uid_t)uid);
    if (pw)
        ft_strlcpy(buf, pw->pw_name, size);
    else
        snprintf(buf, size, "%" PRIu32, uid);
    return buf;
}

static const char *plural(uint64_t n, const char *one, const char *many)
{
    return n == 1 ? one : many;
}

static void history_note(const struct inspect *in, FILE *o)
{
    char since[32];
    bool styled = ft_term_styled(o);

    ft_format_time_local(in->end.observed_since_wall_ns, since, sizeof(since));
    fprintf(o,
            "\n%sHistory starts at %s, when the agent started.\n"
            "Nothing earlier is kept.%s\n",
            styled ? FT_STYLE_DIM : "", since, styled ? FT_STYLE_RESET : "");
}

static void json_tail(const struct inspect *in, FILE *o)
{
    char since[40];

    ft_format_time_rfc3339(in->end.observed_since_wall_ns, since, sizeof(since));
    fprintf(o, ",\"observed_since\":\"%s\",\"events_lost\":%" PRIu64 "}\n", since,
            in->end.lost_events);
}

static int compare_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a;
    uint32_t y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

static int compare_addr(const void *a, const void *b)
{
    const struct ft_endpoint *x = a;
    const struct ft_endpoint *y = b;
    if (x->family != y->family)
        return x->family < y->family ? -1 : 1;
    return memcmp(x->addr, y->addr, sizeof(x->addr));
}

static size_t distinct(void *items, size_t count, size_t size,
                       int (*compare)(const void *, const void *))
{
    const unsigned char *base = items;
    size_t n = 0;

    qsort(items, count, size, compare);
    for (size_t i = 0; i < count; i++) {
        if (i == 0 || compare(base + (i - 1) * size, base + i * size) != 0)
            n++;
    }
    return n;
}

struct transfer_summary {
    uint64_t bytes;
    size_t transfers;
    size_t active;
    size_t destinations;
    size_t processes;
    size_t paths;
    size_t by_method[FT_METHOD_IO_URING + 1];
    size_t by_confidence[FT_CONF_EXACT + 1];
};

/* scratch is left holding the first row, the most recent transfer. */
static bool summarize(const struct ft_rows *rows, struct transfer_summary *sum,
                      struct ft_row_transfer *scratch)
{
    struct ft_endpoint *remotes = calloc(rows->count + 1, sizeof(*remotes));
    uint32_t *pids = calloc(rows->count + 1, sizeof(*pids));
    char *first_path = nullptr;

    memset(sum, 0, sizeof(*sum));
    if (!remotes || !pids) {
        free(remotes);
        free(pids);
        return false;
    }
    for (size_t i = rows->count; i-- > 0;) {
        ft_rows_get(rows, i, scratch, sizeof(*scratch));
        sum->bytes += scratch->bytes;
        sum->transfers++;
        if (scratch->flags & FT_XFER_ACTIVE)
            sum->active++;
        if (scratch->method < FT_ARRAY_LEN(sum->by_method))
            sum->by_method[scratch->method]++;
        if (scratch->confidence < FT_ARRAY_LEN(sum->by_confidence))
            sum->by_confidence[scratch->confidence]++;
        remotes[i] = scratch->remote;
        remotes[i].port = 0;
        pids[i] = scratch->pid;
        if (!first_path)
            first_path = strdup(scratch->path);
        else if (strcmp(first_path, scratch->path) != 0)
            sum->paths = 2;
    }
    if (rows->count && sum->paths == 0)
        sum->paths = 1;
    sum->destinations = distinct(remotes, rows->count, sizeof(*remotes), compare_addr);
    sum->processes = distinct(pids, rows->count, sizeof(*pids), compare_u32);
    free(first_path);
    free(remotes);
    free(pids);
    return true;
}

/* The first limit rows in reverse: the most recent ones, oldest first. */
static void recent_oldest_first(const struct ft_rows *rows, size_t limit, struct ft_rows *out)
{
    size_t n = limit && limit < rows->count ? limit : rows->count;

    ft_rows_init(out, rows->type);
    for (size_t i = n; i-- > 0;)
        ft_rows_append(out, rows->data + rows->offsets[i], rows->sizes[i]);
}

static void more_note(FILE *o, size_t total, size_t shown, const char *one, const char *many)
{
    if (total > shown)
        fprintf(o, "(%zu more %s not shown; raise --limit)\n", total - shown,
                plural(total - shown, one, many));
}

constexpr size_t LISTED = 8; /* items a line names before it counts the rest */

/* A field of up to LISTED items and how many more there are; nothing for no item. */
static void list_field(FILE *o, const char *label, const char *const *items, size_t count,
                       size_t more)
{
    size_t rest = (count > LISTED ? count - LISTED : 0) + more;

    if (count == 0)
        return;
    fprintf(o, "%-18s", label);
    for (size_t i = 0; i < count && i < LISTED; i++)
        fprintf(o, "%s%s", i ? ", " : "", items[i]);
    if (rest)
        fprintf(o, " and %zu more", rest);
    fputc('\n', o);
}

static void names_field(FILE *o, const struct ft_address_names *a)
{
    const char *names[FT_ADDRESS_NAMES];

    for (size_t i = 0; i < a->count; i++)
        names[i] = a->names[i].name;
    list_field(o, "Names:", names, a->count, a->more);
}

static void provenance(FILE *o, const struct transfer_summary *sum)
{
    static const enum ft_method methods[] = {FT_METHOD_SENDFILE, FT_METHOD_READ_SEND};
    static const enum ft_confidence levels[] = {FT_CONF_EXACT, FT_CONF_STRONG, FT_CONF_INFERRED,
                                                FT_CONF_UNKNOWN};
    static const char *const level_titles[] = {"Exact:", "Strong:", "Inferred:", "Unknown:"};
    char label[32];

    section(o, "PROVENANCE");
    for (size_t i = 0; i < FT_ARRAY_LEN(methods); i++) {
        size_t n = sum->by_method[methods[i]];
        if (n == 0)
            continue;
        snprintf(label, sizeof(label), "%s:", ft_method_name(methods[i]));
        field(o, label, "%zu %s", n, plural(n, "transfer", "transfers"));
    }
    for (size_t i = 0; i < FT_ARRAY_LEN(levels); i++) {
        if (sum->by_confidence[levels[i]])
            field(o, level_titles[i], "%zu", sum->by_confidence[levels[i]]);
    }
}

static void provenance_json(FILE *o, const struct transfer_summary *sum)
{
    fprintf(o,
            "\"provenance\":{\"methods\":{\"sendfile\":%zu,\"read-write\":%zu},"
            "\"confidence\":{\"exact\":%zu,\"strong\":%zu,\"inferred\":%zu,\"unknown\":%zu}}",
            sum->by_method[FT_METHOD_SENDFILE], sum->by_method[FT_METHOD_READ_SEND],
            sum->by_confidence[FT_CONF_EXACT], sum->by_confidence[FT_CONF_STRONG],
            sum->by_confidence[FT_CONF_INFERRED], sum->by_confidence[FT_CONF_UNKNOWN]);
}

static const struct ft_view_column history_columns[] = {
    {"TIME", "transfer.started", false},
    {"PROCESS", "process.name", false},
    {"PID", "process.pid", false},
    {"REMOTE", "@remote", false},
    {"NAME", "@name", false},
    {"BYTES", "transfer.bytes_sent", true},
    {"METHOD", "@method", false},
    {"CONFIDENCE", "@confidence", false},
    {"SCRIPT", "process.script", false},
};

static const struct ft_view_column sent_columns[] = {
    {"FILE", "@file", false},
    {"PROCESS", "process.name", false},
    {"REMOTE", "@remote", false},
    {"NAME", "@name", false},
    {"BYTES", "transfer.bytes_sent", true},
    {"METHOD", "@method", false},
    {"CONFIDENCE", "@confidence", false},
    {"SCRIPT", "process.script", false},
};

static void sent_files(const struct inspect *in, const struct ft_rows *transfers, const char *title,
                       const char *none)
{
    FILE *o = in->out.stream;

    fputc('\n', o);
    section(o, title);
    if (transfers->count == 0) {
        fprintf(o, "%s\n", none);
        return;
    }
    ft_view_table(FT_VIEW_FILES, transfers, in->limit, sent_columns, FT_ARRAY_LEN(sent_columns), o);
    more_note(o, transfers->count, in->limit, "transfer", "transfers");
}

static int inspect_file(struct inspect *in, const char *path)
{
    struct ft_row_transfer *row = malloc(sizeof(*row));
    struct transfer_summary sum;
    struct ft_rows rows;
    struct ft_query q;
    FILE *o = in->out.stream;
    char a[64];

    if (!row)
        return FT_EXIT_ERROR;
    if (strlen(path) >= sizeof(q.path)) {
        free(row);
        return ft_usage_error("inspect", "the path is too long");
    }
    ft_query_init(&q, FT_Q_TRANSFERS);
    q.sort = FT_SORT_TIME;
    ft_strlcpy(q.path, path, sizeof(q.path));
    int code = fetch(in, &q, FT_MSG_ROW_TRANSFER, &rows);
    if (code != FT_EXIT_OK || !summarize(&rows, &sum, row)) {
        ft_rows_free(&rows);
        free(row);
        return code != FT_EXIT_OK ? code : FT_EXIT_ERROR;
    }

    if (sum.paths > 1) {
        fprintf(stderr, "filetrace: '%s' matches more than one file; name one of them:\n\n", path);
        ft_view_table(FT_VIEW_FILES, &rows, 0, sent_columns, FT_ARRAY_LEN(sent_columns), stderr);
        ft_rows_free(&rows);
        free(row);
        return FT_EXIT_USAGE;
    }

    if (in->out.format == FT_FMT_JSON) {
        fputs("{\"kind\":\"file\",\"path\":", o);
        ft_json_string(o, path);
        fprintf(o,
                ",\"totals\":{\"bytes_sent\":%" PRIu64 ",\"transfers\":%zu,"
                "\"active_transfers\":%zu,\"destinations\":%zu,\"processes\":%zu},",
                sum.bytes, sum.transfers, sum.active, sum.destinations, sum.processes);
        provenance_json(o, &sum);
        fputs(",\"transfers\":", o);
        ft_view_json_array(FT_VIEW_FILES, &rows, o);
        json_tail(in, o);
    } else if (rows.count == 0) {
        ft_format_time_local(in->end.observed_since_wall_ns, a, sizeof(a));
        fprintf(o,
                "No transfers of %s have been observed since %s.\n"
                "Nothing earlier is kept.\n",
                path, a);
    } else {
        struct ft_rows shown;

        section(o, "FILE");
        field(o, "Path:", "%s", row->path);
#if defined(__linux__)
        field(o, "Device:", "%u:%u", major((dev_t)row->dev), minor((dev_t)row->dev));
#else
        field(o, "Device:", "%" PRIu64, row->dev);
#endif
        field(o, "Inode:", "%" PRIu64, row->ino);
        ft_format_bytes(row->file_size, a, sizeof(a));
        field(o, "Size:", "%s", a);
        field(o, "Owner:", "%s", user_name(row->file_uid, a, sizeof(a)));
        if (row->fs_type[0])
            field(o, "Filesystem:", "%s", row->fs_type);
        field(o, "Deleted:", "%s", (row->flags & FT_XFER_FILE_DELETED) ? "yes" : "no");

        fputc('\n', o);
        section(o, "TRANSFER HISTORY");
        recent_oldest_first(&rows, in->limit, &shown);
        ft_view_table(FT_VIEW_FILES, &shown, 0, history_columns, FT_ARRAY_LEN(history_columns), o);
        more_note(o, rows.count, shown.count, "earlier transfer", "earlier transfers");
        ft_rows_free(&shown);

        fputc('\n', o);
        section(o, "TOTALS");
        ft_format_bytes(sum.bytes, a, sizeof(a));
        field(o, "Total sent:", "%s", a);
        field(o, "Destinations:", "%zu", sum.destinations);
        field(o, "Processes:", "%zu", sum.processes);
        field(o, "Transfers:", "%zu", sum.transfers);
        field(o, "Active transfers:", "%zu", sum.active);

        fputc('\n', o);
        provenance(o, &sum);
        history_note(in, o);
    }
    ft_rows_free(&rows);
    free(row);
    return FT_EXIT_OK;
}

struct destination {
    struct ft_endpoint addr;
    uint64_t tx;
    uint64_t rx;
    uint64_t rate;
};

struct destinations {
    struct destination *items;
    size_t count;
    bool resolve;
};

static int by_rate_then_bytes(const void *a, const void *b)
{
    const struct destination *x = a;
    const struct destination *y = b;
    if (x->rate != y->rate)
        return x->rate < y->rate ? 1 : -1;
    if (x->tx != y->tx)
        return x->tx < y->tx ? 1 : -1;
    return compare_addr(&x->addr, &y->addr);
}

static bool group_destinations(const struct ft_rows *flows, struct destinations *d)
{
    d->items = calloc(flows->count + 1, sizeof(*d->items));
    d->count = 0;
    if (!d->items)
        return false;

    for (size_t i = 0; i < flows->count; i++) {
        struct ft_row_flow flow;
        ft_rows_get(flows, i, &flow, sizeof(flow));
        d->items[i].addr = flow.remote;
        d->items[i].addr.port = 0;
        d->items[i].tx = flow.tx_bytes;
        d->items[i].rx = flow.rx_bytes;
        d->items[i].rate = flow.tx_rate;
    }
    /* The address is the first member, so the address order applies to the items. */
    qsort(d->items, flows->count, sizeof(*d->items), compare_addr);
    for (size_t i = 0; i < flows->count; i++) {
        struct destination *last = d->count ? &d->items[d->count - 1] : nullptr;
        if (last && compare_addr(&last->addr, &d->items[i].addr) == 0) {
            last->tx += d->items[i].tx;
            last->rx += d->items[i].rx;
            last->rate += d->items[i].rate;
        } else {
            d->items[d->count++] = d->items[i];
        }
    }
    qsort(d->items, d->count, sizeof(*d->items), by_rate_then_bytes);
    return true;
}

static const char *destination_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    const struct destinations *d = ctx;
    const struct destination *it = &d->items[r];

    switch (c) {
    case 0: {
        const char *host = d->resolve ? ft_resolver_name(&it->addr) : nullptr;
        if (host)
            snprintf(buf, size, "%s", host);
        else
            ft_addr_format(&it->addr, buf, size);
        break;
    }
    case 1:
        ft_format_rate(it->rate, buf, size);
        break;
    case 2:
        ft_format_bytes(it->tx, buf, size);
        break;
    default:
        ft_format_bytes(it->rx, buf, size);
        break;
    }
    return buf;
}

static void destinations_table(const struct inspect *in, const struct destinations *d)
{
    static const struct ft_column_spec columns[] = {
        {"DESTINATION", false}, {"OUTBOUND", true}, {"SENT", true}, {"RECEIVED", true}};
    FILE *o = in->out.stream;
    size_t shown = in->limit < d->count ? in->limit : d->count;

    fputc('\n', o);
    section(o, "TOP DESTINATIONS");
    if (d->count == 0) {
        fputs("None observed.\n", o);
        return;
    }
    ft_table_print(o, columns, FT_ARRAY_LEN(columns), shown, destination_cell, (void *)(uintptr_t)d,
                   ft_term_styled(o));
    more_note(o, d->count, shown, "destination", "destinations");
}

static void destinations_json(FILE *o, const struct destinations *d)
{
    char addr[64];

    fputs("\"destinations\":[", o);
    for (size_t i = 0; i < d->count; i++) {
        const struct destination *it = &d->items[i];
        ft_addr_format(&it->addr, addr, sizeof(addr));
        fprintf(o,
                "%s{\"remote_ip\":\"%s\",\"bytes_sent\":%" PRIu64 ",\"bytes_received\":%" PRIu64
                ",\"bytes_sent_per_second\":%" PRIu64 "}",
                i ? "," : "", addr, it->tx, it->rx, it->rate);
    }
    fputc(']', o);
}

static int inspect_process(struct inspect *in, const char *arg)
{
    struct ft_rows processes;
    struct ft_rows flows = {0};
    struct ft_rows transfers = {0};
    struct destinations dest = {0};
    struct ft_row_process p;
    struct ft_query q;
    FILE *o = in->out.stream;
    uint32_t pid;
    char a[64];
    char b[64];

    if (!ft_parse_u32(arg, &pid) || pid == 0)
        return ft_usage_error("inspect", "'%s' is not a process ID", arg);

    ft_query_init(&q, FT_Q_PROCESSES);
    q.pid = pid;
    int code = fetch(in, &q, FT_MSG_ROW_PROCESS, &processes);
    if (code == FT_EXIT_OK) {
        ft_query_init(&q, FT_Q_FLOWS);
        q.pid = pid;
        code = fetch(in, &q, FT_MSG_ROW_FLOW, &flows);
    }
    if (code == FT_EXIT_OK) {
        ft_query_init(&q, FT_Q_TRANSFERS);
        q.pid = pid;
        q.sort = FT_SORT_TIME;
        code = fetch(in, &q, FT_MSG_ROW_TRANSFER, &transfers);
    }
    dest.resolve = in->resolve;
    if (code == FT_EXIT_OK && !group_destinations(&flows, &dest))
        code = FT_EXIT_ERROR;
    if (code != FT_EXIT_OK)
        goto out;

    bool found = processes.count > 0;
    bool running = false;
    uint32_t open_files = 0;
    bool have_open_files = false;
    char cgroup[4096] = "";

    if (found) {
        ft_rows_get(&processes, 0, &p, sizeof(p));
        running = !(p.flags & FT_PROC_EXITED);
    }
    /* A PID that has exited may by now name another process, as may one from another namespace. */
    if (running && ft_sysinfo_host_pid_namespace()) {
        have_open_files = ft_sysinfo_process_open_files(pid, &open_files);
        ft_sysinfo_process_cgroup(pid, cgroup, sizeof(cgroup));
    }

    if (in->out.format == FT_FMT_JSON) {
        fprintf(o, "{\"kind\":\"process\",\"pid\":%" PRIu32, pid);
        if (found) {
            fputs(",\"process\":", o);
            ft_view_json_object(FT_VIEW_PROCESSES, &processes, 0, o);
        }
        if (cgroup[0]) {
            fputs(",\"cgroup\":", o);
            ft_json_string(o, cgroup);
        }
        if (have_open_files)
            fprintf(o, ",\"open_files\":%" PRIu32, open_files);
        fputc(',', o);
        destinations_json(o, &dest);
        fputs(",\"transfers\":", o);
        ft_view_json_array(FT_VIEW_FILES, &transfers, o);
        json_tail(in, o);
        goto out;
    }
    if (!found) {
        ft_format_time_local(in->end.observed_since_wall_ns, a, sizeof(a));
        fprintf(o,
                "No network activity of process %" PRIu32 " has been observed since %s.\n"
                "Nothing earlier is kept.\n",
                pid, a);
        goto out;
    }

    section(o, "PROCESS");
    field(o, "Name:", "%s", p.comm[0] ? p.comm : "-");
    field(o, "PID:", "%" PRIu32, p.pid);
    field(o, "PPID:", "%" PRIu32, p.ppid);
    field(o, "User:", "%s", user_name(p.uid, a, sizeof(a)));
    if (p.exe[0])
        field(o, "Executable:", "%s", p.exe);
    struct ft_process_strings text;
    ft_row_process_strings(&p, &text);
    if (text.command_line[0])
        field(o, "Command line:", "%s", text.command_line);
    if (text.cwd[0])
        field(o, "Directory:", "%s", text.cwd);
    if (text.script[0])
        field(o, "Script:", "%s", text.script);
    if (cgroup[0])
        field(o, "Cgroup:", "%s", cgroup);
    else if (p.cgroup_id)
        field(o, "Cgroup:", "id %" PRIu64, p.cgroup_id);
    if (p.netns)
        field(o, "Network ns:", "%" PRIu32, p.netns);
    if (p.start_wall_ns) {
        ft_format_time_local(p.start_wall_ns, a, sizeof(a));
        field(o, "Started:", "%s", a);
    }
    if (running) {
        field(o, "Status:", "running");
    } else {
        ft_format_time_local(p.exit_wall_ns, a, sizeof(a));
        if (WIFSIGNALED(p.exit_status))
            field(o, "Status:", "killed by signal %d at %s", WTERMSIG(p.exit_status), a);
        else
            field(o, "Status:", "exited with %d at %s", WEXITSTATUS(p.exit_status), a);
    }

    fputc('\n', o);
    section(o, "NETWORK");
    field(o, "Connections:", "%" PRIu32 " open", p.connections);
    ft_format_rate(p.tx_rate, a, sizeof(a));
    ft_format_bytes(p.tx_bytes, b, sizeof(b));
    field(o, "Outbound:", "%s (%s sent)", a, b);
    ft_format_rate(p.rx_rate, a, sizeof(a));
    ft_format_bytes(p.rx_bytes, b, sizeof(b));
    field(o, "Inbound:", "%s (%s received)", a, b);

    fputc('\n', o);
    section(o, "FILES");
    if (have_open_files)
        field(o, "Open files:", "%" PRIu32, open_files);
    field(o, "Active transfers:", "%" PRIu32, p.active_transfers);
    field(o, "Unique files:", "%" PRIu32, p.files);
    field(o, "Transfers:", "%" PRIu32, p.transfers);

    destinations_table(in, &dest);
    sent_files(in, &transfers, "FILES SENT", "No file has been associated with what it sent.");
    history_note(in, o);

out:
    free(dest.items);
    ft_rows_free(&processes);
    ft_rows_free(&flows);
    ft_rows_free(&transfers);
    return code;
}

static void times(FILE *o, uint64_t first_wall_ns, uint64_t last_wall_ns, uint64_t closed_wall_ns)
{
    char a[32];

    ft_format_time_local(first_wall_ns, a, sizeof(a));
    field(o, "First seen:", "%s", a);
    ft_format_time_local(last_wall_ns, a, sizeof(a));
    field(o, "Last active:", "%s", a);
    if (closed_wall_ns) {
        ft_format_time_local(closed_wall_ns, a, sizeof(a));
        field(o, "Closed:", "%s", a);
    }
}

static void traffic(FILE *o, uint64_t tx, uint64_t rx, uint64_t tx_rate, uint64_t rx_rate)
{
    char a[32];
    char b[32];

    ft_format_bytes(tx, a, sizeof(a));
    ft_format_rate(tx_rate, b, sizeof(b));
    field(o, "Sent:", "%s (%s)", a, b);
    ft_format_bytes(rx, a, sizeof(a));
    ft_format_rate(rx_rate, b, sizeof(b));
    field(o, "Received:", "%s (%s)", a, b);
}

static void endpoints(FILE *o, uint16_t proto, const struct ft_endpoint *local,
                      const struct ft_endpoint *remote)
{
    char scratch[8];
    char name[8];
    char a[64];
    size_t n = 0;

    for (const char *p = ft_proto_name(proto, scratch); *p && n + 1 < sizeof(name); p++)
        name[n++] = (char)(*p - ('a' <= *p && *p <= 'z' ? 32 : 0));
    name[n] = '\0';
    field(o, "Protocol:", "%s", name);
    ft_endpoint_format(local, a, sizeof(a));
    field(o, "Local:", "%s", local->family || local->port ? a : "*");
    ft_endpoint_format(remote, a, sizeof(a));
    field(o, "Remote:", "%s", remote->family || remote->port ? a : "*");
}

/* What is known of the remote end's names; nothing for one without a name. */
static void names(FILE *o, const struct ft_remote_names *n)
{
    static const char *const from[] = {
        [FT_NAME_SOURCE_LOOKUP] = "lookup",
        [FT_NAME_SOURCE_TLS] = "TLS server name",
        [FT_NAME_SOURCE_LOOKUP_TLS] = "lookup, TLS server name",
    };
    enum ft_name_source source = ft_remote_name_source(n);
    char text[FT_NAMES_TEXT_MAX + 64];
    size_t used = 0;

    if (source == FT_NAME_SOURCE_NONE)
        return;
    ft_remote_name_format(n, text, sizeof(text));
    field(o, "Name:", "%s", text);
    field(o, "Name from:", "%s", from[source]);

    /* The looked-up names are listed where the name line does not already say them all. */
    if (n->listed < 2 && !(source == FT_NAME_SOURCE_TLS && n->listed))
        return;
    for (uint32_t i = 0; i < n->listed && used < sizeof(text); i++)
        used += (size_t)snprintf(text + used, sizeof(text) - used, "%s%s", i ? ", " : "",
                                 n->resolved[i]);
    if (n->count > n->listed && used < sizeof(text))
        snprintf(text + used, sizeof(text) - used, " and %u more", n->count - n->listed);
    field(o, "Resolved names:", "%s", text);
}

static const struct ft_view_column flow_columns[] = {
    {"FLOW", "flow_id", false},
    {"PID", "pid", false},
    {"PROCESS", "process", false},
    {"REMOTE", "@remote", false},
    {"NAME", "@name", false},
    {"SENT", "bytes_sent", true},
    {"RECEIVED", "bytes_received", true},
    {"OUTBOUND", "bytes_sent_per_second", true},
};

static int inspect_socket(struct inspect *in, const char *arg)
{
    struct ft_rows connections;
    struct ft_rows flows = {0};
    struct ft_rows transfers = {0};
    struct ft_row_connection c;
    struct ft_remote_names remote_names;
    struct ft_query q;
    FILE *o = in->out.stream;
    uint64_t id;
    char a[64];

    if (!ft_parse_u64(arg, &id) || id == 0)
        return ft_usage_error("inspect", "'%s' is not a socket ID", arg);

    ft_query_init(&q, FT_Q_CONNECTIONS);
    q.sock_id = id;
    int code = fetch(in, &q, FT_MSG_ROW_CONNECTION, &connections);
    if (code == FT_EXIT_OK) {
        ft_query_init(&q, FT_Q_FLOWS);
        q.sock_id = id;
        code = fetch(in, &q, FT_MSG_ROW_FLOW, &flows);
    }
    if (code == FT_EXIT_OK) {
        ft_query_init(&q, FT_Q_TRANSFERS);
        q.sock_id = id;
        q.sort = FT_SORT_TIME;
        code = fetch(in, &q, FT_MSG_ROW_TRANSFER, &transfers);
    }
    if (code != FT_EXIT_OK)
        goto out;

    if (in->out.format == FT_FMT_JSON) {
        fprintf(o, "{\"kind\":\"socket\",\"socket_id\":%" PRIu64, id);
        if (connections.count) {
            fputs(",\"connection\":", o);
            ft_view_json_object(FT_VIEW_CONNECTIONS, &connections, 0, o);
        }
        fputs(",\"flows\":", o);
        ft_view_json_array(FT_VIEW_FLOWS, &flows, o);
        fputs(",\"transfers\":", o);
        ft_view_json_array(FT_VIEW_FILES, &transfers, o);
        json_tail(in, o);
        goto out;
    }
    if (connections.count == 0) {
        fprintf(o,
                "No socket %" PRIu64
                " is known. 'filetrace connections' lists the IDs of open and\n"
                "recently closed sockets.\n",
                id);
        goto out;
    }

    ft_rows_get(&connections, 0, &c, sizeof(c));
    section(o, "SOCKET");
    field(o, "ID:", "%" PRIu64, c.sock_id);
    endpoints(o, c.proto, &c.local, &c.remote);
    ft_row_connection_names(&c, &remote_names);
    names(o, &remote_names);
    ft_strlcpy(a, ft_sock_state_name((enum ft_sock_state)c.state), sizeof(a));
    field(o, "State:", "%s", a);
    if (c.pid)
        field(o, "Process:", "%s (PID %" PRIu32 ")", c.comm[0] ? c.comm : "-", c.pid);
    else
        field(o, "Process:", "not yet known");
    times(o, c.first_wall_ns, c.last_wall_ns, c.closed_wall_ns);
    traffic(o, c.tx_bytes, c.rx_bytes, c.tx_rate, c.rx_rate);

    fputc('\n', o);
    section(o, "FLOWS");
    if (flows.count) {
        ft_view_table(FT_VIEW_FLOWS, &flows, in->limit, flow_columns, FT_ARRAY_LEN(flow_columns),
                      o);
        more_note(o, flows.count, in->limit, "flow", "flows");
    } else {
        fputs("No bytes have been exchanged on it.\n", o);
    }
    sent_files(in, &transfers, "FILES SENT", "No file has been associated with what it sent.");
    history_note(in, o);

out:
    ft_rows_free(&connections);
    ft_rows_free(&flows);
    ft_rows_free(&transfers);
    return code;
}

static int inspect_flow(struct inspect *in, const char *arg)
{
    struct ft_rows flows;
    struct ft_rows transfers = {0};
    struct ft_row_flow f;
    struct ft_remote_names remote_names;
    struct ft_query q;
    FILE *o = in->out.stream;
    uint64_t id;

    if (!ft_parse_u64(arg, &id) || id == 0)
        return ft_usage_error("inspect", "'%s' is not a flow ID", arg);

    ft_query_init(&q, FT_Q_FLOWS);
    q.flow_id = id;
    int code = fetch(in, &q, FT_MSG_ROW_FLOW, &flows);
    if (code == FT_EXIT_OK && flows.count) {
        ft_rows_get(&flows, 0, &f, sizeof(f));
        ft_query_init(&q, FT_Q_TRANSFERS);
        q.sock_id = f.sock_id;
        q.pid = f.pid;
        q.sort = FT_SORT_TIME;
        code = fetch(in, &q, FT_MSG_ROW_TRANSFER, &transfers);
    }
    if (code != FT_EXIT_OK)
        goto out;

    if (in->out.format == FT_FMT_JSON) {
        fprintf(o, "{\"kind\":\"flow\",\"flow_id\":%" PRIu64, id);
        if (flows.count) {
            fputs(",\"flow\":", o);
            ft_view_json_object(FT_VIEW_FLOWS, &flows, 0, o);
        }
        fputs(",\"transfers\":", o);
        ft_view_json_array(FT_VIEW_FILES, &transfers, o);
        json_tail(in, o);
        goto out;
    }
    if (flows.count == 0) {
        fprintf(o, "No flow %" PRIu64 " is known. 'filetrace flows' lists the IDs of flows.\n", id);
        goto out;
    }

    section(o, "FLOW");
    field(o, "ID:", "%" PRIu64, f.id);
    field(o, "Socket:", "%" PRIu64, f.sock_id);
    endpoints(o, f.proto, &f.local, &f.remote);
    ft_row_flow_names(&f, &remote_names);
    names(o, &remote_names);
    field(o, "Process:", "%s (PID %" PRIu32 ")", f.comm[0] ? f.comm : "-", f.pid);
    times(o, f.first_wall_ns, f.last_wall_ns, 0);
    traffic(o, f.tx_bytes, f.rx_bytes, f.tx_rate, f.rx_rate);
    field(o, "Operations:", "%" PRIu32 " sends, %" PRIu32 " receives", f.tx_ops, f.rx_ops);
    sent_files(in, &transfers, "FILES SENT", "No file has been associated with what it sent.");
    history_note(in, o);

out:
    ft_rows_free(&flows);
    ft_rows_free(&transfers);
    return code;
}

struct talker {
    uint32_t pid;
    char comm[FT_COMM_MAX];
    uint64_t tx;
    uint64_t rx;
    uint64_t rate;
    struct ft_kept_names names; /* of the remote ends it talked to */
};

struct talkers {
    struct talker *items;
    size_t count;
};

static int talker_by_pid(const void *a, const void *b)
{
    return compare_u32(&((const struct talker *)a)->pid, &((const struct talker *)b)->pid);
}

static int talker_by_bytes(const void *a, const void *b)
{
    const struct talker *x = a;
    const struct talker *y = b;
    if (x->tx != y->tx)
        return x->tx < y->tx ? 1 : -1;
    return talker_by_pid(a, b);
}

static void talkers_free(struct talkers *t)
{
    for (size_t i = 0; i < t->count; i++)
        ft_kept_names_free(&t->items[i].names);
    free(t->items);
}

/* On failure, t holds what talkers_free needs. */
static bool group_talkers(const struct ft_rows *flows, struct talkers *t)
{
    size_t n = flows->count;

    t->items = calloc(n + 1, sizeof(*t->items));
    t->count = 0;
    if (!t->items)
        return false;

    for (size_t i = 0; i < n; i++) {
        struct ft_row_flow flow;
        struct ft_remote_names names;
        ft_rows_get(flows, i, &flow, sizeof(flow));
        ft_row_flow_names(&flow, &names);
        t->items[i] = (struct talker){
            .pid = flow.pid, .tx = flow.tx_bytes, .rx = flow.rx_bytes, .rate = flow.tx_rate};
        ft_strlcpy(t->items[i].comm, flow.comm, sizeof(t->items[i].comm));
        if (!ft_kept_names_add(&t->items[i].names, &names, flow.tx_bytes)) {
            t->count = i;
            return false;
        }
    }
    qsort(t->items, n, sizeof(*t->items), talker_by_pid);
    for (size_t i = 0; i < n; i++) {
        struct talker *last = t->count ? &t->items[t->count - 1] : nullptr;
        if (last && last->pid == t->items[i].pid) {
            last->tx += t->items[i].tx;
            last->rx += t->items[i].rx;
            last->rate += t->items[i].rate;
            ft_kept_names_join(&last->names, &t->items[i].names);
        } else {
            t->items[t->count++] = t->items[i];
        }
    }
    qsort(t->items, t->count, sizeof(*t->items), talker_by_bytes);
    return true;
}

/* Every name behind the remote ends of all of them. */
static void talkers_names(const struct talkers *t, struct ft_address_names *behind)
{
    *behind = (struct ft_address_names){0};
    for (size_t i = 0; i < t->count; i++)
        ft_kept_names_gather(&t->items[i].names, behind);
    ft_address_names_sort(behind);
}

enum talker_field : uint8_t {
    TALKER_PID,
    TALKER_PROCESS,
    TALKER_NAME,
    TALKER_RATE,
    TALKER_TX,
    TALKER_RX,
};

struct talker_table {
    const struct talkers *talkers;
    enum talker_field fields[TALKER_RX + 1];
};

static const char *talker_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    const struct talker_table *t = ctx;
    const struct talker *it = &t->talkers->items[r];

    switch (t->fields[c]) {
    case TALKER_PID:
        snprintf(buf, size, "%" PRIu32, it->pid);
        break;
    case TALKER_PROCESS:
        snprintf(buf, size, "%s", it->comm[0] ? it->comm : "-");
        break;
    case TALKER_NAME:
        ft_kept_names_format(&it->names, buf, size);
        return buf[0] ? buf : "-";
    case TALKER_RATE:
        ft_format_rate(it->rate, buf, size);
        break;
    case TALKER_TX:
        ft_format_bytes(it->tx, buf, size);
        break;
    case TALKER_RX:
        ft_format_bytes(it->rx, buf, size);
        break;
    }
    return buf;
}

/* The first shown of them, with a NAME column where one of those has a name. */
static void talkers_table(FILE *o, const struct talkers *t, size_t shown)
{
    static const struct ft_column_spec columns[] = {
        [TALKER_PID] = {"PID", false},   [TALKER_PROCESS] = {"PROCESS", false},
        [TALKER_NAME] = {"NAME", false}, [TALKER_RATE] = {"OUTBOUND", true},
        [TALKER_TX] = {"SENT", true},    [TALKER_RX] = {"RECEIVED", true},
    };
    struct ft_column_spec specs[FT_ARRAY_LEN(columns)];
    struct talker_table table = {.talkers = t};
    bool named = false;
    size_t n = 0;

    for (size_t i = 0; i < shown; i++)
        named = named || t->items[i].names.first;
    for (enum talker_field k = TALKER_PID; k <= TALKER_RX; k++) {
        if (k == TALKER_NAME && !named)
            continue;
        table.fields[n] = k;
        specs[n++] = columns[k];
    }
    ft_table_print(o, specs, n, shown, talker_cell, &table, ft_term_styled(o));
}

static int inspect_ip(struct inspect *in, const char *arg)
{
    struct ft_rows flows;
    struct ft_rows transfers = {0};
    struct talkers talkers = {0};
    struct ft_address_names behind;
    struct ft_endpoint net;
    struct ft_query q;
    FILE *o = in->out.stream;
    uint64_t tx = 0;
    uint64_t rx = 0;
    uint64_t rate = 0;
    uint8_t bits;
    char a[64];
    char b[64];

    if (!ft_prefix_parse(arg, &net, &bits))
        return ft_usage_error("inspect", "'%s' is not an IP address or CIDR network", arg);
    uint8_t host_bits = (uint8_t)((net.family == 6 ? 128 : 32) - bits);

    ft_query_init(&q, FT_Q_FLOWS);
    q.remote = net;
    q.remote_host_bits = host_bits;
    int code = fetch(in, &q, FT_MSG_ROW_FLOW, &flows);
    if (code == FT_EXIT_OK) {
        ft_query_init(&q, FT_Q_TRANSFERS);
        q.remote = net;
        q.remote_host_bits = host_bits;
        q.sort = FT_SORT_TIME;
        code = fetch(in, &q, FT_MSG_ROW_TRANSFER, &transfers);
    }
    if (code == FT_EXIT_OK && !group_talkers(&flows, &talkers))
        code = FT_EXIT_ERROR;
    if (code != FT_EXIT_OK)
        goto out;

    for (size_t i = 0; i < talkers.count; i++) {
        tx += talkers.items[i].tx;
        rx += talkers.items[i].rx;
        rate += talkers.items[i].rate;
    }
    talkers_names(&talkers, &behind);

    if (in->out.format == FT_FMT_JSON) {
        fputs("{\"kind\":\"ip\",\"network\":", o);
        ft_json_string(o, arg);
        fprintf(o,
                ",\"totals\":{\"bytes_sent\":%" PRIu64 ",\"bytes_received\":%" PRIu64
                ",\"bytes_sent_per_second\":%" PRIu64 ",\"flows\":%zu,\"processes\":%zu,"
                "\"transfers\":%zu",
                tx, rx, rate, flows.count, talkers.count, transfers.count);
        ft_json_names(o, "names", &behind);
        fputs("},\"processes\":[", o);
        for (size_t i = 0; i < talkers.count; i++) {
            const struct talker *t = &talkers.items[i];
            struct ft_address_names used;
            fprintf(o, "%s{\"pid\":%" PRIu32 ",\"name\":", i ? "," : "", t->pid);
            ft_json_string(o, t->comm);
            fprintf(o,
                    ",\"bytes_sent\":%" PRIu64 ",\"bytes_received\":%" PRIu64
                    ",\"bytes_sent_per_second\":%" PRIu64,
                    t->tx, t->rx, t->rate);
            ft_kept_names_behind(&t->names, &used);
            ft_json_names(o, "remote_names", &used);
            fputc('}', o);
        }
        fputs("],\"transfers\":", o);
        ft_view_json_array(FT_VIEW_FILES, &transfers, o);
        json_tail(in, o);
        goto out;
    }
    if (flows.count == 0) {
        ft_format_time_local(in->end.observed_since_wall_ns, a, sizeof(a));
        fprintf(o,
                "No traffic with %s has been observed since %s.\n"
                "Nothing earlier is kept.\n",
                arg, a);
        goto out;
    }

    section(o, bits == (net.family == 6 ? 128 : 32) ? "ADDRESS" : "NETWORK");
    field(o, "Remote:", "%s", arg);
    names_field(o, &behind);
    ft_format_bytes(tx, a, sizeof(a));
    ft_format_rate(rate, b, sizeof(b));
    field(o, "Sent to it:", "%s (%s)", a, b);
    ft_format_bytes(rx, a, sizeof(a));
    field(o, "Received from it:", "%s", a);
    field(o, "Flows:", "%zu", flows.count);
    field(o, "Processes:", "%zu", talkers.count);
    field(o, "File transfers:", "%zu", transfers.count);

    size_t shown = in->limit < talkers.count ? in->limit : talkers.count;
    fputc('\n', o);
    section(o, "PROCESSES");
    talkers_table(o, &talkers, shown);
    more_note(o, talkers.count, shown, "process", "processes");

    sent_files(in, &transfers, "FILES SENT TO IT",
               "No file has been associated with what was sent to it.");
    history_note(in, o);

out:
    talkers_free(&talkers);
    ft_rows_free(&flows);
    ft_rows_free(&transfers);
    return code;
}

int ft_cmd_inspect(const struct ft_cli *cli, struct ft_args *a)
{
    static const struct {
        const char *kind;
        int (*run)(struct inspect *in, const char *arg);
    } kinds[] = {
        {"file", inspect_file}, {"process", inspect_process}, {"socket", inspect_socket},
        {"flow", inspect_flow}, {"ip", inspect_ip},
    };
    struct inspect in = {.limit = 20};
    int (*run)(struct inspect *in, const char *arg) = nullptr;
    const char *kind = nullptr;
    const char *subject = nullptr;
    const char *output_path = nullptr;
    const char *v;
    int r;

    ft_output_init(&in.out);
    in.out.format = ft_cli_format(cli, FT_FORMATS_REPORT);
    while (!ft_args_done(a)) {
        if ((r = ft_args_format(a, "inspect", FT_FORMATS_REPORT, &in.out.format)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
        } else if ((r = ft_args_value(a, "--limit", &v)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            if (!ft_parse_u32(v, &in.limit) || in.limit == 0)
                return ft_usage_error("inspect", "invalid value '%s' for --limit", v);
        } else if ((r = ft_args_value(a, "--since", &v)) != 0) {
            uint64_t ago;
            if (r < 0)
                return FT_EXIT_USAGE;
            if (ft_parse_duration(v, &ago)) {
                uint64_t now = ft_clock_wall_ns();
                in.since_wall_ns = ago >= now ? 1 : now - ago;
            } else if (!ft_parse_time_rfc3339(v, &in.since_wall_ns)) {
                return ft_usage_error("inspect",
                                      "invalid value '%s' for --since (expected a duration such "
                                      "as 10m or an RFC 3339 time)",
                                      v);
            }
        } else if ((r = ft_args_value(a, "--output", &v)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            output_path = v;
        } else if (ft_args_flag(a, "--resolve-hostnames")) {
            in.resolve = true;
        } else if (!kind) {
            kind = ft_args_take(a);
        } else if (!subject) {
            subject = ft_args_take(a);
        } else {
            return ft_usage_error("inspect", "unknown argument '%s' for 'inspect'",
                                  ft_args_peek(a));
        }
    }

    for (size_t i = 0; kind && i < FT_ARRAY_LEN(kinds); i++) {
        if (strcmp(kind, kinds[i].kind) == 0)
            run = kinds[i].run;
    }
    if (!kind)
        return ft_usage_error("inspect", "missing what to inspect (file, process, socket, flow "
                                         "or ip)");
    if (!run)
        return ft_usage_error(
            "inspect", "cannot inspect '%s' (expected file, process, socket, flow or ip)", kind);
    if (!subject)
        return ft_usage_error("inspect", "missing the %s to inspect", kind);

    struct ft_session session;
    int code = ft_output_open(&in.out, output_path);
    if (code != FT_EXIT_OK)
        return code;
    code = ft_session_open(cli, false, &session);
    if (code != FT_EXIT_OK) {
        ft_output_close(&in.out);
        return code;
    }

    in.session = &session;
    ft_view_resolve_hosts(in.resolve);
    code = run(&in, subject);
    if (code == FT_EXIT_OK && in.queried) {
        struct ft_error none = {0};
        fflush(in.out.stream);
        code = ft_finish_query(FT_EXIT_OK, &none, &in.end, &in.out);
    }
    ft_session_close(&session);
    ft_output_close(&in.out);
    return code;
}
