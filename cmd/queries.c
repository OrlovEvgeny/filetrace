#include "cmd/cli.h"

#include "exporters/exporters.h"
#include "filetrace/format.h"
#include "ui/ui.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_footer(const struct ft_output *out, const struct ft_rows *rows,
                         const struct ft_msg_end *end, const char *what, bool incomplete)
{
    char since[32];
    bool styled = ft_term_styled(out->stream);

    if (out->format != FT_FMT_TABLE)
        return;
    ft_format_time_local(end->observed_since_wall_ns, since, sizeof(since));
    if (incomplete)
        fputs("\n* Events were lost while this transfer was in progress; "
              "its byte count may be low.\n",
              out->stream);
    fprintf(out->stream, "\n%s", styled ? FT_STYLE_DIM : "");
    if (rows->count == 0)
        fprintf(out->stream, "No %s observed since %s.", what, since);
    else
        fprintf(out->stream, "Observed since %s. History is not kept across agent restarts.",
                since);
    fprintf(out->stream, "%s\n", styled ? FT_STYLE_RESET : "");
}

static bool any_incomplete(const struct ft_rows *rows)
{
    struct ft_row_transfer *row = malloc(sizeof(*row));
    bool found = false;

    for (size_t i = 0; row && i < rows->count && !found; i++) {
        ft_rows_get(rows, i, row, sizeof(*row));
        found = (row->flags & FT_XFER_INCOMPLETE) != 0;
    }
    free(row);
    return found;
}

static int run_list(const struct ft_cli *cli, struct ft_query_args *qa, enum ft_view_id view,
                    uint16_t row_type, bool rank, const char *what)
{
    struct ft_session session;
    struct ft_rows rows;
    struct ft_msg_end end = {0};
    struct ft_error err = {0};

    int code = ft_output_open(&qa->out, qa->output_path);
    if (code != FT_EXIT_OK)
        return code;
    code = ft_session_open(cli, false, &session);
    if (code != FT_EXIT_OK) {
        ft_output_close(&qa->out);
        return code;
    }

    ft_rows_init(&rows, row_type);
    code = ft_client_query(session.client, &qa->query, ft_rows_collect, &rows, &end, &err);
    if (code == FT_EXIT_OK) {
        ft_view_resolve_hosts(qa->resolve);
        ft_view_prefetch_hosts(view, &rows);
        ft_view_render(view, &rows, &qa->out, rank);
        print_footer(&qa->out, &rows, &end, what,
                     row_type == FT_MSG_ROW_TRANSFER && any_incomplete(&rows));
    }
    code = ft_finish_query(code, &err, &end, &qa->out);

    ft_rows_free(&rows);
    ft_session_close(&session);
    ft_output_close(&qa->out);
    return code;
}

static int unknown_argument(const char *command, const struct ft_args *a)
{
    return ft_usage_error(command, "unknown argument '%s' for '%s'", ft_args_peek(a), command);
}

struct group {
    char *label; /* "" for flows without one, as those nobody named */
    uint64_t tx;
    uint64_t rx;
    uint64_t count;
    struct ft_kept_names names; /* of the remote ends of its flows */
    uint8_t confidence;
};

struct groups {
    struct group *items;
    size_t count;
    size_t capacity;
};

struct group_layout {
    const char *label_title;
    const char *label_key;
    const char *count_title; /* nullptr: no count column */
    const char *count_key;
    bool received;
    bool confidence;
    bool rank;
    bool names; /* the names behind each group's remote ends */
};

static bool groups_add(struct groups *g, const char *label, uint64_t tx, uint64_t rx,
                       uint8_t confidence, const struct ft_remote_names *names)
{
    if (g->count == g->capacity) {
        size_t cap = g->capacity ? g->capacity * 2 : 64;
        struct group *items = realloc(g->items, cap * sizeof(*items));
        if (!items)
            return false;
        g->items = items;
        g->capacity = cap;
    }
    char *copy = strdup(label);
    if (!copy)
        return false;
    struct group *it = &g->items[g->count++];
    *it = (struct group){.label = copy, .tx = tx, .rx = rx, .count = 1, .confidence = confidence};
    return !names || ft_kept_names_add(&it->names, names, tx);
}

static void group_free(struct group *g)
{
    free(g->label);
    ft_kept_names_free(&g->names);
}

static int group_by_label(const void *a, const void *b)
{
    return strcmp(((const struct group *)a)->label, ((const struct group *)b)->label);
}

static int group_by_tx(const void *a, const void *b)
{
    const struct group *x = a;
    const struct group *y = b;
    if (x->tx != y->tx)
        return x->tx < y->tx ? 1 : -1;
    return strcmp(x->label, y->label);
}

static int group_by_rx(const void *a, const void *b)
{
    const struct group *x = a;
    const struct group *y = b;
    if (x->rx != y->rx)
        return x->rx < y->rx ? 1 : -1;
    return strcmp(x->label, y->label);
}

static void groups_merge_and_rank(struct groups *g, bool by_received, uint32_t limit)
{
    size_t out = 0;

    if (g->count == 0)
        return;
    qsort(g->items, g->count, sizeof(*g->items), group_by_label);
    for (size_t i = 1; i < g->count; i++) {
        struct group *last = &g->items[out];
        struct group *cur = &g->items[i];
        if (strcmp(last->label, cur->label) == 0) {
            last->tx += cur->tx;
            last->rx += cur->rx;
            last->count += cur->count;
            /* A group is only as certain as its least certain member. */
            if (cur->confidence < last->confidence)
                last->confidence = cur->confidence;
            ft_kept_names_join(&last->names, &cur->names);
            free(cur->label);
        } else {
            g->items[++out] = *cur;
        }
    }
    g->count = out + 1;
    qsort(g->items, g->count, sizeof(*g->items), by_received ? group_by_rx : group_by_tx);
    if (limit && limit < g->count) {
        for (size_t i = limit; i < g->count; i++)
            group_free(&g->items[i]);
        g->count = limit;
    }
}

static void groups_free(struct groups *g)
{
    for (size_t i = 0; i < g->count; i++)
        group_free(&g->items[i]);
    free(g->items);
}

static bool any_group_named(const struct groups *g)
{
    for (size_t i = 0; i < g->count; i++) {
        if (g->items[i].names.first)
            return true;
    }
    return false;
}

/* Every name behind the group, most bytes first, joined by sep. */
static void group_names_text(const struct group *g, const char *sep, char *buf, size_t size)
{
    struct ft_address_names behind;
    size_t used = 0;

    ft_kept_names_behind(&g->names, &behind);
    buf[0] = '\0';
    for (size_t i = 0; i < behind.count && used < size; i++)
        used +=
            (size_t)snprintf(buf + used, size - used, "%s%s", i ? sep : "", behind.names[i].name);
}

static void group_names_json(FILE *o, const struct group *g)
{
    struct ft_address_names behind;

    ft_kept_names_behind(&g->names, &behind);
    ft_json_names(o, "remote_names", &behind);
}

struct group_table {
    const struct groups *groups;
    const struct group_layout *layout;
    uint8_t kinds[7];
};

enum : uint8_t {
    GC_RANK,
    GC_LABEL,
    GC_NAME,
    GC_TX,
    GC_RX,
    GC_COUNT,
    GC_CONFIDENCE
};

static const char *group_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    const struct group_table *t = ctx;
    const struct group *g = &t->groups->items[r];

    switch (t->kinds[c]) {
    case GC_RANK:
        snprintf(buf, size, "%zu", r + 1);
        return buf;
    case GC_LABEL:
        return g->label[0] ? g->label : "-";
    case GC_NAME:
        ft_kept_names_format(&g->names, buf, size);
        return buf[0] ? buf : "-";
    case GC_TX:
        ft_format_bytes(g->tx, buf, size);
        return buf;
    case GC_RX:
        ft_format_bytes(g->rx, buf, size);
        return buf;
    case GC_COUNT:
        snprintf(buf, size, "%" PRIu64, g->count);
        return buf;
    default: {
        const char *name = ft_confidence_name((enum ft_confidence)g->confidence);
        size_t i = 0;
        for (; name[i] && i + 1 < size; i++)
            buf[i] = (char)(name[i] - ('a' <= name[i] && name[i] <= 'z' ? 32 : 0));
        buf[i] = '\0';
        return buf;
    }
    }
}

static void groups_render(const struct groups *g, const struct group_layout *layout,
                          const struct ft_output *out)
{
    FILE *o = out->stream;

    if (out->format == FT_FMT_TABLE) {
        struct ft_column_spec specs[7];
        struct group_table table = {.groups = g, .layout = layout};
        size_t n = 0;

        if (layout->rank) {
            table.kinds[n] = GC_RANK;
            specs[n++] = (struct ft_column_spec){"RANK", false};
        }
        table.kinds[n] = GC_LABEL;
        specs[n++] = (struct ft_column_spec){layout->label_title, false};
        if (layout->names && any_group_named(g)) {
            table.kinds[n] = GC_NAME;
            specs[n++] = (struct ft_column_spec){"NAME", false};
        }
        table.kinds[n] = GC_TX;
        specs[n++] = (struct ft_column_spec){"SENT", true};
        if (layout->received) {
            table.kinds[n] = GC_RX;
            specs[n++] = (struct ft_column_spec){"RECEIVED", true};
        }
        if (layout->count_title) {
            table.kinds[n] = GC_COUNT;
            specs[n++] = (struct ft_column_spec){layout->count_title, true};
        }
        if (layout->confidence) {
            table.kinds[n] = GC_CONFIDENCE;
            specs[n++] = (struct ft_column_spec){"CONFIDENCE", false};
        }
        ft_table_print(o, specs, n, g->count, group_cell, &table, ft_term_styled(o));
        return;
    }

    if (out->format == FT_FMT_QUIET) {
        for (size_t i = 0; i < g->count; i++) {
            if (g->items[i].label[0])
                fprintf(o, "%s\n", g->items[i].label);
        }
        return;
    }

    if (out->format == FT_FMT_CSV) {
        char names[FT_ADDRESS_NAMES * FT_NAME_MAX];

        fprintf(o, "%s,bytes_sent", layout->label_key);
        if (layout->received)
            fputs(",bytes_received", o);
        if (layout->count_key)
            fprintf(o, ",%s", layout->count_key);
        if (layout->confidence)
            fputs(",confidence", o);
        if (layout->names)
            fputs(",remote_names", o);
        fputc('\n', o);
        for (size_t i = 0; i < g->count; i++) {
            const struct group *it = &g->items[i];
            ft_csv_field(o, it->label);
            fprintf(o, ",%" PRIu64, it->tx);
            if (layout->received)
                fprintf(o, ",%" PRIu64, it->rx);
            if (layout->count_key)
                fprintf(o, ",%" PRIu64, it->count);
            if (layout->confidence)
                fprintf(o, ",%s", ft_confidence_name((enum ft_confidence)it->confidence));
            if (layout->names) {
                group_names_text(it, ";", names, sizeof(names));
                fputc(',', o);
                ft_csv_field(o, names);
            }
            fputc('\n', o);
        }
        return;
    }

    bool array = out->format == FT_FMT_JSON;
    if (array)
        fputc('[', o);
    for (size_t i = 0; i < g->count; i++) {
        const struct group *it = &g->items[i];
        if (array)
            fputs(i ? ",\n " : "\n ", o);
        fputc('{', o);
        if (it->label[0]) {
            fprintf(o, "\"%s\":", layout->label_key);
            ft_json_string(o, it->label);
            fputc(',', o);
        }
        fprintf(o, "\"bytes_sent\":%" PRIu64, it->tx);
        if (layout->received)
            fprintf(o, ",\"bytes_received\":%" PRIu64, it->rx);
        if (layout->count_key)
            fprintf(o, ",\"%s\":%" PRIu64, layout->count_key, it->count);
        if (layout->confidence)
            fprintf(o, ",\"confidence\":\"%s\"",
                    ft_confidence_name((enum ft_confidence)it->confidence));
        if (layout->names)
            group_names_json(o, it);
        fputc('}', o);
        if (!array)
            fputc('\n', o);
    }
    if (array)
        fputs(g->count ? "\n]\n" : "]\n", o);
}

enum flow_grouping : uint8_t {
    GROUP_NONE,
    GROUP_PROCESS,
    GROUP_REMOTE,
    GROUP_NAME,
    GROUP_PORT,
    GROUP_PROTOCOL,
    GROUP_FILE,
};

static const struct group_layout flow_layouts[] = {
    [GROUP_PROCESS] = {"PROCESS", "process", "FLOWS", "flows", true, false, false, false},
    [GROUP_REMOTE] = {"REMOTE", "remote_ip", "FLOWS", "flows", true, false, false, true},
    [GROUP_NAME] = {"NAME", "remote_name", "FLOWS", "flows", true, false, false, false},
    [GROUP_PORT] = {"REMOTE PORT", "remote_port", "FLOWS", "flows", true, false, false, false},
    [GROUP_PROTOCOL] = {"PROTO", "protocol", "FLOWS", "flows", true, false, false, false},
    [GROUP_FILE] = {"FILE", "file", "TRANSFERS", "transfers", false, true, false, false},
};

static int run_grouped(const struct ft_cli *cli, struct ft_query_args *qa,
                       enum flow_grouping grouping, bool rank, bool by_received, uint32_t limit,
                       const char *what)
{
    struct ft_session session;
    struct ft_rows rows;
    struct ft_msg_end end = {0};
    struct ft_error err = {0};
    struct groups groups = {0};
    struct group_layout layout = flow_layouts[grouping];
    char label[FT_PATH_MAX + 64];

    layout.rank = rank;
    int code = ft_output_open(&qa->out, qa->output_path);
    if (code != FT_EXIT_OK)
        return code;
    code = ft_session_open(cli, false, &session);
    if (code != FT_EXIT_OK) {
        ft_output_close(&qa->out);
        return code;
    }

    bool files = grouping == GROUP_FILE;
    ft_rows_init(&rows, files ? FT_MSG_ROW_TRANSFER : FT_MSG_ROW_FLOW);
    code = ft_client_query(session.client, &qa->query, ft_rows_collect, &rows, &end, &err);

    if (code == FT_EXIT_OK && grouping == GROUP_REMOTE) {
        ft_view_resolve_hosts(qa->resolve);
        ft_view_prefetch_hosts(FT_VIEW_FLOWS, &rows);
    }

    struct ft_row_transfer *transfer = files ? malloc(sizeof(*transfer)) : nullptr;
    for (size_t i = 0; code == FT_EXIT_OK && i < rows.count; i++) {
        if (files) {
            if (!transfer)
                break;
            ft_rows_get(&rows, i, transfer, sizeof(*transfer));
            if (transfer->flags & FT_XFER_PATH_KNOWN)
                ft_strlcpy(label, transfer->path, sizeof(label));
            else
                snprintf(label, sizeof(label), "(device %" PRIu64 " inode %" PRIu64 ")",
                         transfer->dev, transfer->ino);
            groups_add(&groups, label, transfer->bytes, 0, transfer->confidence, nullptr);
            continue;
        }

        struct ft_row_flow flow;
        struct ft_remote_names names;
        char proto[8];
        ft_rows_get(&rows, i, &flow, sizeof(flow));
        ft_row_flow_names(&flow, &names);
        switch (grouping) {
        case GROUP_PROCESS:
            ft_strlcpy(label, flow.comm, sizeof(label));
            break;
        case GROUP_REMOTE: {
            const char *host = qa->resolve ? ft_resolver_name(&flow.remote) : nullptr;
            if (host)
                snprintf(label, sizeof(label), "%s", host);
            else
                ft_addr_format(&flow.remote, label, sizeof(label));
            break;
        }
        case GROUP_NAME:
            ft_strlcpy(label, ft_remote_name(&names), sizeof(label));
            break;
        case GROUP_PORT:
            snprintf(label, sizeof(label), "%u", flow.remote.port);
            break;
        default:
            snprintf(label, sizeof(label), "%s", ft_proto_name(flow.proto, proto));
            break;
        }
        groups_add(&groups, label, flow.tx_bytes, flow.rx_bytes, FT_CONF_UNKNOWN,
                   layout.names ? &names : nullptr);
    }
    free(transfer);

    if (code == FT_EXIT_OK) {
        struct ft_rows shown = {.count = groups.count};
        groups_merge_and_rank(&groups, by_received, limit);
        shown.count = groups.count;
        groups_render(&groups, &layout, &qa->out);
        print_footer(&qa->out, &shown, &end, what, false);
    }
    code = ft_finish_query(code, &err, &end, &qa->out);

    groups_free(&groups);
    ft_rows_free(&rows);
    ft_session_close(&session);
    ft_output_close(&qa->out);
    return code;
}

int ft_cmd_processes(const struct ft_cli *cli, struct ft_args *a)
{
    struct ft_query_args qa;

    ft_query_args_init(&qa, "processes", FT_Q_PROCESSES, FT_OPTS_PROCESSES, FT_SORTS_PROCESSES);
    while (!ft_args_done(a)) {
        int r = ft_query_args_parse(&qa, a);
        if (r < 0)
            return FT_EXIT_USAGE;
        if (r > 0)
            continue;
        if (ft_args_flag(a, "--active-only"))
            qa.query.flags |= FT_QF_ACTIVE;
        else if (ft_args_flag(a, "--include-children"))
            qa.query.flags |= FT_QF_INCLUDE_CHILDREN;
        else
            return ft_query_args_refuse(&qa, a);
    }
    ft_query_args_finish(&qa, cli);
    return run_list(cli, &qa, FT_VIEW_PROCESSES, FT_MSG_ROW_PROCESS, false,
                    "processes with network activity");
}

int ft_cmd_connections(const struct ft_cli *cli, struct ft_args *a)
{
    struct ft_query_args qa;

    ft_query_args_init(&qa, "connections", FT_Q_CONNECTIONS, FT_OPTS_CONNECTIONS,
                       FT_SORTS_CONNECTIONS);
    while (!ft_args_done(a)) {
        int r = ft_query_args_parse(&qa, a);
        if (r < 0)
            return FT_EXIT_USAGE;
        if (r > 0)
            continue;
        if (ft_args_flag(a, "--active"))
            qa.query.flags |= FT_QF_ACTIVE;
        else
            return ft_query_args_refuse(&qa, a);
    }
    ft_query_args_finish(&qa, cli);
    return run_list(cli, &qa, FT_VIEW_CONNECTIONS, FT_MSG_ROW_CONNECTION, false, "connections");
}

int ft_cmd_flows(const struct ft_cli *cli, struct ft_args *a)
{
    struct ft_query_args qa;
    enum flow_grouping grouping = GROUP_NONE;
    const char *v;

    ft_query_args_init(&qa, "flows", FT_Q_FLOWS, FT_OPTS_FLOWS, FT_SORTS_FLOWS);
    while (!ft_args_done(a)) {
        int r = ft_query_args_parse(&qa, a);
        if (r < 0)
            return FT_EXIT_USAGE;
        if (r > 0)
            continue;
        if (ft_args_flag(a, "--active")) {
            qa.query.flags |= FT_QF_ACTIVE;
        } else if ((r = ft_args_value(a, "--group-by", &v)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            if (strcmp(v, "process") == 0)
                grouping = GROUP_PROCESS;
            else if (strcmp(v, "remote") == 0)
                grouping = GROUP_REMOTE;
            else if (strcmp(v, "name") == 0)
                grouping = GROUP_NAME;
            else if (strcmp(v, "port") == 0)
                grouping = GROUP_PORT;
            else if (strcmp(v, "protocol") == 0)
                grouping = GROUP_PROTOCOL;
            else
                return ft_usage_error("flows",
                                      "invalid value '%s' for --group-by (expected process, "
                                      "remote, name, port or protocol)",
                                      v);
        } else if ((r = ft_args_value(a, "--direction", &v)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            if (strcmp(v, "inbound") == 0)
                qa.query.sort = FT_SORT_INBOUND;
            else if (strcmp(v, "outbound") == 0)
                qa.query.sort = FT_SORT_OUTBOUND;
            else if (strcmp(v, "both") == 0)
                qa.query.sort = FT_SORT_BYTES;
            else
                return ft_usage_error("flows",
                                      "invalid value '%s' for --direction (expected inbound, "
                                      "outbound or both)",
                                      v);
        } else {
            return ft_query_args_refuse(&qa, a);
        }
    }
    ft_query_args_finish(&qa, cli);

    if (grouping == GROUP_NONE)
        return run_list(cli, &qa, FT_VIEW_FLOWS, FT_MSG_ROW_FLOW, false, "network flows");

    uint32_t limit = qa.query.limit;
    qa.query.limit = 0;
    return run_grouped(cli, &qa, grouping, false, qa.query.sort == FT_SORT_INBOUND, limit,
                       "network flows");
}

static int transfer_command(const struct ft_cli *cli, struct ft_args *a, const char *command,
                            enum ft_view_id view, bool unknown_by_default)
{
    struct ft_query_args qa;

    ft_query_args_init(&qa, command, FT_Q_TRANSFERS, FT_OPTS_TRANSFERS, FT_SORTS_TRANSFERS);
    if (unknown_by_default)
        qa.query.flags |= FT_QF_INCLUDE_UNKNOWN;

    while (!ft_args_done(a)) {
        int r = ft_query_args_parse(&qa, a);
        if (r < 0)
            return FT_EXIT_USAGE;
        if (r > 0)
            continue;
        if (ft_args_flag(a, "--deleted")) {
            qa.query.flags |= FT_QF_DELETED;
        } else if (ft_args_flag(a, "--include-unknown")) {
            qa.query.flags |= FT_QF_INCLUDE_UNKNOWN;
        } else {
            return ft_query_args_refuse(&qa, a);
        }
    }
    ft_query_args_finish(&qa, cli);

    /* An empty answer would read as "nothing was sent this way". */
    enum ft_method method = (enum ft_method)qa.query.method;
    if (method != FT_METHOD_ANY && !ft_method_observed(method)) {
        fprintf(stderr,
                "filetrace: transfers made with %s are not observed by this build, so none\n"
                "can be listed. 'filetrace capabilities' shows what is observed.\n",
                ft_method_name(method));
        return FT_EXIT_UNSUPPORTED;
    }
    return run_list(cli, &qa, view, FT_MSG_ROW_TRANSFER, false,
                    unknown_by_default ? "transfers" : "file transfers");
}

int ft_cmd_files(const struct ft_cli *cli, struct ft_args *a)
{
    return transfer_command(cli, a, "files", FT_VIEW_FILES, false);
}

int ft_cmd_transfers(const struct ft_cli *cli, struct ft_args *a)
{
    return transfer_command(cli, a, "transfers", FT_VIEW_TRANSFERS, true);
}

int ft_cmd_top_report(const struct ft_cli *cli, struct ft_args *a)
{
    static const uint32_t common =
        FT_QO_PID | FT_QO_PROCESS | FT_QO_PROTOCOL | FT_QO_TIME | FT_QO_LIMIT | FT_QO_OUTPUT;
    enum {
        TOP_PROCESSES,
        TOP_FILES,
        TOP_DESTINATIONS,
        TOP_CONNECTIONS
    } what;
    const char *subject = ft_args_take(a);
    struct ft_query_args qa;

    if (strcmp(subject, "processes") == 0)
        what = TOP_PROCESSES;
    else if (strcmp(subject, "files") == 0)
        what = TOP_FILES;
    else if (strcmp(subject, "destinations") == 0)
        what = TOP_DESTINATIONS;
    else if (strcmp(subject, "connections") == 0)
        what = TOP_CONNECTIONS;
    else
        return ft_usage_error("top",
                              "unknown subject '%s' (expected processes, files, "
                              "destinations or connections)",
                              subject);

    switch (what) {
    case TOP_PROCESSES:
        ft_query_args_init(&qa, "top", FT_Q_PROCESSES, common & ~(uint32_t)FT_QO_PROTOCOL, 0);
        qa.query.sort = FT_SORT_OUTBOUND;
        break;
    case TOP_FILES:
        ft_query_args_init(&qa, "top", FT_Q_TRANSFERS, common, 0);
        qa.query.sort = FT_SORT_BYTES;
        break;
    default:
        ft_query_args_init(&qa, "top", FT_Q_FLOWS, common, 0);
        qa.query.sort = FT_SORT_OUTBOUND;
        break;
    }
    static const char *const subjects[] = {
        [TOP_PROCESSES] = "top processes",
        [TOP_FILES] = "top files",
        [TOP_DESTINATIONS] = "top destinations",
        [TOP_CONNECTIONS] = "top connections",
    };
    qa.subject = subjects[what];

    while (!ft_args_done(a)) {
        int r = ft_query_args_parse(&qa, a);
        if (r < 0)
            return FT_EXIT_USAGE;
        if (r == 0)
            return ft_query_args_refuse(&qa, a);
    }
    ft_query_args_finish(&qa, cli);
    uint32_t limit = qa.query.limit ? qa.query.limit : 10;

    bool heading = qa.out.format == FT_FMT_TABLE && !qa.output_path;
    static const char *const headings[] = {
        "TOP PROCESSES BY OUTBOUND TRAFFIC",
        "TOP FILES BY BYTES SENT",
        "TOP DESTINATIONS BY OUTBOUND TRAFFIC",
        "TOP CONNECTIONS BY OUTBOUND TRAFFIC",
    };
    if (heading)
        printf("%s\n\n", headings[what]);

    switch (what) {
    case TOP_PROCESSES:
        qa.query.limit = limit;
        qa.query.min_bytes = 1;
        return run_list(cli, &qa, FT_VIEW_PROCESSES, FT_MSG_ROW_PROCESS, true,
                        "processes with network activity");
    case TOP_FILES:
        qa.query.limit = 0;
        return run_grouped(cli, &qa, GROUP_FILE, true, false, limit, "file transfers");
    case TOP_DESTINATIONS:
        qa.query.limit = 0;
        return run_grouped(cli, &qa, GROUP_REMOTE, true, false, limit, "network flows");
    default:
        qa.query.limit = limit;
        return run_list(cli, &qa, FT_VIEW_FLOWS, FT_MSG_ROW_FLOW, true, "network flows");
    }
}

enum stats_section : uint8_t {
    STATS_ALL,
    STATS_EVENTS,
    STATS_BUFFERS,
    STATS_RESOURCES,
};

static void stats_collect(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct ft_row_stats *row = ctx;
    if (type == FT_MSG_ROW_STATS)
        memcpy(row, payload, size < sizeof(*row) ? size : sizeof(*row));
}

static void usage_line(FILE *o, const char *name, const struct ft_table_usage *u)
{
    char count[32];
    char capacity[32];
    char evicted[32];

    ft_format_count(u->count, count, sizeof(count));
    ft_format_count(u->capacity, capacity, sizeof(capacity));
    ft_format_count(u->evictions, evicted, sizeof(evicted));
    fprintf(o, "%-18s%s of %s", name, count, capacity);
    if (u->evictions)
        fprintf(o, " (%s forgotten)", evicted);
    fputc('\n', o);
}

static void stats_table(FILE *o, const struct ft_row_stats *s, enum stats_section section)
{
    char a[64];
    char b[64];
    bool all = section == STATS_ALL;

    if (all) {
        fputs("FILETRACE STATISTICS\n\n", o);
        ft_format_duration(s->now_wall_ns > s->start_wall_ns ? s->now_wall_ns - s->start_wall_ns
                                                             : 0,
                           a, sizeof(a));
        ft_format_time_local(s->start_wall_ns, b, sizeof(b));
        fprintf(o, "UPTIME\n%s (since %s)\n\n", a, b);
    }

    if (all || section == STATS_EVENTS) {
        fputs("EVENTS\n", o);
        ft_format_count(s->events_received, a, sizeof(a));
        fprintf(o, "%-18s%s\n", "Received:", a);
        ft_format_count(s->events_processed, a, sizeof(a));
        fprintf(o, "%-18s%s\n", "Processed:", a);
        ft_format_count(s->events_dropped, a, sizeof(a));
        fprintf(o, "%-18s%s\n", "Dropped:", a);
        fprintf(o, "%-18s%" PRIu64 "\n", "Events/sec:", s->events_per_sec_milli / 1000);
        if (s->events_dropped) {
            static const char *const kinds[] = {"Queue overflow:", "Counter table full:",
                                                "Socket unidentified:", "Path buffer busy:"};
            for (size_t i = 0; i < FT_ARRAY_LEN(kinds); i++) {
                if (s->loss[i]) {
                    ft_format_count(s->loss[i], a, sizeof(a));
                    fprintf(o, "  %-20s%s\n", kinds[i], a);
                }
            }
            ft_format_time_local(s->last_loss_wall_ns, a, sizeof(a));
            fprintf(o, "%-18s%s\n", "Last loss:", a);
        }
        fputc('\n', o);
    }

    if (all || section == STATS_RESOURCES) {
        fputs("RESOURCES\n", o);
        fprintf(o, "%-18s%u.%02u%%\n", "CPU:", s->cpu_milli_percent / 1000,
                s->cpu_milli_percent % 1000 / 10);
        if (s->rss_bytes) {
            ft_format_bytes(s->rss_bytes, a, sizeof(a));
            fprintf(o, "%-18s%s\n", "Memory:", a);
        }
        fprintf(o, "%-18s%u\n\n", "Open FDs:", s->open_fds);
    }

    if (all || section == STATS_BUFFERS) {
        fputs("COLLECTOR\n", o);
        ft_format_bytes(s->queue_bytes, a, sizeof(a));
        fprintf(o, "%-18s%s\n", "Event queue:", a);
        fprintf(o, "%-18s%" PRIu64 "%%\n", "Peak utilization:",
                s->queue_bytes ? s->queue_peak_bytes * 100 / s->queue_bytes : 0);
        if (s->event_log_bytes) {
            ft_format_bytes(s->event_log_bytes, a, sizeof(a));
            ft_format_count(s->event_log_records, b, sizeof(b));
            fprintf(o, "%-18s%s, holding %s events", "Event log:", a, b);
            if (s->event_log_discarded) {
                ft_format_count(s->event_log_discarded, b, sizeof(b));
                fprintf(o, " (%s older ones discarded)", b);
            }
            fputc('\n', o);
        } else {
            fprintf(o, "%-18s%s\n", "Event log:", "off");
        }
        usage_line(o, "Processes:", &s->processes);
        usage_line(o, "Sockets:", &s->sockets);
        usage_line(o, "Flows:", &s->flows);
        usage_line(o, "Files:", &s->files);
        usage_line(o, "Transfers:", &s->transfers);
        if (s->listed_files.capacity) {
            ft_format_count(s->listed_files.count, a, sizeof(a));
            ft_format_count(s->listed_files.capacity, b, sizeof(b));
            fprintf(o, "%-18s%s of %s", "Listed files:", a, b);
            if (s->listed_files.evictions) {
                ft_format_count(s->listed_files.evictions, a, sizeof(a));
                fprintf(o, " (%s refused)", a);
            }
            fputc('\n', o);
        }
        if (s->leaders_bytes) {
            ft_format_bytes(s->leaders_bytes, a, sizeof(a));
            fprintf(o, "%-18s%s\n", "File rankings:", a);
        } else {
            fprintf(o, "%-18s%s\n", "File rankings:", "off");
        }
        if (s->names.capacity) {
            usage_line(o, "Names:", &s->names);
            usage_line(o, "Name lookups:", &s->name_lookups);
            if (s->name_libraries_configured > s->name_libraries.capacity) {
                ft_format_count(s->name_libraries.count, a, sizeof(a));
                ft_format_count(s->name_libraries.capacity, b, sizeof(b));
                fprintf(o, "%-18s%s of %s, ", "Name libraries:", a, b);
                ft_format_count(s->name_libraries_configured, a, sizeof(a));
                fprintf(o, "not the %s configured: the open file limit holds no more", a);
                if (s->name_libraries.evictions) {
                    ft_format_count(s->name_libraries.evictions, a, sizeof(a));
                    fprintf(o, " (%s forgotten)", a);
                }
                fputc('\n', o);
            } else if (s->name_libraries.capacity) {
                usage_line(o, "Name libraries:", &s->name_libraries);
            }
            if (s->tls_libraries) {
                ft_format_count(s->tls_libraries, a, sizeof(a));
                fprintf(o, "%-18s%s\n", "TLS libraries:", a);
            }
            if (s->names_invalid || s->names_refused) {
                ft_format_count(s->names_invalid, a, sizeof(a));
                ft_format_count(s->names_refused, b, sizeof(b));
                fprintf(o, "%-18s%s (invalid or too long), %s (table full)\n", "Names refused:", a,
                        b);
            }
        }
        if (s->candidates_rejected) {
            ft_format_count(s->candidates_rejected, a, sizeof(a));
            fprintf(o, "%-18s%s below the inference thresholds\n", "Candidates:", a);
        }
        fputc('\n', o);
    }

    if (all) {
        fputs("NETWORK\n", o);
        ft_format_bytes(s->tx_bytes, a, sizeof(a));
        ft_format_rate(s->tx_rate, b, sizeof(b));
        fprintf(o, "%-18s%s (%s)\n", "Outbound:", a, b);
        ft_format_bytes(s->rx_bytes, a, sizeof(a));
        ft_format_rate(s->rx_rate, b, sizeof(b));
        fprintf(o, "%-18s%s (%s)\n", "Inbound:", a, b);
        fprintf(o, "%-18s%u\n", "Open sockets:", s->open_sockets);
        fprintf(o, "%-18s%u\n", "Active flows:", s->active_flows);
        fprintf(o, "%-18s%u\n\n", "Active transfers:", s->active_transfers);

        fprintf(o, "BACKEND\n%s, %s mode\n\n", s->backend, s->mode);
        fprintf(o, "STATUS\n%s\n", s->health == FT_HEALTH_OK ? "Healthy" : "Degraded");
    }
}

static void usage_json(FILE *o, const char *name, const struct ft_table_usage *u, bool last)
{
    fprintf(o,
            "\"%s\":{\"entries\":%" PRIu64 ",\"capacity\":%" PRIu64 ",\"evictions\":%" PRIu64 "}%s",
            name, u->count, u->capacity, u->evictions, last ? "" : ",");
}

static void stats_json(FILE *o, const struct ft_row_stats *s)
{
    char started[40];

    ft_format_time_rfc3339(s->start_wall_ns, started, sizeof(started));
    fprintf(o,
            "{\"status\":\"%s\",\"backend\":", s->health == FT_HEALTH_OK ? "healthy" : "degraded");
    ft_json_string(o, s->backend);
    fprintf(o, ",\"mode\":\"%s\",\"version\":\"%s\",\"pid\":%u,\"started\":\"%s\"", s->mode,
            s->version, s->pid, started);
    fprintf(o, ",\"uptime_seconds\":%" PRIu64,
            (s->now_wall_ns > s->start_wall_ns ? s->now_wall_ns - s->start_wall_ns : 0) /
                FT_NS_PER_SEC);
    fprintf(o,
            ",\"events\":{\"received\":%" PRIu64 ",\"processed\":%" PRIu64 ",\"dropped\":%" PRIu64
            ",\"per_second\":%" PRIu64 ".%03" PRIu64 ",\"dropped_queue_overflow\":%" PRIu64
            ",\"dropped_counter_table_full\":%" PRIu64 ",\"dropped_socket_unidentified\":%" PRIu64
            ",\"dropped_path_buffer_busy\":%" PRIu64 "}",
            s->events_received, s->events_processed, s->events_dropped,
            s->events_per_sec_milli / 1000, s->events_per_sec_milli % 1000, s->loss[0], s->loss[1],
            s->loss[2], s->loss[3]);
    fprintf(o,
            ",\"resources\":{\"cpu_percent\":%u.%03u,\"memory_bytes\":%" PRIu64 ",\"open_fds\":%u}",
            s->cpu_milli_percent / 1000, s->cpu_milli_percent % 1000, s->rss_bytes, s->open_fds);
    fprintf(o,
            ",\"collector\":{\"event_queue_bytes\":%" PRIu64 ",\"event_queue_peak_bytes\":%" PRIu64
            ",\"candidates_below_threshold\":%" PRIu64 ",\"event_log_bytes\":%" PRIu64
            ",\"event_log_events\":%" PRIu64 ",\"event_log_discarded\":%" PRIu64
            ",\"file_rankings_bytes\":%" PRIu64 ",",
            s->queue_bytes, s->queue_peak_bytes, s->candidates_rejected, s->event_log_bytes,
            s->event_log_records, s->event_log_discarded, s->leaders_bytes);
    usage_json(o, "processes", &s->processes, false);
    usage_json(o, "sockets", &s->sockets, false);
    usage_json(o, "flows", &s->flows, false);
    usage_json(o, "files", &s->files, false);
    usage_json(o, "transfers", &s->transfers, false);
    usage_json(o, "listed_files", &s->listed_files, !s->names.capacity);
    if (s->names.capacity) {
        usage_json(o, "names", &s->names, false);
        usage_json(o, "name_lookups", &s->name_lookups, false);
        usage_json(o, "name_libraries", &s->name_libraries, false);
        fprintf(o,
                "\"name_libraries_configured\":%" PRIu64 ",\"names_refused_invalid\":%" PRIu64
                ",\"names_refused_full\":%" PRIu64 ",\"tls_libraries\":%" PRIu64
                ",\"tls_library_capacity\":%" PRIu64,
                s->name_libraries_configured, s->names_invalid, s->names_refused, s->tls_libraries,
                s->tls_library_capacity);
    }
    fprintf(o,
            "},\"network\":{\"bytes_sent\":%" PRIu64 ",\"bytes_received\":%" PRIu64
            ",\"bytes_sent_per_second\":%" PRIu64 ",\"bytes_received_per_second\":%" PRIu64
            ",\"open_sockets\":%u,\"active_flows\":%u,\"active_transfers\":%u}}\n",
            s->tx_bytes, s->rx_bytes, s->tx_rate, s->rx_rate, s->open_sockets, s->active_flows,
            s->active_transfers);
}

int ft_cmd_stats(const struct ft_cli *cli, struct ft_args *a)
{
    enum stats_section section = STATS_ALL;
    enum ft_format format = ft_cli_format(cli, FT_FORMATS_REPORT);
    uint64_t interval_ns = FT_NS_PER_SEC;
    bool watch = false;
    const char *v;
    int r;

    const char *sub = ft_args_peek(a);
    if (sub && sub[0] != '-') {
        if (strcmp(sub, "events") == 0)
            section = STATS_EVENTS;
        else if (strcmp(sub, "buffers") == 0)
            section = STATS_BUFFERS;
        else if (strcmp(sub, "resources") == 0)
            section = STATS_RESOURCES;
        else
            return ft_usage_error(
                "stats", "unknown section '%s' (expected events, buffers or resources)", sub);
        ft_args_take(a);
    }
    while (!ft_args_done(a)) {
        if (ft_args_flag(a, "--watch")) {
            watch = true;
        } else if ((r = ft_args_value(a, "--interval", &v)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            if (!ft_parse_duration(v, &interval_ns) || interval_ns < 100 * FT_NS_PER_MS)
                return ft_usage_error("stats", "invalid value '%s' for --interval", v);
            watch = true;
        } else if ((r = ft_args_format(a, "stats", FT_FORMATS_REPORT, &format)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
        } else {
            return unknown_argument("stats", a);
        }
    }

    struct ft_session session;
    int code = ft_session_open(cli, false, &session);
    if (code != FT_EXIT_OK)
        return code;

    for (;;) {
        struct ft_query q;
        struct ft_row_stats row = {0};
        struct ft_msg_end end = {0};
        struct ft_error err = {0};

        ft_query_init(&q, FT_Q_STATS);
        code = ft_client_query(session.client, &q, stats_collect, &row, &end, &err);
        if (code != FT_EXIT_OK) {
            fprintf(stderr, "%s\n", err.msg);
            break;
        }
        if (format == FT_FMT_JSON)
            stats_json(stdout, &row);
        else
            stats_table(stdout, &row, section);
        fflush(stdout);
        if (row.health != FT_HEALTH_OK)
            code = FT_EXIT_PARTIAL;
        if (!watch)
            break;

        struct timespec ts = {(time_t)(interval_ns / FT_NS_PER_SEC),
                              (long)(interval_ns % FT_NS_PER_SEC)};
        nanosleep(&ts, nullptr);
        if (format != FT_FMT_JSON)
            fputc('\n', stdout);
    }
    ft_session_close(&session);
    return code;
}

int ft_cmd_watch(const struct ft_cli *cli, struct ft_args *a)
{
    struct ft_watch_options *opt = calloc(1, sizeof(*opt));
    struct ft_query_args *qa = calloc(1, sizeof(*qa));
    int code = FT_EXIT_OK;
    const char *v;
    int r;

    if (!opt || !qa) {
        free(opt);
        free(qa);
        return FT_EXIT_ERROR;
    }
    opt->interval_ns = FT_NS_PER_SEC;
    opt->timestamps = ft_cli_timestamps(cli);
    ft_query_args_init(qa, "watch", FT_Q_TRANSFERS, FT_OPTS_WATCH, FT_SORTS_WATCH);

    while (code == FT_EXIT_OK && !ft_args_done(a)) {
        r = ft_query_args_parse(qa, a);
        if (r < 0) {
            code = FT_EXIT_USAGE;
        } else if (r > 0) {
            continue;
        } else if ((r = ft_args_value(a, "--interval", &v)) != 0) {
            if (r < 0)
                code = FT_EXIT_USAGE;
            else if (!ft_parse_duration(v, &opt->interval_ns) ||
                     opt->interval_ns < 100 * FT_NS_PER_MS)
                code = ft_usage_error("watch",
                                      "invalid value '%s' for --interval (expected at least "
                                      "100ms)",
                                      v);
        } else if ((r = ft_args_value(a, "--direction", &v)) != 0) {
            if (r < 0)
                code = FT_EXIT_USAGE;
            else if (strcmp(v, "outbound") == 0)
                opt->direction = FT_WATCH_OUTBOUND;
            else if (strcmp(v, "inbound") == 0)
                opt->direction = FT_WATCH_INBOUND;
            else if (strcmp(v, "both") == 0)
                opt->direction = FT_WATCH_BOTH;
            else
                code = ft_usage_error("watch",
                                      "invalid value '%s' for --direction (expected inbound, "
                                      "outbound or both)",
                                      v);
        } else if (ft_args_flag(a, "--no-ui")) {
            opt->plain = true;
        } else if (ft_args_flag(a, "--addresses")) {
            opt->addresses = true;
        } else {
            code = ft_query_args_refuse(qa, a);
        }
    }

    if (code == FT_EXIT_OK) {
        struct ft_session session;

        opt->filter = qa->query;
        opt->resolve = qa->resolve;
        code = ft_session_open(cli, true, &session);
        if (code == FT_EXIT_OK) {
            code = ft_watch_run(&session, opt);
            ft_session_close(&session);
        }
    }
    free(opt);
    free(qa);
    return code;
}
