#include "filetrace/clock.h"
#include "filetrace/format.h"
#include "filetrace/state.h"

#include <regex.h>
#include <stdlib.h>
#include <string.h>

struct candidate {
    const char *text; /* when set, ordered by it first, ascending */
    uint64_t key;
    uint64_t tie;
    uint64_t bytes;
    const void *entry;
    bool unattributed;
};

/* Sorts after every name and path. */
static const char NO_TEXT[] = "\xff";

struct candidates {
    struct candidate *items;
    size_t count;
    size_t capacity;
};

struct span {
    uint64_t from_ns;
    uint64_t to_ns;
};

static struct span query_span(const struct ft_query *q)
{
    return (struct span){
        .from_ns = q->since_wall_ns ? ft_clock_wall_to_mono(q->since_wall_ns) : 0,
        .to_ns = q->until_wall_ns ? ft_clock_wall_to_mono(q->until_wall_ns) : UINT64_MAX,
    };
}

static bool in_span(const struct span *sp, uint64_t first_ns, uint64_t last_ns)
{
    return last_ns >= sp->from_ns && first_ns <= sp->to_ns;
}

static bool match_name(const char *pattern, const char *name)
{
    return pattern[0] == '\0' || ft_glob_match(pattern, name);
}

static bool match_addr(const struct ft_endpoint *filter, uint8_t host_bits,
                       const struct ft_endpoint *ep)
{
    if (filter->family == 0)
        return true;
    unsigned width = filter->family == 6 ? 128 : 32;
    return ft_addr_in_prefix(filter, (uint8_t)(host_bits >= width ? 0 : width - host_bits), ep);
}

static bool match_tuple(const struct ft_query *q, uint16_t proto, const struct ft_endpoint *local,
                        const struct ft_endpoint *remote)
{
    if (q->proto && q->proto != proto)
        return false;
    if (!match_addr(&q->remote, q->remote_host_bits, remote) ||
        !match_addr(&q->local, q->local_host_bits, local))
        return false;
    if (q->port && q->port != local->port && q->port != remote->port)
        return false;
    if (q->family && q->family != local->family && q->family != remote->family)
        return false;
    return true;
}

static bool process_in_scope(const struct ft_query *q, const struct ft_process *p)
{
    if ((q->flags & FT_QF_HAS_UID) && q->uid != p->uid)
        return false;
    if (q->cgroup_id && q->cgroup_id != p->cgroup_id)
        return false;
    return !q->ns_inum || q->ns_inum == p->netns || q->ns_inum == p->pidns ||
           q->ns_inum == p->mntns;
}

/* A socket or transfer is in scope when the process behind it is. */
static bool owner_in_scope(const struct ft_state *st, const struct ft_query *q, uint32_t pid)
{
    if (!q->cgroup_id && !q->ns_inum && !(q->flags & FT_QF_HAS_UID))
        return true;
    const struct ft_process *p = ft_table_find(st->processes, &pid);
    return p && process_in_scope(q, p);
}

static bool candidates_init(struct candidates *c, size_t capacity)
{
    c->items = malloc((capacity ? capacity : 1) * sizeof(*c->items));
    c->count = 0;
    c->capacity = capacity;
    return c->items != nullptr;
}

static void candidates_add(struct candidates *c, struct candidate item)
{
    if (c->count < c->capacity)
        c->items[c->count++] = item;
}

static int compare_candidates(const void *a, const void *b)
{
    const struct candidate *x = a;
    const struct candidate *y = b;
    if (x->text && y->text) {
        int order = strcmp(x->text, y->text);
        if (order != 0)
            return order;
    }
    if (x->key != y->key)
        return x->key < y->key ? 1 : -1;
    if (x->tie != y->tie)
        return x->tie < y->tie ? 1 : -1;
    return 0;
}

static size_t candidates_finish(struct candidates *c, const struct ft_query *q)
{
    qsort(c->items, c->count, sizeof(*c->items), compare_candidates);
    return q->limit && q->limit < c->count ? q->limit : c->count;
}

static bool socket_is_open(const struct ft_state *st, const struct ft_socket *s, uint64_t now_ns)
{
    enum ft_sock_state state = ft_state_socket_state(st, s, now_ns);
    return state != FT_SOCK_CLOSED && state != FT_SOCK_IDLE && state != FT_SOCK_UNKNOWN;
}

static bool transfer_is_active(const struct ft_state *st, uint64_t last_ns, uint64_t now_ns)
{
    return now_ns <= last_ns || now_ns - last_ns <= st->cfg.active_window_ns;
}

struct sent_file {
    uint32_t pid;
    struct ft_file_id file;
};

static int compare_sent_files(const void *a, const void *b)
{
    const struct sent_file *x = a;
    const struct sent_file *y = b;
    if (x->pid != y->pid)
        return x->pid < y->pid ? -1 : 1;
    if (x->file.dev != y->file.dev)
        return x->file.dev < y->file.dev ? -1 : 1;
    if (x->file.ino != y->file.ino)
        return x->file.ino < y->file.ino ? -1 : 1;
    if (x->file.instance != y->file.instance)
        return x->file.instance < y->file.instance ? -1 : 1;
    return 0;
}

static bool prepare_processes(struct ft_state *st, const struct ft_query *q, uint64_t now_ns)
{
    struct sent_file *sent = calloc(ft_table_count(st->transfers) + 1, sizeof(*sent));
    size_t nsent = 0;

    if (!sent)
        return false;

    for (struct ft_process *p = ft_table_first(st->processes); p;
         p = ft_table_next(st->processes, p)) {
        p->q_tx = p->tx_bytes;
        p->q_rx = p->rx_bytes;
        p->q_tx_rate = ft_rate_per_second(&p->tx_rate, now_ns);
        p->q_rx_rate = ft_rate_per_second(&p->rx_rate, now_ns);
        p->q_connections = 0;
        p->q_files = 0;
        p->q_transfers = 0;
        p->q_active_transfers = 0;
    }

    for (struct ft_socket *s = ft_table_first(st->sockets); s; s = ft_table_next(st->sockets, s)) {
        struct ft_process *p = ft_table_find(st->processes, &s->pid);
        if (p && socket_is_open(st, s, now_ns))
            p->q_connections++;
    }

    for (struct ft_transfer *t = ft_table_first(st->transfers); t;
         t = ft_table_next(st->transfers, t)) {
        enum ft_confidence conf;
        uint32_t evidence;
        struct ft_process *p = ft_table_find(st->processes, &t->pid);
        if (!p || !ft_state_classify(st, t, &conf, &evidence))
            continue;
        p->q_transfers++;
        if (transfer_is_active(st, t->last_ns, now_ns))
            p->q_active_transfers++;
        sent[nsent++] = (struct sent_file){.pid = t->pid, .file = t->file};
    }

    /* One file sent over several sockets counts once. */
    qsort(sent, nsent, sizeof(*sent), compare_sent_files);
    for (size_t i = 0; i < nsent; i++) {
        if (i > 0 && compare_sent_files(&sent[i - 1], &sent[i]) == 0)
            continue;
        struct ft_process *p = ft_table_find(st->processes, &sent[i].pid);
        if (p)
            p->q_files++;
    }
    free(sent);

    if (!(q->flags & FT_QF_INCLUDE_CHILDREN))
        return true;

    for (struct ft_process *p = ft_table_first(st->processes); p;
         p = ft_table_next(st->processes, p)) {
        p->q_own_connections = p->q_connections;
        p->q_own_files = p->q_files;
        p->q_own_transfers = p->q_transfers;
        p->q_own_active_transfers = p->q_active_transfers;
    }
    for (struct ft_process *c = ft_table_first(st->processes); c;
         c = ft_table_next(st->processes, c)) {
        uint32_t parent = c->ppid;
        for (int depth = 0; depth < 64 && parent != 0 && parent != c->pid; depth++) {
            struct ft_process *a = ft_table_find(st->processes, &parent);
            if (!a)
                break;
            a->q_tx += c->tx_bytes;
            a->q_rx += c->rx_bytes;
            a->q_tx_rate += ft_rate_per_second(&c->tx_rate, now_ns);
            a->q_rx_rate += ft_rate_per_second(&c->rx_rate, now_ns);
            a->q_connections += c->q_own_connections;
            a->q_files += c->q_own_files;
            a->q_transfers += c->q_own_transfers;
            a->q_active_transfers += c->q_own_active_transfers;
            parent = a->ppid;
        }
    }
    return true;
}

static bool query_processes(struct ft_state *st, const struct ft_query *q, uint64_t now_ns,
                            ft_row_fn *emit, void *ctx, struct ft_msg_end *end)
{
    struct span sp = query_span(q);
    struct candidates c;

    if (!prepare_processes(st, q, now_ns))
        return false;
    if (!candidates_init(&c, ft_table_count(st->processes)))
        return false;

    for (struct ft_process *p = ft_table_first(st->processes); p;
         p = ft_table_next(st->processes, p)) {
        if (p->q_tx == 0 && p->q_rx == 0 && p->q_connections == 0)
            continue;
        if (q->pid && q->pid != p->pid)
            continue;
        if (!process_in_scope(q, p))
            continue;
        if (!match_name(q->process, p->comm))
            continue;
        if ((q->flags & FT_QF_ACTIVE) && (p->exited || p->q_connections == 0))
            continue;
        if (!in_span(&sp, p->start_ns, p->last_ns ? p->last_ns : now_ns))
            continue;

        /* Rates rank what is moving now; totals order everything that is idle. */
        uint64_t key;
        uint64_t tie = UINT32_MAX - p->pid;
        switch (q->sort) {
        case FT_SORT_INBOUND:
            key = p->q_rx_rate;
            tie = p->q_rx;
            break;
        case FT_SORT_BYTES:
            key = p->q_tx + p->q_rx;
            break;
        case FT_SORT_CONNECTIONS:
            key = p->q_connections;
            break;
        case FT_SORT_PID:
            key = UINT32_MAX - p->pid;
            break;
        case FT_SORT_TIME:
            key = p->last_ns;
            break;
        default:
            key = p->q_tx_rate;
            tie = p->q_tx;
            break;
        }
        if (q->min_bytes && (q->sort == FT_SORT_INBOUND ? p->q_rx : p->q_tx) < q->min_bytes)
            continue;
        candidates_add(&c, (struct candidate){
                               .text = q->sort == FT_SORT_PROCESS ? p->comm : nullptr,
                               .key = key,
                               .tie = tie,
                               .entry = p,
                           });
    }

    size_t n = candidates_finish(&c, q);
    struct ft_row_process *row = malloc(sizeof(*row));
    for (size_t i = 0; row && i < n; i++) {
        const struct ft_process *p = c.items[i].entry;
        struct ft_process_strings text = {p->command_line, p->cwd, p->script};
        *row = (struct ft_row_process){
            .start_wall_ns = ft_clock_mono_to_wall(p->start_ns),
            .exit_wall_ns = ft_clock_mono_to_wall(p->exit_ns),
            .tx_bytes = p->q_tx,
            .rx_bytes = p->q_rx,
            .tx_rate = p->q_tx_rate,
            .rx_rate = p->q_rx_rate,
            .cgroup_id = p->cgroup_id,
            .pid = p->pid,
            .ppid = p->ppid,
            .uid = p->uid,
            .gid = p->gid,
            .pidns = p->pidns,
            .mntns = p->mntns,
            .netns = p->netns,
            .connections = p->q_connections,
            .files = p->q_files,
            .transfers = p->q_transfers,
            .active_transfers = p->q_active_transfers,
            .exit_status = p->exit_status,
            .flags = p->exited ? FT_PROC_EXITED : 0,
        };
        ft_strlcpy(row->comm, p->comm, sizeof(row->comm));
        ft_strlcpy(row->exe, p->exe, sizeof(row->exe));
        size_t size = offsetof(struct ft_row_process, text) +
                      ft_process_strings_pack(row->text, sizeof(row->text), &text);
        emit(ctx, FT_MSG_ROW_PROCESS, row, size);
    }
    bool ok = row != nullptr || n == 0;
    end->rows = ok ? (uint32_t)n : 0;
    free(row);
    free(c.items);
    return ok;
}

static void query_connections(struct ft_state *st, const struct ft_query *q, uint64_t now_ns,
                              ft_row_fn *emit, void *ctx, struct ft_msg_end *end)
{
    struct span sp = query_span(q);
    struct candidates c;

    if (!candidates_init(&c, ft_table_count(st->sockets)))
        return;

    for (struct ft_socket *s = ft_table_first(st->sockets); s; s = ft_table_next(st->sockets, s)) {
        enum ft_sock_state state = ft_state_socket_state(st, s, now_ns);

        if (q->state != FT_SOCK_ANY) {
            if (q->state != state)
                continue;
        } else if (state == FT_SOCK_CLOSED && now_ns - s->closed_ns > st->cfg.closed_retention_ns &&
                   q->since_wall_ns == 0 && q->sock_id == 0) {
            continue;
        }
        if ((q->flags & FT_QF_ACTIVE) && !socket_is_open(st, s, now_ns))
            continue;
        if (q->sock_id && q->sock_id != s->id)
            continue;
        if (q->pid && q->pid != s->pid)
            continue;
        if (!match_name(q->process, s->comm))
            continue;
        if (!match_tuple(q, s->proto, &s->local, &s->remote))
            continue;
        if (!in_span(&sp, s->first_ns, s->last_ns))
            continue;
        if (!owner_in_scope(st, q, s->pid))
            continue;

        uint64_t key;
        switch (q->sort) {
        case FT_SORT_OUTBOUND:
            key = s->tx_bytes;
            break;
        case FT_SORT_BYTES:
            key = s->tx_bytes + s->rx_bytes;
            break;
        case FT_SORT_DURATION:
            key = s->last_ns - s->first_ns;
            break;
        case FT_SORT_INBOUND:
            key = s->rx_bytes;
            break;
        case FT_SORT_PID:
            key = UINT32_MAX - s->pid;
            break;
        case FT_SORT_RATE:
            key = ft_rate_per_second(&s->tx_rate, now_ns) + ft_rate_per_second(&s->rx_rate, now_ns);
            break;
        default:
            key = s->last_ns;
            break;
        }
        candidates_add(&c, (struct candidate){
                               .text = q->sort == FT_SORT_PROCESS ? s->comm : nullptr,
                               .key = key,
                               .tie = s->id,
                               .entry = s,
                           });
    }

    size_t n = candidates_finish(&c, q);
    for (size_t i = 0; i < n; i++) {
        const struct ft_socket *s = c.items[i].entry;
        struct ft_row_connection row = {
            .sock_id = s->id,
            .first_wall_ns = ft_clock_mono_to_wall(s->first_ns),
            .last_wall_ns = ft_clock_mono_to_wall(s->last_ns),
            .closed_wall_ns = ft_clock_mono_to_wall(s->closed_ns),
            .tx_bytes = s->tx_bytes,
            .rx_bytes = s->rx_bytes,
            .tx_rate = ft_rate_per_second(&s->tx_rate, now_ns),
            .rx_rate = ft_rate_per_second(&s->rx_rate, now_ns),
            .pid = s->pid,
            .proto = s->proto,
            .state = ft_state_socket_state(st, s, now_ns),
            .local = s->local,
            .remote = s->remote,
        };
        ft_strlcpy(row.comm, s->comm, sizeof(row.comm));
        emit(ctx, FT_MSG_ROW_CONNECTION, &row, sizeof(row));
    }
    end->rows = (uint32_t)n;
    free(c.items);
}

static void query_flows(struct ft_state *st, const struct ft_query *q, uint64_t now_ns,
                        ft_row_fn *emit, void *ctx, struct ft_msg_end *end)
{
    struct span sp = query_span(q);
    struct candidates c;

    if (!candidates_init(&c, ft_table_count(st->flows)))
        return;

    for (struct ft_flow *f = ft_table_first(st->flows); f; f = ft_table_next(st->flows, f)) {
        if (q->flow_id && q->flow_id != f->id)
            continue;
        if (q->sock_id && q->sock_id != f->sock_id)
            continue;
        if (q->pid && q->pid != f->pid)
            continue;
        if (!match_name(q->process, f->comm))
            continue;
        if (!match_tuple(q, f->proto, &f->local, &f->remote))
            continue;
        if (f->tx_bytes + f->rx_bytes < q->min_bytes)
            continue;
        if ((q->flags & FT_QF_ACTIVE) && now_ns - f->last_ns > st->cfg.active_window_ns)
            continue;
        if (!in_span(&sp, f->first_ns, f->last_ns))
            continue;
        if (!owner_in_scope(st, q, f->pid))
            continue;

        uint64_t key;
        switch (q->sort) {
        case FT_SORT_INBOUND:
            key = f->rx_bytes;
            break;
        case FT_SORT_TIME:
            key = f->last_ns;
            break;
        case FT_SORT_PID:
            key = UINT32_MAX - f->pid;
            break;
        case FT_SORT_BYTES:
            key = f->tx_bytes + f->rx_bytes;
            break;
        case FT_SORT_DURATION:
            key = f->last_ns - f->first_ns;
            break;
        case FT_SORT_RATE:
            key = ft_rate_per_second(&f->tx_rate, now_ns) + ft_rate_per_second(&f->rx_rate, now_ns);
            break;
        default:
            key = f->tx_bytes;
            break;
        }
        candidates_add(&c, (struct candidate){
                               .text = q->sort == FT_SORT_PROCESS ? f->comm : nullptr,
                               .key = key,
                               .tie = f->last_ns,
                               .entry = f,
                           });
    }

    size_t n = candidates_finish(&c, q);
    for (size_t i = 0; i < n; i++) {
        const struct ft_flow *f = c.items[i].entry;
        struct ft_row_flow row = {
            .id = f->id,
            .sock_id = f->sock_id,
            .first_wall_ns = ft_clock_mono_to_wall(f->first_ns),
            .last_wall_ns = ft_clock_mono_to_wall(f->last_ns),
            .tx_bytes = f->tx_bytes,
            .rx_bytes = f->rx_bytes,
            .tx_rate = ft_rate_per_second(&f->tx_rate, now_ns),
            .rx_rate = ft_rate_per_second(&f->rx_rate, now_ns),
            .tx_ops = (uint32_t)(f->tx_ops > UINT32_MAX ? UINT32_MAX : f->tx_ops),
            .rx_ops = (uint32_t)(f->rx_ops > UINT32_MAX ? UINT32_MAX : f->rx_ops),
            .pid = f->pid,
            .proto = f->proto,
            .local = f->local,
            .remote = f->remote,
        };
        ft_strlcpy(row.comm, f->comm, sizeof(row.comm));
        emit(ctx, FT_MSG_ROW_FLOW, &row, sizeof(row));
    }
    end->rows = (uint32_t)n;
    free(c.items);
}

static bool match_activity(const struct ft_query *q, bool active)
{
    if ((q->flags & FT_QF_ACTIVE) && !(q->flags & FT_QF_COMPLETED))
        return active;
    if ((q->flags & FT_QF_COMPLETED) && !(q->flags & FT_QF_ACTIVE))
        return !active;
    return true;
}

static uint64_t transfer_sort_key(const struct ft_query *q, uint64_t bytes, uint64_t rate,
                                  uint64_t first_ns, uint64_t last_ns, uint32_t pid)
{
    switch (q->sort) {
    case FT_SORT_BYTES:
    case FT_SORT_OUTBOUND:
    case FT_SORT_PROCESS:
    case FT_SORT_FILE:
        return bytes;
    case FT_SORT_RATE:
        return rate;
    case FT_SORT_DURATION:
        return last_ns - first_ns;
    case FT_SORT_PID:
        return UINT32_MAX - pid;
    default:
        return last_ns;
    }
}

static const char *transfer_sort_text(const struct ft_query *q, const char *comm,
                                      const struct ft_file *file)
{
    switch (q->sort) {
    case FT_SORT_PROCESS:
        return comm;
    case FT_SORT_FILE:
        return file && file->path ? file->path : NO_TEXT;
    default:
        return nullptr;
    }
}

static void emit_transfer(struct ft_state *st, const struct candidate *cand, uint64_t now_ns,
                          ft_row_fn *emit, void *ctx, struct ft_row_transfer *row)
{
    const struct ft_socket *s;
    uint32_t pid;

    memset(row, 0, offsetof(struct ft_row_transfer, path) + 1);

    if (cand->unattributed) {
        s = cand->entry;
        pid = s->pid;
        row->id = s->id;
        row->first_wall_ns = ft_clock_mono_to_wall(s->first_ns);
        row->last_wall_ns = ft_clock_mono_to_wall(s->last_ns);
        row->bytes = cand->bytes;
        row->rate = ft_rate_per_second(&s->tx_rate, now_ns);
        row->confidence = FT_CONF_UNKNOWN;
        row->method = FT_METHOD_NONE;
        if (transfer_is_active(st, s->last_ns, now_ns))
            row->flags |= FT_XFER_ACTIVE;
        if (ft_state_lost_between(st, s->first_ns, s->last_ns, nullptr, nullptr))
            row->flags |= FT_XFER_INCOMPLETE;
        ft_strlcpy(row->comm, s->comm, sizeof(row->comm));
    } else {
        const struct ft_transfer *t = cand->entry;
        enum ft_confidence conf = FT_CONF_UNKNOWN;
        uint32_t evidence = 0;

        ft_state_classify(st, t, &conf, &evidence);
        s = ft_table_find(st->sockets, &t->sock_id);
        pid = t->pid;
        row->id = t->id;
        row->first_wall_ns = ft_clock_mono_to_wall(t->first_ns);
        row->last_wall_ns = ft_clock_mono_to_wall(t->last_ns);
        row->bytes = t->bytes;
        row->read_bytes = t->read_bytes;
        row->rate = ft_rate_per_second(&t->rate, now_ns);
        row->dev = t->file.dev;
        row->ino = t->file.ino;
        row->ops = (uint32_t)(t->ops > UINT32_MAX ? UINT32_MAX : t->ops);
        row->alternations = (uint32_t)(t->alternations > UINT32_MAX ? UINT32_MAX : t->alternations);
        row->evidence = evidence;
        row->confidence = conf;
        row->method = t->method;
        row->flags |= FT_XFER_FILE_KNOWN;
        if (transfer_is_active(st, t->last_ns, now_ns))
            row->flags |= FT_XFER_ACTIVE;
        if (ft_state_lost_between(st, t->first_ns, t->last_ns, nullptr, nullptr))
            row->flags |= FT_XFER_INCOMPLETE;
        ft_strlcpy(row->comm, t->comm, sizeof(row->comm));

        const struct ft_file *f = ft_table_find(st->files, &t->file);
        if (f) {
            row->gen = f->generation;
            row->file_size = f->size;
            row->file_uid = f->uid;
            ft_strlcpy(row->fs_type, f->fs_type, sizeof(row->fs_type));
            if (f->deleted)
                row->flags |= FT_XFER_FILE_DELETED;
            if (f->path_truncated)
                row->flags |= FT_XFER_PATH_TRUNCATED;
            if (f->path) {
                row->flags |= FT_XFER_PATH_KNOWN;
                ft_strlcpy(row->path, f->path, sizeof(row->path));
            }
        }
    }

    row->pid = pid;
    if (s) {
        row->sock_id = s->id;
        row->proto = s->proto;
        row->local = s->local;
        row->remote = s->remote;
    }
    const struct ft_process *p = ft_table_find(st->processes, &pid);
    if (p) {
        row->ppid = p->ppid;
        ft_strlcpy(row->exe, p->exe, sizeof(row->exe));
    }
    if (p && (p->command_line || p->cwd || p->script)) {
        struct ft_process_strings text = {p->command_line, p->cwd, p->script};
        size_t lead = strnlen(row->path, FT_PATH_MAX - 1) + 1;
        ft_process_strings_pack(row->path + lead, sizeof(row->path) - lead, &text);
        row->flags |= FT_XFER_PROCESS_TEXT;
    }
    emit(ctx, FT_MSG_ROW_TRANSFER, row, ft_row_transfer_size(row));
}

static bool query_transfers(struct ft_state *st, const struct ft_query *q, uint64_t now_ns,
                            ft_row_fn *emit, void *ctx, struct ft_msg_end *end,
                            struct ft_error *err)
{
    static const struct ft_endpoint unspecified;
    struct span sp = query_span(q);
    bool with_unknown = (q->flags & FT_QF_INCLUDE_UNKNOWN) != 0;
    bool by_regex = q->path[0] && (q->flags & FT_QF_PATH_REGEX);
    struct candidates c;
    regex_t regex;

    if (by_regex) {
        int rc = regcomp(&regex, q->path, REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            char reason[128];
            regerror(rc, &regex, reason, sizeof(reason));
            ft_error_set(err, FT_EXIT_USAGE, "Invalid path expression '%s': %s", q->path, reason);
            return false;
        }
    }
    if (!candidates_init(&c, ft_table_count(st->transfers) + ft_table_count(st->sockets))) {
        if (by_regex)
            regfree(&regex);
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return false;
    }

    if (with_unknown) {
        for (struct ft_socket *s = ft_table_first(st->sockets); s;
             s = ft_table_next(st->sockets, s))
            s->q_attributed = 0;
    }

    for (struct ft_transfer *t = ft_table_first(st->transfers); t;
         t = ft_table_next(st->transfers, t)) {
        enum ft_confidence conf;
        uint32_t evidence;
        if (!ft_state_classify(st, t, &conf, &evidence))
            continue;

        struct ft_socket *s = ft_table_find(st->sockets, &t->sock_id);
        if (s && with_unknown)
            s->q_attributed += t->bytes;

        if (q->sock_id && q->sock_id != t->sock_id)
            continue;
        if (q->pid && q->pid != t->pid)
            continue;
        if (!match_name(q->process, t->comm))
            continue;
        if (q->method != FT_METHOD_ANY && q->method != t->method)
            continue;
        if (q->confidence != FT_CONF_ANY && q->confidence != conf)
            continue;
        if (t->bytes < q->min_bytes)
            continue;
        if (!match_activity(q, transfer_is_active(st, t->last_ns, now_ns)))
            continue;
        if (!in_span(&sp, t->first_ns, t->last_ns))
            continue;
        if (!match_tuple(q, s ? s->proto : 0, s ? &s->local : &unspecified,
                         s ? &s->remote : &unspecified))
            continue;
        if (!owner_in_scope(st, q, t->pid))
            continue;

        const struct ft_file *f = ft_table_find(st->files, &t->file);
        if ((q->flags & FT_QF_DELETED) && !(f && f->deleted))
            continue;
        if (q->path[0]) {
            if (!f || !f->path)
                continue;
            if (by_regex ? regexec(&regex, f->path, 0, nullptr, 0) != 0
                         : !ft_glob_match(q->path, f->path))
                continue;
        }
        if (q->min_size && !(f && f->size >= q->min_size))
            continue;

        candidates_add(
            &c, (struct candidate){
                    .text = transfer_sort_text(q, t->comm, f),
                    .key = transfer_sort_key(q, t->bytes, ft_rate_per_second(&t->rate, now_ns),
                                             t->first_ns, t->last_ns, t->pid),
                    .tie = t->id,
                    .entry = t,
                });
    }

    bool unknown_wanted = with_unknown && !q->path[0] && !q->min_size &&
                          !(q->flags & FT_QF_DELETED) && q->method == FT_METHOD_ANY &&
                          (q->confidence == FT_CONF_ANY || q->confidence == FT_CONF_UNKNOWN);
    for (struct ft_socket *s = unknown_wanted ? ft_table_first(st->sockets) : nullptr; s;
         s = ft_table_next(st->sockets, s)) {
        if (s->tx_bytes <= s->q_attributed)
            continue;
        uint64_t bytes = s->tx_bytes - s->q_attributed;

        if (q->sock_id && q->sock_id != s->id)
            continue;
        if (q->pid && q->pid != s->pid)
            continue;
        if (!match_name(q->process, s->comm))
            continue;
        if (bytes < q->min_bytes)
            continue;
        if (!match_activity(q, transfer_is_active(st, s->last_ns, now_ns)))
            continue;
        if (!in_span(&sp, s->first_ns, s->last_ns))
            continue;
        if (!match_tuple(q, s->proto, &s->local, &s->remote))
            continue;
        if (!owner_in_scope(st, q, s->pid))
            continue;

        candidates_add(
            &c, (struct candidate){
                    .text = transfer_sort_text(q, s->comm, nullptr),
                    .key = transfer_sort_key(q, bytes, ft_rate_per_second(&s->tx_rate, now_ns),
                                             s->first_ns, s->last_ns, s->pid),
                    .tie = s->id,
                    .bytes = bytes,
                    .entry = s,
                    .unattributed = true,
                });
    }

    size_t n = candidates_finish(&c, q);
    struct ft_row_transfer *row = malloc(sizeof(*row));
    if (row) {
        for (size_t i = 0; i < n; i++)
            emit_transfer(st, &c.items[i], now_ns, emit, ctx, row);
        end->rows = (uint32_t)n;
        free(row);
    }
    free(c.items);
    if (by_regex)
        regfree(&regex);
    return true;
}

bool ft_state_record_matches(const struct ft_query *q, uint64_t from_ns, uint64_t to_ns,
                             const struct ft_row_event *row)
{
    bool about_file = row->type == FT_REC_FILE_SEEN || row->type == FT_REC_FILE_TRANSFER;
    bool network_filter = q->proto || q->port || q->family || q->remote.family || q->local.family;

    if (q->event_types && !(q->event_types & (1u << row->type)))
        return false;
    if (row->time_ns < from_ns || row->time_ns > to_ns)
        return false;
    if (q->pid && q->pid != row->pid)
        return false;
    if (q->sock_id && q->sock_id != row->sock_id)
        return false;
    if (!match_name(q->process, row->comm))
        return false;
    if (q->path[0] && !(about_file && ft_glob_match(q->path, row->text)))
        return false;
    if (network_filter && !(row->sock_id && match_tuple(q, row->proto, &row->local, &row->remote)))
        return false;
    return true;
}

/* Walks the logs in the order the records were made; emits those after the first skip. */
static uint64_t scan_events(struct ft_state *st, const struct ft_query *q, const struct span *sp,
                            uint64_t skip, ft_row_fn *emit, void *ctx, struct ft_row_event *rows)
{
    struct ft_evlog_cursor cursors[FT_LOG_CLASS_COUNT];
    bool pending[FT_LOG_CLASS_COUNT];
    uint64_t matched = 0;
    /* One reading of both clocks keeps the order of the records in their wall times. */
    uint64_t wall_now = ft_clock_wall_ns();
    uint64_t mono_now = ft_clock_mono_ns();

    for (size_t i = 0; i < FT_LOG_CLASS_COUNT; i++) {
        pending[i] = false;
        if (!st->logs[i])
            continue;
        ft_evlog_rewind(st->logs[i], &cursors[i]);
        pending[i] = ft_evlog_peek(st->logs[i], &cursors[i], &rows[i]);
    }

    for (;;) {
        size_t next = FT_LOG_CLASS_COUNT;
        for (size_t i = 0; i < FT_LOG_CLASS_COUNT; i++) {
            if (pending[i] && (next == FT_LOG_CLASS_COUNT || rows[i].seq < rows[next].seq))
                next = i;
        }
        if (next == FT_LOG_CLASS_COUNT)
            break;

        struct ft_row_event *row = &rows[next];
        if (ft_state_record_matches(q, sp->from_ns, sp->to_ns, row) && matched++ >= skip && emit) {
            row->time_ns = row->time_ns <= mono_now ? wall_now - (mono_now - row->time_ns)
                                                    : wall_now + (row->time_ns - mono_now);
            emit(ctx, FT_MSG_ROW_EVENT, row, ft_row_event_size(row));
        }
        ft_evlog_advance(st->logs[next], &cursors[next]);
        pending[next] = ft_evlog_peek(st->logs[next], &cursors[next], row);
    }
    return matched;
}

static bool class_selected(const struct ft_query *q, enum ft_log_class class)
{
    static const uint32_t types[FT_LOG_CLASS_COUNT] = {
        [FT_LOG_TRANSFERS] =
            1u << FT_REC_FILE_SEEN | 1u << FT_REC_FILE_TRANSFER | 1u << FT_REC_EVENT_LOSS,
        [FT_LOG_NETWORK] = 1u << FT_REC_SOCKET_CONNECT | 1u << FT_REC_SOCKET_LISTEN |
                           1u << FT_REC_SOCKET_ESTABLISHED | 1u << FT_REC_SOCKET_CLOSE |
                           1u << FT_REC_NETWORK_SEND | 1u << FT_REC_NETWORK_RECEIVE,
        [FT_LOG_PROCESSES] =
            1u << FT_REC_PROCESS_EXEC | 1u << FT_REC_PROCESS_FORK | 1u << FT_REC_PROCESS_EXIT,
    };
    return q->event_types == 0 || (q->event_types & types[class]) != 0;
}

static bool query_events(struct ft_state *st, const struct ft_query *q, ft_row_fn *emit, void *ctx,
                         struct ft_msg_end *end)
{
    struct span sp = query_span(q);
    struct ft_row_event *rows = calloc(FT_LOG_CLASS_COUNT, sizeof(*rows));
    uint64_t skip = 0;

    if (!rows)
        return false;
    if (q->limit) {
        uint64_t matched = scan_events(st, q, &sp, 0, nullptr, nullptr, rows);
        skip = matched > q->limit ? matched - q->limit : 0;
    }
    uint64_t matched = scan_events(st, q, &sp, skip, emit, ctx, rows);
    end->rows = (uint32_t)(matched - skip);

    /* A log that has discarded records answers only from its oldest one on. */
    for (size_t i = 0; i < FT_LOG_CLASS_COUNT; i++) {
        struct ft_evlog_cursor oldest;
        if (!st->logs[i] || !class_selected(q, (enum ft_log_class)i) ||
            ft_evlog_discarded(st->logs[i]) == 0)
            continue;
        ft_evlog_rewind(st->logs[i], &oldest);
        if (!ft_evlog_peek(st->logs[i], &oldest, &rows[0]))
            continue;
        uint64_t since = ft_clock_mono_to_wall(rows[0].time_ns);
        if (since > end->observed_since_wall_ns)
            end->observed_since_wall_ns = since;
    }
    free(rows);
    return true;
}

bool ft_state_query(struct ft_state *st, const struct ft_query *q, uint64_t now_ns, ft_row_fn *emit,
                    void *ctx, struct ft_msg_end *end, struct ft_error *err)
{
    struct span sp = query_span(q);
    uint64_t first = 0;
    uint64_t last = 0;

    memset(end, 0, sizeof(*end));
    end->observed_since_wall_ns = ft_clock_mono_to_wall(st->start_ns);
    switch (q->kind) {
    case FT_Q_PROCESSES:
        if (!query_processes(st, q, now_ns, emit, ctx, end)) {
            ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
            return false;
        }
        break;
    case FT_Q_CONNECTIONS:
        query_connections(st, q, now_ns, emit, ctx, end);
        break;
    case FT_Q_FLOWS:
        query_flows(st, q, now_ns, emit, ctx, end);
        break;
    case FT_Q_TRANSFERS:
        if (!query_transfers(st, q, now_ns, emit, ctx, end, err))
            return false;
        break;
    case FT_Q_EVENTS:
        if (!query_events(st, q, emit, ctx, end)) {
            ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
            return false;
        }
        break;
    default:
        break;
    }

    end->lost_events = ft_state_lost_between(st, sp.from_ns, sp.to_ns, &first, &last);
    end->loss_first_wall_ns = ft_clock_mono_to_wall(first);
    end->loss_last_wall_ns = ft_clock_mono_to_wall(last);
    end->health = end->lost_events ? FT_HEALTH_DEGRADED : FT_HEALTH_OK;
    return true;
}

static struct ft_table_usage table_usage(const struct ft_table *t)
{
    return (struct ft_table_usage){
        .count = ft_table_count(t),
        .capacity = ft_table_capacity(t),
        .evictions = ft_table_evictions(t),
    };
}

void ft_state_fill_stats(struct ft_state *st, uint64_t now_ns, struct ft_row_stats *row)
{
    row->events_processed = st->events;
    row->tx_bytes = st->tx_bytes;
    row->rx_bytes = st->rx_bytes;
    row->tx_rate = ft_rate_per_second(&st->tx_rate, now_ns);
    row->rx_rate = ft_rate_per_second(&st->rx_rate, now_ns);
    row->last_loss_wall_ns = ft_clock_mono_to_wall(st->last_loss_ns);
    for (size_t i = 0; i < FT_LOSS_KIND_COUNT && i < FT_ARRAY_LEN(row->loss); i++) {
        row->loss[i] = st->loss[i];
        row->events_dropped += st->loss[i];
    }

    row->processes = table_usage(st->processes);
    row->sockets = table_usage(st->sockets);
    row->flows = table_usage(st->flows);
    row->files = table_usage(st->files);
    row->transfers = table_usage(st->transfers);
    for (size_t i = 0; i < FT_LOG_CLASS_COUNT; i++) {
        if (!st->logs[i])
            continue;
        row->event_log_bytes += ft_evlog_capacity(st->logs[i]);
        row->event_log_records += ft_evlog_records(st->logs[i]);
        row->event_log_discarded += ft_evlog_discarded(st->logs[i]);
    }

    for (struct ft_flow *f = ft_table_first(st->flows); f; f = ft_table_next(st->flows, f)) {
        if (now_ns - f->last_ns <= st->cfg.active_window_ns)
            row->active_flows++;
    }
    for (struct ft_socket *s = ft_table_first(st->sockets); s; s = ft_table_next(st->sockets, s)) {
        if (socket_is_open(st, s, now_ns))
            row->open_sockets++;
    }
    for (struct ft_transfer *t = ft_table_first(st->transfers); t;
         t = ft_table_next(st->transfers, t)) {
        enum ft_confidence conf;
        uint32_t evidence;
        if (!ft_state_classify(st, t, &conf, &evidence)) {
            row->candidates_rejected++;
        } else if (transfer_is_active(st, t->last_ns, now_ns)) {
            row->active_transfers++;
            if (conf < FT_ARRAY_LEN(row->active_by_confidence))
                row->active_by_confidence[conf]++;
        }
    }
    for (struct ft_process *p = ft_table_first(st->processes); p;
         p = ft_table_next(st->processes, p)) {
        if (p->last_ns && transfer_is_active(st, p->last_ns, now_ns))
            row->active_processes++;
    }

    /* Recent loss keeps the collector flagged until a clean interval has passed. */
    bool recent_loss = st->last_loss_ns && now_ns - st->last_loss_ns < 60 * FT_NS_PER_SEC;
    row->health = recent_loss ? FT_HEALTH_DEGRADED : FT_HEALTH_OK;
}
