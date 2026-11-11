#include "filetrace/state.h"

#include <stdlib.h>
#include <string.h>

void ft_state_config_defaults(struct ft_state_config *cfg)
{
    *cfg = (struct ft_state_config){
        .max_processes = 4096,
        .max_sockets = 16384,
        .max_flows = 16384,
        .max_files = 16384,
        .max_transfers = 16384,
        .inferred_min_bytes = 1024,
        .inferred_min_permille = 50,
        .active_window_ns = 5 * FT_NS_PER_SEC,
        .idle_socket_ns = 30 * FT_NS_PER_SEC,
        .closed_retention_ns = 60 * FT_NS_PER_SEC,
    };
}

static void release_file(void *value, void *ctx)
{
    (void)ctx;
    struct ft_file *f = value;
    free(f->path);
    f->path = nullptr;
}

struct ft_state *ft_state_create(const struct ft_state_config *cfg)
{
    struct ft_state *st = calloc(1, sizeof(*st));
    if (!st)
        return nullptr;

    st->cfg = *cfg;
    st->processes =
        ft_table_create(cfg->max_processes, sizeof(uint32_t), sizeof(struct ft_process));
    st->sockets = ft_table_create(cfg->max_sockets, sizeof(uint64_t), sizeof(struct ft_socket));
    st->flows = ft_table_create(cfg->max_flows, sizeof(struct ft_flow_key), sizeof(struct ft_flow));
    st->files = ft_table_create(cfg->max_files, sizeof(struct ft_file_id), sizeof(struct ft_file));
    st->transfers = ft_table_create(cfg->max_transfers, sizeof(struct ft_transfer_key),
                                    sizeof(struct ft_transfer));
    if (!st->processes || !st->sockets || !st->flows || !st->files || !st->transfers) {
        ft_state_destroy(st);
        return nullptr;
    }
    ft_table_on_evict(st->files, release_file, nullptr);
    return st;
}

void ft_state_destroy(struct ft_state *st)
{
    if (!st)
        return;
    ft_table_destroy(st->processes);
    ft_table_destroy(st->sockets);
    ft_table_destroy(st->flows);
    ft_table_destroy(st->files);
    ft_table_destroy(st->transfers);
    free(st);
}

/* Start times read back from the system are rounded to scheduler ticks. */
static bool same_start(uint64_t a, uint64_t b)
{
    constexpr uint64_t TOLERANCE_NS = 20 * FT_NS_PER_MS;
    return (a > b ? a - b : b - a) <= TOLERANCE_NS;
}

static struct ft_process *process_record(struct ft_state *st, const struct ft_ev_process *e)
{
    bool created;
    struct ft_process *p = ft_table_insert(st->processes, &e->pid, &created);

    /* A different start time under the same PID is a different process. */
    if (!created && !same_start(p->start_ns, e->start_ns))
        memset(p, 0, sizeof(*p));

    p->pid = e->pid;
    p->ppid = e->ppid;
    p->uid = e->uid;
    p->gid = e->gid;
    p->pidns = e->pidns;
    p->mntns = e->mntns;
    p->netns = e->netns;
    p->cgroup_id = e->cgroup_id;
    p->start_ns = e->start_ns;
    ft_strlcpy(p->comm, e->comm, sizeof(p->comm));
    return p;
}

static struct ft_process *process_ensure(struct ft_state *st, uint32_t pid)
{
    struct ft_process *p = ft_table_touch(st->processes, &pid);
    if (p)
        return p;

    struct ft_ev_process found = {0};
    if (st->cfg.lookup_process && st->cfg.lookup_process(pid, &found)) {
        found.pid = pid;
        p = process_record(st, &found);
        ft_strlcpy(p->exe, found.exe, sizeof(p->exe));
        return p;
    }
    p = ft_table_insert(st->processes, &pid, nullptr);
    p->pid = pid;
    return p;
}

static void ingest_exec(struct ft_state *st, const struct ft_ev_process *e)
{
    struct ft_process *p = process_record(st, e);
    p->exited = false;
    if (e->exe[0])
        ft_strlcpy(p->exe, e->exe, sizeof(p->exe));
}

static void ingest_fork(struct ft_state *st, const struct ft_ev_process *e)
{
    struct ft_process *p = process_record(st, e);
    const struct ft_process *parent = ft_table_find(st->processes, &e->ppid);
    if (!p->exe[0] && parent)
        ft_strlcpy(p->exe, parent->exe, sizeof(p->exe));
}

static void ingest_exit(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_process *e = &ev->process;
    struct ft_process *p = ft_table_find(st->processes, &e->pid);
    if (!p || (p->start_ns && e->start_ns && !same_start(p->start_ns, e->start_ns)))
        return;

    /* Its last counters may still arrive; a sweep removes the entry once idle. */
    p->exited = true;
    p->exit_ns = ev->ts_ns;
    p->exit_status = e->exit_status;
}

void ft_state_sweep(struct ft_state *st, uint64_t now_ns)
{
    constexpr uint64_t GRACE_NS = 2 * FT_NS_PER_SEC;
    uint32_t idle[256];
    size_t count;

    do {
        count = 0;
        for (struct ft_process *p = ft_table_first(st->processes); p && count < FT_ARRAY_LEN(idle);
             p = ft_table_next(st->processes, p)) {
            if (p->exited && p->tx_bytes == 0 && p->rx_bytes == 0 && now_ns > p->exit_ns &&
                now_ns - p->exit_ns > GRACE_NS)
                idle[count++] = p->pid;
        }
        for (size_t i = 0; i < count; i++)
            ft_table_remove(st->processes, &idle[i]);
    } while (count == FT_ARRAY_LEN(idle));
}

static bool endpoint_known(const struct ft_endpoint *ep)
{
    return ep->family != 0 || ep->port != 0;
}

static bool endpoint_equal(const struct ft_endpoint *a, const struct ft_endpoint *b)
{
    return a->port == b->port && ft_addr_equal(a, b);
}

static void socket_set_owner(struct ft_state *st, struct ft_socket *s, uint32_t pid)
{
    const struct ft_process *p = process_ensure(st, pid);
    s->pid = pid;
    ft_strlcpy(s->comm, p->comm, sizeof(s->comm));
}

static void ingest_socket(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_socket *e = &ev->socket;

    if (e->state == FT_SOCK_CLOSED && !ft_table_find(st->sockets, &e->sock_id))
        return;

    bool created;
    struct ft_socket *s = ft_table_insert(st->sockets, &e->sock_id, &created);
    if (created) {
        s->id = e->sock_id;
        s->first_ns = ev->ts_ns;
    }
    s->proto = e->proto;
    s->state = e->state;
    s->last_ns = ev->ts_ns;
    if (e->state == FT_SOCK_CLOSED) {
        /* A closing socket has already given up its port; keep what was seen. */
        s->closed_ns = ev->ts_ns;
    } else {
        if (endpoint_known(&e->local))
            s->local = e->local;
        if (endpoint_known(&e->remote))
            s->remote = e->remote;
    }
    if (e->pid)
        socket_set_owner(st, s, e->pid);
}

static void ingest_flow(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_flow *e = &ev->flow;
    bool created;

    struct ft_socket *s = ft_table_insert(st->sockets, &e->sock_id, &created);
    if (created) {
        s->id = e->sock_id;
        s->first_ns = e->first_ns;
        s->proto = e->proto;
    }
    if (s->state == FT_SOCK_UNKNOWN)
        s->state = e->proto == FT_PROTO_TCP ? FT_SOCK_ESTABLISHED : FT_SOCK_ACTIVE;
    if (endpoint_known(&e->local))
        s->local = e->local;
    if (endpoint_known(&e->remote)) {
        if (s->proto == FT_PROTO_TCP || (!endpoint_known(&s->remote) && !s->many_remotes)) {
            s->remote = e->remote;
        } else if (!endpoint_equal(&s->remote, &e->remote)) {
            /* A connectionless socket talking to several peers has no single remote. */
            s->many_remotes = true;
            memset(&s->remote, 0, sizeof(s->remote));
        }
    }
    s->last_ns = ev->ts_ns;
    s->tx_bytes += e->tx_bytes;
    s->rx_bytes += e->rx_bytes;
    socket_set_owner(st, s, e->pid);

    struct ft_flow_key key;
    memset(&key, 0, sizeof(key));
    key.sock_id = e->sock_id;
    key.pid = e->pid;
    key.remote = e->remote;

    struct ft_flow *f = ft_table_insert(st->flows, &key, &created);
    if (created) {
        f->sock_id = e->sock_id;
        f->pid = e->pid;
        f->proto = e->proto;
        f->remote = e->remote;
        f->first_ns = e->first_ns;
        ft_strlcpy(f->comm, s->comm, sizeof(f->comm));
    }
    f->local = s->local;
    f->last_ns = ev->ts_ns;
    f->tx_bytes += e->tx_bytes;
    f->rx_bytes += e->rx_bytes;
    f->tx_ops += e->tx_ops;
    f->rx_ops += e->rx_ops;

    struct ft_process *p = process_ensure(st, e->pid);
    p->tx_bytes += e->tx_bytes;
    p->rx_bytes += e->rx_bytes;
    p->last_ns = ev->ts_ns;

    st->tx_bytes += e->tx_bytes;
    st->rx_bytes += e->rx_bytes;
}

static void ingest_file(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_file *e = &ev->file;
    bool created;

    struct ft_file *f = ft_table_insert(st->files, &e->id, &created);
    if (created) {
        f->id = e->id;
        f->first_ns = ev->ts_ns;
    }
    f->generation = e->generation;
    f->mnt_id = e->mnt_id;
    f->mntns = e->mntns;
    f->uid = e->uid;
    f->size = e->size;
    f->deleted = e->deleted;
    f->path_truncated = e->path_truncated;
    ft_strlcpy(f->fs_type, e->fs_type, sizeof(f->fs_type));

    if (e->path && (!f->path || strcmp(f->path, e->path) != 0)) {
        char *copy = strndup(e->path, FT_PATH_MAX - 1);
        if (copy) {
            free(f->path);
            f->path = copy;
        }
    }
}

static void ingest_transfer(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_transfer *e = &ev->transfer;
    struct ft_transfer_key key;
    bool created;

    memset(&key, 0, sizeof(key));
    key.sock_id = e->sock_id;
    key.file = e->file;
    key.pid = e->pid;
    key.method = e->method;

    struct ft_transfer *t = ft_table_insert(st->transfers, &key, &created);
    if (created) {
        const struct ft_process *p = process_ensure(st, e->pid);
        t->id = ++st->next_transfer_id;
        t->sock_id = e->sock_id;
        t->file = e->file;
        t->pid = e->pid;
        t->method = e->method;
        t->first_ns = e->first_ns;
        ft_strlcpy(t->comm, p->comm, sizeof(t->comm));
    }
    t->last_ns = ev->ts_ns;
    t->bytes += e->bytes;
    t->read_bytes += e->read_bytes;
    t->ops += e->ops;
    t->alternations += e->alternations;

    /* Keep the file's metadata for as long as transfers refer to it. */
    ft_table_touch(st->files, &e->file);
}

static void ingest_loss(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_loss *e = &ev->loss;

    if (e->kind < FT_LOSS_KIND_COUNT)
        st->loss[e->kind] += e->count;
    st->last_loss_ns = ev->ts_ns;

    if (st->loss_count) {
        struct ft_loss_window *last = &st->loss_windows[(st->loss_count - 1) % FT_LOSS_WINDOWS];
        if (last->end_ns >= e->since_ns) {
            last->end_ns = ev->ts_ns;
            last->count += e->count;
            return;
        }
    }
    st->loss_windows[st->loss_count % FT_LOSS_WINDOWS] = (struct ft_loss_window){
        .start_ns = e->since_ns,
        .end_ns = ev->ts_ns,
        .count = e->count,
    };
    st->loss_count++;
}

void ft_state_ingest(struct ft_state *st, const struct ft_event *ev)
{
    if (st->start_ns == 0)
        st->start_ns = ev->ts_ns;
    st->events++;

    switch (ev->type) {
    case FT_EVENT_PROCESS_EXEC:
        ingest_exec(st, &ev->process);
        break;
    case FT_EVENT_PROCESS_FORK:
        ingest_fork(st, &ev->process);
        break;
    case FT_EVENT_PROCESS_EXIT:
        ingest_exit(st, ev);
        break;
    case FT_EVENT_SOCKET_STATE:
        ingest_socket(st, ev);
        break;
    case FT_EVENT_FILE_SEEN:
        ingest_file(st, ev);
        break;
    case FT_EVENT_FLOW:
        ingest_flow(st, ev);
        break;
    case FT_EVENT_TRANSFER:
        ingest_transfer(st, ev);
        break;
    case FT_EVENT_LOSS:
        ingest_loss(st, ev);
        break;
    }
}

bool ft_state_classify(const struct ft_state *st, const struct ft_transfer *t,
                       enum ft_confidence *confidence, uint32_t *evidence)
{
    uint32_t evd = FT_EVD_FILE_IDENTITY | FT_EVD_SOCKET_IDENTITY;
    const struct ft_socket *s = ft_table_find(st->sockets, &t->sock_id);
    if (s && endpoint_known(&s->remote))
        evd |= FT_EVD_REMOTE_ENDPOINT;

    switch (t->method) {
    case FT_METHOD_SENDFILE:
        *confidence = FT_CONF_EXACT;
        *evidence = evd | FT_EVD_DIRECT_TRANSFER;
        return true;

    case FT_METHOD_READ_SEND:
        if (t->bytes < st->cfg.inferred_min_bytes)
            return false;
        if (t->bytes < t->read_bytes / 1000 * st->cfg.inferred_min_permille)
            return false;
        evd |= FT_EVD_THREAD_SEQUENCE;
        if (t->alternations >= 2)
            evd |= FT_EVD_REPEATED;
        if (t->bytes >= t->read_bytes / 10 * 9)
            evd |= FT_EVD_BYTE_BALANCE;
        *confidence = FT_CONF_INFERRED;
        *evidence = evd;
        return true;

    default:
        return false;
    }
}

uint64_t ft_state_lost_between(const struct ft_state *st, uint64_t from_ns, uint64_t to_ns,
                               uint64_t *first_ns, uint64_t *last_ns)
{
    size_t n = st->loss_count < FT_LOSS_WINDOWS ? st->loss_count : FT_LOSS_WINDOWS;
    uint64_t lost = 0;
    uint64_t first = 0;
    uint64_t last = 0;

    for (size_t i = 0; i < n; i++) {
        const struct ft_loss_window *w = &st->loss_windows[i];
        if (w->end_ns < from_ns || w->start_ns > to_ns)
            continue;
        lost += w->count;
        if (first == 0 || w->start_ns < first)
            first = w->start_ns;
        if (w->end_ns > last)
            last = w->end_ns;
    }
    if (first_ns)
        *first_ns = first;
    if (last_ns)
        *last_ns = last;
    return lost;
}

enum ft_sock_state ft_state_socket_state(const struct ft_state *st, const struct ft_socket *s,
                                         uint64_t now_ns)
{
    if (s->state == FT_SOCK_ACTIVE && now_ns > s->last_ns &&
        now_ns - s->last_ns > st->cfg.idle_socket_ns)
        return FT_SOCK_IDLE;
    return s->state;
}
