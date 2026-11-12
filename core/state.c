#include "filetrace/state.h"

#include "filetrace/format.h"
#include "filetrace/leaders.h"

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
        .max_metric_series = 2048,
        .event_log_bytes = 1024 * 1024,
        .leader_entries = 512,
        .inferred_min_bytes = 1024,
        .inferred_min_permille = 50,
        .min_confidence = FT_CONF_INFERRED,
        .active_window_ns = 5 * FT_NS_PER_SEC,
        .idle_socket_ns = 30 * FT_NS_PER_SEC,
        .closed_retention_ns = 60 * FT_NS_PER_SEC,
        .command_line_arguments = true,
    };
}

void ft_rate_add(struct ft_rate *r, uint64_t now_ns, uint64_t bytes)
{
    uint64_t second = now_ns / FT_NS_PER_SEC;

    /* Records can come out of time order; one older than the previous second is in no rate. */
    if (second + 1 == r->second) {
        r->previous += bytes;
        return;
    }
    if (second < r->second)
        return;
    if (second != r->second) {
        r->previous = second == r->second + 1 ? r->current : 0;
        r->current = 0;
        r->second = second;
    }
    r->current += bytes;
}

uint64_t ft_rate_per_second(const struct ft_rate *r, uint64_t now_ns)
{
    uint64_t second = now_ns / FT_NS_PER_SEC;
    uint64_t bytes;

    if (r->second == second)
        bytes = r->previous + r->current;
    else if (r->second + 1 == second)
        bytes = r->current;
    else
        return 0;

    /* The window is the whole previous second plus what has passed of this one. */
    uint64_t window_ns = FT_NS_PER_SEC + now_ns % FT_NS_PER_SEC;
    return (uint64_t)((long double)bytes * (long double)FT_NS_PER_SEC / (long double)window_ns);
}

static void release_file(void *value, void *ctx)
{
    (void)ctx;
    struct ft_file *f = value;
    free(f->path);
    f->path = nullptr;
}

static void release_transfer(void *value, void *ctx)
{
    struct ft_transfer *t = value;
    (void)ctx;
    free(t->script);
    t->script = nullptr;
}

static void release_process(void *value, void *ctx)
{
    (void)ctx;
    ft_process_text_clear(value);
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
    st->series = ft_series_create(cfg->max_metric_series);
    st->record = calloc(1, sizeof(*st->record));
    st->process_text = malloc(sizeof(*st->process_text));
    bool ok = st->processes && st->sockets && st->flows && st->files && st->transfers &&
              st->series && st->record && st->process_text;

    /* Half for what the tool is about, an eighth for the chattiest and least specific. */
    static const size_t eighths[FT_LOG_CLASS_COUNT] = {
        [FT_LOG_TRANSFERS] = 4,
        [FT_LOG_NETWORK] = 3,
        [FT_LOG_PROCESSES] = 1,
    };
    for (size_t i = 0; cfg->event_log_bytes && i < FT_LOG_CLASS_COUNT; i++) {
        st->logs[i] = ft_evlog_create(cfg->event_log_bytes / 8 * eighths[i]);
        ok = ok && st->logs[i];
    }
    if (cfg->leader_entries) {
        st->leaders =
            ft_leaders_create(&(struct ft_leaders_config){.entries = cfg->leader_entries});
        ok = ok && st->leaders;
    }
    if (!ok) {
        ft_state_destroy(st);
        return nullptr;
    }
    ft_table_on_evict(st->files, release_file, nullptr);
    ft_table_on_evict(st->processes, release_process, nullptr);
    ft_table_on_evict(st->transfers, release_transfer, nullptr);
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
    for (size_t i = 0; i < FT_LOG_CLASS_COUNT; i++)
        ft_evlog_destroy(st->logs[i]);
    ft_leaders_destroy(st->leaders);
    ft_series_destroy(st->series);
    free(st->record);
    free(st->process_text);
    free(st);
}

static bool matches_any(const char *const *patterns, size_t count, const char *text)
{
    for (size_t i = 0; i < count; i++) {
        if (ft_glob_match(patterns[i], text))
            return true;
    }
    return false;
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
    if (!created && !same_start(p->start_ns, e->start_ns)) {
        ft_process_text_clear(p);
        memset(p, 0, sizeof(*p));
    }

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
    p->excluded = matches_any(st->cfg.exclude_processes, st->cfg.exclude_process_count, p->comm);
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

/* Each ingest function returns whether the event changed the state. */

static bool ingest_exec(struct ft_state *st, const struct ft_ev_process *e)
{
    struct ft_process *p = process_record(st, e);
    p->exited = false;
    if (e->exe[0])
        ft_strlcpy(p->exe, e->exe, sizeof(p->exe));
    ft_process_text_exec(st, p, e);
    return !p->excluded;
}

static bool ingest_fork(struct ft_state *st, const struct ft_ev_process *e)
{
    struct ft_process *p = process_record(st, e);
    const struct ft_process *parent = ft_table_find(st->processes, &e->ppid);
    if (!p->exe[0] && parent)
        ft_strlcpy(p->exe, parent->exe, sizeof(p->exe));
    ft_process_text_inherit(p, parent);
    return !p->excluded;
}

static bool ingest_exit(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_process *e = &ev->process;
    struct ft_process *p = ft_table_find(st->processes, &e->pid);
    if (!p || (p->start_ns && e->start_ns && !same_start(p->start_ns, e->start_ns)))
        return false;

    /* Its last counters may still arrive; a sweep removes the entry once idle. */
    p->exited = true;
    p->exit_ns = ev->ts_ns;
    p->exit_status = e->exit_status;
    return !p->excluded;
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

static bool network_ignored(const struct ft_state *st, uint16_t proto,
                            const struct ft_endpoint *local, const struct ft_endpoint *remote)
{
    uint8_t family = local->family ? local->family : remote->family;

    if ((proto == FT_PROTO_TCP && st->cfg.ignore_tcp) ||
        (proto == FT_PROTO_UDP && st->cfg.ignore_udp))
        return true;
    return (family == 4 && st->cfg.ignore_ipv4) || (family == 6 && st->cfg.ignore_ipv6);
}

static void socket_set_owner(struct ft_socket *s, const struct ft_process *p)
{
    s->pid = p->pid;
    ft_strlcpy(s->comm, p->comm, sizeof(s->comm));
}

static bool ingest_socket(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_socket *e = &ev->socket;

    if (e->state == FT_SOCK_CLOSED && !ft_table_find(st->sockets, &e->sock_id))
        return false;
    if (network_ignored(st, e->proto, &e->local, &e->remote))
        return false;
    const struct ft_process *owner = e->pid ? process_ensure(st, e->pid) : nullptr;
    if (owner && owner->excluded)
        return false;

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
    if (owner)
        socket_set_owner(s, owner);
    return true;
}

static bool ingest_flow(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_flow *e = &ev->flow;
    bool created;

    if (network_ignored(st, e->proto, &e->local, &e->remote))
        return false;
    struct ft_process *p = process_ensure(st, e->pid);
    if (p->excluded)
        return false;
    ft_process_text_refresh(st, p, ev->ts_ns);

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
    ft_rate_add(&s->tx_rate, ev->ts_ns, e->tx_bytes);
    ft_rate_add(&s->rx_rate, ev->ts_ns, e->rx_bytes);
    socket_set_owner(s, p);

    struct ft_flow_key key;
    memset(&key, 0, sizeof(key));
    key.sock_id = e->sock_id;
    key.pid = e->pid;
    key.remote = e->remote;

    struct ft_flow *f = ft_table_insert(st->flows, &key, &created);
    if (created) {
        f->id = ++st->next_flow_id;
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
    ft_rate_add(&f->tx_rate, ev->ts_ns, e->tx_bytes);
    ft_rate_add(&f->rx_rate, ev->ts_ns, e->rx_bytes);

    p->tx_bytes += e->tx_bytes;
    p->rx_bytes += e->rx_bytes;
    p->last_ns = ev->ts_ns;
    ft_rate_add(&p->tx_rate, ev->ts_ns, e->tx_bytes);
    ft_rate_add(&p->rx_rate, ev->ts_ns, e->rx_bytes);

    st->tx_bytes += e->tx_bytes;
    st->rx_bytes += e->rx_bytes;
    ft_rate_add(&st->tx_rate, ev->ts_ns, e->tx_bytes);
    ft_rate_add(&st->rx_rate, ev->ts_ns, e->rx_bytes);

    uint8_t proto = (uint8_t)e->proto;
    if (e->tx_bytes)
        ft_series_add(st->series, FT_SERIES_NETWORK_IO, p->comm, proto, FT_DIR_TRANSMIT,
                      e->tx_bytes);
    if (e->rx_bytes)
        ft_series_add(st->series, FT_SERIES_NETWORK_IO, p->comm, proto, FT_DIR_RECEIVE,
                      e->rx_bytes);
    return true;
}

static bool ingest_file(struct ft_state *st, const struct ft_event *ev)
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
    f->excluded =
        f->path && matches_any(st->cfg.exclude_paths, st->cfg.exclude_path_count, f->path);
    f->no_minimum =
        f->path && matches_any(st->cfg.no_minimum_paths, st->cfg.no_minimum_path_count, f->path);
    return !f->excluded;
}

static void rank_transfer(struct ft_state *st, const struct ft_transfer *t,
                          const struct ft_process *p, enum ft_confidence conf, uint64_t bytes,
                          bool started, uint64_t ts_ns)
{
    const struct ft_file *f = ft_table_find(st->files, &t->file);
    const struct ft_socket *s = ft_table_find(st->sockets, &t->sock_id);
    struct ft_leader_sample sample = {
        .ts_ns = ts_ns,
        .file = t->file,
        .path = f ? f->path : nullptr,
        .file_size = f ? f->size : 0,
        .deleted = f && f->deleted,
        .sender = t->comm,
        .script = t->script ? t->script : p->script,
        .method = t->method,
        .confidence = conf,
        .bytes = bytes,
        .started = started,
    };
    if (s)
        sample.remote = s->remote;
    ft_leaders_add(st->leaders, &sample);
}

/* Bytes that preceded the association's first report are counted when it is reported. */
static void count_transfer(struct ft_state *st, struct ft_transfer *t, struct ft_process *p,
                           uint64_t ts_ns)
{
    enum ft_confidence conf;
    uint32_t evidence;
    bool started = false;
    uint64_t delta = 0;

    if (!ft_state_classify(st, t, &conf, &evidence))
        return;
    if (!t->counted) {
        t->counted = true;
        started = true;
        ft_series_add(st->series, FT_SERIES_TRANSFERS_STARTED, t->comm, t->method, conf, 1);
    }
    if (t->bytes > t->counted_bytes) {
        delta = t->bytes - t->counted_bytes;
        ft_series_add(st->series, FT_SERIES_FILE_SENT, t->comm, t->method, conf, delta);
        p->file_bytes += delta;
        t->counted_bytes = t->bytes;
    }
    if (st->leaders && (started || delta))
        rank_transfer(st, t, p, conf, delta, started, ts_ns);
}

static bool ingest_transfer(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_transfer *e = &ev->transfer;
    struct ft_transfer_key key;
    bool created;

    /* With protocols ignored, a socket that was never recorded is one of theirs. */
    bool ignoring =
        st->cfg.ignore_tcp || st->cfg.ignore_udp || st->cfg.ignore_ipv4 || st->cfg.ignore_ipv6;
    if (ignoring && !ft_table_find(st->sockets, &e->sock_id))
        return false;
    const struct ft_file *file = ft_table_touch(st->files, &e->file);
    if (file && file->excluded)
        return false;
    struct ft_process *p = process_ensure(st, e->pid);
    if (p->excluded)
        return false;
    ft_process_text_refresh(st, p, ev->ts_ns);

    memset(&key, 0, sizeof(key));
    key.sock_id = e->sock_id;
    key.file = e->file;
    key.pid = e->pid;
    key.method = e->method;

    struct ft_transfer *t = ft_table_insert(st->transfers, &key, &created);
    if (created) {
        t->id = ++st->next_transfer_id;
        t->sock_id = e->sock_id;
        t->file = e->file;
        t->pid = e->pid;
        t->method = e->method;
        t->first_ns = e->first_ns;
        ft_strlcpy(t->comm, p->comm, sizeof(t->comm));
    }
    /* The path can be learned after the first bytes, so this is refreshed every time. */
    t->no_minimum = file && file->no_minimum;
    t->background = t->background || e->background;
    if (e->script && e->script[0] && (!t->script || strcmp(t->script, e->script) != 0)) {
        char *copy = strdup(e->script);
        if (copy) {
            free(t->script);
            t->script = copy;
        }
    }
    t->last_ns = ev->ts_ns;
    t->bytes += e->bytes;
    t->read_bytes += e->read_bytes;
    t->ops += e->ops;
    t->alternations += e->alternations;
    ft_rate_add(&t->rate, ev->ts_ns, e->bytes);
    count_transfer(st, t, p, ev->ts_ns);
    return true;
}

static bool ingest_loss(struct ft_state *st, const struct ft_event *ev)
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
            return true;
        }
    }
    st->loss_windows[st->loss_count % FT_LOSS_WINDOWS] = (struct ft_loss_window){
        .start_ns = e->since_ns,
        .end_ns = ev->ts_ns,
        .count = e->count,
    };
    st->loss_count++;
    return true;
}

static enum ft_log_class record_class(enum ft_record_type type)
{
    switch (type) {
    case FT_REC_PROCESS_EXEC:
    case FT_REC_PROCESS_FORK:
    case FT_REC_PROCESS_EXIT:
        return FT_LOG_PROCESSES;
    case FT_REC_FILE_SEEN:
    case FT_REC_FILE_TRANSFER:
    case FT_REC_EVENT_LOSS:
        return FT_LOG_TRANSFERS;
    default:
        return FT_LOG_NETWORK;
    }
}

static struct ft_row_event *record_begin(struct ft_state *st, enum ft_record_type type,
                                         uint64_t ts_ns)
{
    struct ft_row_event *r = st->record;

    memset(r, 0, offsetof(struct ft_row_event, text) + 1);
    r->type = type;
    r->time_ns = ts_ns;
    r->confidence = FT_CONF_ANY;
    return r;
}

static void record_commit(struct ft_state *st)
{
    struct ft_row_event *r = st->record;
    struct ft_evlog *log = st->logs[record_class((enum ft_record_type)r->type)];

    r->seq = ++st->next_record_seq;
    /* Counters are collected after the events that followed their last byte. */
    if (r->time_ns < st->last_record_ns)
        r->time_ns = st->last_record_ns;
    st->last_record_ns = r->time_ns;
    if (log)
        ft_evlog_append(log, r, ft_row_event_size(r));
    if (st->on_record)
        st->on_record(st->on_record_ctx, r);
}

static void record_owner(struct ft_state *st, struct ft_row_event *r, uint32_t pid)
{
    const struct ft_process *p = pid ? ft_table_find(st->processes, &pid) : nullptr;

    r->pid = pid;
    if (p) {
        r->ppid = p->ppid;
        r->uid = p->uid;
        ft_strlcpy(r->comm, p->comm, sizeof(r->comm));
    }
}

/*
 * Follows the record's text with the process's command line, working directory and script, or
 * the script of the request the bytes were sent for.
 */
static void record_process_text(struct ft_row_event *r, const struct ft_process *p,
                                const char *script)
{
    if (!script && p)
        script = p->script;
    if (!(p && (p->command_line || p->cwd)) && !script)
        return;
    struct ft_process_strings s = {p ? p->command_line : nullptr, p ? p->cwd : nullptr, script};
    size_t lead = strnlen(r->text, FT_PATH_MAX - 1) + 1;
    ft_process_strings_pack(r->text + lead, sizeof(r->text) - lead, &s);
    r->flags |= FT_EVENT_PROCESS_TEXT;
}

static void record_process(struct ft_state *st, enum ft_record_type type, const struct ft_event *ev)
{
    struct ft_row_event *r = record_begin(st, type, ev->ts_ns);
    const struct ft_process *p = ft_table_find(st->processes, &ev->process.pid);

    r->pid = ev->process.pid;
    r->exit_status = ev->process.exit_status;
    if (p) {
        r->ppid = p->ppid;
        r->uid = p->uid;
        ft_strlcpy(r->comm, p->comm, sizeof(r->comm));
        ft_strlcpy(r->text, p->exe, sizeof(r->text));
    }
    record_process_text(r, p, nullptr);
    record_commit(st);
}

static void record_socket(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_socket *s = ft_table_find(st->sockets, &ev->socket.sock_id);
    enum ft_record_type type;

    switch (ev->socket.state) {
    case FT_SOCK_CONNECTING:
        type = FT_REC_SOCKET_CONNECT;
        break;
    case FT_SOCK_LISTENING:
        type = FT_REC_SOCKET_LISTEN;
        break;
    case FT_SOCK_CLOSED:
        type = FT_REC_SOCKET_CLOSE;
        break;
    case FT_SOCK_ESTABLISHED:
        type = FT_REC_SOCKET_ESTABLISHED;
        break;
    default:
        return;
    }
    if (!s)
        return;

    struct ft_row_event *r = record_begin(st, type, ev->ts_ns);
    r->sock_id = s->id;
    r->proto = s->proto;
    r->local = s->local;
    r->remote = s->remote;
    record_owner(st, r, s->pid);
    record_commit(st);
}

static void record_network(struct ft_state *st, enum ft_record_type type, const struct ft_event *ev,
                           uint64_t bytes)
{
    const struct ft_socket *s = ft_table_find(st->sockets, &ev->flow.sock_id);
    struct ft_row_event *r;

    if (bytes == 0)
        return;
    r = record_begin(st, type, ev->ts_ns);
    r->sock_id = ev->flow.sock_id;
    r->proto = ev->flow.proto;
    r->local = s ? s->local : ev->flow.local;
    r->remote = ev->flow.remote;
    r->bytes = bytes;
    record_owner(st, r, ev->flow.pid);
    record_commit(st);
}

static void record_file(struct ft_row_event *r, const struct ft_file *f)
{
    r->dev = f->id.dev;
    r->ino = f->id.ino;
    r->file_size = f->size;
    if (f->deleted)
        r->flags |= FT_EVENT_FILE_DELETED;
    if (f->path)
        ft_strlcpy(r->text, f->path, sizeof(r->text));
}

static void record_file_seen(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_file *f = ft_table_find(st->files, &ev->file.id);
    if (!f)
        return;
    record_file(record_begin(st, FT_REC_FILE_SEEN, ev->ts_ns), f);
    record_commit(st);
}

static void record_transfer(struct ft_state *st, const struct ft_event *ev)
{
    const struct ft_ev_transfer *e = &ev->transfer;
    const struct ft_socket *s = ft_table_find(st->sockets, &e->sock_id);
    const struct ft_file *f = ft_table_find(st->files, &e->file);
    struct ft_transfer_key key;
    enum ft_confidence conf;
    uint32_t evidence;

    memset(&key, 0, sizeof(key));
    key.sock_id = e->sock_id;
    key.file = e->file;
    key.pid = e->pid;
    key.method = e->method;
    const struct ft_transfer *t = ft_table_find(st->transfers, &key);

    struct ft_row_event *r = record_begin(st, FT_REC_FILE_TRANSFER, ev->ts_ns);
    r->sock_id = e->sock_id;
    r->dev = e->file.dev;
    r->ino = e->file.ino;
    r->bytes = e->bytes;
    r->read_bytes = e->read_bytes;
    r->method = e->method;
    /* The level is that of the whole association so far, not of this part of it. */
    if (t && ft_state_classify(st, t, &conf, &evidence)) {
        r->confidence = conf;
        r->flags |= FT_EVENT_HAS_CONFIDENCE;
    }
    record_owner(st, r, e->pid);
    if (s) {
        r->proto = s->proto;
        r->local = s->local;
        r->remote = s->remote;
    }
    if (f)
        record_file(r, f);
    record_process_text(r, ft_table_find(st->processes, &e->pid), e->script);
    record_commit(st);
}

static void record_loss(struct ft_state *st, const struct ft_event *ev)
{
    struct ft_row_event *r = record_begin(st, FT_REC_EVENT_LOSS, ev->ts_ns);
    r->bytes = ev->loss.count;
    r->loss_kind = ev->loss.kind;
    record_commit(st);
}

void ft_state_ingest(struct ft_state *st, const struct ft_event *ev)
{
    if (st->start_ns == 0)
        st->start_ns = ev->ts_ns;
    st->events++;

    switch (ev->type) {
    case FT_EVENT_PROCESS_EXEC:
        if (ingest_exec(st, &ev->process))
            record_process(st, FT_REC_PROCESS_EXEC, ev);
        break;
    case FT_EVENT_PROCESS_FORK:
        if (ingest_fork(st, &ev->process))
            record_process(st, FT_REC_PROCESS_FORK, ev);
        break;
    case FT_EVENT_PROCESS_EXIT:
        if (ingest_exit(st, ev))
            record_process(st, FT_REC_PROCESS_EXIT, ev);
        break;
    case FT_EVENT_SOCKET_STATE:
        if (ingest_socket(st, ev))
            record_socket(st, ev);
        break;
    case FT_EVENT_FILE_SEEN:
        if (ingest_file(st, ev))
            record_file_seen(st, ev);
        break;
    case FT_EVENT_FLOW:
        if (ingest_flow(st, ev)) {
            record_network(st, FT_REC_NETWORK_SEND, ev, ev->flow.tx_bytes);
            record_network(st, FT_REC_NETWORK_RECEIVE, ev, ev->flow.rx_bytes);
        }
        break;
    case FT_EVENT_TRANSFER:
        if (ingest_transfer(st, ev))
            record_transfer(st, ev);
        break;
    case FT_EVENT_LOSS:
        if (ingest_loss(st, ev))
            record_loss(st, ev);
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
        break;

    case FT_METHOD_READ_SEND:
        if (!t->no_minimum) {
            if (t->bytes < st->cfg.inferred_min_bytes)
                return false;
            if (t->bytes < t->read_bytes / 1000 * st->cfg.inferred_min_permille)
                return false;
        }
        /* A file every program reads counts as sent only when all that was read of it went. */
        if (t->background && t->bytes < t->read_bytes)
            return false;
        evd |= FT_EVD_THREAD_SEQUENCE;
        if (t->alternations >= 2)
            evd |= FT_EVD_REPEATED;
        if (t->bytes >= t->read_bytes / 10 * 9)
            evd |= FT_EVD_BYTE_BALANCE;
        *confidence = FT_CONF_INFERRED;
        *evidence = evd;
        break;

    default:
        return false;
    }
    return *confidence >= st->cfg.min_confidence;
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
