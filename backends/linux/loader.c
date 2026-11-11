#include "backends/linux/linux.h"

#include "filetrace/clock.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "backends/linux/bpf/abi.h"

static const unsigned char probe_object[] = {
#embed FT_BPF_OBJECT
};

const struct ft_probe_def ft_linux_probe_defs[FT_LINUX_PROBES] = {
    {"ft_process_exec", "sched_process_exec", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_process_fork", "sched_process_fork", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_process_exit", "sched_process_exit", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_sock_state", "inet_sock_set_state", "tracepoint", 0, FT_PG_TCP_STATE, FT_MODE_MINIMAL},
    {"ft_inet_sendmsg", "inet_sendmsg", "fexit", 3, FT_PG_NET_IPV4, FT_MODE_MINIMAL},
    {"ft_inet_recvmsg", "inet_recvmsg", "fexit", 4, FT_PG_NET_IPV4, FT_MODE_MINIMAL},
    {"ft_inet6_sendmsg", "inet6_sendmsg", "fexit", 3, FT_PG_NET_IPV6, FT_MODE_MINIMAL},
    {"ft_inet6_recvmsg", "inet6_recvmsg", "fexit", 4, FT_PG_NET_IPV6, FT_MODE_MINIMAL},
    {"ft_vfs_read", "vfs_read", "fexit", 4, FT_PG_FILE_READ, FT_MODE_STANDARD},
    {"ft_splice_direct", "do_splice_direct", "fexit", 6, FT_PG_SENDFILE, FT_MODE_STANDARD},
    {"ft_destroy_inode", "__destroy_inode", "fentry", 1, FT_PG_FILE_END, FT_MODE_STANDARD},
};

static char last_message[512];

static int on_libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    char line[1024];

    if (level == LIBBPF_DEBUG)
        return 0;
    vsnprintf(line, sizeof(line), fmt, ap);
    line[strcspn(line, "\n")] = '\0';
    if (level == LIBBPF_WARN && strncmp(line, "libbpf: ", 8) == 0)
        ft_strlcpy(last_message, line + 8, sizeof(last_message));
    ft_log(FT_LOG_DEBUG, "%s", line);
    return 0;
}

const char *ft_linux_last_libbpf_message(void)
{
    return last_message;
}

/* Parameter count of a kernel function, or -1 when BTF does not describe it. */
static int kernel_func_nargs(const struct btf *vmlinux, const char *name)
{
    int id = btf__find_by_name_kind(vmlinux, name, BTF_KIND_FUNC);
    if (id < 0)
        return -1;
    const struct btf_type *func = btf__type_by_id(vmlinux, (__u32)id);
    const struct btf_type *proto = func ? btf__type_by_id(vmlinux, func->type) : nullptr;
    return proto ? (int)btf_vlen(proto) : -1;
}

static void *rodata_variable(struct bpf_object *obj, const char *name, size_t size)
{
    struct bpf_map *map = bpf_object__find_map_by_name(obj, ".rodata");
    const struct btf *btf = bpf_object__btf(obj);
    size_t map_size = 0;
    void *base = map ? bpf_map__initial_value(map, &map_size) : nullptr;
    int sec_id = btf ? btf__find_by_name_kind(btf, ".rodata", BTF_KIND_DATASEC) : -1;
    if (!base || sec_id < 0)
        return nullptr;

    const struct btf_type *sec = btf__type_by_id(btf, (__u32)sec_id);
    const struct btf_var_secinfo *info = btf_var_secinfos(sec);
    for (unsigned i = 0; i < btf_vlen(sec); i++) {
        const struct btf_type *var = btf__type_by_id(btf, info[i].type);
        if (strcmp(btf__name_by_offset(btf, var->name_off), name) == 0 && info[i].size == size &&
            (size_t)info[i].offset + size <= map_size)
            return (char *)base + info[i].offset;
    }
    return nullptr;
}

static uint32_t round_up_pow2(uint32_t v, uint32_t min)
{
    uint32_t p = min;
    while (p < v && p < (1u << 30))
        p <<= 1;
    return p;
}

static struct bpf_object *open_object(const struct ft_backend_config *cfg,
                                      const bool enabled[FT_LINUX_PROBES])
{
    struct bpf_object_open_opts opts = {.sz = sizeof(opts), .object_name = "filetrace"};
    struct bpf_object *obj = bpf_object__open_mem(probe_object, sizeof(probe_object), &opts);
    if (!obj)
        return nullptr;

    struct ft_bpf_cfg *bpf_cfg = rodata_variable(obj, "cfg", sizeof(*bpf_cfg));
    struct bpf_map *events = bpf_object__find_map_by_name(obj, "events");
    struct bpf_map *agg_a = bpf_object__find_map_by_name(obj, "agg_a");
    struct bpf_map *agg_b = bpf_object__find_map_by_name(obj, "agg_b");
    struct bpf_map *known = bpf_object__find_map_by_name(obj, "known_files");
    if (!bpf_cfg || !events || !agg_a || !agg_b || !known) {
        bpf_object__close(obj);
        errno = EINVAL;
        return nullptr;
    }

    uint32_t queue = round_up_pow2(cfg->queue_bytes, (uint32_t)sysconf(_SC_PAGESIZE));
    bpf_cfg->corr_window_ns = cfg->corr_window_ns;
    bpf_cfg->wakeup_bytes = queue / 4;
    bpf_cfg->file_corr = cfg->mode >= FT_MODE_STANDARD;
    bpf_map__set_max_entries(events, queue);
    bpf_map__set_max_entries(agg_a, cfg->agg_entries);
    bpf_map__set_max_entries(agg_b, cfg->agg_entries);
    bpf_map__set_max_entries(known, cfg->known_files);

    for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
        struct bpf_program *prog =
            bpf_object__find_program_by_name(obj, ft_linux_probe_defs[i].program);
        if (!prog) {
            bpf_object__close(obj);
            errno = EINVAL;
            return nullptr;
        }
        bpf_program__set_autoload(prog, enabled[i]);
    }
    return obj;
}

static int load_with(const struct ft_backend_config *cfg, const bool enabled[FT_LINUX_PROBES],
                     struct bpf_object **out)
{
    struct bpf_object *obj = open_object(cfg, enabled);
    if (!obj)
        return errno ? -errno : -EINVAL;

    int err = bpf_object__load(obj);
    if (err) {
        bpf_object__close(obj);
        return err;
    }
    *out = obj;
    return 0;
}

int ft_linux_probes_load(const struct ft_backend_config *cfg, struct ft_linux_probes *out)
{
    bool enabled[FT_LINUX_PROBES];
    size_t wanted = 0;

    memset(out, 0, sizeof(*out));
    libbpf_set_print(on_libbpf_print);
    last_message[0] = '\0';

    struct btf *vmlinux = btf__load_vmlinux_btf();
    for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
        const struct ft_probe_def *def = &ft_linux_probe_defs[i];

        enabled[i] = cfg->mode >= def->min_mode;
        if (!enabled[i]) {
            out->status[i].state = FT_PROBE_NOT_NEEDED;
            continue;
        }
        if (vmlinux && def->nargs) {
            int nargs = kernel_func_nargs(vmlinux, def->target);
            if (nargs >= 0 && nargs != def->nargs) {
                enabled[i] = false;
                out->status[i].state = FT_PROBE_MISMATCH;
                continue;
            }
        }
        wanted++;
    }
    btf__free(vmlinux);

    int err = wanted ? load_with(cfg, enabled, &out->obj) : -ENOENT;
    if (err && wanted > 1) {
        /* One rejected probe fails the whole object: find which ones load. */
        int first_error = err;
        size_t usable = 0;

        for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
            if (!enabled[i])
                continue;
            bool only[FT_LINUX_PROBES] = {false};
            struct bpf_object *trial = nullptr;

            only[i] = true;
            int trial_err = load_with(cfg, only, &trial);
            if (trial_err) {
                enabled[i] = false;
                out->status[i] = (struct ft_probe_status){FT_PROBE_LOAD_FAILED, -trial_err};
            } else {
                bpf_object__close(trial);
                usable++;
            }
        }
        err = usable ? load_with(cfg, enabled, &out->obj) : first_error;
    }
    if (err) {
        for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
            if (enabled[i])
                out->status[i] = (struct ft_probe_status){FT_PROBE_LOAD_FAILED, -err};
        }
        return err;
    }

    for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
        if (!enabled[i])
            continue;
        struct bpf_program *prog =
            bpf_object__find_program_by_name(out->obj, ft_linux_probe_defs[i].program);
        out->links[i] = bpf_program__attach(prog);
        if (!out->links[i])
            out->status[i] = (struct ft_probe_status){FT_PROBE_ATTACH_FAILED, errno};
        else
            out->status[i].state = FT_PROBE_ATTACHED;
    }
    return 0;
}

void ft_linux_probes_unload(struct ft_linux_probes *p)
{
    for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
        bpf_link__destroy(p->links[i]);
        p->links[i] = nullptr;
    }
    bpf_object__close(p->obj);
    p->obj = nullptr;
}

bool ft_linux_group_attached(const struct ft_probe_status status[FT_LINUX_PROBES],
                             enum ft_probe_group group)
{
    for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
        if (ft_linux_probe_defs[i].group == group && status[i].state != FT_PROBE_ATTACHED)
            return false;
    }
    return true;
}

constexpr size_t DRAIN_BATCH = 512;

struct agg_record {
    struct ft_bpf_agg_key key;
    struct ft_bpf_agg_val val;
};

struct ft_backend {
    struct ft_backend_config cfg;
    struct ft_sink sink;
    struct ft_linux_probes probes;
    struct ring_buffer *ring;
    int agg_fd; /* slot the probes write through */
    int agg_maps[2];
    int active; /* index into agg_maps currently in the slot */
    int counters_fd;
    int ncpus;
    uint64_t *cpu_values;
    uint64_t counters[FT_BPF_CNT_MAX];
    struct ft_bpf_agg_key *keys;
    struct ft_bpf_agg_val *vals;
    struct agg_record *transfers;
    size_t ntransfers;
    uint64_t events;
    uint64_t queue_bytes;
    uint64_t queue_peak_bytes;
    uint64_t last_flush_ns;
    char path[FT_BPF_PATH_BUF + FT_BPF_NAME_MAX + 8];
};

static void emit(struct ft_backend *b, const struct ft_event *ev)
{
    b->events++;
    b->sink.emit(b->sink.ctx, ev);
}

static enum ft_sock_state tcp_state(unsigned state)
{
    switch (state) {
    case 1:
        return FT_SOCK_ESTABLISHED;
    case 2:
        return FT_SOCK_CONNECTING;
    case 7:
        return FT_SOCK_CLOSED;
    case 10:
        return FT_SOCK_LISTENING;
    default:
        return FT_SOCK_UNKNOWN;
    }
}

static void on_process(struct ft_backend *b, const struct ft_bpf_ev_proc *e, const char *exe)
{
    struct ft_event ev = {
        .ts_ns = e->hdr.ts_ns,
        .process =
            {
                .pid = e->pid,
                .ppid = e->ppid,
                .uid = e->uid,
                .gid = e->gid,
                .start_ns = e->start_ns,
                .cgroup_id = e->cgroup_id,
                .pidns = e->pidns,
                .mntns = e->mntns,
                .exit_status = e->exit_code,
            },
    };

    switch (e->hdr.kind) {
    case FT_BPF_EV_EXEC:
        ev.type = FT_EVENT_PROCESS_EXEC;
        break;
    case FT_BPF_EV_FORK:
        ev.type = FT_EVENT_PROCESS_FORK;
        break;
    default:
        ev.type = FT_EVENT_PROCESS_EXIT;
        break;
    }
    memcpy(ev.process.comm, e->comm, sizeof(ev.process.comm));
    ev.process.comm[sizeof(ev.process.comm) - 1] = '\0';
    if (exe)
        ft_strlcpy(ev.process.exe, exe, sizeof(ev.process.exe));
    emit(b, &ev);
}

static void on_sock_state(struct ft_backend *b, const struct ft_bpf_ev_sock *e)
{
    struct ft_event ev = {
        .type = FT_EVENT_SOCKET_STATE,
        .ts_ns = e->hdr.ts_ns,
        .socket =
            {
                .sock_id = e->cookie,
                .pid = e->pid,
                .proto = e->proto,
                .state = tcp_state(e->new_state),
            },
    };
    ft_endpoint_set(&ev.socket.local, e->family == AF_INET6, e->laddr, e->lport);
    ft_endpoint_set(&ev.socket.remote, e->family == AF_INET6, e->raddr, e->rport);
    emit(b, &ev);
}

static struct ft_file_id file_id(uint32_t kernel_dev, uint64_t ino, uint32_t instance)
{
    /* The kernel packs dev_t as major:12 minor:20; stat(2) reports makedev(). */
    return (struct ft_file_id){
        .dev = makedev(kernel_dev >> 20, kernel_dev & 0xfffff),
        .ino = ino,
        .instance = instance,
    };
}

static void on_file(struct ft_backend *b, const struct ft_bpf_ev_file *e, size_t size)
{
    const char *comps = (const char *)(e + 1);
    size_t len = e->path_len;
    if (sizeof(*e) + len > size)
        return;

    /* Components arrive leaf first, each NUL-terminated; join them in reverse. */
    const char *starts[FT_BPF_PATH_DEPTH];
    size_t count = 0;
    for (size_t off = 0; off < len && count < FT_BPF_PATH_DEPTH;) {
        size_t n = strnlen(comps + off, len - off);
        if (off + n >= len)
            break;
        starts[count++] = comps + off;
        off += n + 1;
    }

    size_t out = 0;
    b->path[0] = '\0';
    if (e->flags & FT_BPF_FILE_TRUNCATED)
        out += (size_t)snprintf(b->path, sizeof(b->path), "...");
    for (size_t i = count; i-- > 0;) {
        bool separator = !(e->flags & FT_BPF_FILE_DETACHED) || i + 1 < count;
        int n =
            snprintf(b->path + out, sizeof(b->path) - out, "%s%s", separator ? "/" : "", starts[i]);
        if (n < 0 || (size_t)n >= sizeof(b->path) - out)
            break;
        out += (size_t)n;
    }
    if (count == 0)
        ft_strlcpy(b->path, "/", sizeof(b->path));

    struct ft_event ev = {
        .type = FT_EVENT_FILE_SEEN,
        .ts_ns = e->hdr.ts_ns,
        .file =
            {
                .id = file_id(e->dev, e->ino, e->instance),
                .generation = e->gen,
                .mnt_id = e->mnt_id,
                .mntns = e->mntns,
                .deleted = (e->flags & FT_BPF_FILE_DELETED) != 0,
                .path_truncated = (e->flags & FT_BPF_FILE_TRUNCATED) != 0,
                .path = b->path,
            },
    };
    ft_linux_fs_type(e->fs_magic, ev.file.fs_type, sizeof(ev.file.fs_type));
    emit(b, &ev);
}

static int on_ring_event(void *ctx, void *data, size_t size)
{
    struct ft_backend *b = ctx;
    const struct ft_bpf_ev_hdr *hdr = data;

    if (size < sizeof(*hdr))
        return 0;
    switch (hdr->kind) {
    case FT_BPF_EV_EXEC:
        if (size >= sizeof(struct ft_bpf_ev_exec)) {
            const struct ft_bpf_ev_exec *e = data;
            char exe[FT_BPF_EXE_LEN];
            memcpy(exe, e->exe, sizeof(exe));
            exe[sizeof(exe) - 1] = '\0';
            on_process(b, &e->proc, exe);
        }
        break;
    case FT_BPF_EV_FORK:
    case FT_BPF_EV_EXIT:
        if (size >= sizeof(struct ft_bpf_ev_proc))
            on_process(b, data, nullptr);
        break;
    case FT_BPF_EV_SOCK_STATE:
        if (size >= sizeof(struct ft_bpf_ev_sock))
            on_sock_state(b, data);
        break;
    case FT_BPF_EV_FILE:
        if (size >= sizeof(struct ft_bpf_ev_file))
            on_file(b, data, size);
        break;
    default:
        break;
    }
    return 0;
}

static void emit_flow(struct ft_backend *b, const struct ft_bpf_agg_key *k,
                      const struct ft_bpf_agg_val *v)
{
    struct ft_event ev = {
        .type = FT_EVENT_FLOW,
        .ts_ns = v->last_ns,
        .flow =
            {
                .sock_id = k->cookie,
                .pid = k->tgid,
                .proto = v->proto,
                .first_ns = v->first_ns,
                .tx_bytes = v->flow.bytes[FT_BPF_TX],
                .rx_bytes = v->flow.bytes[FT_BPF_RX],
                .tx_ops = v->flow.ops[FT_BPF_TX],
                .rx_ops = v->flow.ops[FT_BPF_RX],
            },
    };
    ft_endpoint_set(&ev.flow.local, v->family == AF_INET6, v->laddr, v->lport);
    ft_endpoint_set(&ev.flow.remote, v->family == AF_INET6, k->raddr, k->rport);
    emit(b, &ev);
}

static void emit_transfer(struct ft_backend *b, const struct agg_record *r)
{
    bool sendfile = r->key.kind == FT_BPF_AGG_SENDFILE;
    struct ft_event ev = {
        .type = FT_EVENT_TRANSFER,
        .ts_ns = r->val.last_ns,
        .transfer =
            {
                .sock_id = r->key.cookie,
                .pid = r->key.tgid,
                .method = sendfile ? FT_METHOD_SENDFILE : FT_METHOD_READ_SEND,
                .file = file_id(r->key.file.dev, r->key.file.ino, r->key.file.instance),
                .first_ns = r->val.first_ns,
                .bytes = r->val.transfer.sent_bytes,
                .read_bytes = r->val.transfer.read_bytes,
                .ops = r->val.transfer.sends,
                .alternations = r->val.transfer.alternations,
            },
    };
    emit(b, &ev);
}

/* The kernel completes the swap only after running probes finish, so the old map is quiescent. */
static void drain_counters(struct ft_backend *b)
{
    __u32 zero = 0;
    int idle = 1 - b->active;
    int previous = b->agg_maps[b->active];

    if (bpf_map_update_elem(b->agg_fd, &zero, &b->agg_maps[idle], BPF_ANY) != 0) {
        ft_log(FT_LOG_WARN, "cannot rotate the counter maps: %s", strerror(errno));
        return;
    }
    b->active = idle;
    b->ntransfers = 0;

    struct ft_bpf_agg_key cursor;
    void *in = nullptr;
    for (;;) {
        __u32 count = (__u32)DRAIN_BATCH;
        int err = bpf_map_lookup_and_delete_batch(previous, in, &cursor, b->keys, b->vals, &count,
                                                  nullptr);
        if (err && errno != ENOENT) {
            ft_log(FT_LOG_WARN, "cannot read the counter map: %s", strerror(errno));
            break;
        }
        for (__u32 i = 0; i < count; i++) {
            if (b->keys[i].kind == FT_BPF_AGG_FLOW) {
                emit_flow(b, &b->keys[i], &b->vals[i]);
            } else if (b->ntransfers < b->cfg.agg_entries) {
                b->transfers[b->ntransfers].key = b->keys[i];
                b->transfers[b->ntransfers].val = b->vals[i];
                b->ntransfers++;
            }
        }
        if (err)
            break;
        in = &cursor;
    }

    /* Transfers refer to sockets, which the flow records above describe. */
    for (size_t i = 0; i < b->ntransfers; i++)
        emit_transfer(b, &b->transfers[i]);
}

static void read_counters(struct ft_backend *b, uint64_t totals[FT_BPF_CNT_MAX])
{
    for (__u32 idx = 0; idx < FT_BPF_CNT_MAX; idx++) {
        totals[idx] = b->counters[idx];
        if (bpf_map_lookup_elem(b->counters_fd, &idx, b->cpu_values) != 0)
            continue;
        totals[idx] = 0;
        for (int cpu = 0; cpu < b->ncpus; cpu++)
            totals[idx] += b->cpu_values[cpu];
    }
}

static void report_losses(struct ft_backend *b, const uint64_t totals[FT_BPF_CNT_MAX],
                          uint64_t now_ns)
{
    static const struct {
        enum ft_bpf_counter counter;
        enum ft_loss_kind kind;
    } losses[] = {
        {FT_BPF_CNT_RING_FULL, FT_LOSS_EVENT_QUEUE},
        {FT_BPF_CNT_AGG_FULL, FT_LOSS_AGGREGATION},
        {FT_BPF_CNT_SOCK_UNIDENTIFIED, FT_LOSS_SOCKET_IDENT},
    };

    for (size_t i = 0; i < FT_ARRAY_LEN(losses); i++) {
        uint64_t delta = totals[losses[i].counter] - b->counters[losses[i].counter];
        if (delta == 0)
            continue;

        struct ft_event ev = {
            .type = FT_EVENT_LOSS,
            .ts_ns = now_ns,
            .loss = {.kind = losses[i].kind, .count = delta, .since_ns = b->last_flush_ns},
        };
        b->sink.emit(b->sink.ctx, &ev);
    }
}

static void backend_flush(struct ft_backend *b)
{
    uint64_t now_ns = ft_clock_mono_ns();
    uint64_t queued = ring__avail_data_size(ring_buffer__ring(b->ring, 0));
    uint64_t totals[FT_BPF_CNT_MAX];

    if (queued > b->queue_peak_bytes)
        b->queue_peak_bytes = queued;
    ring_buffer__consume(b->ring);

    /* Emptying a counter map walks all of its buckets; skip it while it received no entries. */
    read_counters(b, totals);
    if (totals[FT_BPF_CNT_AGG_INSERTS] != b->counters[FT_BPF_CNT_AGG_INSERTS])
        drain_counters(b);
    report_losses(b, totals, now_ns);

    memcpy(b->counters, totals, sizeof(b->counters));
    b->last_flush_ns = now_ns;
}

static int backend_poll_fd(struct ft_backend *b)
{
    return ring_buffer__epoll_fd(b->ring);
}

static void backend_stats(struct ft_backend *b, struct ft_backend_stats *out)
{
    out->events = b->events;
    out->queue_bytes = b->queue_bytes;
    out->queue_peak_bytes = b->queue_peak_bytes;
}

static void backend_capabilities(struct ft_backend *b, struct ft_capabilities *out)
{
    ft_linux_capabilities(b->probes.status, b->cfg.mode, out);
}

static void backend_close(struct ft_backend *b)
{
    if (!b)
        return;
    ring_buffer__free(b->ring);
    ft_linux_probes_unload(&b->probes);
    free(b->cpu_values);
    free(b->keys);
    free(b->vals);
    free(b->transfers);
    free(b);
}

static struct ft_backend *backend_open(const struct ft_backend_config *cfg,
                                       const struct ft_sink *sink, struct ft_error *err)
{
    if (!ft_linux_privileged()) {
        ft_error_set(err, FT_EXIT_PERMISSION,
                     "Permission denied.\n\n"
                     "Filetrace needs additional privileges to attach its\n"
                     "Linux eBPF instrumentation.\n\n"
                     "Run:\n"
                     "  sudo filetrace doctor\n\n"
                     "Some features may remain unavailable even with root\n"
                     "privileges if the kernel lacks the required support.");
        return nullptr;
    }

    struct ft_backend *b = calloc(1, sizeof(*b));
    if (!b) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return nullptr;
    }
    b->cfg = *cfg;
    b->sink = *sink;

    int rc = ft_linux_probes_load(cfg, &b->probes);
    if (rc) {
        ft_error_set(err, rc == -EPERM || rc == -EACCES ? FT_EXIT_PERMISSION : FT_EXIT_UNSUPPORTED,
                     "Cannot load the Linux eBPF instrumentation: %s.\n"
                     "%s\n\n"
                     "Run:\n"
                     "  sudo filetrace doctor",
                     strerror(-rc), ft_linux_last_libbpf_message());
        free(b);
        return nullptr;
    }

    /* Without network accounting there is nothing to attribute files to. */
    if (!ft_linux_group_attached(b->probes.status, FT_PG_NET_IPV4) &&
        !ft_linux_group_attached(b->probes.status, FT_PG_NET_IPV6)) {
        ft_error_set(err, FT_EXIT_UNSUPPORTED,
                     "The kernel refused the network probes, so no traffic can be observed.\n"
                     "%s\n\n"
                     "Run:\n"
                     "  sudo filetrace doctor",
                     ft_linux_last_libbpf_message());
        backend_close(b);
        return nullptr;
    }
    for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
        const struct ft_probe_status *st = &b->probes.status[i];
        if (st->state != FT_PROBE_ATTACHED && st->state != FT_PROBE_NOT_NEEDED)
            ft_log(FT_LOG_WARN, "probe on %s is unavailable (%s); related features are reduced",
                   ft_linux_probe_defs[i].target,
                   st->state == FT_PROBE_MISMATCH ? "unexpected kernel function signature"
                                                  : strerror(st->error));
    }

    struct bpf_object *obj = b->probes.obj;
    struct bpf_map *events = bpf_object__find_map_by_name(obj, "events");
    b->agg_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "agg"));
    b->agg_maps[0] = bpf_map__fd(bpf_object__find_map_by_name(obj, "agg_a"));
    b->agg_maps[1] = bpf_map__fd(bpf_object__find_map_by_name(obj, "agg_b"));
    b->counters_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "counters"));
    b->queue_bytes = bpf_map__max_entries(events);
    b->ncpus = libbpf_num_possible_cpus();
    b->last_flush_ns = ft_clock_mono_ns();

    b->ring = ring_buffer__new(bpf_map__fd(events), on_ring_event, b, nullptr);
    b->cpu_values = calloc((size_t)(b->ncpus > 0 ? b->ncpus : 1), sizeof(uint64_t));
    b->keys = calloc(DRAIN_BATCH, sizeof(*b->keys));
    b->vals = calloc(DRAIN_BATCH, sizeof(*b->vals));
    b->transfers = calloc(cfg->agg_entries, sizeof(*b->transfers));
    if (!b->ring || b->ncpus <= 0 || !b->cpu_values || !b->keys || !b->vals || !b->transfers) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot set up event collection: %s",
                     strerror(errno ? errno : ENOMEM));
        backend_close(b);
        return nullptr;
    }
    return b;
}

static const struct ft_backend_ops ops = {
    .name = "Linux eBPF",
    .diagnose = ft_linux_diagnose,
    .open = backend_open,
    .poll_fd = backend_poll_fd,
    .flush = backend_flush,
    .stats = backend_stats,
    .capabilities = backend_capabilities,
    .lookup_process = ft_linux_lookup_process,
    .close = backend_close,
};

const struct ft_backend_ops *ft_backend_native(void)
{
    return &ops;
}
