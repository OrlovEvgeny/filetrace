#include "backends/linux/linux.h"

#include "filetrace/clock.h"
#include "filetrace/sysinfo.h"

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

static const unsigned char trampoline_object[] = {
#embed FT_BPF_TRAMPOLINE_OBJECT
};

static const unsigned char kprobe_object[] = {
#embed FT_BPF_KPROBE_OBJECT
};

static const struct ft_probe_def trampoline_defs[] = {
    {"ft_process_exec", "sched_process_exec", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_process_fork", "sched_process_fork", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_process_exit", "sched_process_exit", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_sock_state", "inet_sock_set_state", "tracepoint", 0, FT_PG_TCP_STATE, FT_MODE_MINIMAL},
    {"ft_inet_sendmsg", "inet_sendmsg", "fexit", 3, FT_PG_NET, FT_MODE_MINIMAL},
    {"ft_inet_recvmsg", "inet_recvmsg", "fexit", 4, FT_PG_NET, FT_MODE_MINIMAL},
    {"ft_inet6_sendmsg", "inet6_sendmsg", "fexit", 3, FT_PG_NET_IPV6, FT_MODE_MINIMAL},
    {"ft_inet6_recvmsg", "inet6_recvmsg", "fexit", 4, FT_PG_NET_IPV6, FT_MODE_MINIMAL},
    {"ft_vfs_read", "vfs_read", "fexit", 4, FT_PG_FILE_READ, FT_MODE_STANDARD},
    {"ft_splice_direct", "do_splice_direct", "fexit", 6, FT_PG_SENDFILE, FT_MODE_STANDARD},
    {"ft_destroy_inode", "__destroy_inode", "fentry", 1, FT_PG_FILE_END, FT_MODE_STANDARD},
};

static const struct ft_probe_def kprobe_defs[] = {
    {"ft_process_exec", "sched_process_exec", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_process_fork", "sched_process_fork", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_process_exit", "sched_process_exit", "tracepoint", 0, FT_PG_PROCESS, FT_MODE_MINIMAL},
    {"ft_sock_state", "inet_sock_set_state", "tracepoint", 0, FT_PG_TCP_STATE, FT_MODE_MINIMAL},
    {"ft_tcp_sendmsg", "tcp_sendmsg", "kprobe", 3, FT_PG_NET, FT_MODE_MINIMAL},
    {"ft_tcp_cleanup_rbuf", "tcp_cleanup_rbuf", "kprobe", 2, FT_PG_NET, FT_MODE_MINIMAL},
    {"ft_sock_destruct", "inet_sock_destruct", "kprobe", 1, FT_PG_NET, FT_MODE_MINIMAL},
    {"ft_ip_send_skb", "ip_send_skb", "kprobe", 2, FT_PG_NET, FT_MODE_MINIMAL},
    {"ft_skb_consume_udp", "skb_consume_udp", "kprobe", 3, FT_PG_NET, FT_MODE_MINIMAL},
    {"ft_ip6_send_skb", "ip6_send_skb", "kprobe", 1, FT_PG_NET_IPV6, FT_MODE_MINIMAL},
    {"ft_vfs_read", "vfs_read", "kprobe", 4, FT_PG_FILE_READ, FT_MODE_STANDARD},
    {"ft_splice_direct", "do_splice_direct", "kprobe", 6, FT_PG_SENDFILE, FT_MODE_STANDARD},
    {"ft_destroy_inode", "__destroy_inode", "kprobe", 1, FT_PG_FILE_END, FT_MODE_STANDARD},
};

static_assert(FT_ARRAY_LEN(trampoline_defs) <= FT_LINUX_MAX_PROBES);
static_assert(FT_ARRAY_LEN(kprobe_defs) <= FT_LINUX_MAX_PROBES);
static_assert(FT_BPF_LOOKUP_ADDRS == FT_LOOKUP_ADDRS);
/* A name longer than a host name's 253 bytes arrives longer, never cut to a valid one. */
static_assert(FT_BPF_LOOKUP_NAME > FT_NAME_MAX);

static const struct ft_probe_set trampoline_set = {
    .kind = FT_PROBES_TRAMPOLINE,
    .defs = trampoline_defs,
    .count = FT_ARRAY_LEN(trampoline_defs),
    .object = trampoline_object,
    .object_size = sizeof(trampoline_object),
};

static const struct ft_probe_set kprobe_set = {
    .kind = FT_PROBES_KPROBE,
    .defs = kprobe_defs,
    .count = FT_ARRAY_LEN(kprobe_defs),
    .object = kprobe_object,
    .object_size = sizeof(kprobe_object),
};

static char last_message[512];
static char failed_program[64]; /* the program the kernel refused last */

static int on_libbpf_print(enum libbpf_print_level level, const char *fmt, va_list ap)
{
    char line[1024];
    char program[64];
    int end = 0;

    if (level == LIBBPF_DEBUG)
        return 0;
    vsnprintf(line, sizeof(line), fmt, ap);
    line[strcspn(line, "\n")] = '\0';
    if (level == LIBBPF_WARN && strncmp(line, "libbpf: ", 8) == 0)
        ft_strlcpy(last_message, line + 8, sizeof(last_message));
    if (sscanf(line, "libbpf: prog '%63[^']': failed to load%n", program, &end) == 1 && end)
        ft_strlcpy(failed_program, program, sizeof(failed_program));
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

static bool kernel_struct_has(const struct btf *vmlinux, const char *type, const char *member)
{
    int id = btf__find_by_name_kind(vmlinux, type, BTF_KIND_STRUCT);
    const struct btf_type *t = id < 0 ? nullptr : btf__type_by_id(vmlinux, (__u32)id);
    if (!t)
        return false;

    const struct btf_member *m = btf_members(t);
    for (unsigned i = 0; i < btf_vlen(t); i++) {
        if (strcmp(btf__name_by_offset(vmlinux, m[i].name_off), member) == 0)
            return true;
    }
    return false;
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

static bool probe_wanted(const struct ft_probe_def *def, const struct ft_backend_config *cfg)
{
    if (cfg->mode < def->min_mode)
        return false;
    switch (def->group) {
    case FT_PG_FILE_READ:
        return cfg->track_read;
    case FT_PG_SENDFILE:
        return cfg->track_sendfile;
    case FT_PG_FILE_END:
        return cfg->track_read || cfg->track_sendfile;
    default:
        return true;
    }
}

/* Whether any probe that identifies files is going to be loaded. */
static bool enabled_file_probes(const struct ft_probe_set *set,
                                const bool enabled[FT_LINUX_MAX_PROBES])
{
    for (size_t i = 0; i < set->count; i++) {
        if (enabled[i] &&
            (set->defs[i].group == FT_PG_FILE_READ || set->defs[i].group == FT_PG_SENDFILE))
            return true;
    }
    return false;
}

/* Whether the probes of getaddrinfo are loaded. */
static bool lookups_wanted(const struct ft_backend_config *cfg)
{
    return cfg->lookup_names && cfg->mode >= FT_MODE_STANDARD && ft_sysinfo_host_pid_namespace();
}

static struct bpf_object *open_object(const struct ft_probe_set *set,
                                      const struct ft_backend_config *cfg,
                                      const bool enabled[FT_LINUX_MAX_PROBES], bool lookups)
{
    struct bpf_object_open_opts opts = {.sz = sizeof(opts), .object_name = "filetrace"};
    struct bpf_object *obj = bpf_object__open_mem(set->object, set->object_size, &opts);
    if (!obj)
        return nullptr;

    struct ft_bpf_cfg *bpf_cfg = rodata_variable(obj, "cfg", sizeof(*bpf_cfg));
    struct bpf_map *events = bpf_object__find_map_by_name(obj, "events");
    struct bpf_map *agg_a = bpf_object__find_map_by_name(obj, "agg_a");
    struct bpf_map *agg_b = bpf_object__find_map_by_name(obj, "agg_b");
    struct bpf_map *known = bpf_object__find_map_by_name(obj, "known_files");
    struct bpf_program *lookup = bpf_object__find_program_by_name(obj, "ft_getaddrinfo");
    struct bpf_program *lookup_return =
        bpf_object__find_program_by_name(obj, "ft_getaddrinfo_return");
    struct bpf_map *calls = bpf_object__find_map_by_name(obj, "lookup_calls");
    if (!bpf_cfg || !events || !agg_a || !agg_b || !known || !lookup || !lookup_return || !calls) {
        bpf_object__close(obj);
        errno = EINVAL;
        return nullptr;
    }
    bpf_program__set_autoload(lookup, lookups);
    bpf_program__set_autoload(lookup_return, lookups);
    bpf_map__set_autocreate(calls, lookups);

    uint32_t queue = round_up_pow2(cfg->queue_bytes, (uint32_t)sysconf(_SC_PAGESIZE));
    bpf_cfg->corr_window_ns = cfg->corr_window_ns;
    bpf_cfg->wakeup_bytes = queue / 4;
    bpf_cfg->file_corr = cfg->mode >= FT_MODE_STANDARD && enabled_file_probes(set, enabled);
    bpf_map__set_max_entries(events, queue);
    bpf_map__set_max_entries(agg_a, cfg->agg_entries);
    bpf_map__set_max_entries(agg_b, cfg->agg_entries);
    bpf_map__set_max_entries(known, cfg->known_files);

    for (size_t i = 0; i < set->count; i++) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, set->defs[i].program);
        if (!prog) {
            bpf_object__close(obj);
            errno = EINVAL;
            return nullptr;
        }
        bpf_program__set_autoload(prog, enabled[i]);
    }
    return obj;
}

static int load_with(const struct ft_probe_set *set, const struct ft_backend_config *cfg,
                     const bool enabled[FT_LINUX_MAX_PROBES], bool lookups, struct bpf_object **out,
                     int *aging_error)
{
    struct bpf_object *obj = open_object(set, cfg, enabled, lookups);
    if (!obj)
        return errno ? -errno : -EINVAL;

    int err = bpf_object__load(obj);
    if (err) {
        /* Without the aging iterator, a window is judged at its connection's next event. */
        bpf_object__close(obj);
        obj = open_object(set, cfg, enabled, lookups);
        struct bpf_program *aging =
            obj ? bpf_object__find_program_by_name(obj, "ft_carries_aged") : nullptr;
        if (!aging) {
            bpf_object__close(obj);
            return err;
        }
        bpf_program__set_autoload(aging, false);
        if (bpf_object__load(obj)) {
            bpf_object__close(obj);
            return err;
        }
        if (aging_error)
            *aging_error = -err;
    }
    *out = obj;
    return 0;
}

/* Puts the background and strict lists in place, so that the first read a probe sees is told. */
static void load_lists(struct ft_linux_probes *p, const struct ft_backend_config *cfg)
{
    int files_fd = bpf_map__fd(bpf_object__find_map_by_name(p->obj, "background_files"));
    int names_fd = bpf_map__fd(bpf_object__find_map_by_name(p->obj, "background_names"));
    int suffixes_fd = bpf_map__fd(bpf_object__find_map_by_name(p->obj, "background_suffixes"));
    if (files_fd >= 0)
        p->listed_files = ft_linux_background_load(files_fd, cfg, &p->listed_truncated);
    if (names_fd >= 0 && suffixes_fd >= 0)
        ft_linux_background_names(names_fd, suffixes_fd, cfg);
}

/* Attaches the iterator that judges windows nothing touched lately to the windows' map. */
static void attach_aging(struct ft_linux_probes *p)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(p->obj, "ft_carries_aged");
    struct bpf_map *carries = bpf_object__find_map_by_name(p->obj, "carries");
    if (!prog || !carries || bpf_program__fd(prog) < 0) {
        if (!p->aging_error)
            p->aging_error = ENOENT;
        return;
    }
    union bpf_iter_link_info info = {.map = {.map_fd = (uint32_t)bpf_map__fd(carries)}};
    /* libbpf refuses options whose padding is not zero. */
    struct bpf_iter_attach_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.link_info = &info;
    opts.link_info_len = sizeof(info);
    p->aging = bpf_program__attach_iter(prog, &opts);
    if (!p->aging)
        p->aging_error = errno;
}

static int load_set(const struct ft_probe_set *set, const struct ft_backend_config *cfg,
                    struct ft_linux_probes *out)
{
    bool enabled[FT_LINUX_MAX_PROBES] = {false};
    size_t wanted = 0;

    memset(out, 0, sizeof(*out));
    out->set = set;
    last_message[0] = '\0';
    failed_program[0] = '\0';

    struct btf *vmlinux = btf__load_vmlinux_btf();
    for (size_t i = 0; i < set->count; i++) {
        const struct ft_probe_def *def = &set->defs[i];

        enabled[i] = probe_wanted(def, cfg);
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
        /* Without return probes, the size of a read comes from the task's I/O accounting. */
        if (vmlinux && set->kind == FT_PROBES_KPROBE && def->group == FT_PG_FILE_READ &&
            !kernel_struct_has(vmlinux, "task_io_accounting", "rchar")) {
            enabled[i] = false;
            out->status[i].state = FT_PROBE_NO_ACCOUNTING;
            continue;
        }
        wanted++;
    }
    btf__free(vmlinux);

    bool lookups = lookups_wanted(cfg);
    int err =
        wanted ? load_with(set, cfg, enabled, lookups, &out->obj, &out->aging_error) : -ENOENT;
    if (err && lookups && strncmp(failed_program, "ft_getaddrinfo", 14) == 0) {
        /* Without the probes of getaddrinfo, connections have no looked-up names. */
        out->lookups_error = -err;
        lookups = false;
        err = load_with(set, cfg, enabled, false, &out->obj, &out->aging_error);
    }
    if (err && wanted > 1) {
        /* One rejected probe fails the whole object: find which ones load. */
        int first_error = err;
        size_t usable = 0;

        for (size_t i = 0; i < set->count; i++) {
            if (!enabled[i])
                continue;
            bool only[FT_LINUX_MAX_PROBES] = {false};
            struct bpf_object *trial = nullptr;

            only[i] = true;
            int trial_err = load_with(set, cfg, only, false, &trial, nullptr);
            if (trial_err) {
                enabled[i] = false;
                out->status[i] = (struct ft_probe_status){FT_PROBE_LOAD_FAILED, -trial_err};
            } else {
                bpf_object__close(trial);
                usable++;
            }
        }
        out->aging_error = 0;
        err = usable ? load_with(set, cfg, enabled, lookups, &out->obj, &out->aging_error)
                     : first_error;
    }
    out->lookups = lookups && !err;
    if (err) {
        for (size_t i = 0; i < set->count; i++) {
            if (enabled[i])
                out->status[i] = (struct ft_probe_status){FT_PROBE_LOAD_FAILED, -err};
        }
        return err;
    }

    load_lists(out, cfg);
    for (size_t i = 0; i < set->count; i++) {
        if (!enabled[i])
            continue;
        struct bpf_program *prog = bpf_object__find_program_by_name(out->obj, set->defs[i].program);
        out->links[i] = bpf_program__attach(prog);
        if (!out->links[i])
            out->status[i] = (struct ft_probe_status){FT_PROBE_ATTACH_FAILED, errno};
        else
            out->status[i].state = FT_PROBE_ATTACHED;
    }
    attach_aging(out);
    return 0;
}

int ft_linux_probes_load(const struct ft_backend_config *cfg, struct ft_linux_probes *out)
{
    libbpf_set_print(on_libbpf_print);

    if (cfg->probes == FT_PROBES_KPROBE)
        return load_set(&kprobe_set, cfg, out);

    int err = load_set(&trampoline_set, cfg, out);
    if (cfg->probes == FT_PROBES_TRAMPOLINE || ft_linux_network_attached(out))
        return err;

    /* The kernel loaded the programs but cannot attach them to functions. */
    struct ft_linux_probes fallback;
    int fallback_err = load_set(&kprobe_set, cfg, &fallback);
    if (fallback_err || !ft_linux_network_attached(&fallback)) {
        if (!fallback_err)
            ft_linux_probes_unload(&fallback);
        return err;
    }
    if (!err)
        ft_linux_probes_unload(out);
    *out = fallback;
    return 0;
}

void ft_linux_probes_unload(struct ft_linux_probes *p)
{
    bpf_link__destroy(p->aging);
    p->aging = nullptr;
    for (size_t i = 0; i < FT_LINUX_MAX_PROBES; i++) {
        bpf_link__destroy(p->links[i]);
        p->links[i] = nullptr;
    }
    bpf_object__close(p->obj);
    p->obj = nullptr;
}

bool ft_linux_group_attached(const struct ft_linux_probes *p, enum ft_probe_group group)
{
    if (!p->set || !p->obj)
        return false;
    for (size_t i = 0; i < p->set->count; i++) {
        if (p->set->defs[i].group == group && p->status[i].state != FT_PROBE_ATTACHED)
            return false;
    }
    return true;
}

bool ft_linux_network_attached(const struct ft_linux_probes *p)
{
    /* The kprobe set cannot account TCP without seeing connections open and close. */
    if (p->set && p->set->kind == FT_PROBES_KPROBE && !ft_linux_group_attached(p, FT_PG_TCP_STATE))
        return false;
    return ft_linux_group_attached(p, FT_PG_NET);
}

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
    int background_fd;
    uint64_t background_scan_ns; /* when the background map was last brought up to date */
    uint64_t aged_ns;            /* when the aging iterator last ran */
    struct ft_linux_prober *prober;
    struct ft_linux_php *php;
    int lookup_kind; /* the prober's kind for C libraries, or -1 */
    size_t lookup_capacity;
    char path[FT_BPF_PATH_BUF + FT_BPF_NAME_MAX + 8];
};

/* A bundle replaced by an update is a file with another inode; this long it goes unnoticed. */
#define BACKGROUND_RESCAN_NS (30 * FT_NS_PER_SEC)

static void background_scan(struct ft_backend *b, uint64_t now_ns)
{
    bool truncated = false;
    ft_linux_background_load(b->background_fd, &b->cfg, &truncated);
    b->background_scan_ns = now_ns;
}

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

/* Components arrive leaf first, each NUL-terminated; joins them in reverse. */
static void join_path(const char *comps, size_t len, uint16_t flags, char *path, size_t size)
{
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
    path[0] = '\0';
    if (flags & FT_BPF_FILE_TRUNCATED)
        out += (size_t)snprintf(path, size, "...");
    for (size_t i = count; i-- > 0;) {
        bool separator = !(flags & FT_BPF_FILE_DETACHED) || i + 1 < count;
        int n = snprintf(path + out, size - out, "%s%s", separator ? "/" : "", starts[i]);
        if (n < 0 || (size_t)n >= size - out)
            break;
        out += (size_t)n;
    }
    if (count == 0)
        ft_strlcpy(path, "/", size);
}

/*
 * Has the files a process starts with probed, or those a forked child carries on with: PHP-FPM
 * forks its master off the process that ran it, and web servers load PHP before forking workers.
 */
static void process_started(struct ft_backend *b, const struct ft_bpf_ev_proc *e, const char *exe)
{
    /* The kernel's process ID names the right /proc entry only in the host's namespace. */
    if (!b->prober || !ft_sysinfo_host_pid_namespace())
        return;
    char comm[FT_BPF_COMM_LEN];
    memcpy(comm, e->comm, sizeof(comm));
    comm[sizeof(comm) - 1] = '\0';
    const char *slash = exe ? strrchr(exe, '/') : nullptr;
    const char *name = exe ? (slash ? slash + 1 : exe) : comm;
    ft_linux_prober_started(b->prober, e->pid, name, e->hdr.ts_ns);
}

static void on_process(struct ft_backend *b, const struct ft_bpf_ev_proc *e, const char *exe,
                       const char *args, size_t args_len, const char *cwd)
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
                .netns = e->netns,
                .exit_status = e->exit_code,
                .args = args,
                .args_len = args_len,
                .cwd = cwd,
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

static void on_lookup(struct ft_backend *b, const struct ft_bpf_ev_lookup *e)
{
    char name[FT_BPF_LOOKUP_NAME];
    struct ft_event ev = {
        .type = FT_EVENT_NAME_LOOKUP,
        .ts_ns = e->hdr.ts_ns,
        .lookup =
            {
                .pid = e->pid,
                .tid = e->tid,
                .name = name,
                .addr_count = e->count < FT_LOOKUP_ADDRS ? e->count : FT_LOOKUP_ADDRS,
            },
    };

    memcpy(name, e->name, sizeof(name));
    name[sizeof(name) - 1] = '\0';
    for (uint32_t i = 0; i < ev.lookup.addr_count; i++)
        ft_endpoint_set(&ev.lookup.addrs[i], (e->inet6 >> i) & 1, e->addrs[i], 0);
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
                .tid = e->tid,
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
    join_path(comps, len, e->flags, b->path, sizeof(b->path));

    struct ft_event ev = {
        .type = FT_EVENT_FILE_SEEN,
        .ts_ns = e->hdr.ts_ns,
        .file =
            {
                .id = file_id(e->dev, e->ino, e->instance),
                .generation = e->gen,
                .mnt_id = e->mnt_id,
                .mntns = e->mntns,
                .size = e->size,
                .uid = e->uid,
                .deleted = (e->flags & FT_BPF_FILE_DELETED) != 0,
                .path_truncated = (e->flags & FT_BPF_FILE_TRUNCATED) != 0,
                .path = b->path,
            },
    };
    ft_linux_fs_type(e->fs_magic, ev.file.fs_type, sizeof(ev.file.fs_type));
    if (b->background_fd >= 0 &&
        !(e->flags & (FT_BPF_FILE_TRUNCATED | FT_BPF_FILE_DETACHED | FT_BPF_FILE_DELETED)))
        ft_linux_background_learn(b->background_fd, &b->cfg, e->ino, e->dev, b->path);
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

            const char *tail = (const char *)(e + 1);
            const char *cwd = nullptr;
            const char *args = nullptr;
            size_t args_len = 0;
            if (sizeof(*e) + e->cwd_len + e->args_len <= size) {
                if (e->cwd_len) {
                    join_path(tail, e->cwd_len, e->cwd_flags, b->path, sizeof(b->path));
                    cwd = b->path;
                }
                if (e->args_len) {
                    args = tail + e->cwd_len;
                    args_len = e->args_len;
                }
            }
            on_process(b, &e->proc, exe, args, args_len, cwd);
            process_started(b, &e->proc, exe);
        }
        break;
    case FT_BPF_EV_FORK:
    case FT_BPF_EV_EXIT:
        if (size >= sizeof(struct ft_bpf_ev_proc)) {
            on_process(b, data, nullptr, nullptr, 0, nullptr);
            if (hdr->kind == FT_BPF_EV_FORK)
                process_started(b, data, nullptr);
            else if (ft_sysinfo_host_pid_namespace())
                ft_linux_prober_ended(b->prober, ((const struct ft_bpf_ev_proc *)data)->pid);
        }
        break;
    case FT_BPF_EV_SOCK_STATE:
        if (size >= sizeof(struct ft_bpf_ev_sock))
            on_sock_state(b, data);
        break;
    case FT_BPF_EV_FILE:
        if (size >= sizeof(struct ft_bpf_ev_file))
            on_file(b, data, size);
        break;
    case FT_BPF_EV_SCRIPT:
        if (size >= sizeof(struct ft_bpf_ev_script) && b->php) {
            const struct ft_bpf_ev_script *e = data;
            size_t len = e->len < size - sizeof(*e) ? e->len : size - sizeof(*e);
            ft_linux_php_script_seen(b->php, e->id, e->tgid, e->hash, (const char *)(e + 1), len);
        }
        break;
    case FT_BPF_EV_LOOKUP:
        if (size >= sizeof(struct ft_bpf_ev_lookup))
            on_lookup(b, data);
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
                .background = r->key.background != 0,
                .script = ft_linux_php_script(b->php, r->val.transfer.script),
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
        __u32 count = b->cfg.drain_batch;
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
        {FT_BPF_CNT_PATH_BUSY, FT_LOSS_PATH_BUSY},
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

/* Runs the aging iterator over the windows, which judges the ones nothing touched lately. */
static void age_windows(struct ft_backend *b)
{
    int fd = bpf_iter_create(bpf_link__fd(b->probes.aging));
    if (fd < 0)
        return;
    char buf[64];
    while (read(fd, buf, sizeof(buf)) > 0) {
    }
    close(fd);
}

static void backend_flush(struct ft_backend *b)
{
    uint64_t now_ns = ft_clock_mono_ns();
    uint64_t queued = ring__avail_data_size(ring_buffer__ring(b->ring, 0));
    uint64_t totals[FT_BPF_CNT_MAX];

    if (queued > b->queue_peak_bytes)
        b->queue_peak_bytes = queued;
    ring_buffer__consume(b->ring);
    if (b->probes.aging && now_ns - b->aged_ns >= FT_NS_PER_SEC) {
        age_windows(b);
        b->aged_ns = now_ns;
    }

    /* Emptying a counter map walks all of its buckets; skip it while it received no entries. */
    read_counters(b, totals);
    if (totals[FT_BPF_CNT_AGG_INSERTS] != b->counters[FT_BPF_CNT_AGG_INSERTS])
        drain_counters(b);
    report_losses(b, totals, now_ns);

    memcpy(b->counters, totals, sizeof(b->counters));
    b->last_flush_ns = now_ns;
    if (now_ns - b->background_scan_ns > BACKGROUND_RESCAN_NS) {
        if (b->background_fd >= 0)
            background_scan(b, now_ns);
        ft_linux_prober_rescan(b->prober);
        b->background_scan_ns = now_ns;
    }
    ft_linux_prober_work(b->prober, now_ns);
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
    if (b->background_fd >= 0) {
        out->listed_files = ft_linux_background_count(b->background_fd, &out->listed_refused);
        out->listed_capacity = FT_BPF_BACKGROUND_MAX;
    }
    if (b->lookup_kind >= 0) {
        out->name_libraries = ft_linux_prober_count(b->prober, b->lookup_kind);
        out->name_library_capacity = b->lookup_capacity;
    }
}

static void backend_capabilities(struct ft_backend *b, struct ft_capabilities *out)
{
    ft_linux_capabilities(&b->probes, &b->cfg, out);
}

static void backend_close(struct ft_backend *b)
{
    if (!b)
        return;
    ring_buffer__free(b->ring);
    ft_linux_prober_destroy(b->prober);
    ft_linux_php_close(b->php);
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
    if (b->cfg.drain_batch == 0)
        b->cfg.drain_batch = 512;
    b->sink = *sink;
    b->lookup_kind = -1;

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

    if (!ft_sysinfo_host_pid_namespace())
        ft_log(FT_LOG_WARN, "the agent is not in the host's PID namespace, so it reads nothing "
                            "from /proc: command lines come only from programs started after it");

    /* Without network accounting there is nothing to attribute files to. */
    if (!ft_linux_network_attached(&b->probes)) {
        ft_error_set(err, FT_EXIT_UNSUPPORTED,
                     "The kernel refused the network probes, so no traffic can be observed.\n"
                     "%s\n\n"
                     "Run:\n"
                     "  sudo filetrace doctor",
                     ft_linux_last_libbpf_message());
        backend_close(b);
        return nullptr;
    }
    for (size_t i = 0; i < b->probes.set->count; i++) {
        const struct ft_probe_status *st = &b->probes.status[i];
        if (st->state != FT_PROBE_ATTACHED && st->state != FT_PROBE_NOT_NEEDED)
            ft_log(FT_LOG_WARN, "probe on %s is unavailable (%s); related features are reduced",
                   b->probes.set->defs[i].target,
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
    if (!b->probes.aging)
        ft_log(FT_LOG_WARN,
               "a held transfer is judged only when its connection or thread acts again: "
               "the kernel refused the iterator that judges it after a quiet while (%s)",
               strerror(b->probes.aging_error));
    b->background_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "background_files"));
    b->background_scan_ns = b->last_flush_ns;
    if (b->probes.listed_truncated)
        ft_log(
            FT_LOG_WARN,
            "[correlation] background_paths and strict_paths name more than %d files; %zu are kept",
            FT_BPF_BACKGROUND_MAX, b->probes.listed_files);
    bool php = cfg->php_scripts && cfg->mode >= FT_MODE_STANDARD;
    if (php || b->probes.lookups)
        b->prober = ft_linux_prober_create();
    if (b->prober && php)
        b->php = ft_linux_php_open(obj, b->prober);
    if (b->prober && b->probes.lookups) {
        b->lookup_capacity = cfg->name_libraries;
        b->lookup_kind = ft_linux_lookups_open(obj, b->prober, b->lookup_capacity);
    }
    ft_linux_prober_rescan(b->prober);
    ft_linux_prober_work(b->prober, ft_clock_mono_ns());

    b->ring = ring_buffer__new(bpf_map__fd(events), on_ring_event, b, nullptr);
    b->cpu_values = calloc((size_t)(b->ncpus > 0 ? b->ncpus : 1), sizeof(uint64_t));
    b->keys = calloc(b->cfg.drain_batch, sizeof(*b->keys));
    b->vals = calloc(b->cfg.drain_batch, sizeof(*b->vals));
    b->transfers = calloc(cfg->agg_entries, sizeof(*b->transfers));
    if (!b->ring || b->ncpus <= 0 || !b->cpu_values || !b->keys || !b->vals || !b->transfers) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot set up event collection: %s",
                     strerror(errno ? errno : ENOMEM));
        backend_close(b);
        return nullptr;
    }
    return b;
}

static void backend_describe(struct ft_backend *b, char *buf, size_t size)
{
    snprintf(buf, size, "Linux eBPF (%s)",
             b->probes.set->kind == FT_PROBES_KPROBE ? "kprobes" : "trampolines");
}

static const struct ft_backend_ops ops = {
    .name = "Linux eBPF",
    .describe = backend_describe,
    .diagnose = ft_linux_diagnose,
    .open = backend_open,
    .poll_fd = backend_poll_fd,
    .flush = backend_flush,
    .stats = backend_stats,
    .capabilities = backend_capabilities,
    .lookup_process = ft_linux_lookup_process,
    .read_process_text = ft_linux_read_process_text,
    .close = backend_close,
};

const struct ft_backend_ops *ft_backend_native(void)
{
    return &ops;
}
