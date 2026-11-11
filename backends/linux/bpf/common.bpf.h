#ifndef FILETRACE_LINUX_BPF_COMMON_H
#define FILETRACE_LINUX_BPF_COMMON_H

#include "kernel_types.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "abi.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6

#define S_IFMT 0170000
#define S_IFREG 0100000
#define S_IFSOCK 0140000

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define TCP_LISTEN 10

#define MSG_PEEK 0x2
#define MSG_SPLICE_PAGES 0x8000000

#define EEXIST 17

#define PROC_SUPER_MAGIC 0x9fa0
#define SYSFS_MAGIC 0x62656572
#define CGROUP_SUPER_MAGIC 0x27e0eb
#define CGROUP2_SUPER_MAGIC 0x63677270
#define DEBUGFS_MAGIC 0x64626720
#define TRACEFS_MAGIC 0x74726163
#define SECURITYFS_MAGIC 0x73636673
#define CONFIGFS_MAGIC 0x62656570
#define BPF_FS_MAGIC 0xcafe4a11
#define SELINUX_MAGIC 0xf97cff8c
#define NSFS_MAGIC 0x6e736673
#define PSTOREFS_MAGIC 0x6165676c

const volatile struct ft_bpf_cfg cfg = {
    .corr_window_ns = 2000000000ULL,
    .wakeup_bytes = 1 << 20,
    .file_corr = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct agg_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ft_bpf_agg_key);
    __type(value, struct ft_bpf_agg_val);
};

struct agg_map agg_a SEC(".maps");
struct agg_map agg_b SEC(".maps");

/* Userspace swaps slot 0 to the idle map before reading the other; the swap waits for probes. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, __u32);
    __array(values, struct agg_map);
} agg SEC(".maps") = {
    .values = {[0] = &agg_a},
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, FT_BPF_CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct file_key {
    __u64 ino;
    __u32 dev;
    __u32 gen;
};

/* A file as records refer to it; instance 0 means its path could not be reported yet. */
struct file_ref {
    __u64 ino;
    __u32 dev;
    __u32 instance;
};

/* The file a thread read most recently and how much of it is unsent. */
struct thread_state {
    struct file_ref file;
    __u32 gen;
    __u32 forgotten; /* value of forgotten_files when the instance was resolved */
    __u64 pending;
    __u64 unreported;
    __u64 last_ns;
    __u8 fresh;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct thread_state);
} threads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct file_key);
    __type(value, __u32);
} known_files SEC(".maps");

static __u32 last_file_instance;
static __u32 forgotten_files;

struct path_scratch {
    __u32 busy;
    __u32 pad;
    struct ft_bpf_ev_file ev;
    char comps[FT_BPF_PATH_BUF + FT_BPF_NAME_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_scratch);
} scratch SEC(".maps");

static __always_inline void count(__u32 idx)
{
    __u64 *c = bpf_map_lookup_elem(&counters, &idx);
    if (c)
        *c += 1;
}

static __always_inline __u64 wake_flags(void)
{
    __u64 queued = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
    return queued >= cfg.wakeup_bytes ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
}

static __always_inline void fill_proc(struct ft_bpf_ev_proc *e, struct task_struct *task,
                                      __u32 kind)
{
    __u64 ids = bpf_get_current_uid_gid();

    e->hdr.ts_ns = bpf_ktime_get_boot_ns();
    e->hdr.kind = kind;
    e->hdr.pad = 0;
    e->start_ns = BPF_CORE_READ(task, start_boottime);
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = (__u32)BPF_CORE_READ(task, tgid);
    e->ppid = (__u32)BPF_CORE_READ(task, real_parent, tgid);
    e->uid = (__u32)ids;
    e->gid = (__u32)(ids >> 32);
    e->pidns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    e->mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
    e->exit_code = 0;
    e->pad = 0;
    BPF_CORE_READ_STR_INTO(&e->comm, task, comm);
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(ft_process_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm)
{
    struct ft_bpf_ev_exec *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(FT_BPF_CNT_RING_FULL);
        return 0;
    }
    fill_proc(&e->proc, task, FT_BPF_EV_EXEC);
    const char *filename = BPF_CORE_READ(bprm, filename);
    if (bpf_probe_read_kernel_str(e->exe, sizeof(e->exe), filename) < 0)
        e->exe[0] = 0;
    bpf_ringbuf_submit(e, wake_flags());
    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(ft_process_fork, struct task_struct *parent, struct task_struct *child)
{
    if (child->pid != child->tgid)
        return 0;

    struct ft_bpf_ev_proc *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(FT_BPF_CNT_RING_FULL);
        return 0;
    }
    fill_proc(e, child, FT_BPF_EV_FORK);
    bpf_ringbuf_submit(e, wake_flags());
    return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(ft_process_exit, struct task_struct *task)
{
    /* Report once per process: when its last thread is gone. */
    if (task->pid != task->tgid && BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0;

    struct ft_bpf_ev_proc *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(FT_BPF_CNT_RING_FULL);
        return 0;
    }
    fill_proc(e, task, FT_BPF_EV_EXIT);
    e->exit_code = BPF_CORE_READ(task, exit_code);
    bpf_ringbuf_submit(e, wake_flags());
    return 0;
}

static __always_inline void sock_local(const struct sock *sk, __u16 family, __u8 laddr[16],
                                       __u16 *lport)
{
    *lport = FT_READ(sk, __sk_common.skc_num);
    if (family == AF_INET6) {
        FT_COPY16(laddr, sk, __sk_common.skc_v6_rcv_saddr);
    } else {
        __be32 addr = FT_READ(sk, __sk_common.skc_rcv_saddr);
        __builtin_memset(laddr, 0, 16);
        __builtin_memcpy(laddr, &addr, 4);
    }
}

static __always_inline void sock_remote(const struct sock *sk, __u16 family, __u8 raddr[16],
                                        __u16 *rport)
{
    *rport = bpf_ntohs(FT_READ(sk, __sk_common.skc_dport));
    if (family == AF_INET6) {
        FT_COPY16(raddr, sk, __sk_common.skc_v6_daddr);
    } else {
        __be32 addr = FT_READ(sk, __sk_common.skc_daddr);
        __builtin_memset(raddr, 0, 16);
        __builtin_memcpy(raddr, &addr, 4);
    }
}

static __always_inline struct ft_bpf_agg_val *agg_slot(void *map, const struct ft_bpf_agg_key *key,
                                                       const struct ft_bpf_agg_val *init)
{
    struct ft_bpf_agg_val *v = bpf_map_lookup_elem(map, key);
    if (v)
        return v;

    long err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    if (err && err != -EEXIST) {
        count(FT_BPF_CNT_AGG_FULL);
        return NULL;
    }
    if (!err)
        count(FT_BPF_CNT_AGG_INSERTS);
    return bpf_map_lookup_elem(map, key);
}

static __always_inline void thread_reset(struct thread_state *ts)
{
    ts->pending = 0;
    ts->unreported = 0;
    ts->fresh = 0;
}

/* Attributes a send to the file this thread just read, up to what of it is still unsent. */
static __always_inline void correlate_send(void *map, __u64 cookie, __u32 tgid, __u64 sent,
                                           __u64 now)
{
    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
    if (!ts || !ts->pending)
        return;
    if (now - ts->last_ns > cfg.corr_window_ns) {
        thread_reset(ts);
        return;
    }

    __u64 take = sent < ts->pending ? sent : ts->pending;
    struct ft_bpf_agg_key key = {
        .cookie = cookie,
        .tgid = tgid,
        .kind = FT_BPF_AGG_READ_SEND,
        .file = {.ino = ts->file.ino, .dev = ts->file.dev, .instance = ts->file.instance},
    };
    struct ft_bpf_agg_val init = {.first_ns = now};
    struct ft_bpf_agg_val *v = agg_slot(map, &key, &init);
    if (v) {
        __sync_fetch_and_add(&v->transfer.sent_bytes, take);
        __sync_fetch_and_add(&v->transfer.read_bytes, ts->unreported);
        __sync_fetch_and_add(&v->transfer.sends, 1);
        __sync_fetch_and_add(&v->transfer.alternations, ts->fresh);
        v->last_ns = now;
    }
    ts->pending -= take;
    ts->unreported = 0;
    ts->fresh = 0;
    ts->last_ns = now;
}

/* Pseudo filesystems whose regular files are kernel state, not stored data. */
static __always_inline bool fs_excluded(unsigned long magic)
{
    switch (magic) {
    case PROC_SUPER_MAGIC:
    case SYSFS_MAGIC:
    case CGROUP_SUPER_MAGIC:
    case CGROUP2_SUPER_MAGIC:
    case DEBUGFS_MAGIC:
    case TRACEFS_MAGIC:
    case SECURITYFS_MAGIC:
    case CONFIGFS_MAGIC:
    case BPF_FS_MAGIC:
    case SELINUX_MAGIC:
    case NSFS_MAGIC:
    case PSTOREFS_MAGIC:
        return true;
    default:
        return false;
    }
}

struct path_walk {
    struct path_scratch *scratch;
    struct dentry *dentry;
    struct mount *mnt;
    __u32 off;
    __u16 depth;
    __u16 flags;
};

static long path_step(__u64 index, void *arg)
{
    struct path_walk *w = arg;
    struct path_scratch *s = w->scratch;
    struct dentry *dentry = w->dentry;
    struct mount *mnt = w->mnt;

    struct dentry *root = BPF_CORE_READ(mnt, mnt.mnt_root);
    if (dentry == root) {
        struct mount *up = BPF_CORE_READ(mnt, mnt_parent);
        if (up == mnt) {
            w->flags &= ~FT_BPF_FILE_TRUNCATED;
            return 1;
        }
        w->dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
        w->mnt = up;
        return 0;
    }

    __u32 off = w->off;
    if (off >= FT_BPF_PATH_BUF)
        return 1;

    const unsigned char *name = BPF_CORE_READ(dentry, d_name.name);
    long n =
        bpf_probe_read_kernel_str(&s->comps[off & (FT_BPF_PATH_BUF - 1)], FT_BPF_NAME_MAX, name);
    if (n <= 0)
        return 1;
    w->off = off + (__u32)n;
    w->depth++;

    struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
    if (dentry == parent) {
        /* Not reachable from any mount point: an anonymous file. */
        w->flags = FT_BPF_FILE_DETACHED;
        return 1;
    }
    w->dentry = parent;
    return 0;
}

/* Emits the path components leaf first; userspace joins them in reverse. */
static __always_inline int emit_file(struct file *file, struct inode *inode,
                                     const struct file_key *fk, __u32 instance, __u64 fs_magic)
{
    __u32 zero = 0;
    struct path_scratch *s = bpf_map_lookup_elem(&scratch, &zero);
    if (!s)
        return -1;
    /* Another probe on this CPU was preempted while using the buffer. */
    if (__sync_lock_test_and_set(&s->busy, 1)) {
        count(FT_BPF_CNT_PATH_BUSY);
        return -1;
    }

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    struct vfsmount *vfsmnt = BPF_CORE_READ(file, f_path.mnt);
    struct mount *mnt = (void *)vfsmnt - bpf_core_field_offset(struct mount, mnt);
    struct path_walk w = {
        .scratch = s,
        .dentry = dentry,
        .mnt = mnt,
        .flags = FT_BPF_FILE_TRUNCATED,
    };

    s->ev.mnt_id = (__u32)BPF_CORE_READ(mnt, mnt_id);
    s->ev.mntns = BPF_CORE_READ(mnt, mnt_ns, ns.inum);

    bpf_loop(FT_BPF_PATH_DEPTH, path_step, &w, 0);

    if (BPF_CORE_READ(inode, i_nlink) == 0)
        w.flags |= FT_BPF_FILE_DELETED;

    s->ev.hdr.ts_ns = bpf_ktime_get_boot_ns();
    s->ev.hdr.kind = FT_BPF_EV_FILE;
    s->ev.hdr.pad = 0;
    s->ev.ino = fk->ino;
    s->ev.fs_magic = fs_magic;
    s->ev.dev = fk->dev;
    s->ev.gen = fk->gen;
    s->ev.instance = instance;
    s->ev.pad = 0;
    s->ev.depth = w.depth;
    s->ev.flags = w.flags;

    long err = -1;
    __u32 off = w.off;
    if (off < sizeof(s->comps)) {
        s->ev.path_len = off;
        err = bpf_ringbuf_output(&events, &s->ev, sizeof(s->ev) + off, wake_flags());
        if (err)
            count(FT_BPF_CNT_RING_FULL);
    }
    s->busy = 0;
    return err ? -1 : 0;
}

/* Returns the instance of the file, reporting its path the first time; 0 if that failed. */
static __always_inline __u32 file_instance(struct file *file, struct inode *inode,
                                           const struct file_key *fk, __u64 fs_magic)
{
    __u32 *known = bpf_map_lookup_elem(&known_files, fk);
    if (known)
        return *known;

    __u32 instance = __sync_fetch_and_add(&last_file_instance, 1) + 1;
    if (emit_file(file, inode, fk, instance, fs_magic))
        return 0;
    if (bpf_map_update_elem(&known_files, fk, &instance, BPF_NOEXIST) == -EEXIST) {
        known = bpf_map_lookup_elem(&known_files, fk);
        if (known)
            return *known;
    }
    return instance;
}

/* Points the thread at the file it is about to read, starting over if that is another file. */
static __always_inline void thread_set_file(struct thread_state *ts, struct file *file,
                                            struct inode *inode, const struct file_key *fk,
                                            __u64 fs_magic)
{
    if (ts->file.ino != fk->ino || ts->file.dev != fk->dev || ts->gen != fk->gen) {
        ts->file.ino = fk->ino;
        ts->file.dev = fk->dev;
        ts->file.instance = 0;
        ts->gen = fk->gen;
        thread_reset(ts);
    }
    /* A deleted file's inode number may have been given to this one since. */
    if (ts->forgotten != forgotten_files) {
        ts->forgotten = forgotten_files;
        ts->file.instance = 0;
    }
    if (!ts->file.instance)
        ts->file.instance = file_instance(file, inode, fk, fs_magic);
}

/* A deleted file is gone for good once its inode is destroyed. */
static __always_inline void forget_file(struct inode *inode)
{
    if ((FT_READ(inode, i_mode) & S_IFMT) != S_IFREG || FT_READ(inode, i_nlink))
        return;

    struct super_block *sb = FT_READ(inode, i_sb);
    struct file_key fk = {
        .ino = FT_READ(inode, i_ino),
        .dev = FT_READ(sb, s_dev),
        .gen = FT_READ(inode, i_generation),
    };
    if (!bpf_map_delete_elem(&known_files, &fk))
        __sync_fetch_and_add(&forgotten_files, 1);
}

#endif
