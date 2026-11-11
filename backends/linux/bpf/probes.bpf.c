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

/* The file a thread read most recently and how much of it is unsent. */
struct thread_state {
    struct file_key file;
    __u64 pending;
    __u64 unreported;
    __u64 last_ns;
    __u8 fresh;
    __u8 named;
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
    __type(value, __u8);
} known_files SEC(".maps");

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
    *lport = sk->__sk_common.skc_num;
    if (family == AF_INET6) {
        __builtin_memcpy(laddr, &sk->__sk_common.skc_v6_rcv_saddr, 16);
    } else {
        __be32 addr = sk->__sk_common.skc_rcv_saddr;
        __builtin_memset(laddr, 0, 16);
        __builtin_memcpy(laddr, &addr, 4);
    }
}

static __always_inline void sock_remote(const struct sock *sk, __u16 family, __u8 raddr[16],
                                        __u16 *rport)
{
    *rport = bpf_ntohs(sk->__sk_common.skc_dport);
    if (family == AF_INET6) {
        __builtin_memcpy(raddr, &sk->__sk_common.skc_v6_daddr, 16);
    } else {
        __be32 addr = sk->__sk_common.skc_daddr;
        __builtin_memset(raddr, 0, 16);
        __builtin_memcpy(raddr, &addr, 4);
    }
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(ft_sock_state, struct sock *sk, int oldstate, int newstate)
{
    if (sk->sk_protocol != IPPROTO_TCP)
        return 0;
    if (newstate != TCP_ESTABLISHED && newstate != TCP_SYN_SENT && newstate != TCP_LISTEN &&
        newstate != TCP_CLOSE)
        return 0;

    __u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET && family != AF_INET6)
        return 0;

    struct ft_bpf_ev_sock *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(FT_BPF_CNT_RING_FULL);
        return 0;
    }
    e->hdr.ts_ns = bpf_ktime_get_boot_ns();
    e->hdr.kind = FT_BPF_EV_SOCK_STATE;
    e->hdr.pad = 0;
    e->cookie = bpf_get_socket_cookie(sk);
    /* Only connect() and listen() are certain to run in the owner's context. */
    e->pid = (newstate == TCP_SYN_SENT || newstate == TCP_LISTEN)
                 ? (__u32)(bpf_get_current_pid_tgid() >> 32)
                 : 0;
    e->family = family;
    e->proto = IPPROTO_TCP;
    e->old_state = (__u8)oldstate;
    e->new_state = (__u8)newstate;
    e->pad[0] = 0;
    e->pad[1] = 0;
    sock_local(sk, family, e->laddr, &e->lport);
    sock_remote(sk, family, e->raddr, &e->rport);
    bpf_ringbuf_submit(e, wake_flags());
    return 0;
}

struct sockaddr_any {
    __u16 family;
    __be16 port;
    __u8 rest[20]; /* in: addr[4]; in6: flowinfo[4] addr[16] */
};

static __always_inline bool datagram_peer(const struct msghdr *msg, __u16 family, __u8 raddr[16],
                                          __u16 *rport)
{
    void *name = msg->msg_name;
    int len = msg->msg_namelen;
    struct sockaddr_any sa = {};

    if (!name)
        return false;
    if (len >= (int)sizeof(sa)) {
        if (bpf_probe_read_kernel(&sa, sizeof(sa), name))
            return false;
    } else if (len >= 8) {
        if (bpf_probe_read_kernel(&sa, 8, name))
            return false;
    } else {
        return false;
    }

    if (sa.family == AF_INET) {
        __builtin_memset(raddr, 0, 16);
        if (family == AF_INET6) {
            raddr[10] = 0xff;
            raddr[11] = 0xff;
            __builtin_memcpy(&raddr[12], sa.rest, 4);
        } else {
            __builtin_memcpy(raddr, sa.rest, 4);
        }
    } else if (sa.family == AF_INET6 && len >= (int)sizeof(sa)) {
        __builtin_memcpy(raddr, &sa.rest[4], 16);
    } else {
        return false;
    }
    *rport = bpf_ntohs(sa.port);
    return true;
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
        .file = {.ino = ts->file.ino, .dev = ts->file.dev, .gen = ts->file.gen},
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

static __always_inline int account(struct socket *sock, struct msghdr *msg, long ret, __u16 family,
                                   int dir, bool spliced)
{
    if (ret <= 0)
        return 0;

    struct sock *sk = sock->sk;
    if (!sk)
        return 0;

    __u32 zero = 0;
    void *map = bpf_map_lookup_elem(&agg, &zero);
    if (!map)
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    __u16 proto = sk->sk_protocol;
    struct ft_bpf_agg_key key = {
        .cookie = bpf_get_socket_cookie(sk),
        .tgid = (__u32)(bpf_get_current_pid_tgid() >> 32),
        .kind = FT_BPF_AGG_FLOW,
    };
    if (proto == IPPROTO_TCP || !datagram_peer(msg, family, key.raddr, &key.rport))
        sock_remote(sk, family, key.raddr, &key.rport);

    struct ft_bpf_agg_val *v = bpf_map_lookup_elem(map, &key);
    if (!v) {
        struct ft_bpf_agg_val init = {.first_ns = now, .family = family, .proto = proto};
        sock_local(sk, family, init.laddr, &init.lport);
        v = agg_slot(map, &key, &init);
    }
    if (v) {
        __sync_fetch_and_add(&v->flow.bytes[dir], (__u64)ret);
        __sync_fetch_and_add(&v->flow.ops[dir], 1);
        v->last_ns = now;
    }

    if (!cfg.file_corr)
        return 0;
    if (dir == FT_BPF_TX) {
        if (!spliced)
            correlate_send(map, key.cookie, key.tgid, (__u64)ret, now);
    } else {
        struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
        if (ts && ts->pending)
            thread_reset(ts);
    }
    return 0;
}

SEC("fexit/inet_sendmsg")
int BPF_PROG(ft_inet_sendmsg, struct socket *sock, struct msghdr *msg, size_t size, int ret)
{
    return account(sock, msg, ret, AF_INET, FT_BPF_TX, msg->msg_flags & MSG_SPLICE_PAGES);
}

SEC("fexit/inet6_sendmsg")
int BPF_PROG(ft_inet6_sendmsg, struct socket *sock, struct msghdr *msg, size_t size, int ret)
{
    return account(sock, msg, ret, AF_INET6, FT_BPF_TX, msg->msg_flags & MSG_SPLICE_PAGES);
}

SEC("fexit/inet_recvmsg")
int BPF_PROG(ft_inet_recvmsg, struct socket *sock, struct msghdr *msg, size_t size, int flags,
             int ret)
{
    if (flags & MSG_PEEK)
        return 0;
    return account(sock, msg, ret, AF_INET, FT_BPF_RX, false);
}

SEC("fexit/inet6_recvmsg")
int BPF_PROG(ft_inet6_recvmsg, struct socket *sock, struct msghdr *msg, size_t size, int flags,
             int ret)
{
    if (flags & MSG_PEEK)
        return 0;
    return account(sock, msg, ret, AF_INET6, FT_BPF_RX, false);
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
                                     const struct file_key *fk, __u64 fs_magic)
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

    if (inode->i_nlink == 0)
        w.flags |= FT_BPF_FILE_DELETED;

    s->ev.hdr.ts_ns = bpf_ktime_get_boot_ns();
    s->ev.hdr.kind = FT_BPF_EV_FILE;
    s->ev.hdr.pad = 0;
    s->ev.ino = fk->ino;
    s->ev.fs_magic = fs_magic;
    s->ev.dev = fk->dev;
    s->ev.gen = fk->gen;
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

static __always_inline bool name_file(struct file *file, struct inode *inode,
                                      const struct file_key *fk, __u64 fs_magic)
{
    if (bpf_map_lookup_elem(&known_files, fk))
        return true;
    if (emit_file(file, inode, fk, fs_magic))
        return false;

    __u8 one = 1;
    bpf_map_update_elem(&known_files, fk, &one, BPF_ANY);
    return true;
}

SEC("fexit/vfs_read")
int BPF_PROG(ft_vfs_read, struct file *file, char *buf, size_t len, loff_t *pos, ssize_t ret)
{
    if (ret <= 0)
        return 0;

    struct inode *inode = file->f_inode;
    if ((inode->i_mode & S_IFMT) != S_IFREG)
        return 0;

    struct super_block *sb = inode->i_sb;
    unsigned long magic = sb->s_magic;
    if (fs_excluded(magic))
        return 0;

    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0,
                                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ts)
        return 0;

    struct file_key fk = {.ino = inode->i_ino, .dev = sb->s_dev, .gen = inode->i_generation};
    if (ts->file.ino != fk.ino || ts->file.dev != fk.dev || ts->file.gen != fk.gen) {
        ts->file = fk;
        ts->named = 0;
        thread_reset(ts);
    }
    if (!ts->named)
        ts->named = name_file(file, inode, &fk, magic);

    ts->pending += (__u64)ret;
    ts->unreported += (__u64)ret;
    ts->last_ns = bpf_ktime_get_boot_ns();
    ts->fresh = 1;
    return 0;
}

/* sendfile(2) from a regular file to a socket ends up here. */
SEC("fexit/do_splice_direct")
int BPF_PROG(ft_splice_direct, struct file *in, loff_t *ppos, struct file *out, loff_t *opos,
             size_t len, unsigned int flags, ssize_t ret)
{
    if (ret <= 0)
        return 0;

    struct inode *out_inode = out->f_inode;
    if ((out_inode->i_mode & S_IFMT) != S_IFSOCK)
        return 0;
    struct inode *inode = in->f_inode;
    if ((inode->i_mode & S_IFMT) != S_IFREG)
        return 0;

    struct socket *sock = out->private_data;
    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    /* The cookie is assigned when the socket first passes a send probe. */
    __u64 cookie = (__u64)BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
    if (!cookie) {
        count(FT_BPF_CNT_SOCK_UNIDENTIFIED);
        return 0;
    }

    __u32 zero = 0;
    void *map = bpf_map_lookup_elem(&agg, &zero);
    if (!map)
        return 0;

    struct super_block *sb = inode->i_sb;
    struct file_key fk = {.ino = inode->i_ino, .dev = sb->s_dev, .gen = inode->i_generation};
    name_file(in, inode, &fk, sb->s_magic);

    __u64 now = bpf_ktime_get_boot_ns();
    struct ft_bpf_agg_key key = {
        .cookie = cookie,
        .tgid = (__u32)(bpf_get_current_pid_tgid() >> 32),
        .kind = FT_BPF_AGG_SENDFILE,
        .file = {.ino = fk.ino, .dev = fk.dev, .gen = fk.gen},
    };
    struct ft_bpf_agg_val init = {.first_ns = now};
    struct ft_bpf_agg_val *v = agg_slot(map, &key, &init);
    if (v) {
        __sync_fetch_and_add(&v->transfer.sent_bytes, (__u64)ret);
        __sync_fetch_and_add(&v->transfer.sends, 1);
        v->last_ns = now;
    }
    return 0;
}
