/* Probes for kernels with BPF trampolines: arguments are typed kernel pointers. */
#define FT_READ(ptr, field) ((ptr)->field)
#define FT_COPY16(dst, ptr, field) __builtin_memcpy(dst, &(ptr)->field, 16)

#include "common.bpf.h"

/* Sends are counted as they return, so a window is always up to date. */
static __always_inline bool carry_settle(void *map, __u64 sk, __u64 now)
{
    return false;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(ft_sock_state, struct sock *sk, int oldstate, int newstate)
{
    if (sk->sk_protocol != IPPROTO_TCP)
        return 0;
    __u16 family = sk->__sk_common.skc_family;
    if (family != AF_INET && family != AF_INET6)
        return 0;
    /* A connection that is closing has taken all it is going to. */
    if (cfg.file_corr &&
        (newstate == TCP_FIN_WAIT1 || newstate == TCP_LAST_ACK || newstate == TCP_CLOSE)) {
        void *map = agg_map_now();
        if (map) {
            carry_close(map, (__u64)sk, CARRY_QUIET, bpf_ktime_get_boot_ns());
            dial_close(map, (__u64)sk, bpf_ktime_get_boot_ns());
        }
    }
    if (newstate != TCP_ESTABLISHED && newstate != TCP_SYN_SENT && newstate != TCP_LISTEN &&
        newstate != TCP_CLOSE)
        return 0;
    if (newstate == TCP_SYN_SENT && cfg.file_corr)
        carry_dial(sk, bpf_get_socket_cookie(sk), bpf_ktime_get_boot_ns());

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

static __always_inline int account(struct socket *sock, struct msghdr *msg, long ret, __u16 family,
                                   int dir, bool spliced, size_t asked)
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
    bool tcp = proto == IPPROTO_TCP;
    if (dir == FT_BPF_TX) {
        /* Pages spliced in by sendfile belong to the transfer that sendfile reports. */
        __u64 bytes = spliced ? 0 : (__u64)ret;
        if (tcp)
            carry_send_starts(map, (__u64)sk, bytes, now);
        if (!spliced)
            correlate_send(map, tcp ? (__u64)sk : 0, key.cookie, key.tgid, (__u64)ret, asked, now);
        if (tcp)
            carry_send_counted((__u64)sk, bytes, spliced ? 0 : asked, now);
        return 0;
    }
    if (tcp)
        carry_received(map, (__u64)sk, now);
    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
    if (ts) {
        carry_heard_elsewhere(ts, tcp ? (__u64)sk : 0, now);
        thread_reset(ts);
    }
    return 0;
}

SEC("fexit/inet_sendmsg")
int BPF_PROG(ft_inet_sendmsg, struct socket *sock, struct msghdr *msg, size_t size, int ret)
{
    return account(sock, msg, ret, AF_INET, FT_BPF_TX, msg->msg_flags & MSG_SPLICE_PAGES, size);
}

SEC("fexit/inet6_sendmsg")
int BPF_PROG(ft_inet6_sendmsg, struct socket *sock, struct msghdr *msg, size_t size, int ret)
{
    return account(sock, msg, ret, AF_INET6, FT_BPF_TX, msg->msg_flags & MSG_SPLICE_PAGES, size);
}

SEC("fexit/inet_recvmsg")
int BPF_PROG(ft_inet_recvmsg, struct socket *sock, struct msghdr *msg, size_t size, int flags,
             int ret)
{
    if (flags & MSG_PEEK)
        return 0;
    return account(sock, msg, ret, AF_INET, FT_BPF_RX, false, 0);
}

SEC("fexit/inet6_recvmsg")
int BPF_PROG(ft_inet6_recvmsg, struct socket *sock, struct msghdr *msg, size_t size, int flags,
             int ret)
{
    if (flags & MSG_PEEK)
        return 0;
    return account(sock, msg, ret, AF_INET6, FT_BPF_RX, false, 0);
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
    __u64 now = bpf_ktime_get_boot_ns();
    thread_file_reused(ts, inode, &fk, now);
    __u8 listed = listed_read(ts, BPF_CORE_READ(file, f_path.dentry, d_name.name), &fk);
    if (listed == FT_BPF_LISTED_BACKGROUND)
        return 0;
    file_again(ts, &fk, now);
    thread_set_file(ts, file, inode, &fk, magic);
    ts->file_strict = listed == FT_BPF_LISTED_STRICT;
    if (!ts->pending)
        ts->file_read = 0;
    ts->pending += (__u64)ret;
    ts->unreported += (__u64)ret;
    ts->file_read += (__u64)ret;
    ts->last_ns = now;
    ts->fresh = 1;
    if (!ts->file_strict)
        candidate_read(ts, &ts->file, ts->file_size, (__u64)ret, now);
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
    __u32 instance = file_instance(in, inode, &fk, sb->s_magic);

    __u64 now = bpf_ktime_get_boot_ns();
    struct ft_bpf_agg_key key = {
        .cookie = cookie,
        .tgid = (__u32)(bpf_get_current_pid_tgid() >> 32),
        .kind = FT_BPF_AGG_SENDFILE,
        .file = {.ino = fk.ino, .dev = fk.dev, .instance = instance},
    };
    struct ft_bpf_agg_val init = {.first_ns = now};
    struct ft_bpf_agg_val *v = agg_slot(map, &key, &init);
    if (v) {
        __sync_fetch_and_add(&v->transfer.sent_bytes, (__u64)ret);
        __sync_fetch_and_add(&v->transfer.sends, 1);
        struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
        if (ts && ts->script)
            v->transfer.script = ts->script;
        v->last_ns = now;
    }
    /* A connection's window takes what sendfile sent of a file as already reported. */
    struct file_ref sent = {.ino = fk.ino, .dev = fk.dev};
    dial_charged((__u64)sk, &sent, ret);
    sendfile_read(bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0), fk.ino, fk.dev);
    return 0;
}

SEC("fentry/__destroy_inode")
int BPF_PROG(ft_destroy_inode, struct inode *inode)
{
    forget_file(inode);
    return 0;
}
