/* Entry probes only: a return probe holds one of a few instances for as long as a call blocks. */
#define FT_READ(ptr, field) BPF_CORE_READ(ptr, field)
#define FT_COPY16(dst, ptr, field) bpf_core_read(dst, 16, &(ptr)->field)

#include "common.bpf.h"

#define IPPROTO_UDP 17

#define TCP_CLOSE_WAIT 8

struct sock_track {
    __u64 id;
    __u32 tx_seq; /* write_seq up to which sent bytes are accounted */
    __u32 rx_seq; /* copied_seq, without a consumed FIN, up to which received bytes are */
    __u32 tx_tgid;
    __u32 rx_tgid;
    __u8 tx_live; /* tx_seq is a baseline that write_seq still advances from */
    __u8 rx_live;
    __u8 claim_kind; /* enum ft_bpf_agg_kind, or 0 */
    __u8 claim_fresh;
    __u8 claim_carried; /* the claim's bytes go to the socket's first-flight window */
    __u8 carrying;      /* the socket has a carry window open */
    __u32 claim_script; /* the PHP request of the thread that made the claim, or 0 */
    __u32 claim_tgid;
    __u32 claim_tid;
    __u32 claim_received; /* the thread's receive count when it made the claim */
    struct file_ref claim_file;
    __u64 claim_bytes; /* most that the next bytes sent can carry of the file */
    __u64 claim_read;
};

/* Keyed by the address of the kernel socket, which is unique while it exists. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct sock_track);
} socks SEC(".maps");

static __u64 last_sock_id;

static __always_inline struct sock_track *track(struct sock *sk)
{
    __u64 key = (__u64)sk;
    struct sock_track *t = bpf_map_lookup_elem(&socks, &key);
    if (t)
        return t;

    struct sock_track init = {.id = __sync_fetch_and_add(&last_sock_id, 1) + 1};
    bpf_map_update_elem(&socks, &key, &init, BPF_NOEXIST);
    return bpf_map_lookup_elem(&socks, &key);
}

static __always_inline void flow_add(void *map, struct sock *sk, __u64 id, __u32 tgid,
                                     const __u8 raddr[16], __u16 rport, int dir, __u64 bytes,
                                     __u64 now)
{
    __u16 family = FT_READ(sk, __sk_common.skc_family);
    struct ft_bpf_agg_key key = {
        .cookie = id,
        .tgid = tgid,
        .kind = FT_BPF_AGG_FLOW,
        .rport = rport,
    };
    __builtin_memcpy(key.raddr, raddr, 16);

    struct ft_bpf_agg_val *v = bpf_map_lookup_elem(map, &key);
    if (!v) {
        struct ft_bpf_agg_val init = {
            .first_ns = now,
            .family = family,
            .proto = FT_READ(sk, sk_protocol),
        };
        sock_local(sk, family, init.laddr, &init.lport);
        v = agg_slot(map, &key, &init);
    }
    if (v) {
        __sync_fetch_and_add(&v->flow.bytes[dir], bytes);
        __sync_fetch_and_add(&v->flow.ops[dir], 1);
        v->last_ns = now;
    }
}

static __always_inline void tcp_flow_add(void *map, struct sock *sk, __u64 id, __u32 tgid, int dir,
                                         __u64 bytes, __u64 now)
{
    __u8 raddr[16];
    __u16 rport;

    sock_remote(sk, FT_READ(sk, __sk_common.skc_family), raddr, &rport);
    flow_add(map, sk, id, tgid, raddr, rport, dir, bytes, now);
}

/* Credits the thread with what it read since the mark, as counted by the kernel. */
static __always_inline void read_sync(struct thread_state *ts)
{
    if (!ts->reading && !ts->strict_reading)
        return;

    struct task_struct *task = (void *)bpf_get_current_task();
    __u64 rchar = BPF_CORE_READ(task, ioac.rchar);
    __u64 delta = rchar - ts->rchar_mark;

    ts->rchar_mark = rchar;
    if (!delta)
        return;
    if (ts->strict_reading) {
        ts->strict_pending += delta;
        ts->strict_unreported += delta;
        ts->strict_last_ns = ts->strict_read_ns;
        ts->strict_fresh = 1;
        return;
    }
    ts->pending += delta;
    ts->unreported += delta;
    ts->last_ns = ts->read_ns;
    ts->fresh = 1;
    candidate_read(ts, &ts->file, ts->file_size, delta, ts->read_ns);
}

static __always_inline struct thread_state *thread_now(bool create)
{
    return bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0,
                                create ? BPF_LOCAL_STORAGE_GET_F_CREATE : 0);
}

SEC("kprobe/vfs_read")
int BPF_KPROBE(ft_vfs_read, struct file *file)
{
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    unsigned long magic = BPF_CORE_READ(sb, s_magic);
    bool tracked = (BPF_CORE_READ(inode, i_mode) & S_IFMT) == S_IFREG && !fs_excluded(magic);

    struct thread_state *ts = thread_now(tracked);
    if (!ts)
        return 0;
    read_sync(ts);
    if (!tracked) {
        /* What this call reads would be mistaken for bytes of the tracked file. */
        ts->reading = 0;
        ts->strict_reading = 0;
        return 0;
    }

    struct file_key fk = {
        .ino = BPF_CORE_READ(inode, i_ino),
        .dev = BPF_CORE_READ(sb, s_dev),
        .gen = BPF_CORE_READ(inode, i_generation),
    };
    struct task_struct *task = (void *)bpf_get_current_task();
    __u8 listed = listed_read(ts, BPF_CORE_READ(file, f_path.dentry, d_name.name), &fk);
    if (listed == FT_BPF_LISTED_BACKGROUND) {
        ts->reading = 0;
        ts->strict_reading = 0;
        return 0;
    }
    if (listed == FT_BPF_LISTED_STRICT) {
        thread_set_strict(ts, file, inode, &fk, magic);
        ts->rchar_mark = BPF_CORE_READ(task, ioac.rchar);
        ts->strict_read_ns = bpf_ktime_get_boot_ns();
        ts->strict_reading = 1;
        ts->reading = 0;
        return 0;
    }
    thread_set_file(ts, file, inode, &fk, magic);

    ts->rchar_mark = BPF_CORE_READ(task, ioac.rchar);
    ts->read_ns = bpf_ktime_get_boot_ns();
    ts->reading = 1;
    ts->strict_reading = 0;
    return 0;
}

/* The receive position, not counting the sequence number a consumed FIN takes. */
static __always_inline __u32 tcp_rx_seq(struct sock *sk)
{
    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u32 copied = BPF_CORE_READ(tp, copied_seq);
    unsigned long done = 1UL << bpf_core_enum_value(enum sock_flags, SOCK_DONE);

    if ((BPF_CORE_READ(sk, __sk_common.skc_flags) & done) && copied == BPF_CORE_READ(tp, rcv_nxt))
        return copied - 1;
    return copied;
}

/* Adds what a claim took to the counters, or to the socket's window when the claim is carried. */
static __always_inline void claim_charge(void *map, struct sock *sk, struct sock_track *t,
                                         __u64 take, __u64 now)
{
    if (t->claim_carried) {
        __u64 sock = (__u64)sk;
        struct carry *c = t->carrying ? bpf_map_lookup_elem(&carries, &sock) : NULL;
        if (c && c->tid == t->claim_tid)
            carry_add(c, take, t->claim_read, t->claim_fresh, t->claim_script, now);
        if (t->carrying)
            dial_charged((__u64)sk, &t->claim_file, (__s64)take);
        return;
    }
    if (t->carrying)
        dial_charged((__u64)sk, &t->claim_file, (__s64)take);
    struct ft_bpf_agg_key key = {
        .cookie = t->id,
        .tgid = t->claim_tgid,
        .kind = t->claim_kind,
        .file = {.ino = t->claim_file.ino,
                 .dev = t->claim_file.dev,
                 .instance = t->claim_file.instance},
    };
    struct ft_bpf_agg_val init = {.first_ns = now};
    struct ft_bpf_agg_val *v = agg_slot(map, &key, &init);
    if (v) {
        __sync_fetch_and_add(&v->transfer.sent_bytes, take);
        __sync_fetch_and_add(&v->transfer.read_bytes, t->claim_read);
        __sync_fetch_and_add(&v->transfer.sends, 1);
        __sync_fetch_and_add(&v->transfer.alternations, t->claim_fresh);
        if (t->claim_script)
            v->transfer.script = t->claim_script;
        v->last_ns = now;
    }
}

static __always_inline void claim_settle(void *map, struct sock *sk, struct sock_track *t,
                                         __u64 sent, __u64 now)
{
    if (!t->claim_kind)
        return;

    __u64 take = sent < t->claim_bytes ? sent : t->claim_bytes;
    claim_charge(map, sk, t, take, now);
    t->claim_bytes -= take;
    t->claim_read = 0;
    t->claim_fresh = 0;
    if (!t->claim_bytes) {
        t->claim_kind = 0;
        t->claim_carried = 0;
    }
}

/* Accounts what was queued for sending since the socket was last looked at. */
static __always_inline void tcp_settle_tx(void *map, struct sock *sk, struct sock_track *t,
                                          __u64 now)
{
    if (!t->tx_live)
        return;

    __u32 seq = BPF_CORE_READ((struct tcp_sock *)sk, write_seq);
    __u32 old = t->tx_seq;
    __u32 delta = seq - old;
    if (delta == 0 || delta > 0x7fffffff)
        return;
    /* A state change can look at the socket at the same moment as its owner. */
    if (__sync_val_compare_and_swap(&t->tx_seq, old, seq) != old)
        return;

    tcp_flow_add(map, sk, t->id, t->tx_tgid ? t->tx_tgid : t->rx_tgid, FT_BPF_TX, delta, now);
    /* Pages spliced in by sendfile belong to the transfer that sendfile reports. */
    __u64 spliced = 0;
    if (t->claim_kind == FT_BPF_AGG_SENDFILE)
        spliced = delta < t->claim_bytes ? delta : t->claim_bytes;
    if (t->carrying)
        carry_wire((__u64)sk, delta - spliced);
    claim_settle(map, sk, t, delta, now);
}

static __always_inline void carry_settle(void *map, __u64 sk, __u64 now)
{
    struct sock_track *t = bpf_map_lookup_elem(&socks, &sk);
    if (t)
        tcp_settle_tx(map, (struct sock *)sk, t, now);
}

/* Returns whether the receiver has consumed anything since the socket was last looked at. */
static __always_inline bool tcp_settle_rx(void *map, struct sock *sk, struct sock_track *t,
                                          __u32 tgid, __u64 now)
{
    if (!t->rx_live)
        return false;

    __u32 seq = tcp_rx_seq(sk);
    __u32 old = t->rx_seq;
    __u32 delta = seq - old;
    if (delta == 0 || delta > 0x7fffffff)
        return false;
    if (__sync_val_compare_and_swap(&t->rx_seq, old, seq) != old)
        return false;

    tcp_flow_add(map, sk, t->id, tgid, FT_BPF_RX, delta, now);
    return true;
}

/* A socket first met in mid-connection is accounted from this point on. */
static __always_inline void tcp_adopt(struct sock *sk, struct sock_track *t)
{
    __u8 state = FT_READ(sk, __sk_common.skc_state);

    if (!t->rx_live && state != TCP_LISTEN && state != TCP_SYN_SENT) {
        t->rx_seq = tcp_rx_seq(sk);
        t->rx_live = 1;
    }
    if (!t->tx_live && (state == TCP_ESTABLISHED || state == TCP_CLOSE_WAIT)) {
        t->tx_seq = BPF_CORE_READ((struct tcp_sock *)sk, write_seq);
        t->tx_live = 1;
    }
}

/* Hands a thread back the part of its read that the socket did not take, unless it has received
 * since: a receive on any socket ends the read's claim, as it ends the read itself. */
static __always_inline void claim_release(struct sock_track *t, struct thread_state *ts, __u32 tid)
{
    if (ts && t->claim_kind == FT_BPF_AGG_READ_SEND && t->claim_tid == tid &&
        t->claim_received == ts->received) {
        if (t->claim_file.ino == ts->file.ino && t->claim_file.dev == ts->file.dev &&
            t->claim_file.instance == ts->file.instance) {
            ts->pending += t->claim_bytes;
            ts->unreported += t->claim_read;
        }
    }
    t->claim_kind = 0;
    t->claim_carried = 0;
    t->claim_bytes = 0;
    t->claim_read = 0;
    t->claim_fresh = 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(ft_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    void *map = agg_map_now();
    struct sock_track *t = track(sk);
    if (!map || !t)
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    __u64 ids = bpf_get_current_pid_tgid();

    tcp_adopt(sk, t);
    tcp_settle_tx(map, sk, t, now);
    t->tx_tgid = (__u32)(ids >> 32);

    /* Pages spliced in by sendfile belong to the claim that sendfile made. */
    if (!cfg.file_corr || (BPF_CORE_READ(msg, msg_flags) & MSG_SPLICE_PAGES))
        return 0;

    if (t->carrying)
        carry_sent(map, (__u64)sk, 0, now);
    struct thread_state *ts = thread_now(false);
    claim_release(t, ts, (__u32)ids);
    if (!ts)
        return 0;
    read_sync(ts);
    reads_age(ts, now);

    t->claim_kind = FT_BPF_AGG_READ_SEND;
    t->claim_tgid = (__u32)(ids >> 32);
    t->claim_tid = (__u32)ids;
    t->claim_received = ts->received;
    t->claim_script = ts->script;
    if (!ts->pending && !ts->strict_pending) {
        t->claim_kind = 0;
        return 0;
    }
    bool skip;
    struct carry *c =
        carry_window(ts, (__u64)sk, t->id, (__u32)(ids >> 32), 0, now, ts->pending != 0, &skip);
    if (c) {
        t->carrying = 1;
        if (ts->strict_pending)
            carry_strict(c, ts);
    }
    if (!ts->pending || (!c && skip)) {
        t->claim_kind = 0;
        return 0;
    }
    /* A send carries no more than it was given; the rest of the read stays the thread's. */
    __u64 take = size < ts->pending ? size : ts->pending;
    t->claim_carried = c != NULL;
    t->claim_file = ts->file;
    t->claim_bytes = take;
    t->claim_read = ts->unreported;
    t->claim_fresh = ts->fresh;
    candidate_spent(ts, (__u64)sk);
    ts->pending -= take;
    ts->unreported = 0;
    ts->fresh = 0;
    ts->last_ns = now;
    return 0;
}

/* Runs whenever a receiver has taken data, and before it sleeps waiting for more. */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(ft_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
    void *map = agg_map_now();
    struct sock_track *t = track(sk);
    if (!map || !t)
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    tcp_adopt(sk, t);
    tcp_settle_tx(map, sk, t, now);
    /* The count is no measure of what was consumed: a peek and some callers pass one anyway. */
    if (copied <= 0 || !tcp_settle_rx(map, sk, t, tgid, now))
        return 0;
    t->rx_tgid = tgid;

    if (cfg.file_corr) {
        if (t->carrying)
            carry_received(map, (__u64)sk, now);
        struct thread_state *ts = thread_now(false);
        if (ts) {
            read_sync(ts);
            carry_episode_end(ts, now);
            thread_reset(ts);
            ts->received++;
        }
    }
    return 0;
}

SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(ft_sock_state, struct sock *sk, int oldstate, int newstate)
{
    if (FT_READ(sk, sk_protocol) != IPPROTO_TCP)
        return 0;

    __u16 family = FT_READ(sk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    void *map = agg_map_now();
    struct sock_track *t = track(sk);
    if (!map || !t)
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    switch (newstate) {
    case TCP_SYN_SENT:
        t->tx_tgid = tgid;
        t->tx_live = 0;
        t->rx_live = 0;
        if (cfg.file_corr) {
            struct thread_state *ts = thread_now(false);
            if (ts)
                read_sync(ts);
            if (carry_dial(sk, t->id, now))
                t->carrying = 1;
        }
        break;
    case TCP_ESTABLISHED:
        /* Nothing has been sent or consumed on the connection yet. */
        t->tx_seq = BPF_CORE_READ((struct tcp_sock *)sk, write_seq);
        t->rx_seq = tcp_rx_seq(sk);
        t->tx_live = 1;
        t->rx_live = 1;
        t->claim_kind = 0;
        t->claim_carried = 0;
        break;
    case TCP_FIN_WAIT1:
    case TCP_LAST_ACK:
        /* The FIN that follows takes a sequence number of its own. */
        if (!t->tx_tgid && !t->rx_tgid)
            t->tx_tgid = tgid;
        tcp_settle_tx(map, sk, t, now);
        if (t->carrying && cfg.file_corr) {
            carry_close(map, (__u64)sk, CARRY_QUIET, now);
            dial_close(map, (__u64)sk, now);
            t->carrying = 0;
        }
        t->tx_live = 0;
        break;
    case TCP_CLOSE:
        /* A disconnect rewrites both positions right after this. */
        tcp_settle_tx(map, sk, t, now);
        if (t->carrying && cfg.file_corr) {
            carry_close(map, (__u64)sk, CARRY_QUIET, now);
            dial_close(map, (__u64)sk, now);
            t->carrying = 0;
        }
        t->tx_live = 0;
        break;
    case TCP_LISTEN:
        break;
    default:
        return 0;
    }

    struct ft_bpf_ev_sock *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(FT_BPF_CNT_RING_FULL);
        return 0;
    }
    e->hdr.ts_ns = now;
    e->hdr.kind = FT_BPF_EV_SOCK_STATE;
    e->hdr.pad = 0;
    e->cookie = t->id;
    e->pid = (newstate == TCP_SYN_SENT || newstate == TCP_LISTEN) ? tgid : 0;
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

SEC("kprobe/inet_sock_destruct")
int BPF_KPROBE(ft_sock_destruct, struct sock *sk)
{
    __u64 key = (__u64)sk;
    bpf_map_delete_elem(&socks, &key);
    bpf_map_delete_elem(&carries, &key);
    return 0;
}

SEC("kprobe/do_splice_direct")
int BPF_KPROBE(ft_splice_direct, struct file *in, loff_t *ppos, struct file *out, loff_t *opos,
               size_t len)
{
    __u64 ids = bpf_get_current_pid_tgid();
    struct thread_state *ts = thread_now(false);

    /* sendfile adds what it moves to the task's read counter. */
    if (ts) {
        read_sync(ts);
        ts->reading = 0;
        ts->strict_reading = 0;
    }

    struct inode *inode = BPF_CORE_READ(in, f_inode);
    if ((BPF_CORE_READ(inode, i_mode) & S_IFMT) != S_IFREG)
        return 0;
    if ((BPF_CORE_READ(out, f_inode, i_mode) & S_IFMT) != S_IFSOCK)
        return 0;

    struct socket *sock = BPF_CORE_READ(out, private_data);
    struct sock *sk = BPF_CORE_READ(sock, sk);
    __u16 family = FT_READ(sk, __sk_common.skc_family);
    if ((family != AF_INET && family != AF_INET6) || FT_READ(sk, sk_protocol) != IPPROTO_TCP)
        return 0;

    void *map = agg_map_now();
    struct sock_track *t = track(sk);
    if (!map || !t)
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    tcp_adopt(sk, t);
    tcp_settle_tx(map, sk, t, now);
    t->tx_tgid = (__u32)(ids >> 32);
    claim_release(t, ts, (__u32)ids);

    struct super_block *sb = BPF_CORE_READ(inode, i_sb);
    struct file_key fk = {
        .ino = BPF_CORE_READ(inode, i_ino),
        .dev = BPF_CORE_READ(sb, s_dev),
        .gen = BPF_CORE_READ(inode, i_generation),
    };
    __u32 instance = file_instance(in, inode, &fk, BPF_CORE_READ(sb, s_magic));
    sendfile_read(ts, &fk);

    /* The call can move no more than what is left of the file. */
    loff_t pos = 0;
    loff_t size = BPF_CORE_READ(inode, i_size);
    bpf_probe_read_kernel(&pos, sizeof(pos), ppos);
    __u64 left = size > pos ? (__u64)(size - pos) : 0;

    t->claim_kind = FT_BPF_AGG_SENDFILE;
    t->claim_carried = 0;
    t->claim_script = ts ? ts->script : 0;
    t->claim_file = (struct file_ref){.ino = fk.ino, .dev = fk.dev, .instance = instance};
    t->claim_bytes = len < left ? len : left;
    t->claim_read = 0;
    t->claim_fresh = 0;
    t->claim_tgid = (__u32)(ids >> 32);
    t->claim_tid = (__u32)ids;
    return 0;
}

SEC("kprobe/__destroy_inode")
int BPF_KPROBE(ft_destroy_inode, struct inode *inode)
{
    forget_file(inode);
    return 0;
}

struct udp_ports {
    __be16 source;
    __be16 dest;
};

/* Reads the peer of a datagram from its own headers. */
static __always_inline bool datagram_peer(struct sk_buff *skb, __u16 family, bool sent,
                                          __u8 raddr[16], __u16 *rport)
{
    unsigned char *head = BPF_CORE_READ(skb, head);
    unsigned char *ip = head + BPF_CORE_READ(skb, network_header);
    struct udp_ports ports;
    __u8 version = 0;

    if (bpf_probe_read_kernel(&ports, sizeof(ports), head + BPF_CORE_READ(skb, transport_header)))
        return false;
    if (bpf_probe_read_kernel(&version, 1, ip))
        return false;

    __builtin_memset(raddr, 0, 16);
    if ((version >> 4) == 6) {
        if (bpf_probe_read_kernel(raddr, 16, ip + (sent ? 24 : 8)))
            return false;
    } else if (family == AF_INET6) {
        /* An IPv4 datagram on a dual-stack socket. */
        raddr[10] = 0xff;
        raddr[11] = 0xff;
        if (bpf_probe_read_kernel(&raddr[12], 4, ip + (sent ? 16 : 12)))
            return false;
    } else if (bpf_probe_read_kernel(raddr, 4, ip + (sent ? 16 : 12))) {
        return false;
    }
    *rport = bpf_ntohs(sent ? ports.dest : ports.source);
    return true;
}

static __always_inline int udp_sent(struct sk_buff *skb)
{
    struct sock *sk = BPF_CORE_READ(skb, sk);
    if (!sk || FT_READ(sk, sk_protocol) != IPPROTO_UDP)
        return 0;

    void *map = agg_map_now();
    struct sock_track *t = track(sk);
    if (!map || !t)
        return 0;

    /* The buffer starts at the IP header; the payload follows the UDP header. */
    __u32 headers =
        (__u32)BPF_CORE_READ(skb, transport_header) - (__u32)BPF_CORE_READ(skb, network_header) + 8;
    __u32 len = BPF_CORE_READ(skb, len);
    if (len < headers)
        return 0;

    __u8 raddr[16];
    __u16 rport;
    if (!datagram_peer(skb, FT_READ(sk, __sk_common.skc_family), true, raddr, &rport))
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    flow_add(map, sk, t->id, tgid, raddr, rport, FT_BPF_TX, len - headers, now);

    if (cfg.file_corr) {
        struct thread_state *ts = thread_now(false);
        if (ts) {
            read_sync(ts);
            correlate_send(map, 0, t->id, tgid, len - headers, now);
        }
    }
    return 0;
}

SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ft_ip_send_skb, struct net *net, struct sk_buff *skb)
{
    return udp_sent(skb);
}

SEC("kprobe/ip6_send_skb")
int BPF_KPROBE(ft_ip6_send_skb, struct sk_buff *skb)
{
    return udp_sent(skb);
}

/* Called once a datagram has been copied to its receiver; negative when only peeked at. */
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(ft_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
    if (len <= 0)
        return 0;

    void *map = agg_map_now();
    struct sock_track *t = track(sk);
    if (!map || !t)
        return 0;

    __u8 raddr[16];
    __u16 rport;
    if (!datagram_peer(skb, FT_READ(sk, __sk_common.skc_family), false, raddr, &rport))
        return 0;

    __u64 now = bpf_ktime_get_boot_ns();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    flow_add(map, sk, t->id, tgid, raddr, rport, FT_BPF_RX, (__u32)len, now);

    if (cfg.file_corr) {
        struct thread_state *ts = thread_now(false);
        if (ts) {
            read_sync(ts);
            carry_episode_end(ts, now);
            thread_reset(ts);
            ts->received++;
        }
    }
    return 0;
}
