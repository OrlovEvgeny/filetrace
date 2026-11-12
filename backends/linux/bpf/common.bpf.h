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
#define TCP_FIN_WAIT1 4
#define TCP_CLOSE 7
#define TCP_LISTEN 10
#define TCP_LAST_ACK 9

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

/* A large file a thread read recently, which a connection it opens may carry whole. */
struct candidate {
    struct file_ref file;
    __u64 size;
    __u64 read; /* since the thread began reading it */
    __u64 last_ns;
};

#define CARRY_CANDIDATES 4

/*
 * The file a thread read most recently and how much of it is unsent, apart from it the
 * background file it read last, a candidate only for sends that no other read accounts for,
 * and the large files it read lately, for the connections it opens.
 */
struct thread_state {
    struct file_ref file;
    __u32 gen;
    __u32 forgotten; /* value of forgotten_files when the instance was resolved */
    __u64 pending;
    __u64 unreported;
    __u64 last_ns;
    __u64 read_ns;    /* when the file was last read */
    __u64 rchar_mark; /* the task's read counter up to which reads are accounted */
    __u8 fresh;
    __u8 reading; /* the read counter has grown only by reads of this file */
    __u8 bg_fresh;
    __u8 bg_reading; /* the read counter has grown only by reads of bg_file */
    __u32 received;  /* receives seen; a claim made before the last one is not handed back */
    __u32 script;    /* the PHP request running on this thread, as ft_bpf_ev_script names it */
    __u64 dialed;    /* the TCP socket the thread connected last */
    __u64 dialed_ns;
    __u64 file_size;  /* the file's size at its last read */
    __u64 carry_sock; /* the socket of the window of the connection the thread dialed last */
    struct candidate cands[CARRY_CANDIDATES];
    struct file_ref bg_file;
    __u32 bg_gen;
    __u32 bg_forgotten;
    __u64 bg_pending;
    __u64 bg_unreported;
    __u64 bg_last_ns;
    __u64 bg_read_ns;
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

/*
 * What a connection sends that cannot be told from what it opens with, held back until it can:
 * - DIALED: the thread opened the connection soon after reading large files, so what went over
 *   it is a handshake and a request head besides one of them, if any went at all. The file is
 *   the one candidate the connection took whole; with none or two, nothing is reported.
 * - FLIGHT: the socket had heard nothing from its peer, so the bytes may be a TLS ClientHello
 *   or the first request of a conversation. The charges are dropped if that first flight was
 *   small and the thread sent again after the peer answered.
 */
enum carry_kind {
    CARRY_DIALED = 1,
    CARRY_FLIGHT = 2,
};

/* A candidate as the window of a connection knows it. */
struct carried_file {
    struct file_ref file;
    __u64 size;
    __u64 read;
};

struct carry {
    __u64 cookie;
    __u32 tgid;
    __u32 tid;
    struct file_ref file; /* FLIGHT */
    __u32 script;
    __u32 sends;
    __u32 alternations;
    __u8 kind;
    __u8 background; /* FLIGHT: the charges are of the thread's background file */
    __u64 first_ns;
    __u64 last_ns;
    __u64 wire; /* what the connection took while the window was open, sendfile aside */
    __u64 sent; /* FLIGHT: of that, charged to the file */
    __u64 read; /* FLIGHT: of the file, before those charges */
    struct carried_file cands[CARRY_CANDIDATES]; /* DIALED */
};

static struct carry carry_zero;

/* Keyed by the address of the kernel socket. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct carry);
} carries SEC(".maps");

/* Below this size a file matches the size of too many requests to be judged by size. */
#define CARRY_FLOOR (64 * 1024)
/* What a connection takes besides the file: a handshake, a client certificate, a request head. */
#define CARRY_SLACK (8 * 1024)
/* A first flight this large is no handshake and no request without a body. */
#define CARRY_FLIGHT_MAX (4 * 1024)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FT_BPF_BACKGROUND_MAX);
    __type(key, struct ft_bpf_background_key);
    __type(value, __u8);
} background_files SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64); /* hash of the path */
    __type(value, __u32);
} known_scripts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FT_BPF_BACKGROUND_NAMES);
    __type(key, char[FT_BPF_BACKGROUND_NAME]);
    __type(value, __u8);
} background_names SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, FT_BPF_BACKGROUND_SUFFIXES);
    __type(key, __u32);
    __type(value, struct ft_bpf_background_suffix);
} background_suffixes SEC(".maps");

static __u32 last_file_instance;
static __u32 forgotten_files;
static __u32 last_script_id;

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

/* An exec record and its working directory and arguments, before they are queued. */
struct exec_scratch {
    __u32 busy;
    __u32 pad;
    struct ft_bpf_ev_exec ev;
    char tail[FT_BPF_PATH_BUF + FT_BPF_NAME_MAX + FT_BPF_ARGS_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct exec_scratch);
} exec_scratch SEC(".maps");

static __always_inline void *agg_map_now(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&agg, &zero);
}

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
    e->netns = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);
    e->exit_code = 0;
    BPF_CORE_READ_STR_INTO(&e->comm, task, comm);
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

static __always_inline void foreground_reset(struct thread_state *ts)
{
    ts->pending = 0;
    ts->unreported = 0;
    ts->fresh = 0;
}

static __always_inline void background_reset(struct thread_state *ts)
{
    ts->bg_pending = 0;
    ts->bg_unreported = 0;
    ts->bg_fresh = 0;
}

static __always_inline void thread_reset(struct thread_state *ts)
{
    foreground_reset(ts);
    background_reset(ts);
}

static __always_inline bool is_background(const struct file_key *fk)
{
    struct ft_bpf_background_key key = {.ino = fk->ino, .dev = fk->dev};
    return bpf_map_lookup_elem(&background_files, &key) != NULL;
}

struct suffix_match {
    const char *name;
    __u32 len;
    bool found;
};

static long suffix_step(__u32 index, void *arg)
{
    struct suffix_match *m = arg;
    struct ft_bpf_background_suffix *s = bpf_map_lookup_elem(&background_suffixes, &index);
    if (!s || !s->len)
        return 1;
    if (s->len > m->len || s->len > FT_BPF_BACKGROUND_SUFFIX)
        return 0;
    __u32 from = m->len - s->len;
    for (__u32 i = 0; i < FT_BPF_BACKGROUND_SUFFIX; i++) {
        if (i >= s->len) {
            m->found = true;
            return 1;
        }
        if (m->name[(from + i) & (FT_BPF_BACKGROUND_NAME - 1)] != s->text[i])
            return 0;
    }
    m->found = true;
    return 1;
}

/*
 * Whether a file the thread starts reading is background by its name, as a CA bundle that a
 * library keeps in its own directory is: then from this read on, for every thread.
 */
static __always_inline bool background_by_name(const unsigned char *dname,
                                               const struct file_key *fk)
{
    char name[FT_BPF_BACKGROUND_NAME] = {};
    long n = bpf_probe_read_kernel_str(name, sizeof(name), dname);
    if (n <= 1)
        return false;
    bool found = bpf_map_lookup_elem(&background_names, name) != NULL;
    if (!found) {
        struct suffix_match m = {.name = name, .len = (__u32)n - 1};
        bpf_loop(FT_BPF_BACKGROUND_SUFFIXES, suffix_step, &m, 0);
        found = m.found;
    }
    if (found) {
        struct ft_bpf_background_key key = {.ino = fk->ino, .dev = fk->dev};
        __u8 learned = FT_BPF_BACKGROUND_LEARNED;
        bpf_map_update_elem(&background_files, &key, &learned, BPF_NOEXIST);
    }
    return found;
}

/* Background by inode, or by name for a file other than the ones the thread is reading. */
static __always_inline bool background_read(const struct thread_state *ts,
                                            const unsigned char *dname, const struct file_key *fk)
{
    if (is_background(fk))
        return true;
    if ((ts->file.ino == fk->ino && ts->file.dev == fk->dev && ts->gen == fk->gen) ||
        (ts->bg_file.ino == fk->ino && ts->bg_file.dev == fk->dev && ts->bg_gen == fk->gen))
        return false;
    return background_by_name(dname, fk);
}

/* Adds a send of up to *pending bytes of the file to the counters, and takes it off *pending. */
static __always_inline void charge_send(void *map, __u64 cookie, __u32 tgid,
                                        const struct file_ref *file, __u8 background, __u32 script,
                                        __u64 sent, __u64 *pending, __u64 *unreported, __u8 *fresh,
                                        __u64 now)
{
    __u64 take = sent < *pending ? sent : *pending;
    struct ft_bpf_agg_key key = {
        .cookie = cookie,
        .tgid = tgid,
        .kind = FT_BPF_AGG_READ_SEND,
        .background = background,
        .file = {.ino = file->ino, .dev = file->dev, .instance = file->instance},
    };
    struct ft_bpf_agg_val init = {.first_ns = now};
    struct ft_bpf_agg_val *v = agg_slot(map, &key, &init);
    if (v) {
        __sync_fetch_and_add(&v->transfer.sent_bytes, take);
        __sync_fetch_and_add(&v->transfer.read_bytes, *unreported);
        __sync_fetch_and_add(&v->transfer.sends, 1);
        __sync_fetch_and_add(&v->transfer.alternations, *fresh);
        if (script)
            v->transfer.script = script;
        v->last_ns = now;
    }
    *pending -= take;
    *unreported = 0;
    *fresh = 0;
}

/* Brings what the socket took up to date before its window is judged. */
static __always_inline void carry_settle(void *map, __u64 sk, __u64 now);

static __always_inline bool sock_heard(__u64 sk)
{
    return BPF_CORE_READ((struct tcp_sock *)sk, bytes_received) != 0;
}

/* Whether the socket has sent more than a first flight that is only a handshake or a request. */
static __always_inline bool sock_flown(__u64 sk)
{
    return BPF_CORE_READ((struct tcp_sock *)sk, bytes_sent) >= CARRY_FLIGHT_MAX;
}

/* Why a window closes, which decides a first flight's judgement. */
enum carry_end {
    CARRY_QUIET, /* the socket closed, or the flight grew past what a handshake sends */
    CARRY_AGAIN, /* the connection went on after the peer answered */
    CARRY_NEXT,  /* another file's bytes follow in the same unanswered flight */
};

static __always_inline void carry_report(void *map, const struct carry *c,
                                         const struct file_ref *file, __u8 background, __u64 sent,
                                         __u64 read)
{
    struct ft_bpf_agg_key key = {
        .cookie = c->cookie,
        .tgid = c->tgid,
        .kind = FT_BPF_AGG_READ_SEND,
        .background = background,
        .file = {.ino = file->ino, .dev = file->dev, .instance = file->instance},
    };
    struct ft_bpf_agg_val init = {.first_ns = c->first_ns};
    struct ft_bpf_agg_val *v = agg_slot(map, &key, &init);
    if (v) {
        __sync_fetch_and_add(&v->transfer.sent_bytes, sent);
        __sync_fetch_and_add(&v->transfer.read_bytes, read);
        __sync_fetch_and_add(&v->transfer.sends, c->sends);
        __sync_fetch_and_add(&v->transfer.alternations, c->alternations);
        if (c->script)
            v->transfer.script = c->script;
        v->last_ns = c->last_ns;
    }
}

/* What of a candidate a connection must take whole: what was read of it, up to its size. */
static __always_inline __u64 carried_whole(const struct carried_file *k)
{
    return k->size < k->read ? k->size : k->read;
}

/*
 * Reports the file a dialed connection carried: the one candidate it took whole, give or take
 * a handshake, a client certificate and a request head. With none or two, nothing is.
 */
static __always_inline void carry_judge_dialed(void *map, const struct carry *c)
{
    __u32 matches = 0;
    __u32 match = 0;

#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        __u64 whole = carried_whole(&c->cands[i]);
        if (!c->cands[i].size || whole < CARRY_FLOOR || c->wire < whole ||
            c->wire - whole > CARRY_SLACK + whole / 128)
            continue;
        matches++;
        match = i;
    }
    if (matches != 1)
        return;
    const struct carried_file *k = &c->cands[match & (CARRY_CANDIDATES - 1)];
    carry_report(map, c, &k->file, 0, carried_whole(k), k->read);
}

/* Reports a window's charges, or drops them. */
static __always_inline void carry_judge(void *map, const struct carry *c, enum carry_end end)
{
    if (c->kind == CARRY_DIALED) {
        carry_judge_dialed(map, c);
        return;
    }
    if (!c->sends)
        return;
    /* Within a flight, all of a file that went before another one's bytes is a part. */
    if (end == CARRY_QUIET || c->wire >= CARRY_FLIGHT_MAX ||
        (end == CARRY_NEXT && c->read && c->sent >= c->read))
        carry_report(map, c, &c->file, c->background, c->sent, c->read);
}

/* Closes the window on a socket and judges it. */
static __always_inline void carry_close(void *map, __u64 sk, enum carry_end end, __u64 now)
{
    carry_settle(map, sk, now);
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (!c)
        return;
    carry_judge(map, c, end);
    bpf_map_delete_elem(&carries, &sk);
}

/*
 * Counts a send into the socket's window. A send on a first flight's socket judges the flight
 * once the peer has answered, or once it has grown past what a handshake sends. bytes: what the
 * send took, when it is counted here rather than as the socket is settled.
 */
static __always_inline void carry_sent(void *map, __u64 sk, __u64 bytes, __u64 now)
{
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (!c)
        return;
    if (c->kind == CARRY_FLIGHT && sock_heard(sk)) {
        carry_close(map, sk, CARRY_AGAIN, now);
        return;
    }
    if (c->kind == CARRY_FLIGHT && sock_flown(sk)) {
        carry_close(map, sk, CARRY_QUIET, now);
        return;
    }
    if (c->kind == CARRY_DIALED) {
        __sync_fetch_and_add(&c->sends, 1);
        c->last_ns = now;
    }
    __sync_fetch_and_add(&c->wire, bytes);
}

/* Counts what the socket took into its window, as the socket is settled. */
static __always_inline void carry_wire(__u64 sk, __u64 bytes)
{
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (c)
        __sync_fetch_and_add(&c->wire, bytes);
}

/*
 * A receive on a dialed connection ends its window once the connection has had the correlation
 * window to set itself up, or has taken its largest candidate whole; and when a thread other
 * than the one that dialed it hears the reply. Receives during the setup are a handshake's.
 */
static __always_inline void carry_received(void *map, __u64 sk, __u64 now)
{
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (!c || c->kind != CARRY_DIALED)
        return;
    __u64 largest = 0;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (c->cands[i].size > largest)
            largest = c->cands[i].size;
    }
    if (c->tid == (__u32)bpf_get_current_pid_tgid() && now - c->first_ns <= cfg.corr_window_ns &&
        c->wire < largest)
        return;
    carry_close(map, sk, CARRY_QUIET, now);
}

static __always_inline bool same_file(const struct file_ref *a, const struct file_ref *b)
{
    return a->ino == b->ino && a->dev == b->dev;
}

/* Brings a window's copy of a candidate up to date, or adds it while there is room. */
static __always_inline void carried_read(struct carry *c, const struct candidate *k)
{
    __u32 free = CARRY_CANDIDATES;

#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (c->cands[i].size && same_file(&c->cands[i].file, &k->file)) {
            c->cands[i].size = k->size;
            c->cands[i].read = k->read;
            return;
        }
        if (!c->cands[i].size && free == CARRY_CANDIDATES)
            free = i;
    }
    if (free == CARRY_CANDIDATES)
        return;
    struct carried_file *slot = &c->cands[free & (CARRY_CANDIDATES - 1)];
    slot->file = k->file;
    slot->size = k->size;
    slot->read = k->read;
}

/*
 * Counts a read of the thread's file towards it as a candidate, when it is large enough to be
 * judged by size, and towards the window of the connection the thread dialed last.
 */
static __always_inline void candidate_read(struct thread_state *ts, __u64 bytes, __u64 now)
{
    if (ts->file_size < CARRY_FLOOR || !bytes)
        return;
    __u32 slot = CARRY_CANDIDATES;
    __u32 oldest = 0;
    __u64 oldest_ns = ~0ULL;

#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (ts->cands[i].size && same_file(&ts->cands[i].file, &ts->file)) {
            slot = i;
            break;
        }
        if (ts->cands[i].last_ns < oldest_ns) {
            oldest_ns = ts->cands[i].last_ns;
            oldest = i;
        }
    }
    struct candidate *k;
    if (slot == CARRY_CANDIDATES) {
        k = &ts->cands[oldest & (CARRY_CANDIDATES - 1)];
        k->read = 0;
    } else {
        k = &ts->cands[slot & (CARRY_CANDIDATES - 1)];
        /* A file read again after a pause is read anew. */
        if (now - k->last_ns > cfg.corr_window_ns)
            k->read = 0;
    }
    k->file = ts->file;
    k->size = ts->file_size;
    k->read += bytes;
    k->last_ns = now;

    __u64 sk = ts->carry_sock;
    struct carry *c = sk ? bpf_map_lookup_elem(&carries, &sk) : NULL;
    if (c && c->kind == CARRY_DIALED && c->tid == (__u32)bpf_get_current_pid_tgid())
        carried_read(c, k);
    else
        ts->carry_sock = 0;
}

/*
 * Notes the connection a thread opens, and opens a window on it when the thread read large
 * files within the correlation window: the connection may be setting out to send one of them.
 */
static __always_inline bool carry_dial(struct sock *sk, __u64 cookie, __u64 now)
{
    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
    if (!ts)
        return false;
    __u64 key = (__u64)sk;
    ts->dialed = key;
    ts->dialed_ns = now;

    bool fresh = false;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (ts->cands[i].size && now - ts->cands[i].last_ns <= cfg.corr_window_ns)
            fresh = true;
    }
    if (!fresh || bpf_map_update_elem(&carries, &key, &carry_zero, BPF_ANY))
        return false;
    struct carry *c = bpf_map_lookup_elem(&carries, &key);
    if (!c)
        return false;
    __u64 ids = bpf_get_current_pid_tgid();
    c->cookie = cookie;
    c->tgid = (__u32)(ids >> 32);
    c->tid = (__u32)ids;
    c->kind = CARRY_DIALED;
    c->script = ts->script;
    c->first_ns = now;
    c->last_ns = now;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (ts->cands[i].size && now - ts->cands[i].last_ns <= cfg.corr_window_ns) {
            c->cands[i].file = ts->cands[i].file;
            c->cands[i].size = ts->cands[i].size;
            c->cands[i].read = ts->cands[i].read;
        }
    }
    ts->carry_sock = key;
    return true;
}

/*
 * The first-flight window a send of the thread's read goes into: the one open on the socket
 * for the same file, or a new one when the socket has heard nothing yet. NULL with *skip set:
 * nowhere, as another window holds the socket; NULL otherwise: charged as it is. wire: what the
 * send took, when it is counted here. background: the send is of the thread's background file.
 */
static __always_inline struct carry *carry_window(struct thread_state *ts, __u64 sk, __u64 cookie,
                                                  __u32 tgid, __u64 wire, __u64 now,
                                                  bool background, bool *skip)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    void *map = agg_map_now();
    const struct file_ref *file = background ? &ts->bg_file : &ts->file;

    *skip = false;
    if (!sk || !map)
        return NULL;
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (c && (c->tid != tid || c->kind != CARRY_FLIGHT)) {
        *skip = true;
        return NULL;
    }
    if (c && c->background == background && c->file.ino == file->ino && c->file.dev == file->dev &&
        c->file.instance == file->instance)
        return c;
    if (c)
        carry_close(map, sk, CARRY_NEXT, now);
    if (sock_heard(sk) || sock_flown(sk))
        return NULL;

    if (bpf_map_update_elem(&carries, &sk, &carry_zero, BPF_NOEXIST)) {
        *skip = true;
        return NULL;
    }
    c = bpf_map_lookup_elem(&carries, &sk);
    if (!c) {
        *skip = true;
        return NULL;
    }
    c->cookie = cookie;
    c->tgid = tgid;
    c->tid = tid;
    c->file = *file;
    c->kind = CARRY_FLIGHT;
    c->background = background;
    c->first_ns = now;
    c->last_ns = now;
    c->wire = wire;
    return c;
}

/* Holds a charge in the window instead of the counters. */
static __always_inline void carry_add(struct carry *c, __u64 sent, __u64 read, __u8 fresh,
                                      __u32 script, __u64 now)
{
    __sync_fetch_and_add(&c->sent, sent);
    __sync_fetch_and_add(&c->read, read);
    __sync_fetch_and_add(&c->sends, 1);
    __sync_fetch_and_add(&c->alternations, fresh);
    if (script)
        c->script = script;
    c->last_ns = now;
}

/*
 * Whether the thread's background file was read before it connected the socket, as resolver
 * files are read for the lookup before a connection: then it is not what goes over it.
 */
static __always_inline bool background_dialed(const struct thread_state *ts, __u64 sk)
{
    return sk && ts->dialed == sk && ts->dialed_ns > ts->bg_last_ns;
}

/* The dialed window of the socket, if the thread may send over it. */
static __always_inline struct carry *dialed_window(__u64 sk)
{
    struct carry *c = sk ? bpf_map_lookup_elem(&carries, &sk) : NULL;
    return c && c->kind == CARRY_DIALED ? c : NULL;
}

/*
 * Attributes a send to the file this thread just read, up to what of it is still unsent, or,
 * when no such read accounts for it, to the background file the thread read last. A send in a
 * connection's first flight is held in its window; a send over a dialed connection is judged by
 * its window, and only uses the read up.
 */
static __always_inline void correlate_send(void *map, __u64 sk, __u64 cookie, __u32 tgid,
                                           __u64 sent, __u64 now)
{
    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
    if (!ts)
        return;
    if (ts->pending && now - ts->last_ns > cfg.corr_window_ns)
        foreground_reset(ts);
    struct carry *w = dialed_window(sk);
    if (w) {
        if (w->tid == (__u32)bpf_get_current_pid_tgid()) {
            ts->pending -= sent < ts->pending ? sent : ts->pending;
            ts->unreported = 0;
            ts->fresh = 0;
            background_reset(ts);
        }
        return;
    }
    if (ts->pending) {
        bool skip;
        struct carry *c = carry_window(ts, sk, cookie, tgid, sent, now, false, &skip);
        if (c) {
            __u64 take = sent < ts->pending ? sent : ts->pending;
            carry_add(c, take, ts->unreported, ts->fresh, ts->script, now);
            ts->pending -= take;
            ts->unreported = 0;
            ts->fresh = 0;
            ts->last_ns = now;
            background_reset(ts);
            return;
        }
        if (skip)
            return;
        charge_send(map, cookie, tgid, &ts->file, 0, ts->script, sent, &ts->pending,
                    &ts->unreported, &ts->fresh, now);
        ts->last_ns = now;
        background_reset(ts);
        return;
    }
    if (!ts->bg_pending)
        return;
    if (now - ts->bg_last_ns > cfg.corr_window_ns || background_dialed(ts, sk)) {
        background_reset(ts);
        return;
    }
    bool skip;
    struct carry *c = carry_window(ts, sk, cookie, tgid, sent, now, true, &skip);
    if (c) {
        __u64 take = sent < ts->bg_pending ? sent : ts->bg_pending;
        carry_add(c, take, ts->bg_unreported, ts->bg_fresh, ts->script, now);
        ts->bg_pending -= take;
        ts->bg_unreported = 0;
        ts->bg_fresh = 0;
    } else if (!skip) {
        charge_send(map, cookie, tgid, &ts->bg_file, 1, ts->script, sent, &ts->bg_pending,
                    &ts->bg_unreported, &ts->bg_fresh, now);
    }
    ts->bg_last_ns = now;
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
    char *comps; /* FT_BPF_PATH_BUF + FT_BPF_NAME_MAX bytes */
    struct dentry *dentry;
    struct mount *mnt;
    __u32 off;
    __u16 depth;
    __u16 flags;
};

static long path_step(__u64 index, void *arg)
{
    struct path_walk *w = arg;
    char *comps = w->comps;
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
    long n = bpf_probe_read_kernel_str(&comps[off & (FT_BPF_PATH_BUF - 1)], FT_BPF_NAME_MAX, name);
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
        .comps = s->comps,
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
    s->ev.size = (__u64)BPF_CORE_READ(inode, i_size);
    s->ev.uid = BPF_CORE_READ(inode, i_uid.val);
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

/*
 * Reports a program starting, with its working directory and arguments as the kernel set them
 * up: a process that exits right away is gone before /proc can be read.
 */
static __always_inline void fill_exec(struct ft_bpf_ev_exec *e, struct task_struct *task,
                                      struct linux_binprm *bprm)
{
    fill_proc(&e->proc, task, FT_BPF_EV_EXEC);
    const char *filename = BPF_CORE_READ(bprm, filename);
    if (bpf_probe_read_kernel_str(e->exe, sizeof(e->exe), filename) < 0)
        e->exe[0] = 0;
    e->cwd_len = 0;
    e->cwd_depth = 0;
    e->cwd_flags = 0;
    e->args_len = 0;
    e->pad = 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(ft_process_exec, struct task_struct *task, pid_t old_pid, struct linux_binprm *bprm)
{
    /* A request that starts another program does not carry its script into it. */
    struct thread_state *ts = bpf_task_storage_get(&threads, task, 0, 0);
    if (ts)
        ts->script = 0;

    __u32 zero = 0;
    struct exec_scratch *s = bpf_map_lookup_elem(&exec_scratch, &zero);
    if (!s)
        return 0;
    /* Another exec on this CPU was preempted while using the buffer: report it without text. */
    if (__sync_lock_test_and_set(&s->busy, 1)) {
        count(FT_BPF_CNT_PATH_BUSY);
        struct ft_bpf_ev_exec *plain = bpf_ringbuf_reserve(&events, sizeof(*plain), 0);
        if (!plain) {
            count(FT_BPF_CNT_RING_FULL);
            return 0;
        }
        fill_exec(plain, task, bprm);
        bpf_ringbuf_submit(plain, wake_flags());
        return 0;
    }

    struct ft_bpf_ev_exec *e = &s->ev;
    fill_exec(e, task, bprm);

    struct dentry *dentry = BPF_CORE_READ(task, fs, pwd.dentry);
    struct vfsmount *vfsmnt = BPF_CORE_READ(task, fs, pwd.mnt);
    struct path_walk w = {
        .comps = s->tail,
        .dentry = dentry,
        .mnt = (void *)vfsmnt - bpf_core_field_offset(struct mount, mnt),
        .flags = FT_BPF_FILE_TRUNCATED,
    };
    if (dentry && vfsmnt)
        bpf_loop(FT_BPF_PATH_DEPTH, path_step, &w, 0);
    __u32 cwd = w.off;
    if (cwd >= FT_BPF_PATH_BUF + FT_BPF_NAME_MAX)
        cwd = 0;
    e->cwd_len = cwd;
    e->cwd_depth = cwd ? w.depth : 0;
    e->cwd_flags = cwd ? w.flags : 0;

    __u64 start = BPF_CORE_READ(task, mm, arg_start);
    __u64 end = BPF_CORE_READ(task, mm, arg_end);
    __u32 args = end > start ? (__u32)(end - start) : 0;
    if (args > FT_BPF_ARGS_MAX)
        args = FT_BPF_ARGS_MAX;
    if (args && bpf_probe_read_user(&s->tail[cwd], args, (void *)start) != 0)
        args = 0;
    e->args_len = args;

    __u64 size = sizeof(*e) + cwd + args;
    if (size <= sizeof(*e) + sizeof(s->tail) &&
        bpf_ringbuf_output(&events, e, size, wake_flags()) != 0)
        count(FT_BPF_CNT_RING_FULL);
    s->busy = 0;
    return 0;
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
    ts->file_size = FT_READ(inode, i_size);
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

/* Points the thread's background slot at the file, starting it over if that is another file. */
static __always_inline void thread_set_background(struct thread_state *ts, struct file *file,
                                                  struct inode *inode, const struct file_key *fk,
                                                  __u64 fs_magic)
{
    if (ts->bg_file.ino != fk->ino || ts->bg_file.dev != fk->dev || ts->bg_gen != fk->gen) {
        ts->bg_file.ino = fk->ino;
        ts->bg_file.dev = fk->dev;
        ts->bg_file.instance = 0;
        ts->bg_gen = fk->gen;
        background_reset(ts);
    }
    if (ts->bg_forgotten != forgotten_files) {
        ts->bg_forgotten = forgotten_files;
        ts->bg_file.instance = 0;
    }
    if (!ts->bg_file.instance)
        ts->bg_file.instance = file_instance(file, inode, fk, fs_magic);
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

    /* The inode number can be given to an unrelated file next. */
    struct ft_bpf_background_key bk = {.ino = fk.ino, .dev = fk.dev};
    bpf_map_delete_elem(&background_files, &bk);
}

/* A PHP request's script path, before it is queued. */
struct script_scratch {
    __u32 busy;
    __u32 pad;
    struct ft_bpf_ev_script ev;
    char path[FT_BPF_SCRIPT_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct script_scratch);
} script_scratch SEC(".maps");

struct script_hash {
    const char *path;
    __u32 len;
    __u64 hash;
};

static long script_hash_step(__u64 index, void *arg)
{
    struct script_hash *h = arg;
    if (index >= h->len)
        return 1;
    h->hash ^= (unsigned char)h->path[index & (FT_BPF_SCRIPT_MAX - 1)];
    h->hash *= 0x100000001b3ULL;
    return 0;
}

/* Every SAPI starts a request's script here: FPM, mod_php, the CLI. */
SEC("uprobe")
int BPF_UPROBE(ft_php_execute_script, void *handle)
{
    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0,
                                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ts)
        return 0;
    ts->script = 0;

    /* zend_file_handle: the name follows a 40-byte union in every version. */
    __u64 name = 0;
    if (bpf_probe_read_user(&name, sizeof(name), handle + 40) || !name)
        return 0;
    if (bpf_get_attach_cookie(ctx) == FT_BPF_PHP_ZEND_STRING)
        name += 24; /* past the refcount, hash and length of the zend_string */

    __u32 zero = 0;
    struct script_scratch *s = bpf_map_lookup_elem(&script_scratch, &zero);
    if (!s)
        return 0;
    if (__sync_lock_test_and_set(&s->busy, 1)) {
        count(FT_BPF_CNT_PATH_BUSY);
        return 0;
    }

    long n = bpf_probe_read_user_str(s->path, sizeof(s->path), (void *)name);
    if (n > 1) {
        __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
        struct script_hash h = {
            .path = s->path, .len = (__u32)n - 1, .hash = 0xcbf29ce484222325ULL};
        /* A relative path names another script in every directory it is run from. */
        if (s->path[0] != '/')
            h.hash ^= tgid;
        bpf_loop(FT_BPF_SCRIPT_MAX, script_hash_step, &h, 0);

        __u32 *known = bpf_map_lookup_elem(&known_scripts, &h.hash);
        if (known) {
            ts->script = *known;
        } else {
            __u32 id = __sync_fetch_and_add(&last_script_id, 1) + 1;
            s->ev.hdr.ts_ns = bpf_ktime_get_boot_ns();
            s->ev.hdr.kind = FT_BPF_EV_SCRIPT;
            s->ev.hdr.pad = 0;
            s->ev.id = id;
            s->ev.tgid = tgid;
            s->ev.len = (__u32)n - 1;
            s->ev.pad = 0;
            s->ev.hash = h.hash;
            __u64 len = (__u64)n;
            if (len > FT_BPF_SCRIPT_MAX)
                len = FT_BPF_SCRIPT_MAX;
            __u64 size = sizeof(s->ev) + len;
            if (bpf_ringbuf_output(&events, &s->ev, size, wake_flags()) == 0) {
                bpf_map_update_elem(&known_scripts, &h.hash, &id, BPF_ANY);
                ts->script = id;
            } else {
                count(FT_BPF_CNT_RING_FULL);
            }
        }
    }
    s->busy = 0;
    return 0;
}

/* The request is over once its output is flushed, so later work of the thread is not its. */
SEC("uretprobe")
int BPF_URETPROBE(ft_php_request_shutdown)
{
    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
    if (ts)
        ts->script = 0;
    return 0;
}

#endif
