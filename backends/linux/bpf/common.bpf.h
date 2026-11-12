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
 * The file a thread read most recently and how much of it is unsent, apart from it the strict
 * file it read last, which a send is taken to carry only when it matches its size, and the
 * large files it read lately, for the connections it opens.
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
    __u8 strict_fresh;
    __u8 strict_reading; /* the read counter has grown only by reads of strict_file */
    __u32 received;      /* receives seen; a claim made before the last one is not handed back */
    __u32 script;        /* the PHP request running on this thread, as ft_bpf_ev_script names it */
    __u64 dialed;        /* the TCP socket the thread connected last */
    __u64 dialed_ns;
    __u64 file_size;    /* the file's size at its last read */
    __u64 carry_sock;   /* the socket of the window of the connection the thread dialed last */
    __u64 episode_sock; /* the socket of the thread's window of a reply on a heard connection */
    struct candidate cands[CARRY_CANDIDATES];
    struct file_ref strict_file;
    __u64 strict_size;
    __u32 strict_gen;
    __u32 strict_forgotten;
    __u64 strict_pending;
    __u64 strict_unreported;
    __u64 strict_last_ns;
    __u64 strict_read_ns;
    __u64 strict_datagrams;     /* what datagrams took since the strict file was read */
    __u64 strict_datagram_sock; /* the cookie of the socket that took them */
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
 * - FLIGHT: the socket had heard nothing from its peer, so the bytes may be a TLS ClientHello
 *   or the first request of a conversation. The charges are dropped if that first flight was
 *   small and the thread sent again after the peer answered.
 * - EPISODE: a small file read for a reply over a connection that has heard from its peer, as
 *   a server reads its configuration, a session or a template for each request. The charges are
 *   reported only if what the connection took until the reply ended was about the file and a
 *   response head.
 */
enum carry_kind {
    CARRY_FLIGHT = 2,
    CARRY_EPISODE = 3,
};

struct carry {
    __u64 cookie;
    __u32 tgid;
    __u32 tid;
    struct file_ref file;
    __u32 script;
    __u32 sends;
    __u32 alternations;
    __u8 kind;
    __u64 size; /* the file's size */
    __u64 first_ns;
    __u64 last_ns;
    __u64 wire;                  /* what the connection took while the window was open */
    __u64 sent;                  /* of that, charged to the file */
    __u64 read;                  /* of the file, before those charges */
    struct file_ref strict_file; /* the strict file read before a send, if any */
    __u64 strict_size;
    __u64 strict_read;
};

static struct carry carry_zero;

/* Keyed by the address of the kernel socket. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct carry);
} carries SEC(".maps");

/* A candidate as the window of a connection knows it. */
struct dialed_file {
    struct file_ref file;
    __u64 size;
    __u64 read;
    __u64 last_ns;
    __u64 charged; /* what of it the base rule reported over the connection */
    __u8 fresh;    /* read within the correlation window of the dial */
};

/*
 * A connection a thread opened soon after reading large files. What it sends is charged as over
 * any connection; this adds the upload those charges miss, the one a reply during the setup of
 * the connection hid: a candidate the connection took whole, when it is the only one.
 */
struct dial {
    __u64 cookie;
    __u32 tgid;
    __u32 tid;
    __u32 script;
    __u32 sends;
    __u32 pad;
    __u64 first_ns; /* the dial */
    __u64 sent_ns;  /* the first send, or 0 */
    __u64 last_ns;
    __u64 wire;       /* what the connection took, sendfile aside */
    __u64 burst;      /* of that, since the connection last heard from its peer */
    __u64 max_burst;  /* the most it took between two receives */
    __u64 next_burst; /* the second most */
    struct dialed_file cands[CARRY_CANDIDATES];
};

static struct dial dial_zero;

/* Keyed by the address of the kernel socket. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct dial);
} dials SEC(".maps");

/* Below this size a file matches the size of too many requests to be judged by size. */
#define CARRY_FLOOR (64 * 1024)
/* What a connection takes besides the file: a handshake, a client certificate, a request head. */
#define CARRY_SLACK (8 * 1024)
/* What a reply takes besides a small file it sends: half the file's size, within these. */
#define CARRY_HEAD_MIN 1024
#define CARRY_HEAD_MAX (2 * 1024)
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

/* A thread that sends a file with sendfile read it for something else, as for a checksum. */
static __always_inline void sendfile_read(struct thread_state *ts, const struct file_key *fk)
{
    if (ts && ts->pending && ts->file.ino == fk->ino && ts->file.dev == fk->dev &&
        ts->gen == fk->gen)
        foreground_reset(ts);
}

static __always_inline void strict_reset(struct thread_state *ts)
{
    ts->strict_pending = 0;
    ts->strict_unreported = 0;
    ts->strict_fresh = 0;
    ts->strict_datagrams = 0;
    ts->strict_datagram_sock = 0;
}

static __always_inline void thread_reset(struct thread_state *ts)
{
    foreground_reset(ts);
    strict_reset(ts);
}

/* Which list names the file by its inode, or 0. */
static __always_inline __u8 listed_inode(const struct file_key *fk)
{
    struct ft_bpf_background_key key = {.ino = fk->ino, .dev = fk->dev};
    __u8 *source = bpf_map_lookup_elem(&background_files, &key);
    if (!source)
        return 0;
    return *source & FT_BPF_BACKGROUND_STRICT ? FT_BPF_LISTED_STRICT : FT_BPF_LISTED_BACKGROUND;
}

struct suffix_match {
    const char *name;
    __u32 len;
    __u8 kind;
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
            m->kind = (__u8)s->kind;
            return 1;
        }
        if (m->name[(from + i) & (FT_BPF_BACKGROUND_NAME - 1)] != s->text[i])
            return 0;
    }
    m->kind = (__u8)s->kind;
    return 1;
}

/*
 * Which list names a file the thread starts reading by its name, as a CA bundle that a library
 * keeps in its own directory, or a module: from this read on, for every thread.
 */
static __always_inline __u8 listed_by_name(const unsigned char *dname, const struct file_key *fk)
{
    char name[FT_BPF_BACKGROUND_NAME] = {};
    long n = bpf_probe_read_kernel_str(name, sizeof(name), dname);
    if (n <= 1)
        return 0;
    __u8 *named = bpf_map_lookup_elem(&background_names, name);
    __u8 kind = named ? *named : 0;
    if (!kind) {
        struct suffix_match m = {.name = name, .len = (__u32)n - 1};
        bpf_loop(FT_BPF_BACKGROUND_SUFFIXES, suffix_step, &m, 0);
        kind = m.kind;
    }
    if (kind) {
        struct ft_bpf_background_key key = {.ino = fk->ino, .dev = fk->dev};
        __u8 learned = FT_BPF_BACKGROUND_LEARNED |
                       (kind == FT_BPF_LISTED_STRICT ? FT_BPF_BACKGROUND_STRICT : 0);
        bpf_map_update_elem(&background_files, &key, &learned, BPF_NOEXIST);
    }
    return kind;
}

/* Which list names a file read: by inode, or by name unless it is one the thread is reading. */
static __always_inline __u8 listed_read(const struct thread_state *ts, const unsigned char *dname,
                                        const struct file_key *fk)
{
    __u8 kind = listed_inode(fk);
    if (kind)
        return kind;
    if ((ts->file.ino == fk->ino && ts->file.dev == fk->dev && ts->gen == fk->gen) ||
        (ts->strict_file.ino == fk->ino && ts->strict_file.dev == fk->dev &&
         ts->strict_gen == fk->gen))
        return 0;
    return listed_by_name(dname, fk);
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

static __always_inline bool same_file(const struct file_ref *a, const struct file_ref *b)
{
    return a->ino == b->ino && a->dev == b->dev;
}

/*
 * Notes what the base rule charged of a file over a connection that has a dialed window, held
 * back or not; a held charge that is dropped later is taken off again.
 */
static __always_inline void dial_charged(__u64 sk, const struct file_ref *file, __s64 bytes)
{
    struct dial *d = sk ? bpf_map_lookup_elem(&dials, &sk) : NULL;
    if (!d)
        return;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (d->cands[i].size && same_file(&d->cands[i].file, file))
            __sync_fetch_and_add(&d->cands[i].charged, (__u64)bytes);
    }
}

static __always_inline void transfer_report(void *map, __u64 cookie, __u32 tgid,
                                            const struct file_ref *file, __u64 first_ns,
                                            __u64 last_ns, __u64 sent, __u64 read, __u32 sends,
                                            __u32 alternations, __u32 script)
{
    struct ft_bpf_agg_key key = {
        .cookie = cookie,
        .tgid = tgid,
        .kind = FT_BPF_AGG_READ_SEND,
        .file = {.ino = file->ino, .dev = file->dev, .instance = file->instance},
    };
    struct ft_bpf_agg_val init = {.first_ns = first_ns};
    struct ft_bpf_agg_val *v = agg_slot(map, &key, &init);
    if (v) {
        __sync_fetch_and_add(&v->transfer.sent_bytes, sent);
        __sync_fetch_and_add(&v->transfer.read_bytes, read);
        __sync_fetch_and_add(&v->transfer.sends, sends);
        __sync_fetch_and_add(&v->transfer.alternations, alternations);
        if (script)
            v->transfer.script = script;
        v->last_ns = last_ns;
    }
}

static __always_inline void carry_report(void *map, const struct carry *c,
                                         const struct file_ref *file, __u64 sent, __u64 read)
{
    transfer_report(map, c->cookie, c->tgid, file, c->first_ns, c->last_ns, sent, read, c->sends,
                    c->alternations, c->script);
}

/* Whether what went is the file and up to head bytes besides, give or take a tenth. */
static __always_inline bool volume_within(__u64 wire, __u64 whole, __u64 head)
{
    return whole && wire * 10 >= whole * 9 && wire <= whole + head;
}

/* A reply sends a head besides the file: half the file's size, within these bounds. */
static __always_inline bool volume_matches(__u64 wire, __u64 whole)
{
    __u64 head = whole / 2;
    if (head < CARRY_HEAD_MIN)
        head = CARRY_HEAD_MIN;
    if (head > CARRY_HEAD_MAX)
        head = CARRY_HEAD_MAX;
    return volume_within(wire, whole, head);
}

/*
 * A strict file is sent whole, its head if any gone before it was read: an eighth of its size,
 * within these bounds, so that a request a lookup of it preceded does not pass for it.
 */
static __always_inline bool strict_matches(__u64 wire, __u64 whole)
{
    __u64 head = whole / 8;
    if (head < 256)
        head = 256;
    if (head > 1024)
        head = 1024;
    return volume_within(wire, whole, head);
}

/*
 * Reports the file a first flight or a reply carried, or drops both it may have: the file the
 * thread was sending and the strict file it read before. Of the two, only one can be taken.
 */
static __always_inline void carry_judge(void *map, __u64 sk, const struct carry *c,
                                        enum carry_end end)
{
    bool flight = c->kind == CARRY_FLIGHT;
    /* A small first flight the connection went on from was a hello or a first request. */
    if (flight && end == CARRY_AGAIN && c->wire < CARRY_FLIGHT_MAX) {
        dial_charged(sk, &c->file, -(__s64)c->sent);
        return;
    }
    __u64 whole = c->size && c->size < c->read ? c->size : c->read;
    /* Beside a strict file, the thread's file too must match what went. */
    bool by_volume = !flight || c->strict_read;
    bool file = false;
    if (c->sends && by_volume)
        file = volume_matches(c->wire, whole);
    /* Within a flight, all of a file that went before another one's bytes is a part. */
    else if (c->sends)
        file = end != CARRY_NEXT || (c->read && c->sent >= c->read);

    __u64 strict_whole =
        c->strict_size && c->strict_size < c->strict_read ? c->strict_size : c->strict_read;
    bool strict = c->strict_read && strict_matches(c->wire, strict_whole);

    if (file && !strict) {
        carry_report(map, c, &c->file, by_volume ? whole : c->sent, c->read);
        return;
    }
    dial_charged(sk, &c->file, -(__s64)c->sent);
    if (strict && !file) {
        carry_report(map, c, &c->strict_file, strict_whole, c->strict_read);
        dial_charged(sk, &c->strict_file, (__s64)strict_whole);
    }
}

/* Closes the window on a socket and judges it. */
static __always_inline void carry_close(void *map, __u64 sk, enum carry_end end, __u64 now)
{
    carry_settle(map, sk, now);
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (!c)
        return;
    carry_judge(map, sk, c, end);
    bpf_map_delete_elem(&carries, &sk);
}

/* What of a candidate a connection must take whole: what was read of it, up to its size. */
static __always_inline __u64 dialed_whole(const struct dialed_file *k)
{
    return k->size < k->read ? k->size : k->read;
}

/*
 * Adds the upload a dialed connection carried and the base rule missed: the one candidate the
 * connection took whole, give or take a handshake, a client certificate and a request head, or a
 * first piece read to look at the file. Not when two match or the match is stale, when the
 * connection was not used soon after the dial, or when the two longest runs of sends between
 * receives did not carry nearly the whole file: request and reply traffic adds up to any size,
 * an upload goes out in one run after the setup of its connection, or in two when the client
 * reads a session ticket on the way.
 */
static __always_inline void dial_judge(void *map, const struct dial *d)
{
    if (!d->sent_ns || d->sent_ns - d->first_ns > cfg.corr_window_ns)
        return;
    __u32 matches = 0;
    __u32 match = 0;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        __u64 whole = dialed_whole(&d->cands[i]);
        if (!d->cands[i].size || whole < CARRY_FLOOR || d->wire + whole / 64 < whole ||
            d->wire > whole + CARRY_SLACK + whole / 128)
            continue;
        matches++;
        match = i;
    }
    if (matches != 1)
        return;
    const struct dialed_file *k = &d->cands[match & (CARRY_CANDIDATES - 1)];
    __u64 whole = dialed_whole(k);
    __u64 first = d->max_burst;
    __u64 second = d->next_burst;
    if (d->burst > first) {
        second = first;
        first = d->burst;
    } else if (d->burst > second) {
        second = d->burst;
    }
    if (!k->fresh || (first + second) * 10 < whole * 9 || k->charged * 10 >= whole * 9)
        return;
    transfer_report(map, d->cookie, d->tgid, &k->file, d->first_ns, d->last_ns, whole - k->charged,
                    k->charged ? 0 : k->read, d->sends, 0, d->script);

    /* A file that went is no candidate for the thread's next connection. */
    if (d->tid != (__u32)bpf_get_current_pid_tgid())
        return;
    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
    if (!ts)
        return;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (ts->cands[i].size && same_file(&ts->cands[i].file, &k->file))
            ts->cands[i].size = 0;
    }
}

static __always_inline void dial_close(void *map, __u64 sk, __u64 now)
{
    carry_settle(map, sk, now);
    struct dial *d = bpf_map_lookup_elem(&dials, &sk);
    if (!d)
        return;
    dial_judge(map, d);
    bpf_map_delete_elem(&dials, &sk);
}

/*
 * Counts a send into the socket's windows. A send on a first flight's socket judges the flight
 * once the peer has answered, or once it has grown past what a handshake sends. bytes: what the
 * send took, when it is counted here rather than as the socket is settled.
 */
static __always_inline void carry_sent(void *map, __u64 sk, __u64 bytes, __u64 now)
{
    struct dial *d = bpf_map_lookup_elem(&dials, &sk);
    if (d) {
        __sync_fetch_and_add(&d->sends, 1);
        __sync_fetch_and_add(&d->wire, bytes);
        __sync_fetch_and_add(&d->burst, bytes);
        if (!d->sent_ns)
            d->sent_ns = now;
        d->last_ns = now;
    }
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (!c)
        return;
    if (c->kind == CARRY_FLIGHT && sock_heard(sk)) {
        carry_close(map, sk, CARRY_AGAIN, now);
        return;
    }
    if (c->kind == CARRY_FLIGHT && sock_flown(sk)) {
        /* No hello: a small or a strict file is judged by the whole of what goes. */
        if (!c->strict_read && !(c->size && c->size < CARRY_FLOOR)) {
            carry_close(map, sk, CARRY_QUIET, now);
            return;
        }
        c->kind = CARRY_EPISODE;
    }
    __sync_fetch_and_add(&c->wire, bytes);
}

/* Counts what the socket took into its windows, as the socket is settled. */
static __always_inline void carry_wire(__u64 sk, __u64 bytes)
{
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (c)
        __sync_fetch_and_add(&c->wire, bytes);
    struct dial *d = bpf_map_lookup_elem(&dials, &sk);
    if (d) {
        __sync_fetch_and_add(&d->wire, bytes);
        __sync_fetch_and_add(&d->burst, bytes);
    }
}

/*
 * A receive on a dialed connection ends its window once the connection has had the correlation
 * window to set itself up, or has taken its largest candidate whole; until then a receive is a
 * handshake's. A reply's window ends when a thread other than its own hears on its connection.
 */
static __always_inline void carry_received(void *map, __u64 sk, __u64 now)
{
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (c && c->kind == CARRY_EPISODE && c->tid != (__u32)bpf_get_current_pid_tgid())
        carry_close(map, sk, CARRY_QUIET, now);

    struct dial *d = bpf_map_lookup_elem(&dials, &sk);
    if (!d)
        return;
    if (d->burst > d->max_burst) {
        d->next_burst = d->max_burst;
        d->max_burst = d->burst;
    } else if (d->burst > d->next_burst) {
        d->next_burst = d->burst;
    }
    d->burst = 0;
    __u64 largest = 0;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (d->cands[i].size > largest)
            largest = d->cands[i].size;
    }
    if (now - d->first_ns > cfg.corr_window_ns || d->wire >= largest)
        dial_close(map, sk, now);
}

/* Ends the thread's reply: it heard from a peer, or turned to another file or connection. */
static __always_inline void carry_episode_end(struct thread_state *ts, __u64 now)
{
    __u64 sk = ts->episode_sock;
    struct carry *c = sk ? bpf_map_lookup_elem(&carries, &sk) : NULL;
    void *map = agg_map_now();
    ts->episode_sock = 0;
    if (c && map && c->kind == CARRY_EPISODE && c->tid == (__u32)bpf_get_current_pid_tgid())
        carry_close(map, sk, CARRY_QUIET, now);
}

/* Brings the dialed window's copy of a candidate up to date, or adds it in a free place. */
static __always_inline void dialed_read(struct dial *d, const struct candidate *k)
{
    __u32 free = CARRY_CANDIDATES;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (d->cands[i].size && same_file(&d->cands[i].file, &k->file)) {
            d->cands[i].size = k->size;
            d->cands[i].read = k->read;
            d->cands[i].last_ns = k->last_ns;
            return;
        }
        if (!d->cands[i].size && free == CARRY_CANDIDATES)
            free = i;
    }
    if (free == CARRY_CANDIDATES)
        return;
    struct dialed_file *slot = &d->cands[free & (CARRY_CANDIDATES - 1)];
    slot->file = k->file;
    slot->size = k->size;
    slot->read = k->read;
    slot->last_ns = k->last_ns;
    slot->fresh = 1;
}

/*
 * Counts a read of a file towards it as a candidate, when it is large enough to be judged by
 * size, and towards the window of the connection the thread dialed last. A new candidate takes
 * a free place, else a stale one's, else the place of the one read least.
 */
static __always_inline void candidate_read(struct thread_state *ts, const struct file_ref *file,
                                           __u64 size, __u64 bytes, __u64 now)
{
    if (size < CARRY_FLOOR || !bytes)
        return;
    __u32 slot = CARRY_CANDIDATES;
    __u32 victim = 0;
    __u64 victim_read = ~0ULL;

#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        struct candidate *k = &ts->cands[i];
        if (k->size && same_file(&k->file, file)) {
            slot = i;
            break;
        }
        __u64 weight = !k->size ? 0 : now - k->last_ns > cfg.corr_window_ns ? 1 : k->read + 2;
        if (weight < victim_read) {
            victim_read = weight;
            victim = i;
        }
    }
    struct candidate *k;
    if (slot == CARRY_CANDIDATES) {
        k = &ts->cands[victim & (CARRY_CANDIDATES - 1)];
        k->read = 0;
    } else {
        k = &ts->cands[slot & (CARRY_CANDIDATES - 1)];
        /* A file read again after a pause is read anew. */
        if (now - k->last_ns > cfg.corr_window_ns)
            k->read = 0;
    }
    k->file = *file;
    k->size = size;
    k->read += bytes;
    k->last_ns = now;

    __u64 sk = ts->carry_sock;
    struct dial *d = sk ? bpf_map_lookup_elem(&dials, &sk) : NULL;
    if (d && d->tid == (__u32)bpf_get_current_pid_tgid())
        dialed_read(d, k);
    else
        ts->carry_sock = 0;
}

/* A candidate the base rule charged over a connection without a window has gone there. */
static __always_inline void candidate_spent(struct thread_state *ts, __u64 sk)
{
    if (!sk || bpf_map_lookup_elem(&dials, &sk))
        return;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (ts->cands[i].size && same_file(&ts->cands[i].file, &ts->file))
            ts->cands[i].size = 0;
    }
}

/*
 * Notes the connection a thread opens, and opens a window on it when the thread read large
 * files within the correlation window: the connection may be setting out to send one of them.
 * Candidates read before that are copied too, for a match with them to make the window's
 * judgement ambiguous.
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
    if (!fresh || bpf_map_update_elem(&dials, &key, &dial_zero, BPF_ANY))
        return false;
    struct dial *d = bpf_map_lookup_elem(&dials, &key);
    if (!d)
        return false;
    __u64 ids = bpf_get_current_pid_tgid();
    d->cookie = cookie;
    d->tgid = (__u32)(ids >> 32);
    d->tid = (__u32)ids;
    d->script = ts->script;
    d->first_ns = now;
    d->last_ns = now;
#pragma unroll
    for (__u32 i = 0; i < CARRY_CANDIDATES; i++) {
        if (!ts->cands[i].size)
            continue;
        d->cands[i].file = ts->cands[i].file;
        d->cands[i].size = ts->cands[i].size;
        d->cands[i].read = ts->cands[i].read;
        d->cands[i].last_ns = ts->cands[i].last_ns;
        d->cands[i].fresh = now - ts->cands[i].last_ns <= cfg.corr_window_ns;
    }
    ts->carry_sock = key;
    return true;
}

/*
 * The window a send goes into: the one open on the socket, or a new one when the socket has
 * heard nothing yet, or when the file the thread was sending is small enough to be judged by
 * the reply it went into, or when there is only a strict file to judge. NULL with *skip set:
 * nowhere, as another thread's window holds the socket; NULL otherwise: charged as it is. wire:
 * what the send took, when it is counted here. foreground: the send uses the read of the
 * thread's file.
 */
static __always_inline struct carry *carry_window(struct thread_state *ts, __u64 sk, __u64 cookie,
                                                  __u32 tgid, __u64 wire, __u64 now,
                                                  bool foreground, bool *skip)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    void *map = agg_map_now();

    *skip = false;
    if (!sk || !map)
        return NULL;
    struct carry *c = bpf_map_lookup_elem(&carries, &sk);
    if (c && c->tid != tid) {
        *skip = true;
        return NULL;
    }
    if (c && (!foreground || !c->sends || same_file(&c->file, &ts->file))) {
        if (foreground && !c->sends) {
            c->file = ts->file;
            c->size = ts->file_size;
        }
        /* A first flight turns into a reply as it is sent, and the reply ends as it is heard. */
        if (c->kind == CARRY_EPISODE && ts->episode_sock != sk) {
            carry_episode_end(ts, now);
            ts->episode_sock = sk;
        }
        return c;
    }
    if (c)
        carry_close(map, sk, CARRY_NEXT, now);
    __u8 kind;
    if (!sock_heard(sk) && !sock_flown(sk))
        kind = CARRY_FLIGHT;
    else if (!foreground || (ts->file_size && ts->file_size < CARRY_FLOOR))
        kind = CARRY_EPISODE;
    else
        return NULL;
    if (kind == CARRY_EPISODE)
        carry_episode_end(ts, now);

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
    c->kind = kind;
    if (foreground) {
        c->file = ts->file;
        c->size = ts->file_size;
    }
    c->first_ns = now;
    c->last_ns = now;
    c->wire = wire;
    if (kind == CARRY_EPISODE)
        ts->episode_sock = sk;
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

/* Lets the window judge the strict file the thread read last as well. */
static __always_inline void carry_strict(struct carry *c, const struct thread_state *ts)
{
    c->strict_file = ts->strict_file;
    c->strict_size = ts->strict_size;
    c->strict_read = ts->strict_pending;
}

/* Lets go of reads the correlation window has passed. */
static __always_inline void reads_age(struct thread_state *ts, __u64 now)
{
    if (ts->pending && now - ts->last_ns > cfg.corr_window_ns)
        foreground_reset(ts);
    if (ts->strict_pending && now - ts->strict_last_ns > cfg.corr_window_ns)
        strict_reset(ts);
}

/*
 * Attributes a send to the file this thread just read, up to what of it is still unsent. A
 * send in a connection's first flight, or with the read of a small or a strict file, is held in
 * the connection's window.
 */
static __always_inline void correlate_send(void *map, __u64 sk, __u64 cookie, __u32 tgid,
                                           __u64 sent, __u64 now)
{
    struct thread_state *ts = bpf_task_storage_get(&threads, bpf_get_current_task_btf(), 0, 0);
    if (!ts)
        return;
    reads_age(ts, now);
    if (!ts->pending && !ts->strict_pending)
        return;
    bool skip;
    struct carry *c = carry_window(ts, sk, cookie, tgid, sent, now, ts->pending != 0, &skip);
    if (c) {
        if (ts->pending) {
            __u64 take = sent < ts->pending ? sent : ts->pending;
            carry_add(c, take, ts->unreported, ts->fresh, ts->script, now);
            dial_charged(sk, &ts->file, (__s64)take);
            ts->pending -= take;
            ts->unreported = 0;
            ts->fresh = 0;
            ts->last_ns = now;
            candidate_spent(ts, sk);
        }
        if (ts->strict_pending)
            carry_strict(c, ts);
        return;
    }
    if (skip)
        return;
    if (!ts->pending) {
        /* A datagram socket holds no window: a strict file is sent once datagrams took its size. */
        if (!sk && ts->strict_pending) {
            if (ts->strict_datagram_sock != cookie) {
                ts->strict_datagram_sock = cookie;
                ts->strict_datagrams = 0;
            }
            ts->strict_datagrams += sent;
            if (strict_matches(ts->strict_datagrams, ts->strict_pending)) {
                charge_send(map, cookie, tgid, &ts->strict_file, 0, ts->script, ts->strict_pending,
                            &ts->strict_pending, &ts->strict_unreported, &ts->strict_fresh, now);
                ts->strict_datagrams = 0;
            }
        }
        return;
    }
    __u64 take = sent < ts->pending ? sent : ts->pending;
    charge_send(map, cookie, tgid, &ts->file, 0, ts->script, sent, &ts->pending, &ts->unreported,
                &ts->fresh, now);
    dial_charged(sk, &ts->file, (__s64)take);
    candidate_spent(ts, sk);
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
        carry_episode_end(ts, bpf_ktime_get_boot_ns());
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

/* Points the thread's strict slot at the file, starting it over if that is another file. */
static __always_inline void thread_set_strict(struct thread_state *ts, struct file *file,
                                              struct inode *inode, const struct file_key *fk,
                                              __u64 fs_magic)
{
    ts->strict_size = FT_READ(inode, i_size);
    if (ts->strict_file.ino != fk->ino || ts->strict_file.dev != fk->dev ||
        ts->strict_gen != fk->gen) {
        ts->strict_file.ino = fk->ino;
        ts->strict_file.dev = fk->dev;
        ts->strict_file.instance = 0;
        ts->strict_gen = fk->gen;
        strict_reset(ts);
    }
    if (ts->strict_forgotten != forgotten_files) {
        ts->strict_forgotten = forgotten_files;
        ts->strict_file.instance = 0;
    }
    if (!ts->strict_file.instance)
        ts->strict_file.instance = file_instance(file, inode, fk, fs_magic);
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
