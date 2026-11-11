#ifndef FILETRACE_LINUX_BPF_ABI_H
#define FILETRACE_LINUX_BPF_ABI_H

#define FT_BPF_COMM_LEN 16
#define FT_BPF_EXE_LEN 256
#define FT_BPF_NAME_MAX 256
#define FT_BPF_PATH_BUF 4096
#define FT_BPF_PATH_DEPTH 64

enum ft_bpf_event_kind {
    FT_BPF_EV_EXEC = 1,
    FT_BPF_EV_FORK = 2,
    FT_BPF_EV_EXIT = 3,
    FT_BPF_EV_SOCK_STATE = 4,
    FT_BPF_EV_FILE = 5,
};

struct ft_bpf_ev_hdr {
    __u64 ts_ns; /* CLOCK_BOOTTIME */
    __u32 kind;
    __u32 pad;
};

struct ft_bpf_ev_proc {
    struct ft_bpf_ev_hdr hdr;
    __u64 start_ns; /* CLOCK_BOOTTIME */
    __u64 cgroup_id;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 pidns;
    __u32 mntns;
    __s32 exit_code;
    __u32 pad;
    char comm[FT_BPF_COMM_LEN];
};

struct ft_bpf_ev_exec {
    struct ft_bpf_ev_proc proc;
    char exe[FT_BPF_EXE_LEN];
};

struct ft_bpf_ev_sock {
    struct ft_bpf_ev_hdr hdr;
    __u64 cookie;
    __u32 pid; /* 0 when the transition did not run in the owner's context */
    __u16 family;
    __u16 proto;
    __u16 lport; /* host byte order */
    __u16 rport; /* host byte order */
    __u8 old_state;
    __u8 new_state;
    __u8 pad[2];
    __u8 laddr[16];
    __u8 raddr[16];
};

#define FT_BPF_FILE_TRUNCATED 0x1 /* leading path components are missing */
#define FT_BPF_FILE_DELETED 0x2   /* no remaining directory links */
#define FT_BPF_FILE_DETACHED 0x4  /* not reachable from a mount point */

/* Followed by path_len bytes of NUL-terminated components, leaf first. */
struct ft_bpf_ev_file {
    struct ft_bpf_ev_hdr hdr;
    __u64 ino;
    __u64 fs_magic;
    __u32 dev; /* kernel dev_t encoding */
    __u32 gen;
    __u32 instance; /* tells apart successive files that were given the same inode number */
    __u32 mnt_id;
    __u32 mntns;
    __u32 path_len;
    __u16 depth;
    __u16 flags;
    __u32 pad;
};

enum ft_bpf_agg_kind {
    FT_BPF_AGG_FLOW = 1,
    FT_BPF_AGG_SENDFILE = 2,
    FT_BPF_AGG_READ_SEND = 3,
};

struct ft_bpf_agg_key {
    __u64 cookie;
    __u32 tgid;
    __u8 kind;
    __u8 pad;
    __u16 rport; /* FLOW: host byte order */
    union {
        __u8 raddr[16]; /* FLOW */
        struct {
            __u64 ino;
            __u32 dev;
            __u32 instance;
        } file; /* SENDFILE, READ_SEND */
    };
};

enum ft_bpf_direction {
    FT_BPF_TX = 0,
    FT_BPF_RX = 1,
};

struct ft_bpf_agg_val {
    __u64 first_ns;
    __u64 last_ns;
    union {
        struct {
            __u64 bytes[2]; /* indexed by enum ft_bpf_direction */
            __u32 ops[2];
        } flow;
        struct {
            __u64 sent_bytes;
            __u64 read_bytes; /* READ_SEND only */
            __u32 sends;
            __u32 alternations; /* READ_SEND only: read-then-send sequences */
        } transfer;
    };
    __u8 laddr[16];
    __u16 lport; /* host byte order */
    __u16 family;
    __u16 proto;
    __u16 pad;
};

enum ft_bpf_counter {
    FT_BPF_CNT_RING_FULL = 0,
    FT_BPF_CNT_AGG_FULL = 1,
    FT_BPF_CNT_SOCK_UNIDENTIFIED = 2,
    FT_BPF_CNT_PATH_BUSY = 3,
    FT_BPF_CNT_AGG_INSERTS = 4,
    FT_BPF_CNT_MAX = 5,
};

struct ft_bpf_cfg {
    __u64 corr_window_ns;
    __u64 wakeup_bytes; /* consumer is woken once this much data is queued */
    __u8 file_corr;
    __u8 pad[7];
};

#endif
