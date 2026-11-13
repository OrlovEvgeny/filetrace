#ifndef FILETRACE_LINUX_BPF_ABI_H
#define FILETRACE_LINUX_BPF_ABI_H

#define FT_BPF_COMM_LEN 16
#define FT_BPF_EXE_LEN 256
#define FT_BPF_NAME_MAX 256
#define FT_BPF_PATH_BUF 4096
#define FT_BPF_PATH_DEPTH 64
#define FT_BPF_ARGS_MAX 4096
#define FT_BPF_SCRIPT_MAX 1024
#define FT_BPF_BACKGROUND_MAX 16384
#define FT_BPF_BACKGROUND_NAME 64 /* longest file name, with its NUL, that a pattern can name */
#define FT_BPF_BACKGROUND_NAMES 64
#define FT_BPF_BACKGROUND_SUFFIXES 32
#define FT_BPF_BACKGROUND_SUFFIX 16

enum ft_bpf_event_kind {
    FT_BPF_EV_EXEC = 1,
    FT_BPF_EV_FORK = 2,
    FT_BPF_EV_EXIT = 3,
    FT_BPF_EV_SOCK_STATE = 4,
    FT_BPF_EV_FILE = 5,
    FT_BPF_EV_SCRIPT = 6,
    FT_BPF_EV_LOOKUP = 7,
    FT_BPF_EV_TLS_NAME = 8,
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
    __u32 netns;
    __s32 exit_code;
    char comm[FT_BPF_COMM_LEN];
};

/*
 * Followed by cwd_len bytes of the working directory's components, leaf first as in
 * ft_bpf_ev_file, then args_len bytes of arguments, each ending in a NUL.
 */
struct ft_bpf_ev_exec {
    struct ft_bpf_ev_proc proc;
    char exe[FT_BPF_EXE_LEN];
    __u32 cwd_len;
    __u16 cwd_depth;
    __u16 cwd_flags; /* FT_BPF_FILE_TRUNCATED, FT_BPF_FILE_DETACHED */
    __u32 args_len;
    __u32 pad;
    __u64 exe_ino; /* the program file, as the kernel opened it */
    __u64 exe_size;
};

struct ft_bpf_ev_sock {
    struct ft_bpf_ev_hdr hdr;
    __u64 cookie;
    __u32 pid; /* 0 when the transition did not run in the owner's context */
    __u32 tid; /* SYN_SENT: the thread that called connect; otherwise 0 */
    __u16 family;
    __u16 proto;
    __u16 lport; /* host byte order */
    __u16 rport; /* host byte order */
    __u8 old_state;
    __u8 new_state;
    __u8 pad[6];
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
    __u64 size; /* when the event was recorded */
    __u32 dev;  /* kernel dev_t encoding */
    __u32 gen;
    __u32 instance; /* tells apart successive files that were given the same inode number */
    __u32 mnt_id;
    __u32 mntns;
    __u32 path_len;
    __u16 depth;
    __u16 flags;
    __u32 uid; /* owner */
};

/* The layout of the file handle that php_execute_script takes: the attach cookie of its probe. */
enum ft_bpf_php_layout {
    FT_BPF_PHP_CHAR_NAME = 1,   /* PHP 8.0 and earlier: the name is a const char * */
    FT_BPF_PHP_ZEND_STRING = 2, /* PHP 8.1 and later: the name is a zend_string * */
};

/* A script a PHP request runs, reported the first time; followed by len bytes of its path. */
struct ft_bpf_ev_script {
    struct ft_bpf_ev_hdr hdr;
    __u32 id;
    __u32 tgid; /* the process that ran it, against whose directory a relative path is resolved */
    __u32 len;
    __u32 pad;
    __u64 hash; /* the key of the id in known_scripts */
};

#define FT_BPF_LOOKUP_NAME 256   /* a host name's 253 bytes, and room to tell a longer one */
#define FT_BPF_LOOKUP_ADDRS 16   /* distinct addresses a lookup reports */
#define FT_BPF_LOOKUP_ENTRIES 64 /* entries of a lookup's result looked at */

/* A name a process looked up with getaddrinfo, and the addresses the call returned for it. */
struct ft_bpf_ev_lookup {
    struct ft_bpf_ev_hdr hdr;
    __u32 pid;
    __u32 tid;
    __u32 count;
    __u32 inet6;   /* a bit per address that is IPv6 */
    __u32 library; /* the cookie of the probes of the C library file that answered */
    __u32 pad;
    __u8 addrs[FT_BPF_LOOKUP_ADDRS][16];
    char name[FT_BPF_LOOKUP_NAME]; /* as the process passed it, NUL-terminated */
};

#define FT_BPF_TLS_NAME 256 /* a server name's 253 bytes, and room to tell a longer one */

/* A server name a TLS client set, bound to the socket its handshake's first bytes went out on. */
struct ft_bpf_ev_tls_name {
    struct ft_bpf_ev_hdr hdr;
    __u64 cookie; /* the socket, as the socket event reports it */
    __u32 pid;
    __u32 pad;
    char name[FT_BPF_TLS_NAME]; /* as the client set it, NUL-terminated */
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
    __u8 background; /* READ_SEND: charged to the thread's background file */
    __u16 rport;     /* FLOW: host byte order */
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
            __u32 script;       /* the PHP request in progress at the last send, or 0 */
            __u32 pad;
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

/* How the agent found a listed file: the value stored with its key, with the list's bit. */
enum ft_bpf_background_source {
    FT_BPF_BACKGROUND_SCANNED = 1, /* a pattern resolved in the agent's own file system view */
    FT_BPF_BACKGROUND_LEARNED = 2, /* a path the kernel reported, such as one in a container */
};

/* Set in a key's value for a file of [correlation] strict_paths. */
#define FT_BPF_BACKGROUND_STRICT 0x10

/* Which list names a file: the value of a name, and the kind of a suffix. */
enum ft_bpf_listed {
    FT_BPF_LISTED_BACKGROUND = 1, /* never taken as sent from a read and a send */
    FT_BPF_LISTED_STRICT = 2,     /* taken as sent only when a send matches its size */
};

/*
 * A listed pattern that names files wherever they are, by name ("*" "/" name), by ending
 * ("*" ".ext") or by a part of the name ("*" ".so." "*"): the kernel can tell such a file the
 * first time a thread reads it.
 */
struct ft_bpf_background_suffix {
    __u32 len;
    __u16 kind;   /* enum ft_bpf_listed */
    __u16 inside; /* the text may stand anywhere in the name, not only at its end */
    char text[FT_BPF_BACKGROUND_SUFFIX];
};

/* A file the agent names as background: reading it does not change what a thread sends. */
struct ft_bpf_background_key {
    __u64 ino;
    __u32 dev; /* the kernel's encoding: major in the top 12 bits, minor in the low 20 */
    __u32 pad;
};

struct ft_bpf_cfg {
    __u64 corr_window_ns;
    __u64 wakeup_bytes; /* consumer is woken once this much data is queued */
    __u8 file_corr;
    __u8 exec_wakeup; /* a program starting wakes the consumer, which looks at it promptly */
    __u8 pad[6];
};

#endif
