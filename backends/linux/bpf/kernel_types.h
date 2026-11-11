/* Partial kernel types: CO-RE resolves the listed members against the running kernel's BTF. */
#ifndef FILETRACE_LINUX_BPF_KERNEL_TYPES_H
#define FILETRACE_LINUX_BPF_KERNEL_TYPES_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;

typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s32 s32;
typedef __s64 s64;

typedef int pid_t;
typedef u32 dev_t;
typedef u16 umode_t;
typedef long long loff_t;
typedef unsigned long size_t;
typedef long ssize_t;

enum {
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
};

enum {
    BPF_F_NO_PREALLOC = 1U << 0,
};

enum {
    BPF_LOCAL_STORAGE_GET_F_CREATE = 1ULL << 0,
};

enum {
    BPF_RB_NO_WAKEUP = 1ULL << 0,
    BPF_RB_FORCE_WAKEUP = 1ULL << 1,
};

enum {
    BPF_RB_AVAIL_DATA = 0,
};

enum bpf_map_type {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
    BPF_MAP_TYPE_RINGBUF = 27,
    BPF_MAP_TYPE_TASK_STORAGE = 29,
};

#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)

typedef struct {
    int counter;
} atomic_t;

typedef struct {
    s64 counter;
} atomic64_t;

struct ns_common {
    unsigned int inum;
};

struct pid_namespace {
    struct ns_common ns;
};

struct mnt_namespace {
    struct ns_common ns;
};

struct nsproxy {
    struct mnt_namespace *mnt_ns;
    struct pid_namespace *pid_ns_for_children;
};

struct signal_struct {
    atomic_t live;
};

struct task_struct {
    pid_t pid;
    pid_t tgid;
    struct task_struct *real_parent;
    struct signal_struct *signal;
    struct nsproxy *nsproxy;
    u64 start_boottime;
    int exit_code;
    char comm[16];
};

struct linux_binprm {
    const char *filename;
};

struct qstr {
    const unsigned char *name;
};

struct super_block {
    dev_t s_dev;
    unsigned long s_magic;
};

struct inode {
    umode_t i_mode;
    unsigned long i_ino;
    unsigned int i_nlink;
    u32 i_generation;
    struct super_block *i_sb;
};

struct dentry {
    struct dentry *d_parent;
    struct qstr d_name;
};

struct vfsmount {
    struct dentry *mnt_root;
};

struct mount {
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
    int mnt_id;
    struct mnt_namespace *mnt_ns;
};

struct path {
    struct vfsmount *mnt;
    struct dentry *dentry;
};

struct file {
    struct path f_path;
    struct inode *f_inode;
    void *private_data;
};

struct in6_addr {
    union {
        __u8 u6_addr8[16];
        __be32 u6_addr32[4];
    } in6_u;
};

struct sock_common {
    __be32 skc_daddr;
    __be32 skc_rcv_saddr;
    __be16 skc_dport;
    __u16 skc_num;
    unsigned short skc_family;
    struct in6_addr skc_v6_daddr;
    struct in6_addr skc_v6_rcv_saddr;
    atomic64_t skc_cookie;
};

struct sock {
    struct sock_common __sk_common;
    u16 sk_protocol;
};

struct socket {
    struct sock *sk;
};

struct msghdr {
    void *msg_name;
    int msg_namelen;
    unsigned int msg_flags;
};

#pragma clang attribute pop

#endif
