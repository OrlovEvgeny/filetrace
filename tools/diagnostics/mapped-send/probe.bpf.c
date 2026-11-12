/* Entry-time diagnostics only: these counters are not file-transfer evidence. */
#include "backends/linux/bpf/kernel_types.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

enum iter_type {
    ITER_UBUF,
    ITER_IOVEC
};
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
struct iovec {
    void *iov_base;
    unsigned long iov_len;
};
struct iov_iter___mapped {
    __u8 iter_type;
    unsigned long iov_offset;
    unsigned long count;
    void *ubuf;
    unsigned long nr_segs;
};
struct iov_iter___old {
    const struct iovec *iov;
};
struct iov_iter___new {
    const struct iovec *__iov;
};
struct msghdr___mapped {
    struct iov_iter___mapped msg_iter;
};
struct vm_area_struct {
    unsigned long vm_start;
    unsigned long vm_end;
    unsigned long vm_flags;
    struct file *vm_file;
};
#pragma clang attribute pop

enum counter {
    SENDS,
    UNSUPPORTED,
    MULTI_VECTOR,
    INVALID_RANGE,
    VMA_MISS,
    ANONYMOUS,
    UNSAFE_MAPPING,
    NON_REGULAR,
    MAPPED_READONLY,
    OBSERVED_BYTES,
    COUNTERS
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, COUNTERS);
    __type(key, __u32);
    __type(value, __u64);
} counts SEC(".maps");
static __always_inline void count(__u32 key, __u64 n)
{
    __u64 *v = bpf_map_lookup_elem(&counts, &key);
    if (v)
        __sync_fetch_and_add(v, n);
}
struct range {
    __u64 addr;
    __u64 len;
    __u32 result;
};
static long inspect_vma(struct task_struct *task, struct vm_area_struct *vma, struct range *r)
{
    (void)task;
    __u64 start = BPF_CORE_READ(vma, vm_start), end = BPF_CORE_READ(vma, vm_end);
    if (r->addr < start || r->addr >= end || r->len > end - r->addr) {
        r->result = INVALID_RANGE;
        return 0;
    }
    struct file *file = BPF_CORE_READ(vma, vm_file);
    if (!file) {
        r->result = ANONYMOUS;
        return 0;
    }
    /* VM_MAYSHARE survives MAP_SHARED on an O_RDONLY fd; VM_SHARED does not. */
    unsigned long flags = BPF_CORE_READ(vma, vm_flags);
    if (!(flags & 0x80) || (flags & (0x2 | 0x20))) {
        r->result = UNSAFE_MAPPING;
        return 0;
    }
    if ((BPF_CORE_READ(file, f_inode, i_mode) & 0170000) != 0100000) {
        r->result = NON_REGULAR;
        return 0;
    }
    r->result = MAPPED_READONLY;
    return 0;
}
static __always_inline int observe(struct msghdr *msg)
{
    __u32 zero = 0, *pid = bpf_map_lookup_elem(&target, &zero);
    if (!pid || *pid != (__u32)(bpf_get_current_pid_tgid() >> 32))
        return 0;
    count(SENDS, 1);
    struct msghdr___mapped *m = (void *)msg;
    struct iov_iter___mapped *it = &m->msg_iter;
    __u8 type = BPF_CORE_READ(it, iter_type);
    __u64 off = BPF_CORE_READ(it, iov_offset), n = BPF_CORE_READ(it, count), addr;
    if (type == bpf_core_enum_value(enum iter_type, ITER_UBUF)) {
        addr = (__u64)BPF_CORE_READ(it, ubuf);
    } else if (type == bpf_core_enum_value(enum iter_type, ITER_IOVEC)) {
        if (BPF_CORE_READ(it, nr_segs) != 1) {
            count(MULTI_VECTOR, 1);
            return 0;
        }
        const struct iovec *iov;
        if (bpf_core_field_exists(((struct iov_iter___new *)it)->__iov))
            iov = BPF_CORE_READ((struct iov_iter___new *)it, __iov);
        else
            iov = BPF_CORE_READ((struct iov_iter___old *)it, iov);
        struct iovec vec = {};
        if (bpf_probe_read_kernel(&vec, sizeof(vec), iov) || off > vec.iov_len ||
            n > vec.iov_len - off) {
            count(INVALID_RANGE, 1);
            return 0;
        }
        addr = (__u64)vec.iov_base;
    } else {
        count(UNSUPPORTED, 1);
        return 0;
    }
    if (!n || addr + off < addr) {
        count(INVALID_RANGE, 1);
        return 0;
    }
    struct range r = {.addr = addr + off, .len = n, .result = VMA_MISS};
    long ret = bpf_find_vma(bpf_get_current_task_btf(), r.addr, inspect_vma, &r, 0);
    if (ret)
        count(VMA_MISS, 1);
    else {
        count(r.result, 1);
        if (r.result == MAPPED_READONLY)
            count(OBSERVED_BYTES, n);
    }
    return 0;
}
SEC("fentry/inet_sendmsg")
int BPF_PROG(mapped_fentry, struct socket *sock, struct msghdr *msg)
{
    (void)sock;
    return observe(msg);
}
SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(mapped_kprobe, struct sock *sk, struct msghdr *msg)
{
    (void)sk;
    return observe(msg);
}
