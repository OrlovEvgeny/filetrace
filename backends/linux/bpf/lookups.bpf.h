#ifndef FILETRACE_LINUX_BPF_LOOKUPS_H
#define FILETRACE_LINUX_BPF_LOOKUPS_H

/*
 * The names processes look up with getaddrinfo in the C library, and the addresses the call
 * returns: only its arguments and its result are read.
 */

/* struct addrinfo of 64-bit glibc and musl. */
struct lookup_addrinfo {
    __s32 flags;
    __s32 family;
    __s32 socktype;
    __s32 protocol;
    __u32 addrlen;
    __u32 pad;
    __u64 addr;
    __u64 canonname;
    __u64 next;
};

/* A call in progress on a thread: the name asked for, where the result goes, and its stack. */
struct lookup_call {
    __u64 node;
    __u64 res;
    __u64 sp;
};

/*
 * How far the stack pointer at a return lies from where it was at the call's first instruction:
 * x86-64 has popped the return address, arm64 keeps it in a register.
 */
#if defined(__TARGET_ARCH_x86)
#define LOOKUP_RETURN_SP 8
#else
#define LOOKUP_RETURN_SP 0
#endif

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct lookup_call);
} lookup_calls SEC(".maps");

/*
 * The count lives in the record, which the verifier knows nothing of: before 6.7 it checks a
 * callback once, would take a count on the stack for 0 at every step, and drop the comparison
 * with the address before as dead code.
 */
struct lookup_walk {
    struct ft_bpf_ev_lookup *e;
    __u64 next;
};

/* Takes the address of one entry of the result, unless it repeats the one before it. */
static long lookup_step(__u64 index, void *arg)
{
    struct lookup_walk *w = arg;
    struct ft_bpf_ev_lookup *e = w->e;
    struct lookup_addrinfo ai;
    __u64 addr[2] = {};
    __u32 count = e->count;

    if (!w->next || count >= FT_BPF_LOOKUP_ADDRS ||
        bpf_probe_read_user(&ai, sizeof(ai), (void *)w->next))
        return 1;
    w->next = ai.next;
    /* sin_addr follows the family and the port; sin6_addr also the flow information. */
    if (ai.family == AF_INET && ai.addrlen >= 8) {
        if (bpf_probe_read_user(addr, 4, (void *)(ai.addr + 4)))
            return 0;
    } else if (ai.family == AF_INET6 && ai.addrlen >= 24) {
        if (bpf_probe_read_user(addr, 16, (void *)(ai.addr + 8)))
            return 0;
    } else {
        return 0;
    }

    __u32 inet6 = ai.family == AF_INET6;
    if (count) {
        /* Masked where the verifier sees it: the compiler would drop a mask it knows is moot. */
        __u32 before = count - 1;
        barrier_var(before);
        before &= FT_BPF_LOOKUP_ADDRS - 1;
        __u64 *last = (__u64 *)e->addrs[before];
        if (last[0] == addr[0] && last[1] == addr[1] && ((e->inet6 >> before) & 1) == inet6)
            return 0;
    }
    __builtin_memcpy(e->addrs[count & (FT_BPF_LOOKUP_ADDRS - 1)], addr, 16);
    e->inet6 |= inet6 << count;
    e->count = count + 1;
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(ft_getaddrinfo, const char *node, const char *service, const void *hints, void **res)
{
    struct lookup_call *call = bpf_task_storage_get(&lookup_calls, bpf_get_current_task_btf(), 0,
                                                    BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (call) {
        call->node = (__u64)node;
        call->res = (__u64)res;
        call->sp = PT_REGS_SP(ctx);
    }
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ft_getaddrinfo_return, int ret)
{
    struct lookup_call *call =
        bpf_task_storage_get(&lookup_calls, bpf_get_current_task_btf(), 0, 0);
    if (!call || !call->node)
        return 0;
    __u64 node = call->node;
    __u64 res = call->res;
    call->node = 0;
    /* A call of a signal handler, or one left by longjmp, is not the one this returns from. */
    if (PT_REGS_SP(ctx) != call->sp + LOOKUP_RETURN_SP)
        return 0;

    __u64 list = 0;
    if (ret != 0 || !res || bpf_probe_read_user(&list, sizeof(list), (void *)res) || !list)
        return 0;
    struct ft_bpf_ev_lookup *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(FT_BPF_CNT_RING_FULL);
        return 0;
    }
    struct lookup_walk w = {.e = e, .next = list};
    e->count = 0;
    e->inet6 = 0;
    if (bpf_probe_read_user_str(e->name, sizeof(e->name), (void *)node) > 1)
        bpf_loop(FT_BPF_LOOKUP_ENTRIES, lookup_step, &w, 0);
    if (!e->count) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    __u64 ids = bpf_get_current_pid_tgid();
    e->hdr.ts_ns = bpf_ktime_get_boot_ns();
    e->hdr.kind = FT_BPF_EV_LOOKUP;
    e->hdr.pad = 0;
    e->pid = (__u32)(ids >> 32);
    e->tid = (__u32)ids;
    bpf_ringbuf_submit(e, wake_flags());
    return 0;
}

#endif
