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

/* A call in progress on a thread: the name asked for and where the result goes. */
struct lookup_call {
    __u64 node;
    __u64 res;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct lookup_call);
} lookup_calls SEC(".maps");

struct lookup_walk {
    struct ft_bpf_ev_lookup *e;
    __u64 next;
    __u32 count;
    __u32 inet6;
};

/* Takes the address of one entry of the result, unless it repeats the one before it. */
static long lookup_step(__u64 index, void *arg)
{
    struct lookup_walk *w = arg;
    struct lookup_addrinfo ai;
    __u64 addr[2] = {};

    if (!w->next || w->count >= FT_BPF_LOOKUP_ADDRS ||
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
    if (w->count) {
        __u64 *last = (__u64 *)w->e->addrs[(w->count - 1) & (FT_BPF_LOOKUP_ADDRS - 1)];
        if (last[0] == addr[0] && last[1] == addr[1] && ((w->inet6 >> (w->count - 1)) & 1) == inet6)
            return 0;
    }
    __builtin_memcpy(w->e->addrs[w->count & (FT_BPF_LOOKUP_ADDRS - 1)], addr, 16);
    w->inet6 |= inet6 << w->count;
    w->count++;
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

    __u64 list = 0;
    if (ret != 0 || !res || bpf_probe_read_user(&list, sizeof(list), (void *)res) || !list)
        return 0;
    struct ft_bpf_ev_lookup *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(FT_BPF_CNT_RING_FULL);
        return 0;
    }
    struct lookup_walk w = {.e = e, .next = list};
    if (bpf_probe_read_user_str(e->name, sizeof(e->name), (void *)node) > 1)
        bpf_loop(FT_BPF_LOOKUP_ENTRIES, lookup_step, &w, 0);
    if (!w.count) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    __u64 ids = bpf_get_current_pid_tgid();
    e->hdr.ts_ns = bpf_ktime_get_boot_ns();
    e->hdr.kind = FT_BPF_EV_LOOKUP;
    e->hdr.pad = 0;
    e->pid = (__u32)(ids >> 32);
    e->tid = (__u32)ids;
    e->count = w.count;
    e->inet6 = w.inet6;
    bpf_ringbuf_submit(e, wake_flags());
    return 0;
}

#endif
