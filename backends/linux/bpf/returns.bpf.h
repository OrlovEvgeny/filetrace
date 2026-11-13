#ifndef FILETRACE_LINUX_BPF_RETURNS_H
#define FILETRACE_LINUX_BPF_RETURNS_H

/* Returns from the function the agent tests return probes on, in a process of its own. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} return_checks SEC(".maps");

SEC("uretprobe")
int BPF_URETPROBE(ft_return_check)
{
    __u32 zero = 0;
    __u64 *returns = bpf_map_lookup_elem(&return_checks, &zero);
    if (returns)
        __sync_fetch_and_add(returns, 1);
    return 0;
}

#endif
