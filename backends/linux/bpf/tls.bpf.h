#ifndef FILETRACE_LINUX_BPF_TLS_H
#define FILETRACE_LINUX_BPF_TLS_H

/*
 * The server name a TLS client asks for, read from the library call that sets it and bound to
 * the socket the handshake's first bytes go out on; only the arguments of the calls are read.
 *
 * A name set on a TLS object lives in tls_names until the object is freed; the probes that read
 * it are attached only when names are wanted, so the map exists only then. The send probes run
 * on every connection, so they read the name a handshake carries from the thread's own storage,
 * which costs nothing until a thread is in a handshake.
 */

#define TLS_SET_HOSTNAME 55 /* SSL_CTRL_SET_TLSEXT_HOSTNAME, what SSL_set_tlsext_host_name sends   \
                             */
#define TLS_NAME_DNS 0      /* GNUTLS_NAME_DNS */

/*
 * How far the stack pointer at a return lies from where it was at the call's first instruction:
 * x86-64 has popped the return address, arm64 keeps it in a register.
 */
#if defined(__TARGET_ARCH_x86)
#define TLS_RETURN_SP 8
#else
#define TLS_RETURN_SP 0
#endif

/* A TLS object in the process that set the name: an SSL or a gnutls_session_t. */
struct tls_key {
    __u32 pid;
    __u32 pad;
    __u64 object;
};

struct tls_name {
    char name[FT_BPF_TLS_NAME];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct tls_key);
    __type(value, struct tls_name);
} tls_names SEC(".maps");

/* The handshake a thread is in: the object, the stack to pair the return, and the name to bind. */
struct tls_handshake {
    __u64 object;
    __u64 sp;
    char name[FT_BPF_TLS_NAME];
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct tls_handshake);
} tls_handshakes SEC(".maps");

static __always_inline struct tls_key tls_key_of(__u64 object)
{
    return (struct tls_key){.pid = (__u32)(bpf_get_current_pid_tgid() >> 32), .object = object};
}

/*
 * Stores the name a client set on a TLS object. len < 0 reads a C string, as OpenSSL passes;
 * len >= 0 reads that many bytes, as GnuTLS passes with its length. Never more than the buffer.
 */
static __always_inline void tls_name_set(__u64 object, const void *name, __s64 len)
{
    if (!object || !name)
        return;
    struct tls_name v = {};
    if (len < 0) {
        if (bpf_probe_read_user_str(v.name, sizeof(v.name), name) <= 1)
            return;
    } else {
        if (len == 0 || len >= FT_BPF_TLS_NAME)
            return;
        if (bpf_probe_read_user(v.name, (__u32)len & (FT_BPF_TLS_NAME - 1), name))
            return;
        v.name[len & (FT_BPF_TLS_NAME - 1)] = '\0';
    }
    struct tls_key key = tls_key_of(object);
    bpf_map_update_elem(&tls_names, &key, &v, BPF_ANY);
}

/*
 * Opens the window for a handshake a thread enters, taking the object's name into the thread's
 * storage so the send probe need not reach the names map.
 */
static __always_inline void tls_handshake_enters(__u64 object, __u64 sp)
{
    struct tls_handshake *h = bpf_task_storage_get(&tls_handshakes, bpf_get_current_task_btf(), 0,
                                                   BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!h)
        return;
    h->object = object;
    h->sp = sp;
    h->name[0] = '\0';
    struct tls_key key = tls_key_of(object);
    struct tls_name *v = bpf_map_lookup_elem(&tls_names, &key);
    if (v)
        __builtin_memcpy(h->name, v->name, sizeof(h->name));
}

/*
 * Closes the window at a handshake's return, unless its first send already did. The inner of
 * nested calls on one object clears it and the outer then finds nothing; the stack tells the
 * call that returns from one left by a signal handler or longjmp.
 */
static __always_inline void tls_handshake_returns(__u64 sp)
{
    struct tls_handshake *h =
        bpf_task_storage_get(&tls_handshakes, bpf_get_current_task_btf(), 0, 0);
    if (h && h->object && sp == h->sp + TLS_RETURN_SP)
        h->object = 0;
}

/*
 * Binds the name of the handshake this thread is in to the socket its first send goes out on,
 * and closes the window, so a handshake that completes in one call binds once. A handshake
 * driven in several calls may bind its name again, which names the same socket the same.
 */
static __always_inline void tls_bind_send(__u64 cookie)
{
    struct tls_handshake *h =
        bpf_task_storage_get(&tls_handshakes, bpf_get_current_task_btf(), 0, 0);
    if (!h || !h->object)
        return;
    h->object = 0;
    if (!h->name[0])
        return;
    struct ft_bpf_ev_tls_name *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count(FT_BPF_CNT_RING_FULL);
        return;
    }
    e->hdr.ts_ns = bpf_ktime_get_boot_ns();
    e->hdr.kind = FT_BPF_EV_TLS_NAME;
    e->hdr.pad = 0;
    e->cookie = cookie;
    e->pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    e->pad = 0;
    __builtin_memcpy(e->name, h->name, sizeof(e->name));
    bpf_ringbuf_submit(e, wake_flags());
}

SEC("uprobe")
int BPF_UPROBE(ft_ssl_ctrl, void *ssl, int cmd, long larg, void *parg)
{
    if (cmd == TLS_SET_HOSTNAME)
        tls_name_set((__u64)ssl, parg, -1);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(ft_ssl_connect, void *ssl)
{
    tls_handshake_enters((__u64)ssl, PT_REGS_SP(ctx));
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ft_ssl_connect_return)
{
    tls_handshake_returns(PT_REGS_SP(ctx));
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(ft_ssl_do_handshake, void *ssl)
{
    tls_handshake_enters((__u64)ssl, PT_REGS_SP(ctx));
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ft_ssl_do_handshake_return)
{
    tls_handshake_returns(PT_REGS_SP(ctx));
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(ft_ssl_free, void *ssl)
{
    struct tls_key key = tls_key_of((__u64)ssl);
    bpf_map_delete_elem(&tls_names, &key);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(ft_gnutls_server_name_set, void *session, int type, const void *name, __u64 len)
{
    if (type == TLS_NAME_DNS)
        tls_name_set((__u64)session, name, (__s64)len);
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(ft_gnutls_handshake, void *session)
{
    tls_handshake_enters((__u64)session, PT_REGS_SP(ctx));
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(ft_gnutls_handshake_return)
{
    tls_handshake_returns(PT_REGS_SP(ctx));
    return 0;
}

SEC("uprobe")
int BPF_UPROBE(ft_gnutls_deinit, void *session)
{
    struct tls_key key = tls_key_of((__u64)session);
    bpf_map_delete_elem(&tls_names, &key);
    return 0;
}

#endif
