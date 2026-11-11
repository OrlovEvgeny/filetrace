#include "backends/linux/linux.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

constexpr int ENOTSUPP_KERNEL = 524; /* the kernel's ENOTSUPP, which libc cannot name */

static const char *group_title(const struct ft_linux_probes *p, enum ft_probe_group group)
{
    bool kprobes = p->set->kind == FT_PROBES_KPROBE;

    switch (group) {
    case FT_PG_PROCESS:
        return "Process lifecycle tracepoints";
    case FT_PG_TCP_STATE:
        return "TCP state tracepoint";
    case FT_PG_NET:
        return kprobes ? "Network send and receive probes" : "IPv4 send and receive probes";
    case FT_PG_NET_IPV6:
        return kprobes ? "IPv6 datagram probe" : "IPv6 send and receive probes";
    case FT_PG_FILE_READ:
        return "File read probe";
    case FT_PG_SENDFILE:
        return "sendfile probe";
    default:
        return "File deletion probe";
    }
}

static const char *error_text(int error)
{
    return error == ENOTSUPP_KERNEL ? "not supported by this kernel" : strerror(error);
}

static const char *probe_problem(const struct ft_probe_status *st, char *buf, size_t size)
{
    switch (st->state) {
    case FT_PROBE_MISMATCH:
        return "the kernel function has an unexpected signature";
    case FT_PROBE_NO_ACCOUNTING:
        return "the kernel is built without CONFIG_TASK_XACCT, which sizes reads";
    case FT_PROBE_LOAD_FAILED:
        snprintf(buf, size, "rejected by the kernel: %s", error_text(st->error));
        return buf;
    case FT_PROBE_ATTACH_FAILED:
        snprintf(buf, size, "cannot attach: %s", error_text(st->error));
        return buf;
    default:
        return "";
    }
}

/* First problem among the probes of a group, or nullptr when all are attached. */
static const char *group_problem(const struct ft_linux_probes *p, enum ft_probe_group group,
                                 char *buf, size_t size)
{
    for (size_t i = 0; i < p->set->count; i++) {
        const struct ft_probe_def *def = &p->set->defs[i];
        if (def->group != group || p->status[i].state == FT_PROBE_ATTACHED)
            continue;
        if (p->status[i].state == FT_PROBE_NOT_NEEDED)
            return "not used in this mode";

        char why[160];
        snprintf(buf, size, "%s %s: %s", def->kind, def->target,
                 probe_problem(&p->status[i], why, sizeof(why)));
        return buf;
    }
    return nullptr;
}

void ft_linux_capabilities(const struct ft_linux_probes *p, enum ft_mode mode,
                           struct ft_capabilities *out)
{
    char why[240];
    const char *problem;
    const char *minimal = "disabled in minimal mode";
    bool kprobes = p->set->kind == FT_PROBES_KPROBE;
    bool net = ft_linux_network_attached(p);
    bool v6 = ft_linux_group_attached(p, FT_PG_NET_IPV6);

    problem = group_problem(p, FT_PG_PROCESS, why, sizeof(why));
    if (problem)
        ft_capability_set(out, FT_FEAT_PROCESS, FT_CAP_PARTIAL,
                          "processes are described from /proc when first seen; %s", problem);
    else
        ft_capability_set(out, FT_FEAT_PROCESS, FT_CAP_FULL, "%s", "");

    if (!net) {
        problem = group_problem(p, FT_PG_NET, why, sizeof(why));
        if (!problem)
            problem = group_problem(p, FT_PG_TCP_STATE, why, sizeof(why));
        ft_capability_set(out, FT_FEAT_TCP, FT_CAP_UNAVAILABLE, "%s", problem);
        ft_capability_set(out, FT_FEAT_UDP, FT_CAP_UNAVAILABLE, "%s", problem);
        ft_capability_set(out, FT_FEAT_IPV6, FT_CAP_UNAVAILABLE, "%s", problem);
    } else if (kprobes) {
        ft_capability_set(out, FT_FEAT_TCP, FT_CAP_FULL,
                          "bytes are read from each socket's sequence numbers: the last send "
                          "on an idle connection appears when the socket is next used or "
                          "closed, and kernel TLS counts encrypted bytes");
        ft_capability_set(out, FT_FEAT_UDP, v6 ? FT_CAP_FULL : FT_CAP_PARTIAL, "%s",
                          v6 ? "" : "datagrams sent over IPv6 are not counted");
        ft_capability_set(out, FT_FEAT_IPV6, v6 ? FT_CAP_FULL : FT_CAP_PARTIAL, "%s",
                          v6 ? "" : group_problem(p, FT_PG_NET_IPV6, why, sizeof(why)));
    } else {
        if (!ft_linux_group_attached(p, FT_PG_TCP_STATE))
            ft_capability_set(out, FT_FEAT_TCP, FT_CAP_PARTIAL,
                              "byte counts only; connection states are not observed: %s",
                              group_problem(p, FT_PG_TCP_STATE, why, sizeof(why)));
        else
            ft_capability_set(out, FT_FEAT_TCP, FT_CAP_FULL, "%s", "");
        ft_capability_set(out, FT_FEAT_UDP, FT_CAP_FULL,
                          "received datagrams show their sender only when the application "
                          "asks for it");
        if (v6)
            ft_capability_set(out, FT_FEAT_IPV6, FT_CAP_FULL, "%s", "");
        else
            ft_capability_set(out, FT_FEAT_IPV6, FT_CAP_UNAVAILABLE, "%s",
                              group_problem(p, FT_PG_NET_IPV6, why, sizeof(why)));
    }

    ft_capability_set(out, FT_FEAT_FILE_OPEN, FT_CAP_UNAVAILABLE,
                      "open and close are not traced; a file is identified when it is "
                      "read or sent");
    ft_capability_set(out, FT_FEAT_FILE_WRITE, FT_CAP_UNAVAILABLE, "writes are not traced");

    if (mode < FT_MODE_STANDARD) {
        ft_capability_set(out, FT_FEAT_FILE_READ, FT_CAP_DISABLED, "%s", minimal);
        ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_DISABLED, "%s", minimal);
        ft_capability_set(out, FT_FEAT_READ_SEND, FT_CAP_DISABLED, "%s", minimal);
    } else {
        problem = group_problem(p, FT_PG_FILE_READ, why, sizeof(why));
        if (problem) {
            ft_capability_set(out, FT_FEAT_FILE_READ, FT_CAP_UNAVAILABLE, "%s", problem);
            ft_capability_set(out, FT_FEAT_READ_SEND, FT_CAP_UNAVAILABLE, "%s", problem);
        } else {
            ft_capability_set(out, FT_FEAT_FILE_READ, FT_CAP_PARTIAL,
                              "read(2) and pread(2) on regular files; readv, io_uring and "
                              "memory-mapped reads are not observed");
            ft_capability_set(out, FT_FEAT_READ_SEND, net ? FT_CAP_PARTIAL : FT_CAP_UNAVAILABLE,
                              "%s",
                              net ? "a thread that reads a file and then sends is reported "
                                    "as INFERRED; reads and sends on different threads are "
                                    "not associated"
                                  : "network probes are unavailable");
        }

        problem = group_problem(p, FT_PG_SENDFILE, why, sizeof(why));
        if (problem)
            ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_UNAVAILABLE, "%s", problem);
        else if (!net)
            ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_UNAVAILABLE,
                              "network probes are unavailable");
        else
            ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_FULL, "%s",
                              kprobes ? "to TCP sockets; the bytes moved are read from the "
                                        "socket's sequence numbers"
                                      : "");
    }

    ft_capability_set(out, FT_FEAT_SPLICE, FT_CAP_UNAVAILABLE,
                      "transfers through pipes with splice(2) are not followed");
    ft_capability_set(out, FT_FEAT_IO_URING, net ? FT_CAP_PARTIAL : FT_CAP_UNAVAILABLE, "%s",
                      net ? "bytes sent through io_uring are counted per socket; file reads "
                            "through io_uring are not observed"
                          : "network probes are unavailable");
    ft_capability_set(out, FT_FEAT_MMAP, FT_CAP_UNAVAILABLE,
                      "data read through memory mappings is not observed");
    ft_capability_set(out, FT_FEAT_PACKET_EGRESS, FT_CAP_UNAVAILABLE,
                      "bytes are counted when the socket accepts them, not per packet");
    ft_capability_set(out, FT_FEAT_NAMESPACES, FT_CAP_PARTIAL,
                      "cgroup and namespace identifiers are recorded per process; "
                      "container names are not resolved");
}

static bool lockdown_blocks_reads(void)
{
    char buf[128] = {0};
    FILE *f = fopen("/sys/kernel/security/lockdown", "re");
    if (!f)
        return false;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, "[confidentiality]") != nullptr;
}

/* Adds one check per probe group; returns how many groups are not fully attached. */
static size_t report_groups(struct ft_diagnosis *out, const struct ft_linux_probes *p)
{
    size_t failed = 0;

    for (size_t g = 0; g < FT_PG_COUNT; g++) {
        enum ft_probe_group group = (enum ft_probe_group)g;
        char why[240];
        const char *problem = group_problem(p, group, why, sizeof(why));
        bool required =
            group == FT_PG_NET || (group == FT_PG_TCP_STATE && p->set->kind == FT_PROBES_KPROBE);

        if (problem) {
            ft_diagnosis_add(out, required ? FT_CHECK_FAIL : FT_CHECK_WARN, !required,
                             group_title(p, group), "%s", problem);
            failed++;
        } else {
            ft_diagnosis_add(out, FT_CHECK_OK, !required, group_title(p, group), "%s", "");
        }
    }
    return failed;
}

void ft_linux_diagnose(const struct ft_backend_config *requested, struct ft_diagnosis *out)
{
    unsigned major = 0;
    unsigned minor = 0;
    bool blocked = false;

    snprintf(out->backend, sizeof(out->backend), "Linux eBPF");

    if (!ft_linux_kernel_version(&major, &minor))
        ft_diagnosis_add(out, FT_CHECK_WARN, true, "Kernel version",
                         "cannot determine the kernel version");
    else if (major < 6 || (major == 6 && minor < 1))
        ft_diagnosis_add(out, FT_CHECK_WARN, true, "Kernel version",
                         "%u.%u is older than 6.1, the oldest kernel Filetrace is built for", major,
                         minor);
    else
        ft_diagnosis_add(out, FT_CHECK_OK, false, "Kernel version", "%u.%u", major, minor);

    if (access("/sys/kernel/btf/vmlinux", R_OK) == 0) {
        ft_diagnosis_add(out, FT_CHECK_OK, false, "BTF available", "%s", "");
    } else {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "BTF available",
                         "/sys/kernel/btf/vmlinux is missing; the kernel must be built with "
                         "CONFIG_DEBUG_INFO_BTF");
        blocked = true;
    }

    ft_diagnosis_add(out, FT_CHECK_OK, false, "libbpf available", "version %s",
                     libbpf_version_string());

    if (lockdown_blocks_reads()) {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "Kernel lockdown",
                         "confidentiality mode forbids reading kernel memory from BPF");
        blocked = true;
    }

    if (!ft_linux_privileged()) {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "Required privileges",
                         "root, or CAP_BPF with CAP_PERFMON, is needed to load BPF programs");
        ft_capability_set_all(&out->caps, FT_CAP_UNAVAILABLE,
                              "not verified: insufficient privileges");
        out->exit_code = FT_EXIT_PERMISSION;
        snprintf(out->result, sizeof(out->result),
                 "Cannot verify monitoring without additional privileges");
        snprintf(out->advice, sizeof(out->advice),
                 "Run:\n"
                 "  sudo filetrace doctor\n\n"
                 "Some features may remain unavailable even with root privileges\n"
                 "if the kernel lacks the required support.");
        return;
    }
    ft_diagnosis_add(out, FT_CHECK_OK, false, "Required privileges", "%s", "");

    if (libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, nullptr) == 1) {
        ft_diagnosis_add(out, FT_CHECK_OK, false, "Ring Buffer support", "%s", "");
    } else {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "Ring Buffer support",
                         "the kernel cannot create BPF ring buffers");
        blocked = true;
    }
    if (libbpf_probe_bpf_map_type(BPF_MAP_TYPE_TASK_STORAGE, nullptr) == 1) {
        ft_diagnosis_add(out, FT_CHECK_OK, false, "Task storage support", "%s", "");
    } else {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "Task storage support",
                         "the kernel cannot create BPF task storage maps");
        blocked = true;
    }

    struct ft_backend_config cfg;
    struct ft_linux_probes probes;
    enum ft_probes wanted = requested ? requested->probes : FT_PROBES_AUTO;

    ft_backend_config_defaults(&cfg);
    cfg.queue_bytes = 64 * 1024;
    cfg.agg_entries = 64;
    cfg.known_files = 64;

    /* Trampolines are tried on their own first, to be able to say why they are not used. */
    cfg.probes = wanted == FT_PROBES_KPROBE ? FT_PROBES_KPROBE : FT_PROBES_TRAMPOLINE;
    int rc = ft_linux_probes_load(&cfg, &probes);
    if (wanted == FT_PROBES_AUTO && (rc || !ft_linux_network_attached(&probes))) {
        char why[240] = "";
        const char *problem =
            rc ? strerror(-rc) : group_problem(&probes, FT_PG_NET, why, sizeof(why));

        ft_diagnosis_add(out, FT_CHECK_WARN, false, "BPF trampolines",
                         "unavailable (%s); kernel functions are traced with kprobes", problem);
        if (!rc)
            ft_linux_probes_unload(&probes);
        cfg.probes = FT_PROBES_KPROBE;
        rc = ft_linux_probes_load(&cfg, &probes);
    } else if (wanted != FT_PROBES_KPROBE) {
        ft_diagnosis_add(out, FT_CHECK_OK, false, "BPF trampolines", "%s", "");
    }

    if (rc) {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "BPF programs load", "%s (%s)", strerror(-rc),
                         ft_linux_last_libbpf_message());
        ft_capability_set_all(&out->caps, FT_CAP_UNAVAILABLE,
                              "the BPF programs could not be loaded");
        out->exit_code = FT_EXIT_UNSUPPORTED;
        snprintf(out->result, sizeof(out->result), "Monitoring unavailable");
        return;
    }
    ft_diagnosis_add(out, FT_CHECK_OK, false, "BPF programs load", "%s", "");

    size_t failed_groups = report_groups(out, &probes);
    bool have_network = ft_linux_network_attached(&probes);
    bool kprobes = probes.set->kind == FT_PROBES_KPROBE;

    ft_linux_capabilities(&probes, cfg.mode, &out->caps);
    snprintf(out->backend, sizeof(out->backend), "Linux eBPF (%s)",
             kprobes ? "kprobes" : "trampolines");
    ft_linux_probes_unload(&probes);

    if (blocked || !have_network) {
        out->exit_code = FT_EXIT_UNSUPPORTED;
        snprintf(out->result, sizeof(out->result), "Monitoring unavailable");
        snprintf(out->advice, sizeof(out->advice),
                 "Filetrace needs a Linux 6.1 or newer kernel with BTF, and either BPF\n"
                 "trampolines or kprobes on the functions listed above.");
    } else if (failed_groups) {
        out->exit_code = FT_EXIT_PARTIAL;
        snprintf(out->result, sizeof(out->result), "Partial monitoring available");
        snprintf(out->advice, sizeof(out->advice),
                 "Run 'filetrace capabilities' to see which features are reduced.");
    } else {
        out->exit_code = FT_EXIT_OK;
        snprintf(out->result, sizeof(out->result), "Monitoring available");
        snprintf(out->advice, sizeof(out->advice), "%s",
                 kprobes ? "Kernel functions are traced with kprobes instead of BPF trampolines:\n"
                           "each traced call costs more, and TCP bytes are read from the\n"
                           "sockets' own counters. Run 'filetrace capabilities' for the\n"
                           "differences."
                         : "Every probe this build uses is attached. Run 'filetrace capabilities'\n"
                           "for the list of features and their limits.");
    }
}
