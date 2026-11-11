#include "backends/linux/linux.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *const group_titles[FT_PG_COUNT] = {
    [FT_PG_PROCESS] = "Process lifecycle tracepoints",
    [FT_PG_TCP_STATE] = "TCP state tracepoint",
    [FT_PG_NET_IPV4] = "IPv4 send and receive probes",
    [FT_PG_NET_IPV6] = "IPv6 send and receive probes",
    [FT_PG_FILE_READ] = "File read probe",
    [FT_PG_SENDFILE] = "sendfile probe",
};

static const char *probe_problem(const struct ft_probe_status *st, char *buf, size_t size)
{
    switch (st->state) {
    case FT_PROBE_MISMATCH:
        return "the kernel function has an unexpected signature";
    case FT_PROBE_LOAD_FAILED:
        snprintf(buf, size, "rejected by the kernel: %s", strerror(st->error));
        return buf;
    case FT_PROBE_ATTACH_FAILED:
        snprintf(buf, size, "cannot attach: %s", strerror(st->error));
        return buf;
    default:
        return "";
    }
}

/* First problem among the probes of a group, or nullptr when all are attached. */
static const char *group_problem(const struct ft_probe_status status[FT_LINUX_PROBES],
                                 enum ft_probe_group group, char *buf, size_t size)
{
    for (size_t i = 0; i < FT_LINUX_PROBES; i++) {
        const struct ft_probe_def *def = &ft_linux_probe_defs[i];
        if (def->group != group || status[i].state == FT_PROBE_ATTACHED)
            continue;
        if (status[i].state == FT_PROBE_NOT_NEEDED)
            return "not used in this mode";

        char why[160];
        snprintf(buf, size, "%s %s: %s", def->kind, def->target,
                 probe_problem(&status[i], why, sizeof(why)));
        return buf;
    }
    return nullptr;
}

void ft_linux_capabilities(const struct ft_probe_status status[FT_LINUX_PROBES], enum ft_mode mode,
                           struct ft_capabilities *out)
{
    char why[240];
    const char *problem;
    const char *minimal = "disabled in minimal mode";

    problem = group_problem(status, FT_PG_PROCESS, why, sizeof(why));
    if (problem)
        ft_capability_set(out, FT_FEAT_PROCESS, FT_CAP_PARTIAL,
                          "processes are described from /proc when first seen; %s", problem);
    else
        ft_capability_set(out, FT_FEAT_PROCESS, FT_CAP_FULL, "%s", "");

    bool v4 = ft_linux_group_attached(status, FT_PG_NET_IPV4);
    bool v6 = ft_linux_group_attached(status, FT_PG_NET_IPV6);
    bool tcp_state = ft_linux_group_attached(status, FT_PG_TCP_STATE);

    if (!v4 && !v6) {
        problem = group_problem(status, FT_PG_NET_IPV4, why, sizeof(why));
        ft_capability_set(out, FT_FEAT_TCP, FT_CAP_UNAVAILABLE, "%s", problem);
        ft_capability_set(out, FT_FEAT_UDP, FT_CAP_UNAVAILABLE, "%s", problem);
    } else {
        if (!tcp_state)
            ft_capability_set(out, FT_FEAT_TCP, FT_CAP_PARTIAL,
                              "byte counts only; connection states are not observed: %s",
                              group_problem(status, FT_PG_TCP_STATE, why, sizeof(why)));
        else if (!v4)
            ft_capability_set(out, FT_FEAT_TCP, FT_CAP_PARTIAL, "IPv6 only: %s",
                              group_problem(status, FT_PG_NET_IPV4, why, sizeof(why)));
        else
            ft_capability_set(out, FT_FEAT_TCP, FT_CAP_FULL, "%s", "");

        if (!v4)
            ft_capability_set(out, FT_FEAT_UDP, FT_CAP_PARTIAL, "IPv6 only: %s",
                              group_problem(status, FT_PG_NET_IPV4, why, sizeof(why)));
        else
            ft_capability_set(out, FT_FEAT_UDP, FT_CAP_FULL,
                              "received datagrams show their sender only when the "
                              "application asks for it");
    }

    if (v6)
        ft_capability_set(out, FT_FEAT_IPV6, FT_CAP_FULL, "%s", "");
    else
        ft_capability_set(out, FT_FEAT_IPV6, FT_CAP_UNAVAILABLE, "%s",
                          group_problem(status, FT_PG_NET_IPV6, why, sizeof(why)));

    ft_capability_set(out, FT_FEAT_FILE_OPEN, FT_CAP_UNAVAILABLE,
                      "open and close are not traced; a file is identified when it is "
                      "read or sent");
    ft_capability_set(out, FT_FEAT_FILE_WRITE, FT_CAP_UNAVAILABLE, "writes are not traced");

    bool net = v4 || v6;
    if (mode < FT_MODE_STANDARD) {
        ft_capability_set(out, FT_FEAT_FILE_READ, FT_CAP_DISABLED, "%s", minimal);
        ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_DISABLED, "%s", minimal);
        ft_capability_set(out, FT_FEAT_READ_SEND, FT_CAP_DISABLED, "%s", minimal);
    } else {
        problem = group_problem(status, FT_PG_FILE_READ, why, sizeof(why));
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

        problem = group_problem(status, FT_PG_SENDFILE, why, sizeof(why));
        if (problem)
            ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_UNAVAILABLE, "%s", problem);
        else if (!net)
            ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_UNAVAILABLE,
                              "network probes are unavailable");
        else
            ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_FULL, "%s", "");
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

void ft_linux_diagnose(struct ft_diagnosis *out)
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
    ft_backend_config_defaults(&cfg);
    cfg.queue_bytes = 64 * 1024;
    cfg.agg_entries = 64;
    cfg.known_files = 64;

    int rc = ft_linux_probes_load(&cfg, &probes);
    if (rc) {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "BPF programs load", "%s (%s)", strerror(-rc),
                         ft_linux_last_libbpf_message());
        blocked = true;
    } else {
        ft_diagnosis_add(out, FT_CHECK_OK, false, "BPF programs load", "%s", "");
    }

    size_t failed_groups = 0;
    for (size_t g = 0; g < FT_PG_COUNT && !rc; g++) {
        char why[240];
        const char *problem =
            group_problem(probes.status, (enum ft_probe_group)g, why, sizeof(why));
        bool optional = g != FT_PG_NET_IPV4;
        if (problem) {
            ft_diagnosis_add(out, optional ? FT_CHECK_WARN : FT_CHECK_FAIL, optional,
                             group_titles[g], "%s", problem);
            failed_groups++;
        } else {
            ft_diagnosis_add(out, FT_CHECK_OK, optional, group_titles[g], "%s", "");
        }
    }

    bool have_network = !rc && (ft_linux_group_attached(probes.status, FT_PG_NET_IPV4) ||
                                ft_linux_group_attached(probes.status, FT_PG_NET_IPV6));
    if (rc)
        ft_capability_set_all(&out->caps, FT_CAP_UNAVAILABLE,
                              "the BPF programs could not be loaded");
    else
        ft_linux_capabilities(probes.status, cfg.mode, &out->caps);
    if (!rc)
        ft_linux_probes_unload(&probes);

    if (blocked || !have_network) {
        out->exit_code = FT_EXIT_UNSUPPORTED;
        snprintf(out->result, sizeof(out->result), "Monitoring unavailable");
        snprintf(out->advice, sizeof(out->advice),
                 "Filetrace needs a Linux 6.1 or newer kernel with BTF and BPF\n"
                 "trampolines (fentry/fexit). On arm64 those require Linux 6.4.");
    } else if (failed_groups) {
        out->exit_code = FT_EXIT_PARTIAL;
        snprintf(out->result, sizeof(out->result), "Partial monitoring available");
        snprintf(out->advice, sizeof(out->advice),
                 "Run 'filetrace capabilities' to see which features are reduced.");
    } else {
        out->exit_code = FT_EXIT_OK;
        snprintf(out->result, sizeof(out->result), "Monitoring available");
        snprintf(out->advice, sizeof(out->advice),
                 "Every probe this build uses is attached. Run 'filetrace capabilities'\n"
                 "for the list of features and their limits.");
    }
}
