#include "backends/linux/linux.h"

#include "filetrace/sysinfo.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

constexpr int ENOTSUPP_KERNEL = 524; /* the kernel's ENOTSUPP, which libc cannot name */

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

static void name_capability(const struct ft_linux_probes *p, const struct ft_backend_config *cfg,
                            const struct ft_backend_stats *libraries, struct ft_capabilities *out)
{
    bool lookups = cfg->lookup_names;
    bool tls = cfg->tls_names;

    if (cfg->mode < FT_MODE_STANDARD) {
        ft_capability_set(out, FT_FEAT_DESTINATION_NAMES, FT_CAP_DISABLED, "%s",
                          "disabled in minimal mode");
        return;
    }
    if (!lookups && !tls) {
        ft_capability_set(out, FT_FEAT_DESTINATION_NAMES, FT_CAP_DISABLED, "%s",
                          "turned off in the configuration");
        return;
    }
    if (!ft_sysinfo_host_pid_namespace()) {
        ft_capability_set(out, FT_FEAT_DESTINATION_NAMES, FT_CAP_UNAVAILABLE, "%s",
                          "the agent is not in the host's PID namespace, where it finds the C "
                          "libraries processes map");
        return;
    }
    if (lookups && !p->lookups) {
        ft_capability_set(out, FT_FEAT_DESTINATION_NAMES, FT_CAP_UNAVAILABLE,
                          "the kernel refused the probes of getaddrinfo: %s",
                          error_text(p->lookups_error));
        return;
    }
    if (!ft_linux_returns_allowed(p, cfg)) {
        char why[320];
        ft_capability_set(out, FT_FEAT_DESTINATION_NAMES, FT_CAP_UNAVAILABLE, "%s",
                          ft_linux_returns_refusal(p, why, sizeof(why)));
        return;
    }

    /* One sentence for each half of the feature: what is probed, or that it is turned off. */
    uint64_t name_libs = libraries ? libraries->name_libraries : 0;
    uint64_t tls_libs = libraries ? libraries->tls_libraries : 0;
    char cut[96] = "";
    if (libraries && libraries->name_libraries_configured > libraries->name_library_capacity)
        snprintf(cut, sizeof(cut), "; the open file limit holds no more than %llu",
                 (unsigned long long)libraries->name_library_capacity);

    char lookup[200];
    if (!lookups)
        snprintf(lookup, sizeof(lookup), "lookups are turned off in the configuration");
    else if (name_libs == 0)
        snprintf(lookup, sizeof(lookup), "lookups are probed in the C libraries processes map");
    else
        snprintf(lookup, sizeof(lookup), "lookups probed in %llu %s%s",
                 (unsigned long long)name_libs, name_libs == 1 ? "library" : "libraries", cut);

    char tlsc[120];
    if (!tls)
        snprintf(tlsc, sizeof(tlsc), "TLS server names are turned off in the configuration");
    else if (tls_libs == 0)
        snprintf(tlsc, sizeof(tlsc),
                 "TLS server names are read where the client's library is probed");
    else
        snprintf(tlsc, sizeof(tlsc), "TLS server names in %llu %s", (unsigned long long)tls_libs,
                 tls_libs == 1 ? "library" : "libraries");

    enum ft_cap_status status =
        lookups && tls && name_libs && tls_libs ? FT_CAP_FULL : FT_CAP_PARTIAL;
    ft_capability_set(out, FT_FEAT_DESTINATION_NAMES, status, "%s; %s", lookup, tlsc);
}
static void php_capability(const struct ft_linux_probes *p, const struct ft_backend_config *cfg,
                           struct ft_capabilities *out)
{
    char why[320];

    if (cfg->mode < FT_MODE_STANDARD)
        ft_capability_set(out, FT_FEAT_PHP_SCRIPTS, FT_CAP_DISABLED, "%s",
                          "disabled in minimal mode");
    else if (!cfg->php_scripts)
        ft_capability_set(out, FT_FEAT_PHP_SCRIPTS, FT_CAP_DISABLED, "%s",
                          "turned off in the configuration");
    else if (!ft_linux_returns_allowed(p, cfg))
        ft_capability_set(out, FT_FEAT_PHP_SCRIPTS, FT_CAP_UNAVAILABLE, "%s",
                          ft_linux_returns_refusal(p, why, sizeof(why)));
    else
        ft_capability_set(out, FT_FEAT_PHP_SCRIPTS, FT_CAP_FULL, "%s", "");
}

void ft_linux_capabilities(const struct ft_linux_probes *p, const struct ft_backend_config *cfg,
                           const struct ft_backend_stats *libraries, struct ft_capabilities *out)
{
    char why[240];
    const char *problem;
    const char *minimal = "disabled in minimal mode";
    const char *configured = "turned off in the configuration";
    enum ft_mode mode = cfg->mode;
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
        if (!cfg->track_read) {
            ft_capability_set(out, FT_FEAT_FILE_READ, FT_CAP_DISABLED, "%s", configured);
            ft_capability_set(out, FT_FEAT_READ_SEND, FT_CAP_DISABLED, "%s", configured);
        } else if (problem) {
            ft_capability_set(out, FT_FEAT_FILE_READ, FT_CAP_UNAVAILABLE, "%s", problem);
            ft_capability_set(out, FT_FEAT_READ_SEND, FT_CAP_UNAVAILABLE, "%s", problem);
        } else {
            ft_capability_set(out, FT_FEAT_FILE_READ, FT_CAP_PARTIAL,
                              "read(2) and pread(2) on regular files; readv, io_uring and "
                              "memory-mapped reads are not observed");
            ft_capability_set(out, FT_FEAT_READ_SEND, net ? FT_CAP_PARTIAL : FT_CAP_UNAVAILABLE,
                              "%s%s",
                              net ? "a thread that reads a file and then sends is reported "
                                    "as INFERRED; reads and sends on different threads are "
                                    "not associated"
                                  : "network probes are unavailable",
                              net && !p->aging ? "; a held transfer is judged only when its "
                                                 "connection or thread acts again"
                                               : "");
        }

        problem = group_problem(p, FT_PG_SENDFILE, why, sizeof(why));
        if (!cfg->track_sendfile)
            ft_capability_set(out, FT_FEAT_SENDFILE, FT_CAP_DISABLED, "%s", configured);
        else if (problem)
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
    name_capability(p, cfg, libraries, out);
    php_capability(p, cfg, out);
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

/* Adds one check per probe that was to be attached; returns how many are not. */
static size_t report_probes(struct ft_diagnosis *out, const struct ft_linux_probes *p)
{
    size_t failed = 0;

    for (size_t i = 0; i < p->set->count; i++) {
        const struct ft_probe_def *def = &p->set->defs[i];
        const struct ft_probe_status *st = &p->status[i];
        bool required = def->group == FT_PG_NET ||
                        (def->group == FT_PG_TCP_STATE && p->set->kind == FT_PROBES_KPROBE);
        char name[96];
        char why[160];

        if (st->state == FT_PROBE_NOT_NEEDED)
            continue;
        snprintf(name, sizeof(name), "%s %s", def->kind, def->target);
        if (st->state == FT_PROBE_ATTACHED) {
            ft_diagnosis_add_probe(out, FT_CHECK_OK, !required, name, "%s", "");
        } else {
            ft_diagnosis_add_probe(out, required ? FT_CHECK_FAIL : FT_CHECK_WARN, !required, name,
                                   "%s", probe_problem(st, why, sizeof(why)));
            failed++;
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

    if (access("/sys/kernel/btf/vmlinux", R_OK) == 0) {
        ft_diagnosis_add(out, FT_CHECK_OK, false, "BTF", "%s", "");
    } else {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "BTF",
                         "/sys/kernel/btf/vmlinux is missing; the kernel must be built with "
                         "CONFIG_DEBUG_INFO_BTF");
        blocked = true;
    }

    struct ft_linux_caps caps;
    ft_linux_held_capabilities(&caps);
    ft_diagnosis_add(out, caps.bpf || caps.sys_admin ? FT_CHECK_OK : FT_CHECK_FAIL, false,
                     "CAP_BPF", "%s", caps.bpf || !caps.sys_admin ? "" : "through CAP_SYS_ADMIN");
    ft_diagnosis_add(out, caps.perfmon || caps.sys_admin ? FT_CHECK_OK : FT_CHECK_FAIL, false,
                     "CAP_PERFMON", "%s",
                     caps.perfmon || !caps.sys_admin ? "" : "through CAP_SYS_ADMIN");

    if (!ft_sysinfo_host_pid_namespace())
        ft_diagnosis_add(out, FT_CHECK_WARN, true, "PID namespace",
                         "not the host's: command lines of processes older than the agent, "
                         "PHP-FPM pool names, and inspect's cgroup and open files are not read; "
                         "run it in the host's PID namespace, as with docker run --pid=host");

    if (lockdown_blocks_reads()) {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "Kernel lockdown",
                         "confidentiality mode forbids reading kernel memory from BPF");
        blocked = true;
    }

    if (!ft_linux_privileged()) {
        ft_diagnosis_add(out, FT_CHECK_WARN, false, "BPF",
                         "not checked: loading BPF programs needs root, or CAP_BPF with "
                         "CAP_PERFMON");
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
    bool ring = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, nullptr) == 1;
    bool storage = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_TASK_STORAGE, nullptr) == 1;
    if (ring && storage) {
        ft_diagnosis_add(out, FT_CHECK_OK, false, "BPF", "libbpf %s", libbpf_version_string());
    } else {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "BPF", "the kernel cannot create %s",
                         ring ? "BPF task storage maps" : "BPF ring buffers");
        blocked = true;
    }

    struct ft_backend_config cfg;
    struct ft_linux_probes probes;
    enum ft_probes wanted = requested ? requested->probes : FT_PROBES_AUTO;

    ft_backend_config_defaults(&cfg);
    cfg.queue_bytes = 64 * 1024;
    cfg.agg_entries = 64;
    cfg.known_files = 64;

    cfg.probes = wanted;
    int rc = ft_linux_probes_load(&cfg, &probes);
    if (wanted == FT_PROBES_AUTO && !rc && probes.set->kind == FT_PROBES_KPROBE) {
        const struct ft_probe_def *def = probes.trampoline_def;
        char why[160];

        if (def)
            ft_diagnosis_add(out, FT_CHECK_WARN, false, "BPF trampolines",
                             "%s %s: %s; kernel functions are traced with kprobes instead",
                             def->kind, def->target,
                             probe_problem(&probes.trampoline, why, sizeof(why)));
        else
            ft_diagnosis_add(out, FT_CHECK_WARN, false, "BPF trampolines",
                             "%s; kernel functions are traced with kprobes instead",
                             error_text(probes.trampoline.error));
    } else if (wanted == FT_PROBES_TRAMPOLINE || (wanted == FT_PROBES_AUTO && !rc)) {
        ft_diagnosis_add(out, FT_CHECK_OK, false, "BPF trampolines", "%s", "");
    }

    if (rc) {
        ft_diagnosis_add(out, FT_CHECK_FAIL, false, "BPF programs", "do not load: %s (%s)",
                         strerror(-rc), ft_linux_last_libbpf_message());
        ft_capability_set_all(&out->caps, FT_CAP_UNAVAILABLE,
                              "the BPF programs could not be loaded");
        out->exit_code = FT_EXIT_UNSUPPORTED;
        snprintf(out->result, sizeof(out->result), "Monitoring unavailable");
        return;
    }
    ft_diagnosis_add(out, FT_CHECK_OK, false, "BPF programs",
                     "loaded; every kernel field they read was found");
    if (probes.returns == FT_RETURNS_NO_SYSCALL) {
        ft_diagnosis_add(out, FT_CHECK_OK, true, "Return probes",
                         "this architecture returns from them without a system call");
    } else if (probes.returns == FT_RETURNS_SAFE) {
        ft_diagnosis_add(out, FT_CHECK_OK, true, "Return probes",
                         "a process whose seccomp filter refuses the uretprobe system call "
                         "survived one");
    } else if (probes.returns != FT_RETURNS_NOT_TESTED) {
        char why[320];
        ft_diagnosis_add(out, FT_CHECK_WARN, true, "Return probes", "%s",
                         ft_linux_returns_row(&probes, why, sizeof(why)));
    }

    size_t failed_groups = report_probes(out, &probes);
    if (probes.aging) {
        ft_diagnosis_add_probe(out, FT_CHECK_OK, true, "iter bpf_map_elem", "%s", "");
    } else {
        ft_diagnosis_add_probe(out, FT_CHECK_WARN, true, "iter bpf_map_elem",
                               "%s; a held transfer is judged only when its connection or "
                               "thread acts again",
                               error_text(probes.aging_error));
        failed_groups++;
    }
    bool have_network = ft_linux_network_attached(&probes);
    bool kprobes = probes.set->kind == FT_PROBES_KPROBE;

    ft_linux_capabilities(&probes, &cfg, nullptr, &out->caps);
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
