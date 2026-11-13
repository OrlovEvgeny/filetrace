#include "cmd/cli.h"

#include "backends/backend.h"
#include "exporters/exporters.h"
#include "filetrace/format.h"
#include "filetrace/sysinfo.h"
#include "ui/ui.h"

#include <stdlib.h>
#include <string.h>

static const char *system_title(const struct ft_host_info *host)
{
    return strcmp(host->system, "Darwin") == 0 ? "macOS" : host->system;
}

static const char *level_tag(enum ft_check_level level)
{
    switch (level) {
    case FT_CHECK_OK:
        return "[OK]";
    case FT_CHECK_WARN:
        return "[WARN]";
    default:
        return "[FAIL]";
    }
}

static const char *level_word(enum ft_check_level level)
{
    switch (level) {
    case FT_CHECK_OK:
        return "AVAILABLE";
    case FT_CHECK_WARN:
        return "LIMITED";
    default:
        return "MISSING";
    }
}

static const char *feature_tag(enum ft_cap_status status)
{
    switch (status) {
    case FT_CAP_FULL:
        return "[OK]";
    case FT_CAP_PARTIAL:
        return "[WARN]";
    case FT_CAP_DISABLED:
        return "[OFF]";
    default:
        return "[NONE]";
    }
}

static const char *status_word(int exit_code)
{
    switch (exit_code) {
    case FT_EXIT_OK:
        return "READY";
    case FT_EXIT_PARTIAL:
        return "DEGRADED";
    case FT_EXIT_PERMISSION:
        return "NEEDS PRIVILEGES";
    default:
        return "UNAVAILABLE";
    }
}

static void doctor_text(const struct ft_diagnosis *d, const struct ft_host_info *host,
                        enum ft_agent_state agent, const struct ft_row_stats *stats, int code)
{
    char a[64];
    bool probes = false;

    printf("FILETRACE DIAGNOSTICS\n\n");
    printf("%-20s%s\n", "Platform:", system_title(host));
    printf("%-20s%s\n", "Kernel:", host->release);
    printf("%-20s%s\n", "Architecture:", host->arch);
    for (size_t i = 0; i < d->count; i++) {
        const struct ft_check *c = &d->checks[i];
        if (c->probe) {
            probes = true;
            continue;
        }
        snprintf(a, sizeof(a), "%s:", c->text);
        printf("%-20s%s", a, level_word(c->level));
        if (c->detail[0])
            printf(" (%s)", c->detail);
        putchar('\n');
    }
    printf("%-20s%s\n", "Backend:", d->backend);

    if (probes) {
        printf("\nPROBES\n");
        for (size_t i = 0; i < d->count; i++) {
            const struct ft_check *c = &d->checks[i];
            if (!c->probe)
                continue;
            printf("  %s %s", level_tag(c->level), c->text);
            if (c->detail[0])
                printf(": %s", c->detail);
            putchar('\n');
        }
        printf("  Each probe above was loaded into the kernel and attached for this check.\n");
    }

    /* One cause behind every feature is stated once instead of on each line. */
    bool uniform = d->caps.items[0].reason[0] != '\0';
    for (size_t f = 1; f < FT_FEAT_COUNT; f++) {
        if (d->caps.items[f].status != d->caps.items[0].status ||
            strcmp(d->caps.items[f].reason, d->caps.items[0].reason) != 0)
            uniform = false;
    }
    printf("\nFEATURES\n");
    for (size_t f = 0; f < FT_FEAT_COUNT; f++) {
        const struct ft_capability *cap = &d->caps.items[f];
        printf("  %s %s", feature_tag(cap->status), ft_feature_title((enum ft_feature)f));
        if (!uniform && cap->reason[0] && cap->status != FT_CAP_FULL)
            printf(": %s", cap->reason);
        putchar('\n');
    }
    if (uniform)
        printf("  Reason: %s.\n", d->caps.items[0].reason);

    printf("\nEVENT PIPELINE\n");
    if (agent == FT_AGENT_RUNNING) {
        printf("  %-18s%s, PID %u, %s mode\n", "Agent:", "running", stats->pid, stats->mode);
        ft_format_count(stats->events_received, a, sizeof(a));
        printf("  %-18s%s\n", "Events received:", a);
        ft_format_count(stats->events_dropped, a, sizeof(a));
        printf("  %-18s%s\n", "Events dropped:", a);
        ft_format_bytes(stats->queue_bytes, a, sizeof(a));
        printf("  %-18s%s\n", "Ring buffer:", a);
        if (stats->event_log_bytes) {
            ft_format_bytes(stats->event_log_bytes, a, sizeof(a));
            printf("  %-18s%s\n", "Event log:", a);
        } else {
            printf("  %-18s%s\n", "Event log:", "off");
        }
        if (stats->name_libraries_configured) {
            char b[64];
            ft_format_count(stats->name_libraries.count, a, sizeof(a));
            ft_format_count(stats->name_libraries.capacity, b, sizeof(b));
            printf("  %-18s%s of %s", "Name libraries:", a, b);
            if (stats->name_libraries_configured > stats->name_libraries.capacity) {
                ft_format_count(stats->name_libraries_configured, a, sizeof(a));
                printf(", not the %s configured: the agent's open file limit holds no more", a);
            }
            putchar('\n');
        }
        if (stats->tls_libraries) {
            ft_format_count(stats->tls_libraries, a, sizeof(a));
            printf("  %-18s%s\n", "TLS libraries:", a);
        }
    } else if (agent == FT_AGENT_UNREACHABLE) {
        printf("  %-18s%s\n", "Agent:", "running, but its socket is not accessible to this user");
    } else {
        printf("  %-18s%s\n", "Agent:",
               d->exit_code == FT_EXIT_OK || d->exit_code == FT_EXIT_PARTIAL
                   ? "not running; start it with 'sudo filetrace agent run'"
                   : "not running");
    }

    printf("\nSTATUS: %s\n", status_word(code));
    if (agent == FT_AGENT_RUNNING && stats->health != FT_HEALTH_OK)
        printf("\nThe running agent has lost events recently; see 'filetrace stats'.\n");
    if (d->advice[0])
        printf("\n%s\n", d->advice);
}

static void doctor_json(const struct ft_diagnosis *d, const struct ft_host_info *host,
                        enum ft_agent_state agent, const struct ft_row_stats *stats, int code)
{
    static const char *const levels[] = {"ok", "warn", "fail"};
    static const char *const agents[] = {"running", "stopped", "unreachable"};
    const char *status = status_word(code);
    bool first = true;

    printf("{\"status\":\"");
    for (const char *p = status; *p; p++)
        putchar(*p == ' ' ? '_' : (*p >= 'A' && *p <= 'Z' ? *p + 32 : *p));
    printf("\",\"platform\":\"%s\",\"kernel\":", system_title(host));
    ft_json_string(stdout, host->release);
    printf(",\"architecture\":");
    ft_json_string(stdout, host->arch);
    printf(",\"backend\":");
    ft_json_string(stdout, d->backend);

    for (int probes = 0; probes < 2; probes++) {
        printf(",\"%s\":[", probes ? "probes" : "checks");
        first = true;
        for (size_t i = 0; i < d->count; i++) {
            const struct ft_check *c = &d->checks[i];
            if (c->probe != (probes == 1))
                continue;
            printf("%s{\"name\":", first ? "" : ",");
            ft_json_string(stdout, c->text);
            printf(",\"status\":\"%s\"", levels[c->level]);
            if (c->detail[0]) {
                printf(",\"detail\":");
                ft_json_string(stdout, c->detail);
            }
            putchar('}');
            first = false;
        }
        putchar(']');
    }

    printf(",\"features\":[");
    for (size_t f = 0; f < FT_FEAT_COUNT; f++) {
        const struct ft_capability *cap = &d->caps.items[f];
        printf("%s{\"feature\":\"%s\",\"status\":\"%s\"", f ? "," : "",
               ft_feature_key((enum ft_feature)f), ft_cap_status_name(cap->status));
        if (cap->reason[0]) {
            printf(",\"detail\":");
            ft_json_string(stdout, cap->reason);
        }
        putchar('}');
    }
    printf("],\"agent\":{\"state\":\"%s\"", agents[agent]);
    if (agent == FT_AGENT_RUNNING)
        printf(",\"pid\":%u,\"mode\":\"%s\",\"events_received\":%llu,\"events_dropped\":%llu,"
               "\"ring_buffer_bytes\":%llu,\"event_log_bytes\":%llu",
               stats->pid, stats->mode, (unsigned long long)stats->events_received,
               (unsigned long long)stats->events_dropped, (unsigned long long)stats->queue_bytes,
               (unsigned long long)stats->event_log_bytes);
    if (agent == FT_AGENT_RUNNING && stats->name_libraries_configured)
        printf(",\"name_libraries\":{\"entries\":%llu,\"capacity\":%llu,\"configured\":%llu}",
               (unsigned long long)stats->name_libraries.count,
               (unsigned long long)stats->name_libraries.capacity,
               (unsigned long long)stats->name_libraries_configured);
    if (agent == FT_AGENT_RUNNING && stats->tls_libraries)
        printf(",\"tls_libraries\":%llu", (unsigned long long)stats->tls_libraries);
    printf("}}\n");
}

int ft_cmd_doctor(const struct ft_cli *cli, struct ft_args *a)
{
    enum ft_format format = ft_cli_format(cli, FT_FORMATS_REPORT);
    struct ft_backend_config cfg;
    const char *v;
    int r;

    ft_backend_config_defaults(&cfg);
    while (!ft_args_done(a)) {
        if ((r = ft_args_format(a, "doctor", FT_FORMATS_REPORT, &format)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            continue;
        }
        if ((r = ft_args_value(a, "--probes", &v)) == 0)
            return ft_usage_error("doctor", "unknown argument '%s'", ft_args_peek(a));
        if (r < 0)
            return FT_EXIT_USAGE;
        if (!ft_probes_parse(v, &cfg.probes))
            return ft_usage_error("doctor",
                                  "invalid value '%s' for --probes (expected auto, trampoline "
                                  "or kprobe)",
                                  v);
    }

    struct ft_diagnosis *d = calloc(1, sizeof(*d));
    struct ft_row_stats *stats = calloc(1, sizeof(*stats));
    struct ft_host_info host;
    if (!d || !stats) {
        free(d);
        free(stats);
        return FT_EXIT_ERROR;
    }

    ft_sysinfo_host(&host);
    ft_backend_native()->diagnose(&cfg, d);
    enum ft_agent_state agent = ft_agent_ask(cli, stats);

    /* Probes that attach do not help an agent that is dropping what they produce. */
    int code = d->exit_code;
    if (code == FT_EXIT_OK && agent == FT_AGENT_RUNNING && stats->health != FT_HEALTH_OK)
        code = FT_EXIT_PARTIAL;

    if (format == FT_FMT_JSON)
        doctor_json(d, &host, agent, stats, code);
    else
        doctor_text(d, &host, agent, stats, code);
    free(d);
    free(stats);
    return code;
}

struct capability_rows {
    struct ft_row_capability rows[FT_FEAT_COUNT];
    size_t count;
};

static void capability_collect(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct capability_rows *c = ctx;
    if (type != FT_MSG_ROW_CAPABILITY || c->count >= FT_FEAT_COUNT)
        return;
    memset(&c->rows[c->count], 0, sizeof(c->rows[0]));
    memcpy(&c->rows[c->count], payload, size < sizeof(c->rows[0]) ? size : sizeof(c->rows[0]));
    c->rows[c->count].reason[sizeof(c->rows[0].reason) - 1] = '\0';
    c->count++;
}

int ft_cmd_capabilities(const struct ft_cli *cli, struct ft_args *a)
{
    enum ft_format format = ft_cli_format(cli, FT_FORMATS_REPORT);

    while (!ft_args_done(a)) {
        int r = ft_args_format(a, "capabilities", FT_FORMATS_REPORT, &format);
        if (r < 0)
            return FT_EXIT_USAGE;
        if (r == 0)
            return ft_usage_error("capabilities", "unknown argument '%s'", ft_args_peek(a));
    }

    /* A running agent knows what is attached; without one the backend checks the machine. */
    struct capability_rows caps = {0};
    const char *source = "the running agent";
    struct ft_error err = {0};
    struct ft_client *c = ft_client_connect(cli->socket_path, &err);
    int code = FT_EXIT_OK;

    if (c) {
        struct ft_query q;
        ft_query_init(&q, FT_Q_CAPABILITIES);
        code = ft_client_query(c, &q, capability_collect, &caps, nullptr, &err);
        ft_client_close(c);
        if (code != FT_EXIT_OK) {
            fprintf(stderr, "%s\n", err.msg);
            return code;
        }
    } else {
        struct ft_diagnosis *d = calloc(1, sizeof(*d));
        if (!d)
            return FT_EXIT_ERROR;
        ft_backend_native()->diagnose(nullptr, d);
        for (size_t f = 0; f < FT_FEAT_COUNT; f++) {
            caps.rows[f].feature = (uint8_t)f;
            caps.rows[f].status = d->caps.items[f].status;
            ft_strlcpy(caps.rows[f].reason, d->caps.items[f].reason, sizeof(caps.rows[f].reason));
        }
        caps.count = FT_FEAT_COUNT;
        source = err.code == FT_EXIT_PERMISSION
                     ? "a check of this machine (the agent's socket is not accessible)"
                     : "a check of this machine (no agent is running)";
        if (d->exit_code == FT_EXIT_PERMISSION || d->exit_code == FT_EXIT_UNSUPPORTED)
            code = d->exit_code;
        free(d);
    }

    if (format == FT_FMT_JSON) {
        printf("[");
        for (size_t i = 0; i < caps.count; i++) {
            const struct ft_row_capability *row = &caps.rows[i];
            printf("%s\n {\"feature\":\"%s\",\"status\":\"%s\"", i ? "," : "",
                   ft_feature_key((enum ft_feature)row->feature),
                   ft_cap_status_name((enum ft_cap_status)row->status));
            if (row->reason[0]) {
                printf(",\"detail\":");
                ft_json_string(stdout, row->reason);
            }
            printf("}");
        }
        printf("\n]\n");
        return code;
    }

    size_t width = strlen("FEATURE");
    bool uniform = caps.count > 1 && caps.rows[0].reason[0] != '\0';
    for (size_t i = 0; i < caps.count; i++) {
        size_t w = strlen(ft_feature_title((enum ft_feature)caps.rows[i].feature));
        if (w > width)
            width = w;
        if (caps.rows[i].status != caps.rows[0].status ||
            strcmp(caps.rows[i].reason, caps.rows[0].reason) != 0)
            uniform = false;
    }

    /* One cause behind every row is stated once instead of on each line. */
    bool styled = ft_term_styled(stdout);
    printf("%s%-*s  %s%s%s\n", styled ? FT_STYLE_BOLD : "", (int)width, "FEATURE",
           uniform ? "STATUS" : "STATUS       ", uniform ? "" : "DETAIL",
           styled ? FT_STYLE_RESET : "");
    for (size_t i = 0; i < caps.count; i++) {
        const struct ft_row_capability *row = &caps.rows[i];
        const char *title = ft_feature_title((enum ft_feature)row->feature);
        const char *status = ft_cap_status_name((enum ft_cap_status)row->status);
        if (uniform)
            printf("%-*s  %s\n", (int)width, title, status);
        else
            printf("%-*s  %-11s  %s\n", (int)width, title, status, row->reason);
    }
    if (uniform)
        printf("\nReason: %s.\n", caps.rows[0].reason);
    printf("\nReported by %s.\n", source);
    return code;
}

int ft_cmd_version(const struct ft_cli *cli, struct ft_args *a)
{
    if (!ft_args_done(a))
        return ft_usage_error("version", "unknown argument '%s'", ft_args_peek(a));

    struct ft_host_info host;
    struct ft_error err = {0};
    struct ft_client *c = ft_client_connect(cli->socket_path, &err);

    ft_sysinfo_host(&host);
    printf("Filetrace %s\n\n", FT_VERSION);
    printf("Platform:       %s %s\n", system_title(&host), host.arch);
    printf("Kernel:         %s\n", host.release);
    printf("Backend:        %s\n", ft_backend_native()->name);
#if defined(__clang__)
    printf("Compiler:       Clang %d.%d.%d\n", __clang_major__, __clang_minor__,
           __clang_patchlevel__);
#elif defined(__GNUC__)
    printf("Compiler:       GCC %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif
    printf("Build:          %s\n", FT_BUILD_TYPE);
    printf("Commit:         %s\n", FT_COMMIT);
    printf("Agent:          %s\n", c ? "Running"
                                   : err.code == FT_EXIT_PERMISSION
                                       ? "Running (socket not accessible)"
                                       : "Not running");
    ft_client_close(c);
    return FT_EXIT_OK;
}
