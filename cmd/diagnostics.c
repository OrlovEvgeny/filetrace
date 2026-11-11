#include "cmd/cli.h"

#include "backends/backend.h"
#include "exporters/exporters.h"
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

static void print_checks(const struct ft_diagnosis *d, bool optional)
{
    for (size_t i = 0; i < d->count; i++) {
        const struct ft_check *c = &d->checks[i];
        if (c->optional != optional)
            continue;
        printf("%s %s", level_tag(c->level), c->text);
        if (c->detail[0])
            printf(c->level == FT_CHECK_OK ? " (%s)" : ": %s", c->detail);
        putchar('\n');
    }
}

static bool has_optional(const struct ft_diagnosis *d)
{
    for (size_t i = 0; i < d->count; i++) {
        if (d->checks[i].optional)
            return true;
    }
    return false;
}

static void print_daemon_line(const struct ft_cli *cli)
{
    struct ft_error err = {0};
    struct ft_client *c = ft_client_connect(cli->socket_path, &err);

    if (c)
        printf("Running (%s)\n", cli->socket_path);
    else if (err.code == FT_EXIT_PERMISSION)
        printf("Running, but its socket is not accessible to this user\n");
    else
        printf("Not running\n");
    ft_client_close(c);
}

int ft_cmd_doctor(const struct ft_cli *cli, struct ft_args *a)
{
    if (!ft_args_done(a))
        return ft_usage_error("doctor", "unknown argument '%s'", ft_args_peek(a));

    struct ft_diagnosis *d = calloc(1, sizeof(*d));
    struct ft_host_info host;
    if (!d)
        return FT_EXIT_ERROR;

    ft_sysinfo_host(&host);
    ft_backend_native()->diagnose(d);

    printf("FILETRACE DOCTOR\n\n"
           "Platform: %s\n"
           "%s %s\n"
           "Arch:     %s\n\n",
           system_title(&host),
           strcmp(host.system, "Linux") == 0 ? "Kernel:  " : "Version: ", host.release, host.arch);

    printf("CHECKS\n");
    print_checks(d, false);
    if (has_optional(d)) {
        printf("\nOPTIONAL\n");
        print_checks(d, true);
    }
    printf("\nBACKEND\n%s\n", d->backend);
    printf("\nDAEMON\n");
    print_daemon_line(cli);
    printf("\nRESULT\n%s\n", d->result);
    if (d->advice[0])
        printf("\n%s\n", d->advice);

    int code = d->exit_code;
    free(d);
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
    enum ft_format format = FT_FMT_TABLE;
    const char *v;
    int r;

    while (!ft_args_done(a)) {
        if ((r = ft_args_value(a, "--format", &v)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            if (strcmp(v, "json") == 0)
                format = FT_FMT_JSON;
            else if (strcmp(v, "table") != 0)
                return ft_usage_error(
                    "capabilities", "invalid value '%s' for --format (expected table or json)", v);
        } else {
            return ft_usage_error("capabilities", "unknown argument '%s'", ft_args_peek(a));
        }
    }

    /* A running daemon knows what is attached; without one the backend checks the machine. */
    struct capability_rows caps = {0};
    const char *source = "the running daemon";
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
        ft_backend_native()->diagnose(d);
        for (size_t f = 0; f < FT_FEAT_COUNT; f++) {
            caps.rows[f].feature = (uint8_t)f;
            caps.rows[f].status = d->caps.items[f].status;
            ft_strlcpy(caps.rows[f].reason, d->caps.items[f].reason, sizeof(caps.rows[f].reason));
        }
        caps.count = FT_FEAT_COUNT;
        source = "a check of this machine (no daemon is running)";
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
    printf("Daemon:         %s\n", c ? "Running"
                                   : err.code == FT_EXIT_PERMISSION
                                       ? "Running (socket not accessible)"
                                       : "Not running");
    ft_client_close(c);
    return FT_EXIT_OK;
}
