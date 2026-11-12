#include "cmd/cli.h"

#include "agent/agent.h"
#include "filetrace/format.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* How long a collector has to fail before the screen opens over its start. */
constexpr int FAIL_FAST_MS = 200;

/* "filetrace top": what to type again with sudo. */
static void command_text(const struct ft_cli *cli, char *buf, size_t size)
{
    snprintf(buf, size, "filetrace%s%s", cli->command ? " " : "", cli->command ? cli->command : "");
}

int ft_session_failed(const struct ft_cli *cli, int code, const char *msg)
{
    char command[64];

    if (code != FT_EXIT_PERMISSION) {
        fprintf(stderr, "%s\n", msg);
        return code;
    }
    command_text(cli, command, sizeof(command));
    fprintf(stderr,
            "Permission denied.\n\n"
            "%s reads file and network activity from the kernel, which needs\n"
            "root. No service has to be installed or running:\n\n"
            "  sudo %s\n",
            command, command);
    return code;
}

static int socket_denied(const struct ft_cli *cli)
{
    char command[64];

    command_text(cli, command, sizeof(command));
    fprintf(stderr,
            "Permission denied.\n\n"
            "The agent's socket %s is not open to this user:\n\n"
            "  sudo %s\n",
            cli->socket_path, command);
    return FT_EXIT_PERMISSION;
}

/*
 * The collector serves only this process and stops when the session closes. Returns with *failed
 * set when it has written its answer, which can only be why it stopped, within wait_ms.
 */
static int start_collector(const struct ft_cli *cli, struct ft_session *s, int wait_ms,
                           bool *failed)
{
    int pair[2];

    *failed = false;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        fprintf(stderr, "filetrace: cannot create a socket pair: %s\n", strerror(errno));
        return FT_EXIT_ERROR;
    }

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "filetrace: cannot start a collector: %s\n", strerror(errno));
        close(pair[0]);
        close(pair[1]);
        return FT_EXIT_ERROR;
    }
    if (pid == 0) {
        struct ft_agent_config cfg;
        struct ft_error err = {0};

        close(pair[0]);
        /* An interrupt ends the foreground command; the collector stops with its session. */
        signal(SIGINT, SIG_IGN);
        /* A session closed while the probes attach ends the collector with this signal. */
        signal(SIGTERM, SIG_DFL);
        /* A screen owns the terminal: what the collector logs must not be written over it. */
        int null = wait_ms > 0 ? open("/dev/null", O_WRONLY) : -1;
        if (null >= 0) {
            dup2(null, STDOUT_FILENO);
            dup2(null, STDERR_FILENO);
        }
        if (ft_cli_collector_config(cli))
            cfg = *ft_cli_collector_config(cli);
        else
            ft_agent_config_defaults(&cfg);
        /* A command that collects for itself is asked for files, whatever the service is given. */
        cfg.backend_cfg.mode = FT_MODE_STANDARD;
        cfg.socket_path = nullptr;
        cfg.session_fd = pair[1];
        /* Exporting is the agent's business, not that of one command's collector. */
        cfg.prometheus.enabled = false;
        cfg.otlp.enabled = false;
        cfg.api.enabled = false;
        _exit(ft_agent_run(&cfg, &err));
    }

    close(pair[1]);
    s->collector = pid;
    s->mode_overridden = ft_cli_collector_config(cli) &&
                         ft_cli_collector_config(cli)->backend_cfg.mode == FT_MODE_MINIMAL;
    if (wait_ms > 0) {
        struct pollfd pfd = {.fd = pair[0], .events = POLLIN};
        int n;
        while ((n = poll(&pfd, 1, wait_ms)) < 0 && errno == EINTR)
            continue;
        *failed = n > 0;
    }
    s->client = ft_client_adopt(pair[0]);
    if (!s->client) {
        fprintf(stderr, "filetrace: out of memory\n");
        ft_session_close(s);
        return FT_EXIT_ERROR;
    }
    return FT_EXIT_OK;
}

/* The first answer tells whether the collector could attach at all. */
static int first_answer(const struct ft_cli *cli, struct ft_session *s)
{
    struct ft_error err = {0};
    struct ft_query q;

    ft_query_init(&q, FT_Q_STATS);
    int code = ft_client_query(s->client, &q, nullptr, nullptr, nullptr, &err);
    if (code != FT_EXIT_OK) {
        ft_session_close(s);
        return ft_session_failed(cli, code, err.msg);
    }
    s->answered = true;
    return FT_EXIT_OK;
}

/* Returns FT_EXIT_NO_AGENT, with nothing reported yet, when no agent listens. */
static int connect_agent(const struct ft_cli *cli, struct ft_session *s, struct ft_error *err)
{
    *s = (struct ft_session){0};
    s->client = ft_client_connect(cli->socket_path, err);
    if (s->client)
        return FT_EXIT_OK;
    if (err->code == FT_EXIT_PERMISSION)
        return socket_denied(cli);
    if (err->code != FT_EXIT_NO_AGENT)
        fprintf(stderr, "%s\n", err->msg);
    return err->code;
}

int ft_session_open(const struct ft_cli *cli, bool allow_foreground, struct ft_session *s)
{
    struct ft_error err = {0};
    bool failed;

    int code = connect_agent(cli, s, &err);
    if (code != FT_EXIT_NO_AGENT)
        return code;
    if (!allow_foreground) {
        fprintf(stderr, "%s\n", err.msg);
        return code;
    }

    code = start_collector(cli, s, 0, &failed);
    if (code == FT_EXIT_OK)
        code = first_answer(cli, s);
    if (code != FT_EXIT_OK)
        return code;
    fprintf(stderr, "The Filetrace agent is not running; monitoring in the foreground for this\n"
                    "session. Only activity from now on is shown.\n");
    if (s->mode_overridden)
        fprintf(stderr, "The configuration file asks for minimal mode; this session collects in\n"
                        "standard mode, with files.\n");
    return FT_EXIT_OK;
}

int ft_session_start(const struct ft_cli *cli, struct ft_session *s)
{
    struct ft_error err = {0};
    bool failed;

    int code = connect_agent(cli, s, &err);
    if (code != FT_EXIT_NO_AGENT)
        return code;
    code = start_collector(cli, s, FAIL_FAST_MS, &failed);
    if (code == FT_EXIT_OK && failed)
        code = first_answer(cli, s);
    return code;
}

void ft_session_close(struct ft_session *s)
{
    ft_client_close(s->client);
    s->client = nullptr;
    if (s->collector > 0) {
        int status;
        if (!s->answered)
            kill(s->collector, SIGTERM);
        while (waitpid(s->collector, &status, 0) < 0 && errno == EINTR)
            continue;
        s->collector = 0;
    }
    s->answered = false;
}

void ft_session_release(struct ft_session *s)
{
    ft_client_close(s->client);
    s->client = nullptr;
    if (s->collector > 0 && !s->answered)
        kill(s->collector, SIGTERM);
    s->collector = 0;
    s->answered = false;
}

static void stats_collect(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct ft_row_stats *row = ctx;
    if (type == FT_MSG_ROW_STATS)
        memcpy(row, payload, size < sizeof(*row) ? size : sizeof(*row));
}

enum ft_agent_state ft_agent_ask(const struct ft_cli *cli, struct ft_row_stats *stats)
{
    struct ft_error err = {0};
    struct ft_client *c = ft_client_connect(cli->socket_path, &err);
    struct ft_query q;

    memset(stats, 0, sizeof(*stats));
    if (!c)
        return err.code == FT_EXIT_PERMISSION ? FT_AGENT_UNREACHABLE : FT_AGENT_STOPPED;
    ft_query_init(&q, FT_Q_STATS);
    int code = ft_client_query(c, &q, stats_collect, stats, nullptr, &err);
    ft_client_close(c);
    return code == FT_EXIT_OK ? FT_AGENT_RUNNING : FT_AGENT_UNREACHABLE;
}

static int agent_status(const struct ft_cli *cli)
{
    struct ft_error err = {0};
    struct ft_client *c = ft_client_connect(cli->socket_path, &err);

    if (!c) {
        if (err.code == FT_EXIT_NO_AGENT) {
            printf("Monitoring: STOPPED\n\nStart it with:\n  sudo filetrace agent run\n");
            return FT_EXIT_NO_AGENT;
        }
        fprintf(stderr, "%s\n", err.msg);
        return err.code;
    }

    struct ft_query q;
    struct ft_row_stats row = {0};
    char started[32];
    char uptime[32];

    ft_query_init(&q, FT_Q_STATS);
    int code = ft_client_query(c, &q, stats_collect, &row, nullptr, &err);
    ft_client_close(c);
    if (code != FT_EXIT_OK) {
        fprintf(stderr, "%s\n", err.msg);
        return code;
    }

    ft_format_time_local(row.start_wall_ns, started, sizeof(started));
    ft_format_duration(row.now_wall_ns > row.start_wall_ns ? row.now_wall_ns - row.start_wall_ns
                                                           : 0,
                       uptime, sizeof(uptime));
    printf("Monitoring: RUNNING\n"
           "Backend:    %s\n"
           "Mode:       %s\n"
           "PID:        %u\n"
           "Started:    %s\n"
           "Uptime:     %s\n"
           "Health:     %s\n",
           row.backend, row.mode, row.pid, started, uptime,
           row.health == FT_HEALTH_OK ? "Healthy" : "Degraded");
    return row.health == FT_HEALTH_OK ? FT_EXIT_OK : FT_EXIT_PARTIAL;
}

static int agent_stop(const struct ft_cli *cli)
{
    struct ft_error err = {0};
    struct ft_client *c = ft_client_connect(cli->socket_path, &err);

    if (!c) {
        fprintf(stderr, "%s\n", err.msg);
        return err.code;
    }
    int code = ft_client_shutdown(c, &err);
    ft_client_close(c);
    if (code != FT_EXIT_OK) {
        fprintf(stderr, "%s\n", err.msg);
        return code;
    }
    printf("The agent is stopping.\n");
    return FT_EXIT_OK;
}

int ft_cmd_agent(const struct ft_cli *cli, struct ft_args *a)
{
    const char *action = ft_args_take(a);

    if (!action)
        return ft_usage_error("agent", "missing action (expected run, status or stop)");

    if (strcmp(action, "status") == 0) {
        if (!ft_args_done(a))
            return ft_usage_error("agent", "unknown argument '%s'", ft_args_peek(a));
        return agent_status(cli);
    }
    if (strcmp(action, "stop") == 0) {
        if (!ft_args_done(a))
            return ft_usage_error("agent", "unknown argument '%s'", ft_args_peek(a));
        return agent_stop(cli);
    }
    if (strcmp(action, "run") == 0) {
        /* Hand over to the agent's own option parser, keeping --config and --socket. */
        int extra = a->argc - a->pos;
        char **argv = calloc((size_t)extra + 6, sizeof(char *));
        char config_opt[] = "--config";
        char socket_opt[] = "--socket";
        char name[] = "filetrace agent run";
        int n = 0;

        if (!argv)
            return FT_EXIT_ERROR;
        argv[n++] = name;
        if (cli->config_path) {
            argv[n++] = config_opt;
            argv[n++] = (char *)(uintptr_t)cli->config_path;
        }
        if (cli->socket_given) {
            argv[n++] = socket_opt;
            argv[n++] = (char *)(uintptr_t)cli->socket_path;
        }
        for (int i = 0; i < extra; i++)
            argv[n++] = a->argv[a->pos + i];

        int code = ft_agent_main(n, argv, "filetrace agent run");
        free(argv);
        return code;
    }
    return ft_usage_error("agent", "unknown action '%s' (expected run, status or stop)", action);
}
