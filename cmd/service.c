#include "cmd/cli.h"

#include "agent/agent.h"
#include "filetrace/format.h"

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

/* The collector serves only this process and stops when the session closes. */
static int start_collector(const struct ft_cli *cli, struct ft_session *s)
{
    int pair[2];

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
        if (ft_cli_collector_config(cli))
            cfg = *ft_cli_collector_config(cli);
        else
            ft_agent_config_defaults(&cfg);
        cfg.socket_path = nullptr;
        cfg.session_fd = pair[1];
        _exit(ft_agent_run(&cfg, &err));
    }

    close(pair[1]);
    s->client = ft_client_adopt(pair[0]);
    s->collector = pid;
    if (!s->client) {
        fprintf(stderr, "filetrace: out of memory\n");
        ft_session_close(s);
        return FT_EXIT_ERROR;
    }
    return FT_EXIT_OK;
}

int ft_session_open(const struct ft_cli *cli, bool allow_foreground, struct ft_session *s)
{
    struct ft_error err = {0};

    s->collector = 0;
    s->client = ft_client_connect(cli->socket_path, &err);
    if (s->client)
        return FT_EXIT_OK;

    if (err.code != FT_EXIT_NO_AGENT || !allow_foreground) {
        fprintf(stderr, "%s\n", err.msg);
        return err.code;
    }

    int code = start_collector(cli, s);
    if (code != FT_EXIT_OK)
        return code;

    /* The first reply tells whether the collector could attach at all. */
    struct ft_query q;
    ft_query_init(&q, FT_Q_STATS);
    code = ft_client_query(s->client, &q, nullptr, nullptr, nullptr, &err);
    if (code != FT_EXIT_OK) {
        fprintf(stderr, "%s\n", err.msg);
        ft_session_close(s);
        return code;
    }
    fprintf(stderr, "The Filetrace agent is not running; monitoring in the foreground for this\n"
                    "session. Only activity from now on is shown.\n");
    return FT_EXIT_OK;
}

void ft_session_close(struct ft_session *s)
{
    ft_client_close(s->client);
    s->client = nullptr;
    if (s->collector > 0) {
        int status;
        while (waitpid(s->collector, &status, 0) < 0 && errno == EINTR)
            continue;
        s->collector = 0;
    }
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
