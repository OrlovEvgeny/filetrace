#include "sim/sim.h"

#include "sim/scenario.h"

#include "agent/agent.h"
#include "filetrace/format.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

constexpr uint32_t MAX_TRANSFERS = 1'000'000;

static void on_signal(int signo)
{
    (void)signo;
    ft_agent_stop();
}

static void usage(FILE *out, const char *program)
{
    fprintf(out,
            "Usage:\n"
            "  %s --socket <path> [options]\n"
            "\n"
            "Runs the agent on made-up traffic, so every filetrace command can be tried\n"
            "without privileges on any system. The same seed gives the same traffic.\n"
            "\n"
            "Options:\n"
            "  --socket <path>      Listening socket (required)\n"
            "  --scenario <name>    edge (default), quiet or storm\n"
            "  --seed <n>           Seed of the pseudo-random sequence (default: 1)\n"
            "  --history <time>     Past activity to generate before serving, such as\n"
            "                       10m or 2h (default: 0)\n"
            "  --transfers <n>      Concurrent transfers of storm (default: 10000)\n"
            "  --log-level <level>  error, warn, info or debug (default: info)\n"
            "  -h, --help           Show this help\n"
            "\n"
            "Scenarios:\n"
            "  edge   A web, streaming and data host: nginx, php-fpm, kafka, backups and\n"
            "         replication, about 50 active transfers.\n"
            "  quiet  Three processes and a few transfers; often nothing is active.\n"
            "  storm  Short transfers of a few dozen processes to thousands of addresses.\n",
            program);
}

static bool option_value(int argc, char **argv, int *i, const char *name, const char **value)
{
    size_t len = strlen(name);
    const char *arg = argv[*i];

    if (strncmp(arg, name, len) != 0)
        return false;
    if (arg[len] == '=') {
        *value = arg + len + 1;
        return true;
    }
    if (arg[len] != '\0')
        return false;
    *value = *i + 1 < argc ? argv[++*i] : nullptr;
    return true;
}

static bool parse_history(const char *text, uint64_t *ns)
{
    if (strcmp(text, "0") == 0) {
        *ns = 0;
        return true;
    }
    return ft_parse_duration(text, ns);
}

int main(int argc, char **argv)
{
    struct ft_sim_options opt = {.scenario = "edge", .seed = 1, .transfers = 10000};
    enum ft_log_level level = FT_LOG_INFO;
    const char *socket_path = nullptr;
    const char *program = argc > 0 ? argv[0] : "ft_sim_agent";

    for (int i = 1; i < argc; i++) {
        const char *value = nullptr;
        bool ok = true;

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout, program);
            return FT_EXIT_OK;
        } else if (option_value(argc, argv, &i, "--socket", &value)) {
            socket_path = value;
            ok = value && value[0];
        } else if (option_value(argc, argv, &i, "--scenario", &value)) {
            opt.scenario = value;
            ok = value && ft_sim_scenario_known(value);
        } else if (option_value(argc, argv, &i, "--seed", &value)) {
            ok = value && ft_parse_u64(value, &opt.seed);
        } else if (option_value(argc, argv, &i, "--history", &value)) {
            ok = value && parse_history(value, &opt.history_ns);
        } else if (option_value(argc, argv, &i, "--transfers", &value)) {
            ok = value && ft_parse_u32(value, &opt.transfers) && opt.transfers > 0 &&
                 opt.transfers <= MAX_TRANSFERS;
        } else if (option_value(argc, argv, &i, "--log-level", &value)) {
            ok = value && ft_log_level_parse(value, &level);
        } else {
            fprintf(stderr, "%s: unknown option '%s'\n\n", program, argv[i]);
            usage(stderr, program);
            return FT_EXIT_USAGE;
        }
        if (!ok) {
            fprintf(stderr, "%s: invalid or missing value for '%s'\n\n", program, argv[i]);
            usage(stderr, program);
            return FT_EXIT_USAGE;
        }
    }
    if (!socket_path) {
        fprintf(stderr, "%s: --socket is required\n\n", program);
        usage(stderr, program);
        return FT_EXIT_USAGE;
    }

    ft_sim_configure(&opt);
    ft_log_set_level(level);

    struct ft_agent_config cfg;
    ft_agent_config_defaults(&cfg);
    cfg.backend = ft_sim_backend();
    cfg.socket_path = socket_path;
    if (strcmp(opt.scenario, "storm") == 0) {
        size_t room = (size_t)opt.transfers * 3;
        if (room > cfg.state_cfg.max_transfers) {
            cfg.state_cfg.max_transfers = room;
            cfg.state_cfg.max_sockets = room;
            cfg.state_cfg.max_flows = room;
        }
    }

    struct sigaction sa = {.sa_handler = on_signal};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);

    struct ft_error err = {0};
    int code = ft_agent_run(&cfg, &err);
    if (code != FT_EXIT_OK)
        fprintf(stderr, "%s\n", err.msg);
    return code;
}
