#include "daemon/config.h"

#include "filetrace/format.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>

static void on_signal(int signo)
{
    (void)signo;
    ft_daemon_stop();
}

static void usage(FILE *out, const char *program)
{
    fprintf(out,
            "Usage:\n"
            "  %s [options]\n"
            "\n"
            "Collects file-to-network activity in the foreground and serves\n"
            "queries from the filetrace command over a local socket.\n"
            "\n"
            "Settings come from the configuration file; an option given here\n"
            "overrides the file.\n"
            "\n"
            "Options:\n"
            "  --config <path>           Configuration file (default: %s,\n"
            "                            if it exists)\n"
            "  --socket <path>           Listening socket (default: %s)\n"
            "  --mode <mode>             minimal or standard (default: standard)\n"
            "  --probes <kind>           auto, trampoline or kprobe (default: auto)\n"
            "  --flush-interval <time>   How often counters are collected (default: 250ms)\n"
            "  --queue-size <size>       Kernel event queue size (default: 4MB, or 1MB\n"
            "                            in minimal mode)\n"
            "  --event-log-size <size>   Memory for the log of recent events; 0 keeps\n"
            "                            none (default: 1MB, or 256KB in minimal mode)\n"
            "  --correlation-window <time>\n"
            "                            Longest read-to-send gap that still\n"
            "                            associates a file with a send (default: 2s)\n"
            "  --log-level <level>       error, warn, info or debug (default: info)\n"
            "  -h, --help                Show this help\n"
            "\n"
            "Modes:\n"
            "  minimal    Processes, sockets and network byte counts.\n"
            "  standard   Adds file identity and file-to-network attribution.\n"
            "\n"
            "'filetrace config show' prints every setting of the configuration file.\n"
            "\n"
            "Exit codes:\n"
            "  0 stopped normally, 2 invalid arguments, 3 permission denied,\n"
            "  5 unsupported platform or kernel, 6 invalid configuration,\n"
            "  1 other errors.\n",
            program, ft_config_default_path(), ft_default_socket_path());
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

static int run(struct ft_config *config, int argc, char **argv, const char *program)
{
    struct ft_daemon_config *cfg = &config->daemon;
    struct ft_error err = {0};
    const char *config_path = nullptr;

    /* The file is read before the other options, which override it wherever they stand. */
    for (int i = 1; i < argc; i++) {
        const char *value = nullptr;
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(stdout, program);
            return FT_EXIT_OK;
        }
        if (option_value(argc, argv, &i, "--config", &value)) {
            if (!value || !value[0]) {
                fprintf(stderr, "%s: invalid or missing value for '--config'\n", program);
                return FT_EXIT_USAGE;
            }
            config_path = value;
        }
    }
    if (ft_config_load(config, config_path, &err) != FT_EXIT_OK) {
        fprintf(stderr, "%s\n", err.msg);
        return err.code;
    }

    for (int i = 1; i < argc; i++) {
        const char *value = nullptr;
        const char *arg = argv[i];
        uint64_t number;
        bool ok = true;

        if (option_value(argc, argv, &i, "--config", &value)) {
            continue;
        } else if (option_value(argc, argv, &i, "--socket", &value)) {
            ok = value && value[0] && strlen(value) < sizeof(config->socket_path);
            if (ok)
                ft_strlcpy(config->socket_path, value, sizeof(config->socket_path));
        } else if (option_value(argc, argv, &i, "--mode", &value)) {
            ok = value && ft_mode_parse(value, &cfg->backend_cfg.mode);
        } else if (option_value(argc, argv, &i, "--probes", &value)) {
            ok = value && ft_probes_parse(value, &cfg->backend_cfg.probes);
        } else if (option_value(argc, argv, &i, "--flush-interval", &value)) {
            ok = value && ft_parse_duration(value, &number) && number >= 10 * FT_NS_PER_MS &&
                 number <= 60 * FT_NS_PER_SEC;
            if (ok)
                cfg->flush_interval_ms = (uint32_t)(number / FT_NS_PER_MS);
        } else if (option_value(argc, argv, &i, "--queue-size", &value)) {
            ok = value && ft_parse_size(value, &number) && number >= 64 * 1024 &&
                 number <= 1024u * 1024u * 1024u;
            if (ok)
                cfg->backend_cfg.queue_bytes = (uint32_t)number;
            config->queue_size_set = true;
        } else if (option_value(argc, argv, &i, "--event-log-size", &value)) {
            ok = value && ft_parse_size(value, &number) &&
                 (number == 0 || (number >= 64 * 1024 && number <= 256u * 1024u * 1024u));
            if (ok)
                cfg->state_cfg.event_log_bytes = (size_t)number;
            config->event_log_size_set = true;
        } else if (option_value(argc, argv, &i, "--correlation-window", &value)) {
            ok = value && ft_parse_duration(value, &number) && number > 0;
            if (ok)
                cfg->backend_cfg.corr_window_ns = number;
        } else if (option_value(argc, argv, &i, "--log-level", &value)) {
            ok = value && ft_log_level_parse(value, &config->log_level);
        } else {
            fprintf(stderr, "%s: unknown option '%s'\n\n", program, arg);
            usage(stderr, program);
            return FT_EXIT_USAGE;
        }
        if (!ok) {
            fprintf(stderr, "%s: invalid or missing value for '%s'\n\n", program, arg);
            usage(stderr, program);
            return FT_EXIT_USAGE;
        }
    }
    ft_config_finish(config);

    ft_log_set_level(config->log_level);
    if (config->source[0])
        ft_log(FT_LOG_INFO, "settings read from %s", config->source);
    for (size_t i = 0; i < config->warning_count; i++)
        ft_log(FT_LOG_WARN, "%s: %s", config->source, config->warnings[i]);
    if (!config->enabled) {
        ft_log(FT_LOG_WARN, "%s sets [agent] enabled = false: not collecting", config->source);
        return FT_EXIT_OK;
    }

    struct sigaction sa = {.sa_handler = on_signal};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    int code = ft_daemon_run(cfg, &err);
    if (code != FT_EXIT_OK)
        fprintf(stderr, "%s\n", err.msg);
    return code;
}

int ft_daemon_main(int argc, char **argv, const char *program)
{
    struct ft_config *config = ft_config_new();
    if (!config) {
        fprintf(stderr, "%s: out of memory\n", program);
        return FT_EXIT_ERROR;
    }
    int code = run(config, argc, argv, program);
    ft_config_free(config);
    return code;
}
