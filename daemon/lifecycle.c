#include "daemon/daemon.h"

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
            "Options:\n"
            "  --socket <path>           Listening socket (default: %s)\n"
            "  --mode <mode>             minimal or standard (default: standard)\n"
            "  --flush-interval <time>   How often counters are collected (default: 250ms)\n"
            "  --queue-size <size>       Kernel event queue size (default: 4MB)\n"
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
            "Exit codes:\n"
            "  0 stopped normally, 2 invalid arguments, 3 permission denied,\n"
            "  5 unsupported platform or kernel, 1 other errors.\n",
            program, ft_default_socket_path());
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

int ft_daemon_main(int argc, char **argv, const char *program)
{
    struct ft_daemon_config cfg;
    enum ft_log_level log_level = FT_LOG_INFO;

    ft_daemon_config_defaults(&cfg);

    for (int i = 1; i < argc; i++) {
        const char *value = nullptr;
        const char *arg = argv[i];
        uint64_t number;
        bool ok = true;

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            usage(stdout, program);
            return FT_EXIT_OK;
        } else if (option_value(argc, argv, &i, "--socket", &value)) {
            ok = value && value[0];
            cfg.socket_path = value;
        } else if (option_value(argc, argv, &i, "--mode", &value)) {
            ok = value && ft_mode_parse(value, &cfg.backend_cfg.mode);
        } else if (option_value(argc, argv, &i, "--flush-interval", &value)) {
            ok = value && ft_parse_duration(value, &number) && number >= 10 * FT_NS_PER_MS &&
                 number <= 60 * FT_NS_PER_SEC;
            if (ok)
                cfg.flush_interval_ms = (uint32_t)(number / FT_NS_PER_MS);
        } else if (option_value(argc, argv, &i, "--queue-size", &value)) {
            ok = value && ft_parse_size(value, &number) && number >= 64 * 1024 &&
                 number <= 1024u * 1024u * 1024u;
            if (ok)
                cfg.backend_cfg.queue_bytes = (uint32_t)number;
        } else if (option_value(argc, argv, &i, "--correlation-window", &value)) {
            ok = value && ft_parse_duration(value, &number) && number > 0;
            if (ok)
                cfg.backend_cfg.corr_window_ns = number;
        } else if (option_value(argc, argv, &i, "--log-level", &value)) {
            ok = value && ft_log_level_parse(value, &log_level);
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

    ft_log_set_level(log_level);

    struct sigaction sa = {.sa_handler = on_signal};
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    struct ft_error err = {0};
    int code = ft_daemon_run(&cfg, &err);
    if (code != FT_EXIT_OK)
        fprintf(stderr, "%s\n", err.msg);
    return code;
}
