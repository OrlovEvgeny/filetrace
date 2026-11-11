#include "cmd/cli.h"

#include "daemon/config.h"

#include <string.h>

enum ft_format ft_cli_format(const struct ft_cli *cli, uint32_t accepted)
{
    static const char *const names[] = {"table", "json", "jsonl", "csv", "quiet"};

    for (size_t i = 0; cli->config && i < FT_ARRAY_LEN(names); i++) {
        if (strcmp(cli->config->format, names[i]) == 0 && (accepted & FT_FMT_BIT(i)))
            return (enum ft_format)i;
    }
    return FT_FMT_TABLE;
}

bool ft_cli_timestamps(const struct ft_cli *cli)
{
    return !cli->config || cli->config->timestamps;
}

const struct ft_daemon_config *ft_cli_collector_config(const struct ft_cli *cli)
{
    return cli->config ? &cli->config->daemon : nullptr;
}

int ft_cli_load_config(struct ft_cli *cli)
{
    struct ft_config *config = ft_config_new();
    struct ft_error err = {0};

    if (!config) {
        fprintf(stderr, "filetrace: out of memory\n");
        return FT_EXIT_ERROR;
    }
    if (ft_config_load(config, cli->config_path, &err) != FT_EXIT_OK) {
        fprintf(stderr, "%s\n\nCheck the file with:\n  filetrace config validate %s\n", err.msg,
                cli->config_path ? cli->config_path : ft_config_default_path());
        ft_config_free(config);
        return FT_EXIT_CONFIG;
    }
    ft_config_finish(config);
    cli->config = config;
    if (!cli->socket_path)
        cli->socket_path = config->daemon.socket_path;
    return FT_EXIT_OK;
}

void ft_cli_free_config(struct ft_cli *cli)
{
    /* The socket path may live in the configuration. */
    cli->socket_path = nullptr;
    ft_config_free((struct ft_config *)(uintptr_t)cli->config);
    cli->config = nullptr;
}

const char *ft_config_default_path_text(void)
{
    return "/etc/filetrace/config.toml";
}

static void print_warnings(const struct ft_config *config)
{
    for (size_t i = 0; i < config->warning_count; i++)
        fprintf(stderr, "warning: %s\n", config->warnings[i]);
}

int ft_cmd_config(const struct ft_cli *cli, struct ft_args *a)
{
    const char *action = ft_args_take(a);
    const char *path = cli->config_path;
    const char *v;
    int r;

    if (!action)
        return ft_usage_error("config", "missing action (expected show, validate or path)");
    if (strcmp(action, "show") != 0 && strcmp(action, "validate") != 0 &&
        strcmp(action, "path") != 0)
        return ft_usage_error("config", "unknown action '%s' (expected show, validate or path)",
                              action);

    while (!ft_args_done(a)) {
        if ((r = ft_args_value(a, "--config", &v)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            path = v;
        } else if (strcmp(action, "validate") == 0 && ft_args_peek(a)[0] != '-') {
            path = ft_args_take(a);
        } else {
            return ft_usage_error("config", "unknown argument '%s'", ft_args_peek(a));
        }
    }

    const char *shown = path ? path : ft_config_default_path();
    if (strcmp(action, "path") == 0) {
        printf("%s\n", shown);
        return FT_EXIT_OK;
    }

    struct ft_config *config = ft_config_new();
    struct ft_error err = {0};
    if (!config)
        return FT_EXIT_ERROR;
    if (ft_config_load(config, path, &err) != FT_EXIT_OK) {
        fprintf(stderr, "%s\n", err.msg);
        ft_config_free(config);
        return FT_EXIT_CONFIG;
    }
    ft_config_finish(config);

    if (strcmp(action, "validate") == 0) {
        if (!config->source[0])
            printf("No configuration file at %s; the built-in defaults apply.\n", shown);
        else if (config->warning_count)
            printf("%s is valid, with %zu %s.\n", config->source, config->warning_count,
                   config->warning_count == 1 ? "warning" : "warnings");
        else
            printf("%s is valid.\n", config->source);
    } else {
        if (config->source[0])
            printf("# Settings in effect, read from %s.\n\n", config->source);
        else
            printf("# Built-in defaults; there is no configuration file at %s.\n\n", shown);
        ft_config_print(config, stdout);
    }
    fflush(stdout);
    print_warnings(config);
    ft_config_free(config);
    return FT_EXIT_OK;
}
