#include "cmd/cli.h"

#include <stdlib.h>
#include <string.h>

struct command {
    const char *name;
    const char *summary;
    int (*run)(const struct ft_cli *cli, struct ft_args *a);
    void (*help)(FILE *out);
};

static const char exit_codes[] =
    "\nExit codes:\n"
    "  0  success                      4  daemon unavailable\n"
    "  1  general error                5  unsupported platform or capability\n"
    "  2  invalid arguments            9  partial results: events were lost in\n"
    "  3  permission denied               the queried time range\n";

static const char confidence_levels[] =
    "\nConfidence:\n"
    "  EXACT     The kernel moved the file's data to the socket itself (sendfile).\n"
    "  INFERRED  A thread read the file and then sent on the socket. The payload\n"
    "            cannot be proven to come only from this file.\n"
    "  UNKNOWN   Bytes sent with no file that could be associated with them.\n"
    "A '*' after the level marks a transfer during which events were lost.\n";

static const char machine_output[] =
    "\nMachine-readable formats carry exact byte counts and RFC 3339 timestamps.\n";

static void help_watch(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace watch [options]\n"
          "\n"
          "Live overview: traffic totals, the processes sending the most, and the\n"
          "file transfers in progress. When no daemon is running, collection runs in\n"
          "the foreground for as long as the command does.\n"
          "\n"
          "Options:\n"
          "  --interval <time>       Refresh interval (default: 1s)\n"
          "  --direction <dir>       Rank processes by outbound (default) or inbound\n"
          "  --protocol tcp|udp      Only this protocol\n"
          "  --pid <pid>             Only this process\n"
          "  --process <name>        Only processes with this name\n"
          "  --limit <n>             Rows per section (default: 10)\n"
          "  --no-ui                 Print a snapshot per interval instead of a\n"
          "                          dashboard; the default when output is not a\n"
          "                          terminal\n"
          "\n"
          "Keys: q quit, p pause, ? help\n"
          "\n"
          "Examples:\n"
          "  sudo filetrace watch\n"
          "  sudo filetrace watch --interval 2s --protocol tcp\n"
          "  sudo filetrace watch --no-ui > activity.log\n",
          o);
    fputs(exit_codes, o);
}

static void help_top(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace top [processes|files|destinations|connections] [options]\n"
          "\n"
          "The highest-volume processes (default), files, remote addresses or\n"
          "connections by bytes sent.\n"
          "\n"
          "Options:\n",
          o);
    ft_query_args_help(o, FT_QO_PID | FT_QO_PROCESS | FT_QO_PROTOCOL | FT_QO_TIME | FT_QO_OUTPUT,
                       0);
    fputs("  --limit <n>             Number of rows (default: 10)\n"
          "\n"
          "Examples:\n"
          "  filetrace top\n"
          "  filetrace top files --since 1h\n"
          "  filetrace top destinations --protocol tcp --limit 20\n",
          o);
    fputs(machine_output, o);
    fputs(exit_codes, o);
}

static void help_transfer_options(FILE *o)
{
    ft_query_args_help(o, FT_OPTS_TRANSFERS, FT_SORTS_TRANSFERS);
}

static void help_files(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace files [options]\n"
          "\n"
          "Files associated with network transfers, most recent first. Every row\n"
          "carries the confidence of the association.\n"
          "\n"
          "Options:\n"
          "  --deleted               Only files that no longer have a directory entry\n"
          "  --include-unknown       Also list sent bytes with no associated file\n",
          o);
    help_transfer_options(o);
    fputs(confidence_levels, o);
    fputs("\nExamples:\n"
          "  filetrace files --active\n"
          "  filetrace files --path /data/report.csv\n"
          "  filetrace files --path '/data/*' --since 1h\n"
          "  filetrace files --confidence exact --min-bytes 100MB\n"
          "  filetrace files --jsonl\n"
          "\n"
          "--format quiet prints one file path per row.\n",
          o);
    fputs(machine_output, o);
    fputs(exit_codes, o);
}

static void help_transfers(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace transfers [options]\n"
          "\n"
          "Transfer records, most recent first, including sent bytes that could not\n"
          "be associated with a file (FILE shows 'unknown').\n"
          "\n"
          "Options:\n"
          "  --deleted               Only files that no longer have a directory entry\n",
          o);
    help_transfer_options(o);
    fputs(confidence_levels, o);
    fputs("\nExamples:\n"
          "  filetrace transfers --active\n"
          "  filetrace transfers --remote 203.0.113.42 --min-bytes 1GB\n"
          "  filetrace transfers --confidence unknown --since 30m\n"
          "\n"
          "--format quiet prints one transfer ID per row.\n",
          o);
    fputs(machine_output, o);
    fputs(exit_codes, o);
}

static void help_processes(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace processes [options]\n"
          "\n"
          "Processes with network activity and the bytes they sent and received,\n"
          "largest sender first.\n"
          "\n"
          "Options:\n"
          "  --active-only           Only running processes with open connections\n"
          "  --include-children      Add each process's descendants to its totals\n",
          o);
    ft_query_args_help(o, FT_OPTS_PROCESSES, FT_SORTS_PROCESSES);
    fputs("\nExamples:\n"
          "  filetrace processes --sort outbound\n"
          "  filetrace processes --name nginx --include-children\n"
          "  filetrace processes --format csv > processes.csv\n"
          "\n"
          "--format quiet prints one process ID per row.\n",
          o);
    fputs(machine_output, o);
    fputs(exit_codes, o);
}

static void help_connections(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace connections [options]\n"
          "\n"
          "Open and recently closed sockets, most recently active first. The owning\n"
          "process of an accepted connection is known once it sends or receives.\n"
          "\n"
          "Options:\n"
          "  --active                Only sockets that are open\n",
          o);
    ft_query_args_help(o, FT_OPTS_CONNECTIONS, FT_SORTS_CONNECTIONS);
    fputs("\nExamples:\n"
          "  filetrace connections --protocol tcp\n"
          "  filetrace connections --remote 203.0.113.42\n"
          "  filetrace connections --pid 1842 --state established\n"
          "\n"
          "--format quiet prints one socket ID per row.\n",
          o);
    fputs(machine_output, o);
    fputs(exit_codes, o);
}

static void help_flows(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace flows [options]\n"
          "\n"
          "Bytes exchanged per process, socket and remote endpoint, largest sender\n"
          "first. SENT counts bytes the local socket accepted, not bytes the remote\n"
          "end acknowledged.\n"
          "\n"
          "Options:\n"
          "  --group-by <key>        Merge flows by process, remote, port or protocol\n"
          "  --direction <dir>       Order by inbound, outbound (default) or both\n"
          "  --active                Only flows with recent traffic\n",
          o);
    ft_query_args_help(o, FT_OPTS_FLOWS, FT_SORTS_FLOWS);
    fputs("\nExamples:\n"
          "  filetrace flows --group-by remote\n"
          "  filetrace flows --pid 1842 --min-bytes 10MB\n"
          "  filetrace flows --direction inbound --since 1h\n"
          "\n"
          "--format quiet prints one flow ID per row.\n",
          o);
    fputs(machine_output, o);
    fputs(exit_codes, o);
}

static void help_stats(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace stats [events|buffers|resources] [options]\n"
          "\n"
          "The collector's own statistics: events received and lost, CPU and memory\n"
          "use, and how full its bounded tables are.\n"
          "\n"
          "Options:\n"
          "  --watch                 Repeat until interrupted\n"
          "  --interval <time>       Repeat at this interval (default: 1s)\n"
          "  --format table|json     Output format (default: table)\n"
          "  --json                  Short for --format json\n"
          "\n"
          "Examples:\n"
          "  filetrace stats\n"
          "  filetrace stats events --watch\n"
          "  filetrace stats --format json\n"
          "\n"
          "Exits with 9 while the collector reports recent event loss.\n",
          o);
    fputs(exit_codes, o);
}

static void help_doctor(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace doctor [--probes auto|trampoline|kprobe]\n"
          "\n"
          "Checks whether this machine can be monitored: kernel support, privileges\n"
          "and each instrumentation point. The probes are loaded and attached for\n"
          "the duration of the check, then removed.\n"
          "\n"
          "Kernel functions are traced through BPF trampolines where the kernel has\n"
          "them and through kprobes otherwise; --probes checks one of the two.\n"
          "\n"
          "Examples:\n"
          "  sudo filetrace doctor\n"
          "  sudo filetrace doctor --probes kprobe\n"
          "\n"
          "Exit codes:\n"
          "  0  monitoring available         5  monitoring unavailable\n"
          "  3  privileges missing           9  partial monitoring available\n",
          o);
}

static void help_capabilities(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace capabilities [--format table|json] [--json]\n"
          "\n"
          "Features available on this machine, each FULL, PARTIAL, UNAVAILABLE or\n"
          "DISABLED, with the reason. Asks the running daemon; without one, checks\n"
          "the machine directly, which needs the same privileges as the daemon.\n"
          "\n"
          "Examples:\n"
          "  filetrace capabilities\n"
          "  sudo filetrace capabilities --format json\n",
          o);
    fputs(exit_codes, o);
}

static void help_version(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace version\n"
          "\n"
          "Version, build and platform information, and whether the daemon is\n"
          "running.\n",
          o);
}

static void help_daemon(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace daemon run [options]\n"
          "  filetrace daemon status\n"
          "  filetrace daemon stop\n"
          "\n"
          "run     Collect in the foreground and serve queries, like filetraced.\n"
          "        Service managers should start filetraced directly.\n"
          "status  Report whether a daemon is serving the socket.\n"
          "stop    Ask the running daemon to stop.\n"
          "\n"
          "Options of 'run':\n"
          "  --mode <mode>             minimal or standard (default: standard)\n"
          "  --probes <kind>           auto, trampoline or kprobe (default: auto)\n"
          "  --flush-interval <time>   How often counters are collected (default: 250ms)\n"
          "  --queue-size <size>       Kernel event queue size (default: 4MB, or 1MB in\n"
          "                            minimal mode)\n"
          "  --correlation-window <time>\n"
          "                            Longest read-to-send gap that still associates\n"
          "                            a file with a send (default: 2s)\n"
          "  --log-level <level>       error, warn, info or debug (default: info)\n"
          "\n"
          "Examples:\n"
          "  sudo filetrace daemon run\n"
          "  sudo filetrace daemon run --mode minimal\n"
          "  sudo filetrace daemon status\n"
          "\n"
          "'status' exits with 0 when running, 4 when stopped, 9 when degraded.\n",
          o);
}

static void help_help(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace help [command]\n"
          "\n"
          "Shows the overview, or the help of one command.\n",
          o);
}

static int cmd_help(const struct ft_cli *cli, struct ft_args *a);

static const struct command commands[] = {
    {"watch", "Live system overview", ft_cmd_watch, help_watch},
    {"top", "Show top senders", ft_cmd_top, help_top},
    {"files", "Inspect file transfers", ft_cmd_files, help_files},
    {"transfers", "Inspect transfer records", ft_cmd_transfers, help_transfers},
    {"processes", "Inspect process activity", ft_cmd_processes, help_processes},
    {"connections", "Inspect network connections", ft_cmd_connections, help_connections},
    {"flows", "Inspect network flows", ft_cmd_flows, help_flows},
    {"stats", "Display collection statistics", ft_cmd_stats, help_stats},
    {"daemon", "Run or control the background daemon", ft_cmd_daemon, help_daemon},
    {"doctor", "Diagnose system compatibility", ft_cmd_doctor, help_doctor},
    {"capabilities", "Show supported features", ft_cmd_capabilities, help_capabilities},
    {"version", "Display version information", ft_cmd_version, help_version},
    {"help", "Show command help", cmd_help, help_help},
};

void ft_help_overview(FILE *o)
{
    fputs("Filetrace - File-to-Network Observability\n"
          "\n"
          "Usage:\n"
          "  filetrace [--socket <path>] <command> [options]\n"
          "\n"
          "Commands:\n",
          o);
    for (size_t i = 0; i < FT_ARRAY_LEN(commands); i++)
        fprintf(o, "  %-13s %s\n", commands[i].name, commands[i].summary);
    fprintf(o,
            "\n"
            "Global options:\n"
            "  --socket <path>   Daemon socket (default: %s,\n"
            "                    or $FILETRACE_SOCKET)\n"
            "  -h, --help        Show help\n"
            "  --version         Show version information\n"
            "\n"
            "Start with:\n"
            "  sudo filetrace watch\n"
            "\n"
            "See 'filetrace help <command>' for a command's options and examples.\n",
            ft_default_socket_path());
}

bool ft_help_command(FILE *out, const char *name)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(commands); i++) {
        if (strcmp(commands[i].name, name) == 0) {
            fprintf(out, "filetrace %s - %s\n\n", commands[i].name, commands[i].summary);
            commands[i].help(out);
            return true;
        }
    }
    return false;
}

static int cmd_help(const struct ft_cli *cli, struct ft_args *a)
{
    (void)cli;
    const char *name = ft_args_take(a);

    if (!name) {
        ft_help_overview(stdout);
        return FT_EXIT_OK;
    }
    if (!ft_help_command(stdout, name))
        return ft_usage_error(nullptr, "unknown command '%s'", name);
    return FT_EXIT_OK;
}

static bool wants_help(const struct ft_args *a)
{
    for (int i = a->pos; i < a->argc; i++) {
        if (strcmp(a->argv[i], "-h") == 0 || strcmp(a->argv[i], "--help") == 0)
            return true;
    }
    return false;
}

int main(int argc, char **argv)
{
    struct ft_cli cli = {.socket_path = getenv("FILETRACE_SOCKET")};
    struct ft_args args = {.argc = argc, .argv = argv, .pos = 1};
    const char *value;
    int r;

    if (!cli.socket_path || !cli.socket_path[0])
        cli.socket_path = ft_default_socket_path();

    while ((r = ft_args_value(&args, "--socket", &value)) != 0) {
        if (r < 0)
            return FT_EXIT_USAGE;
        cli.socket_path = value;
    }

    const char *name = ft_args_take(&args);
    if (!name || strcmp(name, "-h") == 0 || strcmp(name, "--help") == 0) {
        ft_help_overview(stdout);
        return FT_EXIT_OK;
    }
    if (strcmp(name, "--version") == 0)
        name = "version";

    for (size_t i = 0; i < FT_ARRAY_LEN(commands); i++) {
        if (strcmp(commands[i].name, name) != 0)
            continue;
        /* 'daemon run' forwards its options, including --help, to the daemon. */
        if (commands[i].run != cmd_help && wants_help(&args) &&
            !(commands[i].run == ft_cmd_daemon && ft_args_peek(&args) &&
              strcmp(ft_args_peek(&args), "run") == 0)) {
            ft_help_command(stdout, name);
            return FT_EXIT_OK;
        }
        return commands[i].run(&cli, &args);
    }
    return ft_usage_error(nullptr, "unknown command '%s'", name);
}
