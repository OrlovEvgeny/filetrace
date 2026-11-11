#include "cmd/cli.h"

#include "filetrace/format.h"
#include "ui/ui.h"

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
          "Live view of what the machine is sending: the file transfers in progress,\n"
          "with the process, the destination, the method and the current rate of\n"
          "each. When no daemon is running, collection runs in the foreground for as\n"
          "long as the command does.\n"
          "\n"
          "Options:\n"
          "  --interval <time>       Refresh interval (default: 1s)\n"
          "  --direction <dir>       Traffic that ranks processes and connections:\n"
          "                          outbound (default), inbound or both\n"
          "  --no-ui                 Print a snapshot per interval instead of a\n"
          "                          dashboard; the default when output is not a\n"
          "                          terminal\n",
          o);
    ft_query_args_help(o, FT_OPTS_WATCH & ~(uint32_t)FT_QO_LIMIT, FT_SORTS_WATCH, 0);
    fputs("  --limit <n>             Rows per table (default: as many as fit, or 10\n"
          "                          with --no-ui)\n"
          "\n"
          "--sort orders the transfers and defaults to rate. --file and --remote\n"
          "select transfers; the other filters apply to every view.\n"
          "\n"
          "Keys: f files, p processes, n network, space pause, ? help, q quit\n"
          "\n"
          "The line under the table counts the transfers in progress by confidence\n"
          "and the events lost since the collector started.\n"
          "\n"
          "Examples:\n"
          "  sudo filetrace watch\n"
          "  sudo filetrace watch --remote 203.0.113.0/24 --confidence exact\n"
          "  sudo filetrace watch --sort bytes --min-bytes 1MB --interval 2s\n"
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
    ft_query_args_help(o, FT_QO_PID | FT_QO_PROCESS | FT_QO_PROTOCOL | FT_QO_TIME | FT_QO_OUTPUT, 0,
                       FT_FORMATS_ALL);
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
    ft_query_args_help(o, FT_OPTS_TRANSFERS, FT_SORTS_TRANSFERS, FT_FORMATS_ALL);
}

static void help_files(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace files [options]\n"
          "\n"
          "Files associated with network transfers, most recent first: which process\n"
          "sent each file, to which address, how many bytes and by which method.\n"
          "Every row carries the confidence of the association.\n"
          "\n"
          "BYTES counts what the socket accepted from this file. It is neither the\n"
          "size of the file nor the bytes read from it; machine-readable formats\n"
          "carry all three as file.size, transfer.bytes_read and transfer.bytes_sent.\n"
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
          "Processes with network activity. OUTBOUND is the rate at which a process\n"
          "is sending now, FILES the distinct files it has sent, CONNECTIONS its open\n"
          "sockets. Ordered by outbound rate, then by bytes sent.\n"
          "\n"
          "Options:\n"
          "  --active-only           Only running processes with open connections\n"
          "  --include-children      Add each process's descendants to its totals\n",
          o);
    ft_query_args_help(o, FT_OPTS_PROCESSES, FT_SORTS_PROCESSES, FT_FORMATS_ALL);
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
          "Open and recently closed sockets, most recently active first. LOCAL and\n"
          "REMOTE are the two ends as this machine sees them: for a server the remote\n"
          "end is the client. The owning process of an accepted connection is known\n"
          "once it sends or receives. SOCKET is the ID that 'inspect socket' takes.\n"
          "\n"
          "Options:\n"
          "  --active                Only sockets that are open\n",
          o);
    ft_query_args_help(o, FT_OPTS_CONNECTIONS, FT_SORTS_CONNECTIONS, FT_FORMATS_ALL);
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
          "end acknowledged. FLOW is the ID that 'inspect flow' takes.\n"
          "\n"
          "Options:\n"
          "  --group-by <key>        Merge flows by process, remote, port or protocol\n"
          "  --direction <dir>       Order by inbound, outbound (default) or both\n"
          "  --active                Only flows with recent traffic\n",
          o);
    ft_query_args_help(o, FT_OPTS_FLOWS, FT_SORTS_FLOWS, FT_FORMATS_ALL);
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

static void help_inspect(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace inspect file <path>\n"
          "  filetrace inspect process <pid>\n"
          "  filetrace inspect socket <id>\n"
          "  filetrace inspect flow <id>\n"
          "  filetrace inspect ip <address|cidr>\n"
          "\n"
          "Everything known about one thing, from whichever side it is approached:\n"
          "\n"
          "  file     Who sent this file, to whom, how much and by which method\n"
          "  process  What this process is sending now, where to, and which files\n"
          "  socket   One socket: its ends, owner, traffic and the files sent on it\n"
          "  flow     One process's traffic with one remote endpoint on a socket\n"
          "  ip       Which processes talk to this address or network, and which\n"
          "           files were sent to it\n"
          "\n"
          "Socket and flow IDs are the SOCKET and FLOW columns of 'connections' and\n"
          "'flows'. A file is named by its path, with '*' wildcards if they match a\n"
          "single file.\n"
          "\n"
          "Options:\n"
          "  --since <when>          Only what was active at or after this time (10m,\n"
          "                          1h, 7d or an RFC 3339 timestamp)\n"
          "  --limit <n>             Rows per list (default: 20)\n"
          "  --format table|json     Output format (default: table)\n"
          "  --json                  Short for --format json\n"
          "  --output <file>         Write to a file instead of standard output\n"
          "\n"
          "History begins when the daemon starts and is kept in memory only; every\n"
          "report says from when it reaches.\n"
          "\n"
          "Examples:\n"
          "  filetrace inspect file /data/backup.tar.gz\n"
          "  filetrace inspect process 1245\n"
          "  filetrace inspect ip 203.0.113.0/24 --since 1h\n"
          "  filetrace inspect socket 928374 --json\n",
          o);
    fputs(confidence_levels, o);
    fputs(exit_codes, o);
}

static void help_events(FILE *o)
{
    fputs("Usage:\n"
          "  filetrace events [options]\n"
          "\n"
          "The collector's records in the order they were made, oldest first: what\n"
          "the other commands add up. Byte counts are gathered in the kernel and\n"
          "collected several times a second, so a network or transfer event carries\n"
          "the bytes of one such interval, not of one system call.\n"
          "\n"
          "Event types:\n"
          "  process_exec, process_fork, process_exit\n"
          "  socket_connect, socket_listen, socket_established, socket_close\n"
          "  file_seen        A file was read or sent for the first time\n"
          "  network_send     Bytes a socket accepted\n"
          "  network_receive  Bytes a socket delivered\n"
          "  file_transfer    File bytes attributed to a socket, with the method and\n"
          "                   the confidence of the association so far\n"
          "  event_loss       Events the collector could not record\n"
          "\n"
          "File opens and individual system calls are not recorded.\n"
          "\n"
          "Options:\n"
          "  --type <types>          Only these event types, separated by commas\n"
          "  --follow, -f            Keep printing events as they happen; starts at\n"
          "                          the present unless --since or --limit is given\n"
          "  --raw                   One line per event with every field unformatted\n",
          o);
    ft_query_args_help(o, FT_OPTS_EVENTS & ~(uint32_t)FT_QO_LIMIT, 0, FT_FORMATS_EVENTS);
    fputs("  --limit <n>             Only the most recent n events\n"
          "\n"
          "Past events come from a log of bounded size kept in memory: it holds only\n"
          "the most recent ones and starts empty when the daemon does. Without a\n"
          "running daemon, --follow collects in the foreground.\n"
          "\n"
          "Examples:\n"
          "  sudo filetrace events --follow\n"
          "  filetrace events --type file_transfer,network_send --pid 1245 --since 5m\n"
          "  filetrace events --file '/data/*' --remote 203.0.113.0/24\n"
          "  filetrace events --since 1h --format jsonl\n",
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
          "  filetrace doctor [--probes auto|trampoline|kprobe] [--json]\n"
          "\n"
          "Checks whether this machine can be monitored and how well:\n"
          "\n"
          "  the kernel, BTF, BPF and the capabilities needed to load programs;\n"
          "  PROBES    every instrumentation point, loaded into the kernel and\n"
          "            attached for the duration of the check, then removed;\n"
          "  FEATURES  what the attached probes add up to: [OK] in full, [WARN]\n"
          "            in part, [OFF] turned off, [NONE] not available;\n"
          "  EVENT PIPELINE\n"
          "            what the running agent received and dropped.\n"
          "\n"
          "A probe is reported as attached only if the kernel accepted the program\n"
          "and every kernel field it reads was found.\n"
          "\n"
          "Kernel functions are traced through BPF trampolines where the kernel has\n"
          "them and through kprobes otherwise; --probes checks one of the two.\n"
          "\n"
          "Examples:\n"
          "  sudo filetrace doctor\n"
          "  sudo filetrace doctor --probes kprobe\n"
          "  sudo filetrace doctor --json\n"
          "\n"
          "Exit codes:\n"
          "  0  READY                        5  UNAVAILABLE\n"
          "  3  NEEDS PRIVILEGES             9  DEGRADED: some probes are missing,\n"
          "                                     or the agent is losing events\n",
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

static void help_config(FILE *o)
{
    fprintf(o,
            "Usage:\n"
            "  filetrace config show\n"
            "  filetrace config validate [<file>]\n"
            "  filetrace config path\n"
            "\n"
            "show      Print every setting with the value in effect, in the format of\n"
            "          the configuration file. Without a file these are the defaults.\n"
            "validate  Check a configuration file and report what is wrong with it.\n"
            "path      Print which file is read.\n"
            "\n"
            "The file is %s, or $FILETRACE_CONFIG, or\n"
            "the one named with the global option --config. The agent reads it when it\n"
            "starts; its own command-line options override it. The commands take their\n"
            "default output format, and the socket to reach the agent on, from it.\n"
            "\n"
            "A setting that asks for something this build cannot do, such as\n"
            "[storage] enabled = true, is reported as a warning and ignored. An unknown\n"
            "setting or a value of the wrong kind is an error.\n"
            "\n"
            "Examples:\n"
            "  filetrace config show > /etc/filetrace/config.toml\n"
            "  filetrace config validate ./config.toml\n"
            "  filetrace --config ./config.toml config show\n"
            "\n"
            "Exit codes:\n"
            "  0  the configuration is usable    6  it is not\n",
            ft_config_default_path_text());
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

/* The commands of the everyday workflow come first; the rest follow them. */
static const struct command commands[] = {
    {"watch", "Live monitoring", ft_cmd_watch, help_watch},
    {"files", "File transfers", ft_cmd_files, help_files},
    {"processes", "Process activity", ft_cmd_processes, help_processes},
    {"connections", "Network connections", ft_cmd_connections, help_connections},
    {"flows", "Network flow details", ft_cmd_flows, help_flows},
    {"inspect", "Inspect a file, process, socket, flow or address", ft_cmd_inspect, help_inspect},
    {"events", "Raw events", ft_cmd_events, help_events},
    {"stats", "Agent statistics", ft_cmd_stats, help_stats},
    {"doctor", "System diagnostics", ft_cmd_doctor, help_doctor},
    {"config", "Show or validate the configuration", ft_cmd_config, help_config},
    {"version", "Version and build information", ft_cmd_version, help_version},
    {"top", "Highest-volume processes, files or destinations", ft_cmd_top, help_top},
    {"transfers", "Transfer records, with unattributed bytes", ft_cmd_transfers, help_transfers},
    {"capabilities", "Supported features", ft_cmd_capabilities, help_capabilities},
    {"daemon", "Run or control the background daemon", ft_cmd_daemon, help_daemon},
    {"help", "Help for a command", cmd_help, help_help},
};

constexpr size_t MAIN_COMMANDS = 11;

static void list_commands(FILE *o)
{
    fputs("Main commands:\n", o);
    for (size_t i = 0; i < FT_ARRAY_LEN(commands); i++) {
        if (i == MAIN_COMMANDS)
            fputs("\nMore commands:\n", o);
        fprintf(o, "  %-13s %s\n", commands[i].name, commands[i].summary);
    }
}

void ft_help_overview(FILE *o)
{
    fputs("Filetrace - File-to-Network Observability\n"
          "\n"
          "Usage:\n"
          "  filetrace [--socket <path>] [--config <path>] <command> [options]\n"
          "\n",
          o);
    list_commands(o);
    fprintf(o,
            "\n"
            "Global options:\n"
            "  --socket <path>   Daemon socket (default: %s,\n"
            "                    or $FILETRACE_SOCKET, or the configured one)\n"
            "  --config <path>   Configuration file (see 'filetrace help config')\n"
            "  -h, --help        Show help\n"
            "  --version         Show version information\n"
            "\n"
            "Start with:\n"
            "  sudo filetrace watch\n"
            "\n"
            "See 'filetrace help <command>' for a command's options and examples.\n",
            ft_default_socket_path());
}

void ft_status_overview(const struct ft_cli *cli, FILE *o)
{
    struct ft_row_stats *stats = calloc(1, sizeof(*stats));
    bool styled = ft_term_styled(o);
    char rate[32];

    if (!stats)
        return;
    fputs("Filetrace - File-to-Network Observability\n\n", o);
    switch (ft_agent_ask(cli, stats)) {
    case FT_AGENT_RUNNING: {
        /* Tenths of a percent of the events that reached the collector. */
        uint64_t delivered =
            stats->events_received
                ? (stats->events_received - stats->events_dropped) * 1000 / stats->events_received
                : 1000;
        ft_format_rate(stats->tx_rate, rate, sizeof(rate));
        fprintf(o, "%s\u25cf RUNNING%s   %s, %s mode\n", styled ? "\033[32m" : "",
                styled ? FT_STYLE_RESET : "", stats->backend, stats->mode);
        fprintf(o,
                "  %u active transfers   %u processes   %s outbound   "
                "%llu.%llu%% of events delivered\n",
                stats->active_transfers, stats->active_processes, rate,
                (unsigned long long)(delivered / 10), (unsigned long long)(delivered % 10));
        break;
    }
    case FT_AGENT_UNREACHABLE:
        fprintf(o, "%s\u25cf RUNNING%s   its socket is not accessible to this user; use sudo\n",
                styled ? "\033[33m" : "", styled ? FT_STYLE_RESET : "");
        break;
    default:
        fputs("\u25cb NOT RUNNING   'sudo filetrace watch' collects for as long as it runs;\n"
              "                'sudo filetrace daemon run' collects in the background\n",
              o);
        break;
    }
    free(stats);

    fputc('\n', o);
    list_commands(o);
    fputs("\nSee 'filetrace help' for the options, and 'filetrace help <command>' for a\n"
          "command's own.\n",
          o);
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
    const char *env_socket = getenv("FILETRACE_SOCKET");
    struct ft_cli cli = {0};
    struct ft_args args = {.argc = argc, .argv = argv, .pos = 1};
    const char *value;
    int r;

    if (env_socket && env_socket[0]) {
        cli.socket_path = env_socket;
        cli.socket_given = true;
    }
    for (;;) {
        if ((r = ft_args_value(&args, "--socket", &value)) != 0) {
            cli.socket_path = value;
            cli.socket_given = true;
        } else if ((r = ft_args_value(&args, "--config", &value)) != 0) {
            cli.config_path = value;
        } else {
            break;
        }
        if (r < 0)
            return FT_EXIT_USAGE;
    }

    const char *name = ft_args_take(&args);
    if (!name) {
        /* A broken configuration file has been reported; the overview is still due. */
        ft_cli_load_config(&cli);
        if (!cli.socket_path)
            cli.socket_path = ft_default_socket_path();
        ft_status_overview(&cli, stdout);
        ft_cli_free_config(&cli);
        return FT_EXIT_OK;
    }
    if (strcmp(name, "-h") == 0 || strcmp(name, "--help") == 0) {
        ft_help_overview(stdout);
        return FT_EXIT_OK;
    }
    if (strcmp(name, "--version") == 0)
        name = "version";

    const struct command *command = nullptr;
    for (size_t i = 0; i < FT_ARRAY_LEN(commands); i++) {
        if (strcmp(commands[i].name, name) == 0)
            command = &commands[i];
    }
    if (!command)
        return ft_usage_error(nullptr, "unknown command '%s'", name);

    /* 'daemon run' forwards its options, including --help, to the daemon. */
    if (command->run != cmd_help && wants_help(&args) &&
        !(command->run == ft_cmd_daemon && ft_args_peek(&args) &&
          strcmp(ft_args_peek(&args), "run") == 0)) {
        ft_help_command(stdout, name);
        return FT_EXIT_OK;
    }

    /* 'config' reads the file itself, to report on it rather than depend on it. */
    if (command->run != cmd_help && command->run != ft_cmd_config) {
        int code = ft_cli_load_config(&cli);
        if (code != FT_EXIT_OK)
            return code;
    }
    if (!cli.socket_path)
        cli.socket_path = ft_default_socket_path();

    int code = command->run(&cli, &args);
    ft_cli_free_config(&cli);
    return code;
}
