#include "unit/test.h"

#include "agent/config.h"
#include "filetrace/format.h"

#include <stdlib.h>
#include <unistd.h>

static char *write_file(const char *text)
{
    char *path = strdup("/tmp/filetrace-config-XXXXXX");
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    close(fd);
    return path;
}

static int load(struct ft_config *cfg, const char *text, struct ft_error *err)
{
    char *path = write_file(text);
    int code = ft_config_load(cfg, path, err);
    unlink(path);
    free(path);
    return code;
}

static bool warned(const struct ft_config *cfg, const char *about)
{
    for (size_t i = 0; i < cfg->warning_count; i++) {
        if (strstr(cfg->warnings[i], about))
            return true;
    }
    return false;
}

/* Every key is known; each one asking for what cannot be done draws a warning. */
static const char every_section[] = "[agent]\n"
                                    "enabled = true\n"
                                    "ring_buffer_size = \"64MB\"\n"
                                    "event_batch_size = 4096\n"
                                    "\n"
                                    "[network]\n"
                                    "tcp = true\n"
                                    "udp = true\n"
                                    "ipv4 = true\n"
                                    "ipv6 = true\n"
                                    "tc_egress = true\n"
                                    "\n"
                                    "[file]\n"
                                    "track_open = true\n"
                                    "track_read = true\n"
                                    "track_mmap = true\n"
                                    "track_sendfile = true\n"
                                    "track_splice = true\n"
                                    "\n"
                                    "[correlation]\n"
                                    "enabled = true\n"
                                    "track_fd_lifecycle = true\n"
                                    "track_process_lifecycle = true\n"
                                    "track_io_uring = true\n"
                                    "confidence_threshold = \"inferred\"\n"
                                    "\n"
                                    "[storage]\n"
                                    "enabled = true\n"
                                    "path = \"/var/lib/filetrace\"\n"
                                    "retention = \"7d\"\n"
                                    "\n"
                                    "[output]\n"
                                    "format = \"table\"\n"
                                    "timestamps = true\n"
                                    "\n"
                                    "[filters]\n"
                                    "exclude_processes = [\"systemd\"]\n"
                                    "exclude_paths = [\"/proc/*\", \"/sys/*\"]\n"
                                    "\n"
                                    "[limits]\n"
                                    "metric_series = 512\n"
                                    "\n"
                                    "[prometheus]\n"
                                    "enabled = true\n"
                                    "listen = \"127.0.0.1:9900\"\n"
                                    "\n"
                                    "[otlp]\n"
                                    "enabled = true\n"
                                    "endpoint = \"unix:/run/otelcol.sock\"\n"
                                    "metrics = false\n"
                                    "events = [\"file_transfer\", \"process_exec\"]\n"
                                    "file_paths = false\n"
                                    "batch_size = 256\n"
                                    "flush_interval = \"500ms\"\n"
                                    "timeout = \"3s\"\n"
                                    "\n"
                                    "[grpc]\n"
                                    "enabled = true\n"
                                    "listen = \"127.0.0.1:9500\"\n";

static void reads_every_section(void)
{
    struct ft_config *cfg = ft_config_new();
    struct ft_error err = {0};

    CHECK_U64(load(cfg, every_section, &err), FT_EXIT_OK);
    ft_config_finish(cfg);
    CHECK(cfg->enabled);
    CHECK_U64(cfg->agent.backend_cfg.queue_bytes, 64u * 1024 * 1024);
    CHECK_U64(cfg->agent.backend_cfg.drain_batch, 4096);
    CHECK(cfg->agent.backend_cfg.track_read);
    CHECK(cfg->agent.backend_cfg.track_sendfile);
    CHECK_U64(cfg->agent.state_cfg.min_confidence, FT_CONF_INFERRED);
    CHECK_U64(cfg->agent.state_cfg.exclude_process_count, 1);
    CHECK_STR(cfg->agent.state_cfg.exclude_processes[0], "systemd");
    CHECK_U64(cfg->agent.state_cfg.exclude_path_count, 2);
    CHECK_STR(cfg->agent.state_cfg.exclude_paths[1], "/sys/*");
    CHECK_STR(cfg->format, "table");
    CHECK_U64(cfg->agent.state_cfg.max_metric_series, 512);
    CHECK(cfg->agent.prometheus.enabled);
    CHECK_STR(cfg->agent.prometheus.listen, "127.0.0.1:9900");
    CHECK(cfg->agent.otlp.enabled);
    CHECK(cfg->agent.otlp.logs);
    CHECK(!cfg->agent.otlp.metrics);
    CHECK(!cfg->agent.otlp.file_paths);
    CHECK_STR(cfg->agent.otlp.endpoint, "unix:/run/otelcol.sock");
    CHECK_U64(cfg->agent.otlp.event_types, 1u << FT_REC_FILE_TRANSFER | 1u << FT_REC_PROCESS_EXEC);
    CHECK_U64(cfg->agent.otlp.batch_size, 256);
    CHECK_U64(cfg->agent.otlp.flush_interval_ns, 500 * FT_NS_PER_MS);
    CHECK_U64(cfg->agent.otlp.metrics_interval_ns, 30 * FT_NS_PER_SEC);
    CHECK_U64(cfg->agent.otlp.timeout_ns, 3 * FT_NS_PER_SEC);
    CHECK(cfg->agent.api.enabled);
    CHECK_STR(cfg->agent.api.listen, "127.0.0.1:9500");

    CHECK_U64(cfg->warning_count, 7);
    CHECK(warned(cfg, "[network] tc_egress"));
    CHECK(warned(cfg, "[file] track_open"));
    CHECK(warned(cfg, "[file] track_mmap"));
    CHECK(warned(cfg, "[file] track_splice"));
    CHECK(warned(cfg, "[correlation] track_fd_lifecycle"));
    CHECK(warned(cfg, "[correlation] track_io_uring"));
    CHECK(warned(cfg, "[storage] enabled"));
    ft_config_free(cfg);
}

static void applies_every_kind_of_value(void)
{
    struct ft_config *cfg = ft_config_new();
    struct ft_error err = {0};
    int code = load(cfg,
                    "# a comment\n"
                    "[agent]\n"
                    "mode = 'minimal'   # literal strings work too\n"
                    "probes = \"kprobe\"\n"
                    "socket = \"/run/ft/a \\\"b\\\".sock\"\n"
                    "flush_interval = \"100ms\"\n"
                    "log_level = \"debug\"\n"
                    "[network]\n"
                    "udp = false\n"
                    "ipv6 = false\n"
                    "[file]\n"
                    "track_read = false\n"
                    "[correlation]\n"
                    "window = \"5s\"\n"
                    "confidence_threshold = \"exact\"\n"
                    "inferred_min_bytes = 4096\n"
                    "inferred_min_percent = 20\n"
                    "[limits]\n"
                    "transfers = 1_000\n"
                    "kernel_counters = 2048\n"
                    "[output]\n"
                    "format = \"jsonl\"\n"
                    "timestamps = false\n"
                    "[filters]\n"
                    "exclude_paths = [\n"
                    "  \"/proc/*\",   # one per line\n"
                    "  \"/sys/*\",\n"
                    "]\n",
                    &err);

    CHECK_U64(code, FT_EXIT_OK);
    ft_config_finish(cfg);
    CHECK_U64(cfg->agent.backend_cfg.mode, FT_MODE_MINIMAL);
    CHECK_U64(cfg->agent.backend_cfg.probes, FT_PROBES_KPROBE);
    CHECK_STR(cfg->agent.socket_path, "/run/ft/a \"b\".sock");
    CHECK_U64(cfg->agent.flush_interval_ms, 100);
    CHECK_U64(cfg->log_level, FT_LOG_DEBUG);
    CHECK(cfg->agent.state_cfg.ignore_udp);
    CHECK(cfg->agent.state_cfg.ignore_ipv6);
    CHECK(!cfg->agent.state_cfg.ignore_tcp);
    CHECK(!cfg->agent.backend_cfg.track_read);
    CHECK(cfg->agent.backend_cfg.track_sendfile);
    CHECK_U64(cfg->agent.backend_cfg.corr_window_ns, 5 * FT_NS_PER_SEC);
    CHECK_U64(cfg->agent.state_cfg.min_confidence, FT_CONF_EXACT);
    CHECK_U64(cfg->agent.state_cfg.inferred_min_bytes, 4096);
    CHECK_U64(cfg->agent.state_cfg.inferred_min_permille, 200);
    CHECK_U64(cfg->agent.state_cfg.max_transfers, 1000);
    CHECK_U64(cfg->agent.backend_cfg.agg_entries, 2048);
    CHECK_STR(cfg->format, "jsonl");
    CHECK(!cfg->timestamps);
    CHECK_U64(cfg->exclude_path_count, 2);
    CHECK_U64(cfg->warning_count, 0);
    /* Minimal mode shrinks what the file left unset. */
    CHECK_U64(cfg->agent.backend_cfg.queue_bytes, 1024 * 1024);
    CHECK_U64(cfg->agent.state_cfg.event_log_bytes, 256 * 1024);
    ft_config_free(cfg);
}

static void rejects(const char *text, const char *expected)
{
    struct ft_config *cfg = ft_config_new();
    struct ft_error err = {0};

    CHECK_U64(load(cfg, text, &err), FT_EXIT_CONFIG);
    if (!strstr(err.msg, expected)) {
        printf("message is \"%s\", expected it to contain \"%s\"\n", err.msg, expected);
        CHECK(false);
    }
    ft_config_free(cfg);
}

static void accepts(const char *text)
{
    struct ft_config *cfg = ft_config_new();
    struct ft_error err = {0};

    if (load(cfg, text, &err) != FT_EXIT_OK) {
        printf("refused \"%s\": %s\n", text, err.msg);
        CHECK(false);
    }
    ft_config_free(cfg);
}

static void reports_what_is_wrong(void)
{
    rejects("[agent]\nenabled = true\ntrak_open = true\n",
            ":3: unknown setting 'trak_open' in [agent]");
    rejects("[agents]\n", ":1: unknown section [agents]");
    rejects("enabled = true\n", ":1: 'enabled' is set before any [section]");
    rejects("[agent]\nenabled = \"yes\"\n", ":2: [agent] enabled: expected true or false");
    rejects("[agent]\nring_buffer_size = 64MB\n", ":2: expected a whole number; quote sizes");
    rejects("[agent]\nring_buffer_size = \"1KB\"\n",
            "[agent] ring_buffer_size: expected a size from");
    rejects("[agent]\nmode = \"detailed\"\n", "expected \"minimal\" or \"standard\"");
    rejects("[correlation]\nconfidence_threshold = \"unknown\"\n", "expected \"inferred\"");
    rejects("[limits]\nflows = 3\n", "[limits] flows: expected a whole number from 64");
    rejects("[filters]\nexclude_paths = \"/proc/*\"\n", "expected a list of strings");
    rejects("[correlation]\nno_minimum_paths = \"/etc/*\"\n", "expected a list of strings");
    rejects("[correlation]\nbackground_paths = [\"\"]\n", "a pattern is empty");
    rejects("[filters]\nexclude_paths = [\"/proc/*\"\n", "expected ',' or ']'");
    rejects("[otlp]\nevents = [\"file_sent\"]\n", "\"file_sent\" is not an event type");
    rejects("[otlp]\nbatch_size = 5\n", "[otlp] batch_size: expected a whole number from 16");
    rejects("[prometheus]\nport = 9464\n", "unknown setting 'port' in [prometheus]");
    rejects("[agent]\nsocket = \"/run/x\n", ":2: the string is not closed");
    rejects("[agent]\nenabled = true false\n", ":2: unexpected text after the value");
    rejects("[prometheus]\nenabled = true\nlisten = \"9464\"\n",
            "[prometheus] listen = \"9464\" is not an address and port");
    rejects("[prometheus]\nenabled = true\nlisten = \"unix:/run/metrics.sock\"\n",
            "[prometheus] listen = \"unix:/run/metrics.sock\" is not an address and port");
    rejects("[otlp]\nendpoint = \"collector:4317\"\nenabled = true\n",
            "[otlp] endpoint = \"collector:4317\" is not a numeric address and port");
    rejects("[grpc]\nenabled = true\nlisten = \"/run/filetrace/api.sock\"\n",
            "[grpc] listen = \"/run/filetrace/api.sock\" is neither \"unix:\"");

    accepts("[prometheus]\nenabled = true\nlisten = \"[::1]:9464\"\n");
    accepts("[otlp]\nenabled = true\nendpoint = \"unix:/run/collector.sock\"\n");
    accepts("[grpc]\nenabled = true\nlisten = \"unix:/run/filetrace/api.sock\"\n");
    /* A section that is off, or an exporter with nothing to send, is not started. */
    accepts("[grpc]\nlisten = \"api.sock\"\n");
    accepts("[otlp]\nenabled = true\nlogs = false\nmetrics = false\n"
            "endpoint = \"collector:4317\"\n");

    struct ft_config *cfg = ft_config_new();
    struct ft_error err = {0};
    CHECK_U64(ft_config_load(cfg, "/nonexistent/filetrace.toml", &err), FT_EXIT_CONFIG);
    CHECK(strstr(err.msg, "/nonexistent/filetrace.toml") != nullptr);
    ft_config_free(cfg);
}

static void prints_what_it_reads(void)
{
    struct ft_config *first = ft_config_new();
    struct ft_config *second = ft_config_new();
    struct ft_error err = {0};
    char *text = nullptr;
    size_t size = 0;

    CHECK_U64(load(first, every_section, &err), FT_EXIT_OK);
    ft_config_finish(first);
    FILE *mem = open_memstream(&text, &size);
    ft_config_print(first, mem);
    fclose(mem);

    CHECK_U64(load(second, text, &err), FT_EXIT_OK);
    ft_config_finish(second);
    CHECK_U64(second->agent.backend_cfg.queue_bytes, first->agent.backend_cfg.queue_bytes);
    CHECK_U64(second->agent.backend_cfg.drain_batch, 4096);
    CHECK_U64(second->agent.state_cfg.event_log_bytes, first->agent.state_cfg.event_log_bytes);
    CHECK_U64(second->exclude_path_count, 2);
    CHECK_STR(second->exclude_paths[0], "/proc/*");
    CHECK_U64(second->warning_count, first->warning_count);
    CHECK_U64(second->storage_retention_ns, first->storage_retention_ns);
    CHECK(second->agent.prometheus.enabled);
    CHECK_STR(second->agent.prometheus.listen, "127.0.0.1:9900");
    CHECK_U64(second->agent.otlp.event_types, first->agent.otlp.event_types);
    CHECK_U64(second->agent.otlp.flush_interval_ns, 500 * FT_NS_PER_MS);
    CHECK(!second->agent.otlp.file_paths);
    CHECK_STR(second->agent.api.listen, "127.0.0.1:9500");

    /* Printing the defaults reads back without a warning. */
    free(text);
    text = nullptr;
    struct ft_config *defaults = ft_config_new();
    mem = open_memstream(&text, &size);
    ft_config_print(defaults, mem);
    fclose(mem);
    struct ft_config *reread = ft_config_new();
    CHECK_U64(load(reread, text, &err), FT_EXIT_OK);
    CHECK_U64(reread->warning_count, 0);
    CHECK_U64(reread->agent.state_cfg.max_flows, defaults->agent.state_cfg.max_flows);
    CHECK_U64(reread->agent.backend_cfg.corr_window_ns, defaults->agent.backend_cfg.corr_window_ns);
    CHECK_U64(reread->background_path_count, defaults->background_path_count);
    CHECK_STR(reread->background_paths[0], defaults->background_paths[0]);

    free(text);
    ft_config_free(first);
    ft_config_free(second);
    ft_config_free(defaults);
    ft_config_free(reread);
}

/* The trust stores and resolver files are background unless the list is replaced or emptied. */
static void background_paths_default_to_shared_files(void)
{
    struct ft_config *cfg = ft_config_new();
    struct ft_error err = {0};

    ft_config_finish(cfg);
    const struct ft_backend_config *backend = &cfg->agent.backend_cfg;
    bool bundle = false;
    bool passwd = false;
    for (size_t i = 0; i < backend->background_path_count; i++) {
        const char *pattern = backend->background_paths[i];
        if (ft_glob_match(pattern, "/etc/ssl/certs/ca-certificates.crt"))
            bundle = true;
        if (ft_glob_match(pattern, "/etc/passwd"))
            passwd = true;
        CHECK(!ft_glob_match(pattern, "/etc/ssl/private/server.key"));
    }
    CHECK(bundle);
    CHECK(passwd);

    CHECK_U64(load(cfg, "[correlation]\nbackground_paths = []\n", &err), FT_EXIT_OK);
    ft_config_finish(cfg);
    CHECK_U64(backend->background_path_count, 0);

    CHECK_U64(load(cfg, "[correlation]\nbackground_paths = [\"/opt/app/ca.pem\"]\n", &err),
              FT_EXIT_OK);
    ft_config_finish(cfg);
    CHECK_U64(backend->background_path_count, 1);
    CHECK_STR(backend->background_paths[0], "/opt/app/ca.pem");
    ft_config_free(cfg);
}

void test_config(void)
{
    reads_every_section();
    applies_every_kind_of_value();
    reports_what_is_wrong();
    prints_what_it_reads();
    background_paths_default_to_shared_files();
}
