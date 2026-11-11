#include "unit/test.h"

#include "exporters/exporters.h"
#include "filetrace/schema.h"
#include "filetrace/state.h"

#include <stdlib.h>

static char *render(const struct ft_state *st, const struct ft_row_stats *stats, uint64_t cpu_ns)
{
    static const struct ft_metric_attr resource[] = {
        {FT_ATTR_SERVICE_NAME, "filetrace"},
        {FT_ATTR_HOST_NAME, "web-01"},
    };
    struct ft_metrics_input in = {.series = st->series, .stats = stats, .cpu_ns = cpu_ns};
    struct ft_prometheus writer;
    char *text = nullptr;
    size_t size = 0;

    FILE *mem = open_memstream(&text, &size);
    ft_prometheus_begin(&writer, mem, resource, FT_ARRAY_LEN(resource));
    ft_metrics_collect(&in, ft_prometheus_point, &writer);
    fclose(mem);
    return text;
}

static void flow(struct ft_state *st, uint32_t pid, uint64_t sock, uint16_t proto, uint64_t tx,
                 uint64_t rx)
{
    struct ft_event ev = {.type = FT_EVENT_FLOW, .ts_ns = FT_NS_PER_SEC};

    ev.flow.sock_id = sock;
    ev.flow.pid = pid;
    ev.flow.proto = proto;
    ev.flow.tx_bytes = tx;
    ev.flow.rx_bytes = rx;
    ft_state_ingest(st, &ev);
}

static void process(struct ft_state *st, uint32_t pid, const char *comm)
{
    struct ft_event ev = {.type = FT_EVENT_PROCESS_EXEC, .ts_ns = FT_NS_PER_SEC};

    ev.process.pid = pid;
    ev.process.start_ns = FT_NS_PER_SEC;
    ft_strlcpy(ev.process.comm, comm, sizeof(ev.process.comm));
    ft_state_ingest(st, &ev);
}

static void transfer(struct ft_state *st, uint32_t pid, uint64_t sock, enum ft_method method,
                     uint64_t bytes, uint64_t read_bytes)
{
    struct ft_event ev = {.type = FT_EVENT_TRANSFER, .ts_ns = FT_NS_PER_SEC};

    ev.transfer.sock_id = sock;
    ev.transfer.pid = pid;
    ev.transfer.method = method;
    ev.transfer.file = (struct ft_file_id){.dev = 1, .ino = 42};
    ev.transfer.bytes = bytes;
    ev.transfer.read_bytes = read_bytes;
    ft_state_ingest(st, &ev);
}

static void counts_by_process_and_keeps_names_standard(void)
{
    struct ft_state_config cfg;
    struct ft_row_stats stats = {.rss_bytes = 4096, .events_processed = 7, .open_sockets = 2};

    ft_state_config_defaults(&cfg);
    struct ft_state *st = ft_state_create(&cfg);
    stats.loss[FT_LOSS_EVENT_QUEUE] = 3;
    stats.active_by_confidence[FT_CONF_EXACT] = 1;

    process(st, 10, "nginx");
    process(st, 11, "back\"up\\");
    flow(st, 10, 1, FT_PROTO_TCP, 5000, 100);
    flow(st, 10, 1, FT_PROTO_TCP, 1000, 0);
    flow(st, 11, 2, FT_PROTO_UDP, 70, 0);
    transfer(st, 10, 1, FT_METHOD_SENDFILE, 4000, 0);
    transfer(st, 10, 1, FT_METHOD_SENDFILE, 500, 0);

    char *text = render(st, &stats, 1'500'000'000);
    CHECK(strstr(text, "# TYPE target_info gauge\n"
                       "target_info{service_name=\"filetrace\",host_name=\"web-01\"} 1\n"));
    CHECK(strstr(text, "# TYPE filetrace_network_io_bytes_total counter\n"));
    CHECK(strstr(text, "filetrace_network_io_bytes_total{process_executable_name=\"nginx\","
                       "network_transport=\"tcp\",network_io_direction=\"transmit\"} 6000\n"));
    CHECK(strstr(text, "filetrace_network_io_bytes_total{process_executable_name=\"nginx\","
                       "network_transport=\"tcp\",network_io_direction=\"receive\"} 100\n"));
    CHECK(strstr(text, "{process_executable_name=\"back\\\"up\\\\\",network_transport=\"udp\","
                       "network_io_direction=\"transmit\"} 70\n"));
    CHECK(strstr(text, "filetrace_file_sent_bytes_total{process_executable_name=\"nginx\","
                       "filetrace_transfer_method=\"sendfile\","
                       "filetrace_transfer_confidence=\"exact\"} 4500\n"));
    CHECK(strstr(text, "filetrace_transfers_started_total{process_executable_name=\"nginx\","
                       "filetrace_transfer_method=\"sendfile\","
                       "filetrace_transfer_confidence=\"exact\"} 1\n"));
    CHECK(strstr(text, "# TYPE filetrace_transfers_active gauge\n"));
    CHECK(strstr(text, "filetrace_transfers_active{filetrace_transfer_confidence=\"exact\"} 1\n"));
    CHECK(strstr(text, "filetrace_connections_active 2\n"));
    CHECK(strstr(text, "filetrace_events_processed_total 7\n"));
    CHECK(strstr(text, "filetrace_events_dropped_total{filetrace_loss_kind=\"event_queue\"} 3\n"));
    CHECK(strstr(text, "process_cpu_time_seconds_total 1.500000\n"));
    CHECK(strstr(text, "process_memory_usage_bytes 4096\n"));

    free(text);
    ft_state_destroy(st);
}

/* What was sent before an inferred association is reported is counted once it is. */
static void counts_an_inferred_transfer_from_its_first_byte(void)
{
    static const char sent[] = "filetrace_file_sent_bytes_total{process_executable_name=\"python\","
                               "filetrace_transfer_method=\"read-write\","
                               "filetrace_transfer_confidence=\"inferred\"} ";
    struct ft_state_config cfg;
    struct ft_row_stats stats = {0};
    char expected[256];

    ft_state_config_defaults(&cfg);
    struct ft_state *st = ft_state_create(&cfg);
    process(st, 20, "python");

    transfer(st, 20, 5, FT_METHOD_READ_SEND, 600, 600);
    char *text = render(st, &stats, 0);
    CHECK(!strstr(text, sent));
    CHECK(!strstr(text, "filetrace_transfers_started_total{"));
    free(text);

    transfer(st, 20, 5, FT_METHOD_READ_SEND, 600, 600);
    transfer(st, 20, 5, FT_METHOD_READ_SEND, 300, 300);
    text = render(st, &stats, 0);
    snprintf(expected, sizeof(expected), "%s1500\n", sent);
    CHECK(strstr(text, expected));
    CHECK(strstr(text, "filetrace_transfer_confidence=\"inferred\"} 1\n"));
    free(text);
    ft_state_destroy(st);
}

static void sums_label_sets_beyond_the_limit(void)
{
    struct ft_state_config cfg;
    struct ft_row_stats stats = {0};
    char name[FT_COMM_MAX];

    ft_state_config_defaults(&cfg);
    cfg.max_metric_series = 2;
    struct ft_state *st = ft_state_create(&cfg);

    for (uint32_t i = 0; i < 5; i++) {
        snprintf(name, sizeof(name), "worker-%u", i);
        process(st, 100 + i, name);
        flow(st, 100 + i, 900 + i, FT_PROTO_TCP, 10, 0);
    }
    flow(st, 100, 900, FT_PROTO_TCP, 5, 0);
    flow(st, 104, 904, FT_PROTO_TCP, 1, 0);

    char *text = render(st, &stats, 0);
    CHECK(strstr(text, "{process_executable_name=\"worker-0\",network_transport=\"tcp\","
                       "network_io_direction=\"transmit\"} 15\n"));
    CHECK(strstr(text, "process_executable_name=\"worker-1\""));
    CHECK(!strstr(text, "process_executable_name=\"worker-2\""));
    CHECK(strstr(text, "filetrace_network_io_bytes_total{otel_metric_overflow=\"true\"} 31\n"));
    free(text);
    ft_state_destroy(st);
}

void test_metrics(void)
{
    counts_by_process_and_keeps_names_standard();
    counts_an_inferred_transfer_from_its_first_byte();
    sums_label_sets_beyond_the_limit();
}
