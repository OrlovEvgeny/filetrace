#include "unit/test.h"

#include "cmd/cli.h"
#include "filetrace/format.h"

#include <stdlib.h>

static char *render(enum ft_view_id view, const struct ft_rows *rows, enum ft_format format,
                    bool rank)
{
    char *text = nullptr;
    size_t size = 0;
    FILE *mem = open_memstream(&text, &size);
    struct ft_output out = {.format = format, .stream = mem};

    ft_view_render(view, rows, &out, rank);
    fclose(mem);
    return text;
}

/* Collapses runs of spaces so that column widths do not matter. */
static char *squeeze(char *text)
{
    char *out = text;
    for (const char *in = text; *in; in++) {
        if (*in == ' ' && out > text && out[-1] == ' ')
            continue;
        *out++ = *in;
    }
    *out = '\0';
    return text;
}

static struct ft_endpoint endpoint(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port)
{
    uint8_t raw[16] = {a, b, c, d};
    struct ft_endpoint ep;
    ft_endpoint_set(&ep, false, raw, port);
    return ep;
}

static void transfers(void)
{
    struct ft_row_transfer *row = calloc(1, sizeof(*row));
    struct ft_rows rows;
    uint64_t when = 0;

    CHECK(ft_parse_time_rfc3339("2026-11-10T21:42:11.210Z", &when));
    ft_rows_init(&rows, FT_MSG_ROW_TRANSFER);

    row->id = 0x2a;
    row->sock_id = 0x7f;
    row->first_wall_ns = when - 8200 * FT_NS_PER_MS;
    row->last_wall_ns = when;
    row->bytes = 148293012;
    row->rate = 1258291;
    row->dev = 2049;
    row->ino = 928371;
    row->file_size = 148293012;
    row->ops = 1248;
    row->pid = 1842;
    row->ppid = 1;
    row->evidence = FT_EVD_DIRECT_TRANSFER | FT_EVD_FILE_IDENTITY | FT_EVD_SOCKET_IDENTITY |
                    FT_EVD_REMOTE_ENDPOINT;
    row->proto = FT_PROTO_TCP;
    row->confidence = FT_CONF_EXACT;
    row->method = FT_METHOD_SENDFILE;
    row->flags = FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN;
    row->local = endpoint(10, 0, 0, 10, 443);
    row->remote = endpoint(203, 0, 113, 42, 52144);
    ft_strlcpy(row->comm, "nginx", sizeof(row->comm));
    ft_strlcpy(row->exe, "/usr/sbin/nginx", sizeof(row->exe));
    ft_strlcpy(row->fs_type, "ext4", sizeof(row->fs_type));
    ft_strlcpy(row->path, "/data/export/report, \"final\".csv", sizeof(row->path));
    CHECK(ft_rows_append(&rows, row, ft_row_transfer_size(row)));

    /* Sent bytes that no file accounts for, on a transfer that lost events. */
    memset(row, 0, sizeof(*row));
    row->id = 0x1001;
    row->sock_id = 0x1001;
    row->last_wall_ns = when;
    row->first_wall_ns = when;
    row->bytes = 12582912;
    row->pid = 2910;
    row->proto = FT_PROTO_TCP;
    row->confidence = FT_CONF_UNKNOWN;
    row->flags = FT_XFER_INCOMPLETE;
    row->remote = endpoint(192, 0, 2, 10, 443);
    ft_strlcpy(row->comm, "python", sizeof(row->comm));
    CHECK(ft_rows_append(&rows, row, ft_row_transfer_size(row)));

    char *text = squeeze(render(FT_VIEW_FILES, &rows, FT_FMT_TABLE, false));
    CHECK_STR(text,
              "FILE PID PROCESS REMOTE SENT CONFIDENCE\n"
              "/data/export/report, \"final\".csv 1842 nginx 203.0.113.42:52144 141 MB EXACT\n"
              "unknown 2910 python 192.0.2.10:443 12.0 MB UNKNOWN*\n");
    free(text);

    text = squeeze(render(FT_VIEW_TRANSFERS, &rows, FT_FMT_TABLE, false));
    CHECK(strstr(text, "ID PROCESS FILE REMOTE BYTES METHOD CONFIDENCE\n") == text);
    CHECK(strstr(text, "tr_2a nginx /data/export/report, \"final\".csv 203.0.113.42:52144 "
                       "141 MB sendfile EXACT\n") != nullptr);
    CHECK(strstr(text, "tr_s1001 python unknown 192.0.2.10:443 12.0 MB - UNKNOWN*\n") != nullptr);
    free(text);

    text = render(FT_VIEW_TRANSFERS, &rows, FT_FMT_QUIET, false);
    CHECK_STR(text, "tr_2a\ntr_s1001\n");
    free(text);

    /* Quiet output of files lists paths, so rows without one are left out. */
    text = render(FT_VIEW_FILES, &rows, FT_FMT_QUIET, false);
    CHECK_STR(text, "/data/export/report, \"final\".csv\n");
    free(text);

    text = render(FT_VIEW_FILES, &rows, FT_FMT_JSONL, false);
    CHECK(strstr(text, "{\"event\":\"transfer.completed\",\"transfer_id\":\"tr_2a\","
                       "\"timestamp\":\"2026-11-10T21:42:11.210Z\",\"host\":\"") == text);
    CHECK(strstr(text, "\"process\":{\"pid\":1842,\"ppid\":1,\"name\":\"nginx\","
                       "\"executable\":\"/usr/sbin/nginx\"},") != nullptr);
    CHECK(strstr(text, "\"file\":{\"path\":\"/data/export/report, \\\"final\\\".csv\","
                       "\"inode\":928371,\"device\":2049,\"size\":148293012,"
                       "\"owner\":\"root\",\"filesystem\":\"ext4\","
                       "\"deleted\":false},") != nullptr);
    CHECK(strstr(text, "\"network\":{\"protocol\":\"tcp\",\"socket_id\":\"sk_7f\","
                       "\"local_address\":\"10.0.0.10\",\"local_port\":443,"
                       "\"remote_address\":\"203.0.113.42\",\"remote_port\":52144},") != nullptr);
    CHECK(strstr(text, "\"transfer\":{\"method\":\"sendfile\",\"bytes\":148293012,"
                       "\"bytes_per_second\":1258291,\"operations\":1248,\"duration_ms\":8200,"
                       "\"state\":\"completed\"},") != nullptr);
    CHECK(strstr(text,
                 "\"attribution\":{\"confidence\":\"exact\",\"evidence\":["
                 "\"direct_file_to_socket_transfer\",\"file_identity\","
                 "\"socket_identity\",\"remote_endpoint\"],\"incomplete\":false}}\n") != nullptr);

    /* What was not observed is absent rather than invented. */
    const char *second = strchr(text, '\n') + 1;
    CHECK(strstr(second, "\"transfer_id\":\"tr_s1001\"") != nullptr);
    CHECK(strstr(second, "\"file\"") == nullptr);
    CHECK(strstr(second, "\"method\"") == nullptr);
    CHECK(strstr(second, "\"evidence\"") == nullptr);
    CHECK(strstr(second, "\"process\":{\"pid\":2910,\"name\":\"python\"},") != nullptr);
    CHECK(strstr(second, "\"attribution\":{\"confidence\":\"unknown\",\"incomplete\":true}}\n") !=
          nullptr);
    free(text);

    text = render(FT_VIEW_FILES, &rows, FT_FMT_JSON, false);
    CHECK(text[0] == '[');
    CHECK(strstr(text, "},\n {\"event\"") != nullptr);
    CHECK(strcmp(text + strlen(text) - 3, "\n]\n") == 0);
    free(text);

    text = render(FT_VIEW_FILES, &rows, FT_FMT_CSV, false);
    CHECK(strstr(text,
                 "event,transfer_id,timestamp,host,platform,process.pid,process.ppid,"
                 "process.name,process.executable,file.path,file.inode,file.device,") == text);
    /* A field containing a comma or a quote is quoted, with quotes doubled. */
    CHECK(strstr(text, ",nginx,/usr/sbin/nginx,\"/data/export/report, \"\"final\"\".csv\","
                       "928371,2049,148293012,root,ext4,false,tcp,sk_7f,10.0.0.10,443,203.0.113.42,"
                       "52144,"
                       "sendfile,148293012,,1258291,1248,8200,completed,exact,") != nullptr);
    free(text);

    ft_rows_clear(&rows);
    text = render(FT_VIEW_FILES, &rows, FT_FMT_JSON, false);
    CHECK_STR(text, "[]\n");
    free(text);

    ft_rows_free(&rows);
    free(row);
}

static void processes(void)
{
    struct ft_row_process row = {
        .tx_bytes = 1524713390,
        .rx_bytes = 85983232,
        .tx_rate = 13002342,
        .pid = 1842,
        .ppid = 1,
        .uid = 4'000'000'000u,
        .connections = 12,
    };
    struct ft_rows rows;

    ft_strlcpy(row.comm, "nginx", sizeof(row.comm));
    ft_rows_init(&rows, FT_MSG_ROW_PROCESS);
    CHECK(ft_rows_append(&rows, &row, sizeof(row)));

    /* A user ID without an account is shown as the number. */
    char *text = squeeze(render(FT_VIEW_PROCESSES, &rows, FT_FMT_TABLE, true));
    CHECK_STR(text, "RANK PID PPID PROCESS USER OUTBOUND INBOUND\n"
                    "1 1842 1 nginx 4000000000 1.42 GB 82.0 MB\n");
    free(text);

    text = render(FT_VIEW_PROCESSES, &rows, FT_FMT_JSONL, false);
    CHECK_STR(text, "{\"pid\":1842,\"ppid\":1,\"name\":\"nginx\",\"user\":\"4000000000\","
                    "\"uid\":4000000000,\"gid\":0,\"outbound_bytes\":1524713390,"
                    "\"inbound_bytes\":85983232,\"outbound_bytes_per_second\":13002342,"
                    "\"inbound_bytes_per_second\":0,\"connections\":12,\"transfers\":0,"
                    "\"status\":\"running\"}\n");
    free(text);

    text = render(FT_VIEW_PROCESSES, &rows, FT_FMT_QUIET, false);
    CHECK_STR(text, "1842\n");
    free(text);
    ft_rows_free(&rows);
}

static void connections(void)
{
    static const uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    struct ft_row_connection row = {
        .sock_id = 0x12,
        .pid = 3821,
        .proto = FT_PROTO_UDP,
        .state = FT_SOCK_ACTIVE,
    };
    struct ft_rows rows;

    ft_endpoint_set(&row.local, true, v6, 53001);
    ft_strlcpy(row.comm, "python", sizeof(row.comm));
    ft_rows_init(&rows, FT_MSG_ROW_CONNECTION);
    CHECK(ft_rows_append(&rows, &row, sizeof(row)));

    char *text = squeeze(render(FT_VIEW_CONNECTIONS, &rows, FT_FMT_TABLE, false));
    CHECK_STR(text, "PROTO PID PROCESS LOCAL REMOTE STATE\n"
                    "UDP 3821 python [2001:db8::1]:53001 * ACTIVE\n");
    free(text);

    text = render(FT_VIEW_CONNECTIONS, &rows, FT_FMT_JSONL, false);
    CHECK_STR(text, "{\"socket_id\":\"sk_12\",\"protocol\":\"udp\",\"pid\":3821,"
                    "\"process\":\"python\",\"local_address\":\"2001:db8::1\","
                    "\"local_port\":53001,\"state\":\"active\",\"sent_bytes\":0,"
                    "\"received_bytes\":0,\"sent_bytes_per_second\":0,"
                    "\"received_bytes_per_second\":0}\n");
    free(text);
    ft_rows_free(&rows);
}

void test_views(void)
{
    transfers();
    processes();
    connections();
}
