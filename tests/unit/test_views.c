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
    CHECK_STR(text, "FILE PROCESS DESTINATION BYTES METHOD CONFIDENCE\n"
                    "/data/export/report, \"final\".csv nginx 203.0.113.42 141 MB sendfile EXACT\n"
                    "unknown python 192.0.2.10 12.0 MB - UNKNOWN*\n");
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
    CHECK(strstr(text, "{\"event\":\"file_transfer\",\"transfer_id\":\"tr_2a\","
                       "\"timestamp\":\"2026-11-10T21:42:11.210Z\",\"host\":\"") == text);
    CHECK(strstr(text, "\"process\":{\"pid\":1842,\"ppid\":1,\"name\":\"nginx\","
                       "\"executable\":\"/usr/sbin/nginx\"},") != nullptr);
    CHECK(strstr(text, "\"file\":{\"path\":\"/data/export/report, \\\"final\\\".csv\","
                       "\"inode\":928371,\"device\":2049,\"size\":148293012,"
                       "\"owner\":\"root\",\"filesystem\":\"ext4\","
                       "\"deleted\":false},") != nullptr);
    CHECK(strstr(text, "\"network\":{\"protocol\":\"tcp\",\"socket_id\":127,"
                       "\"local_ip\":\"10.0.0.10\",\"local_port\":443,"
                       "\"remote_ip\":\"203.0.113.42\",\"remote_port\":52144},") != nullptr);
    CHECK(strstr(text,
                 "\"transfer\":{\"method\":\"sendfile\",\"bytes_sent\":148293012,"
                 "\"bytes_per_second\":1258291,\"operations\":1248,"
                 "\"started\":\"2026-11-10T21:42:03.010Z\",\"duration_ms\":8200,"
                 "\"state\":\"completed\",\"confidence\":\"exact\",\"evidence\":["
                 "\"direct_file_to_socket_transfer\",\"file_identity\","
                 "\"socket_identity\",\"remote_endpoint\"],\"incomplete\":false}}\n") != nullptr);

    /* What was not observed is absent rather than invented. */
    const char *second = strchr(text, '\n') + 1;
    CHECK(strstr(second, "\"transfer_id\":\"tr_s1001\"") != nullptr);
    CHECK(strstr(second, "\"file\"") == nullptr);
    CHECK(strstr(second, "\"method\"") == nullptr);
    CHECK(strstr(second, "\"evidence\"") == nullptr);
    CHECK(strstr(second, "\"process\":{\"pid\":2910,\"name\":\"python\"},") != nullptr);
    CHECK(strstr(second, "{\"event\":\"network_transfer\",") == second);
    CHECK(strstr(second, "\"state\":\"completed\",\"confidence\":\"unknown\","
                         "\"incomplete\":true}}\n") != nullptr);
    free(text);

    text = render(FT_VIEW_FILES, &rows, FT_FMT_JSON, false);
    CHECK(text[0] == '[');
    CHECK(strstr(text, "},\n {\"event\"") != nullptr);
    CHECK(strcmp(text + strlen(text) - 3, "\n]\n") == 0);
    free(text);

    text = render(FT_VIEW_FILES, &rows, FT_FMT_CSV, false);
    CHECK(strstr(text,
                 "event,transfer_id,timestamp,host,platform,process.pid,process.ppid,"
                 "process.name,process.executable,process.command_line,"
                 "process.working_directory,process.script,file.path,file.inode,file.device,") ==
          text);
    /* A field containing a comma or a quote is quoted, with quotes doubled. */
    CHECK(
        strstr(text,
               ",nginx,/usr/sbin/nginx,,,,\"/data/export/report, \"\"final\"\".csv\","
               "928371,2049,148293012,root,ext4,false,tcp,127,10.0.0.10,443,203.0.113.42,"
               "52144,,,,,,"
               "sendfile,148293012,,1258291,1248,2026-11-10T21:42:03.010Z,8200,completed,exact,") !=
        nullptr);
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
        .files = 18,
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
    CHECK_STR(text, "RANK PID PROCESS OUTBOUND FILES CONNECTIONS SENT RECEIVED\n"
                    "1 1842 nginx 12.4 MB/s 18 12 1.42 GB 82.0 MB\n");
    free(text);

    text = render(FT_VIEW_PROCESSES, &rows, FT_FMT_JSONL, false);
    CHECK_STR(text,
              "{\"pid\":1842,\"ppid\":1,\"name\":\"nginx\",\"user\":\"4000000000\","
              "\"uid\":4000000000,\"gid\":0,\"bytes_sent\":1524713390,"
              "\"bytes_received\":85983232,\"bytes_sent_per_second\":13002342,"
              "\"bytes_received_per_second\":0,\"connections\":12,\"files\":18,\"transfers\":0,"
              "\"active_transfers\":0,"
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
    CHECK_STR(text, "PID PROCESS PROTOCOL LOCAL REMOTE STATE SENT RECEIVED SOCKET\n"
                    "3821 python UDP [2001:db8::1]:53001 * ACTIVE 0 B 0 B 18\n");
    free(text);

    text = render(FT_VIEW_CONNECTIONS, &rows, FT_FMT_JSONL, false);
    CHECK_STR(text, "{\"socket_id\":18,\"protocol\":\"udp\",\"pid\":3821,"
                    "\"process\":\"python\",\"local_ip\":\"2001:db8::1\","
                    "\"local_port\":53001,\"state\":\"active\",\"bytes_sent\":0,"
                    "\"bytes_received\":0,\"bytes_sent_per_second\":0,"
                    "\"bytes_received_per_second\":0}\n");
    free(text);
    ft_rows_free(&rows);
}

/* Follows the row's path with what the process runs. */
static void set_process_strings(struct ft_row_transfer *row, const char *command_line,
                                const char *cwd, const char *script)
{
    struct ft_process_strings text = {command_line, cwd, script};
    size_t lead = strlen(row->path) + 1;
    ft_process_strings_pack(row->path + lead, sizeof(row->path) - lead, &text);
    row->flags |= FT_XFER_PROCESS_TEXT;
}

static void interpreters_name_their_scripts(void)
{
    struct ft_row_transfer *row = calloc(1, sizeof(*row));
    struct ft_rows rows;

    ft_rows_init(&rows, FT_MSG_ROW_TRANSFER);
    row->id = 7;
    row->pid = 3100;
    row->bytes = 2048;
    row->method = FT_METHOD_READ_SEND;
    row->confidence = FT_CONF_INFERRED;
    row->flags = FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN;
    row->remote = endpoint(192, 0, 2, 10, 443);
    ft_strlcpy(row->comm, "python3", sizeof(row->comm));
    ft_strlcpy(row->exe, "/usr/bin/python3.11", sizeof(row->exe));
    ft_strlcpy(row->path, "/data/users.csv", sizeof(row->path));
    set_process_strings(row, "python3 export.py --all", "/srv/app", "/srv/app/export.py");
    CHECK(ft_rows_append(&rows, row, ft_row_transfer_size(row)));

    memset(row, 0, sizeof(*row));
    row->id = 8;
    row->pid = 1842;
    row->bytes = 4096;
    row->method = FT_METHOD_SENDFILE;
    row->confidence = FT_CONF_EXACT;
    row->flags = FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN;
    row->remote = endpoint(192, 0, 2, 11, 443);
    ft_strlcpy(row->comm, "nginx", sizeof(row->comm));
    ft_strlcpy(row->path, "/var/www/index.html", sizeof(row->path));
    set_process_strings(row, "nginx: worker process", "/", "");
    CHECK(ft_rows_append(&rows, row, ft_row_transfer_size(row)));

    /* The script column appears once a row has a script. */
    char *text = squeeze(render(FT_VIEW_FILES, &rows, FT_FMT_TABLE, false));
    CHECK_STR(text, "FILE PROCESS DESTINATION BYTES METHOD CONFIDENCE SCRIPT\n"
                    "/data/users.csv python3 192.0.2.10 2.00 KB read-write INFERRED "
                    "/srv/app/export.py\n"
                    "/var/www/index.html nginx 192.0.2.11 4.00 KB sendfile EXACT -\n");
    free(text);

    text = render(FT_VIEW_TRANSFERS, &rows, FT_FMT_JSONL, false);
    CHECK(strstr(text, "\"process\":{\"pid\":3100,\"name\":\"python3\","
                       "\"executable\":\"/usr/bin/python3.11\","
                       "\"command_line\":\"python3 export.py --all\","
                       "\"working_directory\":\"/srv/app\",\"script\":\"/srv/app/export.py\"},") !=
          nullptr);
    CHECK(strstr(text, "\"process\":{\"pid\":1842,\"name\":\"nginx\","
                       "\"command_line\":\"nginx: worker process\","
                       "\"working_directory\":\"/\"},") != nullptr);
    free(text);

    text = render(FT_VIEW_FILES, &rows, FT_FMT_CSV, false);
    CHECK(strstr(text, ",python3,/usr/bin/python3.11,python3 export.py --all,/srv/app,"
                       "/srv/app/export.py,/data/users.csv,") != nullptr);
    free(text);

    struct ft_row_process *process = calloc(1, sizeof(*process));
    struct ft_process_strings strings = {"php-fpm: pool site1", "/", "pool:site1"};
    process->pid = 701;
    process->tx_bytes = 1024;
    ft_strlcpy(process->comm, "php-fpm8.2", sizeof(process->comm));
    size_t size = offsetof(struct ft_row_process, text) +
                  ft_process_strings_pack(process->text, sizeof(process->text), &strings);
    CHECK_U64(size, ft_row_process_size(process));
    ft_rows_free(&rows);
    ft_rows_init(&rows, FT_MSG_ROW_PROCESS);
    CHECK(ft_rows_append(&rows, process, size));

    text = squeeze(render(FT_VIEW_PROCESSES, &rows, FT_FMT_TABLE, false));
    CHECK_STR(text, "PID PROCESS OUTBOUND FILES CONNECTIONS SENT RECEIVED SCRIPT\n"
                    "701 php-fpm8.2 0 B/s 0 0 1.00 KB 0 B pool:site1\n");
    free(text);
    text = render(FT_VIEW_PROCESSES, &rows, FT_FMT_JSONL, false);
    CHECK(strstr(text, "\"name\":\"php-fpm8.2\",") != nullptr);
    CHECK(strstr(text, "\"command_line\":\"php-fpm: pool site1\",\"working_directory\":\"/\","
                       "\"script\":\"pool:site1\",") != nullptr);
    free(text);
    text = render(FT_VIEW_PROCESSES, &rows, FT_FMT_CSV, false);
    CHECK(strstr(text, "executable,command_line,working_directory,script,") != nullptr);
    CHECK(strstr(text, ",php-fpm: pool site1,/,pool:site1,") != nullptr);
    free(text);

    ft_rows_free(&rows);
    free(process);
    free(row);
}

static void add_connection(struct ft_rows *rows, uint64_t sock, uint32_t pid, const char *comm,
                           struct ft_endpoint remote, const struct ft_remote_names *names)
{
    struct ft_row_connection row = {
        .sock_id = sock,
        .pid = pid,
        .proto = FT_PROTO_TCP,
        .state = FT_SOCK_ESTABLISHED,
        .local = endpoint(10, 0, 0, 12, 50412),
        .remote = remote,
    };

    ft_strlcpy(row.comm, comm, sizeof(row.comm));
    ft_remote_names_pack(names, &row.names, row.text, sizeof(row.text));
    CHECK(ft_rows_append(rows, &row, ft_row_connection_size(&row)));
}

static void remote_ends_have_names(void)
{
    struct ft_remote_names settled = {
        .tls = "files.example.com", .resolved = {"files.example.com"}, .listed = 1, .count = 1};
    struct ft_remote_names several = {
        .tls = "", .resolved = {"cdn.example.com", "static.example.com"}, .listed = 2, .count = 2};
    struct ft_remote_names proxied = {
        .tls = "s3.example.com", .resolved = {"proxy.corp.example"}, .listed = 1, .count = 1};
    struct ft_remote_names none = {.tls = ""};
    struct ft_rows rows;

    ft_rows_init(&rows, FT_MSG_ROW_CONNECTION);
    add_connection(&rows, 41, 2210, "php-fpm", endpoint(203, 0, 113, 25, 443), &settled);
    add_connection(&rows, 52, 3312, "curl", endpoint(203, 0, 113, 25, 80), &several);
    add_connection(&rows, 58, 4120, "python3", endpoint(10, 0, 0, 5, 3128), &proxied);
    add_connection(&rows, 17, 1840, "nginx", endpoint(198, 51, 100, 4, 51344), &none);

    char *text = render(FT_VIEW_CONNECTIONS, &rows, FT_FMT_JSONL, false);
    CHECK(strstr(text, "\"remote_port\":443,\"remote_name\":\"files.example.com\","
                       "\"remote_name_source\":\"lookup+tls\","
                       "\"resolved_names\":[\"files.example.com\"],"
                       "\"resolved_name_count\":1,\"state\":") != nullptr);
    CHECK(strstr(text, "\"remote_port\":80,\"remote_name\":\"cdn.example.com\","
                       "\"remote_name_source\":\"lookup\","
                       "\"resolved_names\":[\"cdn.example.com\",\"static.example.com\"],"
                       "\"resolved_name_count\":2,\"state\":") != nullptr);
    CHECK(strstr(text, "\"remote_port\":3128,\"remote_name\":\"s3.example.com\","
                       "\"remote_name_source\":\"tls\","
                       "\"resolved_names\":[\"proxy.corp.example\"],") != nullptr);
    /* A remote end nobody named has none of the four members. */
    CHECK(strstr(text, "\"remote_ip\":\"198.51.100.4\",\"remote_port\":51344,\"state\":") !=
          nullptr);
    free(text);

    text = render(FT_VIEW_CONNECTIONS, &rows, FT_FMT_CSV, false);
    CHECK(strstr(text, ",remote_ip,remote_port,remote_host,remote_name,remote_name_source,"
                       "resolved_names,resolved_name_count,state,") != nullptr);
    CHECK(strstr(text, ",203.0.113.25,80,,cdn.example.com,lookup,"
                       "cdn.example.com;static.example.com,2,established,") != nullptr);
    CHECK(strstr(text, ",198.51.100.4,51344,,,,,,established,") != nullptr);
    free(text);
    ft_rows_free(&rows);

    struct ft_row_transfer *row = calloc(1, sizeof(*row));
    row->id = 0x1a;
    row->pid = 2210;
    row->bytes = 2048;
    row->proto = FT_PROTO_TCP;
    row->method = FT_METHOD_READ_SEND;
    row->confidence = FT_CONF_INFERRED;
    row->flags = FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN;
    row->remote = endpoint(203, 0, 113, 25, 443);
    ft_strlcpy(row->comm, "php-fpm", sizeof(row->comm));
    ft_strlcpy(row->path, "/data/invoice.pdf", sizeof(row->path));
    set_process_strings(row, "php-fpm: pool www", "/", "/srv/blog/index.php");
    size_t at = ft_row_transfer_size(row) - offsetof(struct ft_row_transfer, path);
    ft_remote_names_pack(&settled, &row->names, row->path + at, sizeof(row->path) - at);
    ft_rows_init(&rows, FT_MSG_ROW_TRANSFER);
    CHECK(ft_rows_append(&rows, row, ft_row_transfer_size(row)));

    text = render(FT_VIEW_FILES, &rows, FT_FMT_JSONL, false);
    CHECK(strstr(text, "\"remote_ip\":\"203.0.113.25\",\"remote_port\":443,"
                       "\"remote_name\":\"files.example.com\","
                       "\"remote_name_source\":\"lookup+tls\","
                       "\"resolved_names\":[\"files.example.com\"],"
                       "\"resolved_name_count\":1},\"transfer\":{") != nullptr);
    free(text);
    ft_rows_free(&rows);
    free(row);
}

void test_views(void)
{
    remote_ends_have_names();
    transfers();
    processes();
    connections();
    interpreters_name_their_scripts();
}
