#include "unit/test.h"

#include "filetrace/wire.h"

static void names_after_a_connection(void)
{
    struct ft_row_connection row = {0};
    struct ft_remote_names out;
    struct ft_remote_names in = {
        .tls = "files.example.com",
        .resolved = {"cdn.example.com", "files.example.com"},
        .listed = 2,
        .count = 5,
    };

    size_t used = ft_remote_names_pack(&in, &row.names, row.text, sizeof(row.text));
    CHECK_U64(used, 2 * sizeof("files.example.com") + sizeof("cdn.example.com"));
    CHECK_U64(ft_row_connection_size(&row), offsetof(struct ft_row_connection, text) + used);
    ft_row_connection_names(&row, &out);
    CHECK_STR(out.tls, "files.example.com");
    CHECK_U64(out.listed, 2);
    CHECK_STR(out.resolved[0], "cdn.example.com");
    CHECK_STR(out.resolved[1], "files.example.com");
    CHECK_U64(out.count, 5);

    /* Without a TLS name the looked-up ones start the block. */
    in.tls = "";
    in.count = 0;
    used = ft_remote_names_pack(&in, &row.names, row.text, sizeof(row.text));
    CHECK_U64(used, sizeof("cdn.example.com") + sizeof("files.example.com"));
    ft_row_connection_names(&row, &out);
    CHECK_STR(out.tls, "");
    CHECK_STR(out.resolved[0], "cdn.example.com");
    CHECK_U64(out.count, 2);

    in = (struct ft_remote_names){.tls = ""};
    CHECK_U64(ft_remote_names_pack(&in, &row.names, row.text, sizeof(row.text)), 0);
    CHECK_U64(ft_row_connection_size(&row), offsetof(struct ft_row_connection, text));
    ft_row_connection_names(&row, &out);
    CHECK_STR(out.tls, "");
    CHECK_U64(out.listed + out.count, 0);

    /* A row that promises more names than it holds gives those it holds. */
    struct ft_row_flow flow = {.names = {.count = 3, .listed = 3, .tls = 1}};
    ft_strlcpy(flow.text, "tls.example.com", sizeof(flow.text));
    ft_row_flow_names(&flow, &out);
    CHECK_STR(out.tls, "tls.example.com");
    CHECK_U64(out.listed, 0);
    CHECK_U64(ft_row_flow_size(&flow),
              offsetof(struct ft_row_flow, text) + sizeof("tls.example.com"));
}

static void names_after_the_other_strings(void)
{
    static struct ft_row_transfer row;
    static struct ft_row_event record;
    struct ft_process_strings text = {"curl -T q3.zip", "/data", ""};
    struct ft_remote_names in = {.tls = "", .resolved = {"proxy.corp.example"}, .listed = 1};
    struct ft_remote_names out;

    ft_strlcpy(row.path, "/data/q3.zip", sizeof(row.path));
    size_t at = sizeof("/data/q3.zip");
    size_t names = ft_remote_names_pack(&in, &row.names, row.path + at, sizeof(row.path) - at);
    CHECK_U64(ft_row_transfer_size(&row), offsetof(struct ft_row_transfer, path) + at + names);
    ft_row_transfer_names(&row, &out);
    CHECK_STR(out.resolved[0], "proxy.corp.example");

    row.flags |= FT_XFER_PROCESS_TEXT;
    at += ft_process_strings_pack(row.path + at, FT_PROCESS_TEXT_MAX, &text);
    names = ft_remote_names_pack(&in, &row.names, row.path + at, sizeof(row.path) - at);
    CHECK_U64(ft_row_transfer_size(&row), offsetof(struct ft_row_transfer, path) + at + names);
    ft_row_transfer_names(&row, &out);
    CHECK_STR(out.resolved[0], "proxy.corp.example");
    CHECK_U64(out.count, 1);
    ft_row_transfer_strings(&row, &text);
    CHECK_STR(text.cwd, "/data");

    ft_strlcpy(record.text, "/data/q3.zip", sizeof(record.text));
    CHECK_STR(ft_row_event_name(&record), "");
    size_t bare = ft_row_event_size(&record);
    CHECK_U64(bare, offsetof(struct ft_row_event, text) + sizeof("/data/q3.zip"));
    ft_row_event_set_name(&record, FT_NAME_SOURCE_TLS, "s3.example.com");
    CHECK_STR(ft_row_event_name(&record), "s3.example.com");
    CHECK_U64(ft_row_event_size(&record), bare + sizeof("s3.example.com"));

    record.flags |= FT_EVENT_PROCESS_TEXT;
    at = sizeof("/data/q3.zip");
    text = (struct ft_process_strings){"curl -T q3.zip", "/data", "/srv/up.php"};
    size_t strings = ft_process_strings_pack(record.text + at, FT_PROCESS_TEXT_MAX, &text);
    ft_row_event_set_name(&record, FT_NAME_SOURCE_LOOKUP, "proxy.corp.example");
    CHECK_STR(ft_row_event_name(&record), "proxy.corp.example");
    CHECK_U64(ft_row_event_size(&record), bare + strings + sizeof("proxy.corp.example"));
    ft_row_event_strings(&record, &text);
    CHECK_STR(text.script, "/srv/up.php");

    /* No name, whatever the source says, leaves the record without one. */
    ft_row_event_set_name(&record, FT_NAME_SOURCE_LOOKUP, "");
    CHECK_U64(record.name_source, FT_NAME_SOURCE_NONE);
    CHECK_U64(ft_row_event_size(&record), bare + strings);
}

void test_wire(void)
{
    names_after_a_connection();
    names_after_the_other_strings();
}
