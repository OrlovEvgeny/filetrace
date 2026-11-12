#include "unit/test.h"

#include "ui/top/document.h"
#include "ui/top/model.h"
#include "ui/top/once.h"
#include "ui/top/plain.h"

#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

constexpr uint64_t SECOND = FT_NS_PER_SEC;
constexpr uint64_t WALL = 1'790'000'000 * FT_NS_PER_SEC;

/* A JSON checker that tells whether a text is one value, with every string valid UTF-8. */
struct json {
    const char *p;
};

static void blanks(struct json *j)
{
    while (*j->p == ' ' || *j->p == '\n' || *j->p == '\t' || *j->p == '\r')
        j->p++;
}

static bool string_ok(struct json *j)
{
    if (*j->p != '"')
        return false;
    for (j->p++; *j->p != '"'; j->p++) {
        unsigned char c = (unsigned char)*j->p;
        if (c == '\0' || c < 0x20)
            return false;
        if (c == '\\') {
            j->p++;
            if (!strchr("\"\\/bfnrtu", *j->p) || *j->p == '\0')
                return false;
            if (*j->p == 'u') {
                for (int i = 1; i <= 4; i++) {
                    if (!strchr("0123456789abcdefABCDEF", j->p[i]) || j->p[i] == '\0')
                        return false;
                }
                j->p += 4;
            }
        } else if (c >= 0x80) {
            int extra = c >= 0xf0 ? 3 : c >= 0xe0 ? 2 : c >= 0xc2 ? 1 : -1;
            if (extra < 0)
                return false;
            for (int i = 1; i <= extra; i++) {
                if (((unsigned char)j->p[i] & 0xc0) != 0x80)
                    return false;
            }
            j->p += extra;
        }
    }
    j->p++;
    return true;
}

static bool value_ok(struct json *j, int depth);

static bool number_ok(struct json *j)
{
    const char *start = j->p;

    if (*j->p == '-')
        j->p++;
    if (*j->p == '0')
        j->p++;
    else if (*j->p >= '1' && *j->p <= '9')
        while (*j->p >= '0' && *j->p <= '9')
            j->p++;
    else
        return false;
    if (*j->p == '.') {
        j->p++;
        if (!(*j->p >= '0' && *j->p <= '9'))
            return false;
        while (*j->p >= '0' && *j->p <= '9')
            j->p++;
    }
    return j->p > start;
}

static bool container_ok(struct json *j, int depth, char close, bool named)
{
    j->p++;
    blanks(j);
    if (*j->p == close) {
        j->p++;
        return true;
    }
    for (;;) {
        blanks(j);
        if (named) {
            if (!string_ok(j))
                return false;
            blanks(j);
            if (*j->p++ != ':')
                return false;
            blanks(j);
        }
        if (!value_ok(j, depth + 1))
            return false;
        blanks(j);
        if (*j->p == close) {
            j->p++;
            return true;
        }
        if (*j->p++ != ',')
            return false;
    }
}

static bool value_ok(struct json *j, int depth)
{
    if (depth > 16)
        return false;
    blanks(j);
    if (*j->p == '{')
        return container_ok(j, depth, '}', true);
    if (*j->p == '[')
        return container_ok(j, depth, ']', false);
    if (*j->p == '"')
        return string_ok(j);
    static const char *const words[] = {"true", "false", "null"};
    for (size_t i = 0; i < FT_ARRAY_LEN(words); i++) {
        size_t len = strlen(words[i]);
        if (strncmp(j->p, words[i], len) == 0) {
            j->p += len;
            return true;
        }
    }
    return number_ok(j);
}

static bool json_ok(const char *text)
{
    struct json j = {text};
    bool ok = value_ok(&j, 0);
    blanks(&j);
    return ok && *j.p == '\0';
}

static bool has(const char *text, const char *needle)
{
    return strstr(text, needle) != nullptr;
}

static bool starts(const char *text, const char *prefix)
{
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

static bool ends(const char *text, const char *suffix)
{
    size_t len = strlen(text);
    size_t tail = strlen(suffix);

    return len >= tail && strcmp(text + len - tail, suffix) == 0;
}

static size_t count(const char *text, char c)
{
    size_t n = 0;

    for (; *text; text++)
        n += *text == c;
    return n;
}

struct fixture {
    struct ft_top_model *m;
    struct ft_rows transfers;
    struct ft_rows processes;
    struct ft_row_stats stats;
};

static void fixture_init(struct fixture *f)
{
    *f = (struct fixture){.m = ft_top_model_create()};
    CHECK(f->m != nullptr);
    ft_rows_init(&f->transfers, FT_MSG_ROW_TRANSFER);
    ft_rows_init(&f->processes, FT_MSG_ROW_PROCESS);
}

static void fixture_free(struct fixture *f)
{
    ft_top_model_destroy(f->m);
    ft_rows_free(&f->transfers);
    ft_rows_free(&f->processes);
}

static void process(struct fixture *f, uint32_t pid, uint32_t ppid, const char *comm,
                    const char *command_line, const char *script, uint64_t file_bytes)
{
    struct ft_row_process *row = calloc(1, sizeof(*row));
    struct ft_process_strings text = {command_line, "/srv", script};

    row->pid = pid;
    row->ppid = ppid;
    row->file_bytes = file_bytes;
    ft_strlcpy(row->comm, comm, sizeof(row->comm));
    size_t size = offsetof(struct ft_row_process, text) +
                  ft_process_strings_pack(row->text, sizeof(row->text), &text);
    CHECK(ft_rows_append(&f->processes, row, size));
    free(row);
}

struct xfer {
    uint64_t id;
    uint32_t pid;
    uint64_t rate;
    const char *path;
    const char *remote;
    uint8_t method; /* sendfile when 0 */
    uint64_t bytes;
    uint64_t size;
    uint64_t ino; /* the id when 0 */
    const char *script;
};

static void transfer(struct fixture *f, struct xfer x)
{
    struct ft_row_transfer *row = calloc(1, sizeof(*row));
    struct ft_process_strings text = {"", "/srv", x.script ? x.script : ""};

    row->id = x.id;
    row->pid = x.pid;
    row->rate = x.rate;
    row->bytes = x.bytes;
    row->file_size = x.size;
    row->dev = 2049;
    row->ino = x.ino ? x.ino : x.id;
    row->first_wall_ns = WALL;
    row->method = x.method ? x.method : FT_METHOD_SENDFILE;
    row->confidence = row->method == FT_METHOD_SENDFILE ? FT_CONF_EXACT : FT_CONF_INFERRED;
    row->flags = FT_XFER_ACTIVE | FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN | FT_XFER_PROCESS_TEXT;
    CHECK(ft_addr_parse(x.remote ? x.remote : "203.0.113.7", &row->remote));
    row->remote.port = 443;
    ft_strlcpy(row->comm, "worker", sizeof(row->comm));
    ft_strlcpy(row->path, x.path ? x.path : "/srv/data/file.bin", FT_PATH_MAX);
    size_t lead = strlen(row->path) + 1;
    ft_process_strings_pack(row->path + lead, sizeof(row->path) - lead, &text);
    CHECK(ft_rows_append(&f->transfers, row, ft_row_transfer_size(row)));
    free(row);
}

static void sample(struct fixture *f, double at)
{
    uint64_t at_ns = (uint64_t)(at * (double)SECOND);

    f->stats.now_wall_ns = WALL + at_ns;
    struct ft_top_sample s = {
        .mono_ns = at_ns + SECOND,
        .stats = &f->stats,
        .transfers = &f->transfers,
        .processes = &f->processes,
    };
    CHECK(ft_top_model_sample(f->m, &s));
    ft_rows_clear(&f->transfers);
    ft_rows_clear(&f->processes);
}

/* The document as text; the caller frees it. */
static char *document(const struct ft_top_model *m, enum ft_top_mode mode, bool indent)
{
    char *text = nullptr;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);

    CHECK(out != nullptr);
    if (!out)
        return strdup("");
    ft_top_write_document(m, mode, nullptr, indent, out);
    fclose(out);
    return text;
}

/* A path with every character JSON has to escape, and one that is not ASCII. */
static const char *const AWKWARD = "/srv/q\"u\\o\nt\xc3\xa9.bin";

static void fill(struct fixture *f)
{
    process(f, 100, 1, "nginx", "nginx: master process /usr/sbin/nginx", "", 0);
    process(f, 101, 100, "nginx", "nginx: worker process", "", 1000);
    process(f, 200, 1, "php-fpm8.3", "php-fpm: pool www", "/srv/app/public/download.php", 7);
    transfer(f, (struct xfer){.id = 1,
                              .pid = 101,
                              .rate = 4000,
                              .bytes = 9'007'199'254'740'993ull,
                              .size = 0,
                              .path = "/var/www/video.mp4",
                              .remote = "198.51.100.4"});
    transfer(f, (struct xfer){.id = 2,
                              .pid = 101,
                              .rate = 900,
                              .bytes = 5000,
                              .size = 10000,
                              .path = "/var/www/hero.webp",
                              .remote = "10.0.0.5"});
    transfer(f, (struct xfer){.id = 3,
                              .pid = 200,
                              .rate = 300,
                              .bytes = 12,
                              .size = 100,
                              .path = AWKWARD,
                              .remote = "198.51.100.4",
                              .method = FT_METHOD_READ_SEND,
                              .script = "/srv/app/public/download.php"});
    sample(f, 0);
}

static void documents(void)
{
    static const char *const names[] = {"transfers", "processes", "destinations", "files"};
    static const enum ft_top_mode modes[] = {FT_TOP_TRANSFERS, FT_TOP_PROCESSES,
                                             FT_TOP_DESTINATIONS, FT_TOP_FILES};
    struct fixture f;

    fixture_init(&f);
    fill(&f);
    for (size_t i = 0; i < FT_ARRAY_LEN(modes); i++) {
        for (int indent = 0; indent < 2; indent++) {
            char *text = document(f.m, modes[i], indent);
            char key[32];

            CHECK(json_ok(text));
            snprintf(key, sizeof(key), "\"mode\"%s\"%s\"", indent ? ": " : ":", names[i]);
            CHECK(has(text, key));
            CHECK(has(text, indent ? "\n  \"totals\": {" : "\"totals\":{"));
            CHECK(indent ? count(text, '\n') > 10 : count(text, '\n') == 1);
            free(text);
        }
    }

    char *text = document(f.m, FT_TOP_TRANSFERS, true);
    /* Integers past 2^53 are not rounded, an unknown size and progress are null. */
    CHECK(has(text, "\"bytes_sent\": 9007199254740993,"));
    CHECK(has(text, "\"size\": null,\n      \"bytes_sent\": 9007199254740993,\n"
                    "      \"progress\": null,"));
    CHECK(has(text, "\"progress\": 0.5,"));
    CHECK(has(text, "\"time\": \"2026-09-21T14:13:20.000Z\""));
    CHECK(has(text, "\"id\": \"tr_1\""));
    CHECK(has(text, "\"method\": \"read-write\""));
    CHECK(has(text, "\"confidence\": \"inferred\""));
    CHECK(has(text,
              "\"remote\": {\n        \"address\": \"198.51.100.4\",\n        \"port\": 443,\n"
              "        \"public\": true,\n        \"host\": null\n      }"));
    CHECK(has(text, "\"script\": \"/srv/app/public/download.php\""));
    /* The quote, the backslash and the newline are escaped; the accented letter is kept. */
    CHECK(has(text, "\"file\": \"/srv/q\\\"u\\\\o\\nt\xc3\xa9.bin\""));
    free(text);

    text = document(f.m, FT_TOP_TRANSFERS, false);
    CHECK(has(text, "\"remote\":{\"address\":\"10.0.0.5\",\"port\":443,\"public\":false,"));
    free(text);

    text = document(f.m, FT_TOP_DESTINATIONS, true);
    CHECK(has(text, "\"address\": \"198.51.100.4\""));
    CHECK(has(text, "\"trend\": ["));
    free(text);

    text = document(f.m, FT_TOP_FILES, true);
    CHECK(has(text, "\"senders\": [\n"));
    free(text);
    fixture_free(&f);
}

static void grouped_and_tree(void)
{
    struct fixture f;

    fixture_init(&f);
    process(&f, 100, 1, "nginx", "nginx: master process /usr/sbin/nginx", "", 0);
    for (uint32_t pid = 101; pid <= 104; pid++)
        process(&f, pid, 100, "nginx", "nginx: worker process", "", 1000);
    process(&f, 200, 1, "php-fpm8.3", "php-fpm: pool www", "/srv/download.php", 7);
    for (uint32_t pid = 101; pid <= 104; pid++)
        transfer(&f, (struct xfer){.id = pid, .pid = pid, .rate = 100 * (105 - pid)});
    transfer(&f, (struct xfer){.id = 201, .pid = 200, .rate = 50, .script = "/srv/download.php"});
    sample(&f, 0);

    /* Group headings are not rows: each row names its group instead. */
    ft_top_set_group(f.m, FT_TOP_TRANSFERS, FT_TOP_GROUP_SCRIPT);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 7);
    FILE *null = fopen("/dev/null", "w");
    CHECK_U64(ft_top_write_document(f.m, FT_TOP_TRANSFERS, nullptr, false, null), 5);
    fclose(null);
    char *text = document(f.m, FT_TOP_TRANSFERS, false);
    CHECK(json_ok(text));
    CHECK(has(text, "\"group\":\"script\""));
    CHECK(has(text, "\"transfers\":[{\"group\":null,\"id\":\"tr_65\""));
    CHECK(has(text, "{\"group\":\"/srv/download.php\",\"id\":\"tr_c9\""));
    free(text);

    /* A tree row has its depth, and holds a process, a fold of its siblings or a transfer. */
    ft_top_set_tree(f.m, true);
    ft_top_toggle_expanded(f.m, FT_TOP_PROCESSES, 1);
    text = document(f.m, FT_TOP_PROCESSES, true);
    CHECK(json_ok(text));
    CHECK(has(text, "\"tree\": true"));
    CHECK(has(text, "\"group\": null"));
    CHECK(has(text, "\"depth\": 0,\n      \"pid\": 100,\n      \"ppid\": 1,"));
    CHECK(has(text, "\"depth\": 2,\n      \"transfer\": {\n        \"id\": \"tr_65\","));
    CHECK(has(text, "\"fold\": {\n        \"process\": \"nginx: worker process\",\n"
                    "        \"count\": 3,\n        \"pids\": [102, 103, 104],"));
    free(text);
    fixture_free(&f);
}

static char *row_json(const struct ft_top_model *m, enum ft_top_mode mode, size_t index)
{
    char *text = nullptr;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);

    CHECK(out != nullptr);
    if (!out)
        return strdup("");
    ft_top_row_json(m, mode, index, out);
    fclose(out);
    return text;
}

static void single_rows(void)
{
    struct fixture f;

    fixture_init(&f);
    fill(&f);

    /* An object that stands alone: indented from the margin, without a final newline. */
    char *text = row_json(f.m, FT_TOP_TRANSFERS, 0);
    CHECK(json_ok(text));
    CHECK(starts(text, "{\n  \"id\": \"tr_1\",\n"));
    CHECK(has(text, "\n  \"remote\": {\n    \"address\": \"198.51.100.4\","));
    CHECK(ends(text, "\n}"));
    free(text);

    text = row_json(f.m, FT_TOP_TRANSFERS, 99);
    CHECK_STR(text, "");
    free(text);

    /* A group heading is a row too, and a row of a group names it. */
    ft_top_set_group(f.m, FT_TOP_TRANSFERS, FT_TOP_GROUP_SCRIPT);
    text = row_json(f.m, FT_TOP_TRANSFERS, 0);
    CHECK(json_ok(text));
    CHECK(starts(text, "{\n  \"group\": null,\n  \"rows\": 2,"));
    free(text);
    text = row_json(f.m, FT_TOP_TRANSFERS, 4);
    CHECK(json_ok(text));
    CHECK(has(text, "\"group\": \"/srv/app/public/download.php\",\n  \"id\": \"tr_3\""));
    free(text);
    fixture_free(&f);
}

static char *csv(const struct ft_top_model *m, enum ft_top_mode mode, size_t *rows)
{
    char *text = nullptr;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);

    CHECK(out != nullptr);
    if (!out)
        return strdup("");
    *rows = ft_top_write_csv(m, mode, out);
    fclose(out);
    return text;
}

/* Reads one record, counting its fields; quoted fields may hold commas, quotes and newlines. */
static bool csv_record(const char **cursor, size_t *fields)
{
    const char *p = *cursor;
    bool quoted = false;

    if (!*p)
        return false;
    *fields = 1;
    for (; *p; p++) {
        if (quoted) {
            if (*p == '"' && p[1] == '"')
                p++;
            else if (*p == '"')
                quoted = false;
        } else if (*p == '"') {
            quoted = true;
        } else if (*p == ',') {
            (*fields)++;
        } else if (*p == '\n') {
            p++;
            break;
        }
    }
    *cursor = p;
    return true;
}

/* Every record has as many fields as the header; returns how many records there are. */
static size_t csv_records(const char *text, size_t *columns)
{
    const char *cursor = text;
    size_t fields = 0;
    size_t records = 0;

    while (csv_record(&cursor, &fields)) {
        if (records == 0)
            *columns = fields;
        CHECK_U64(fields, *columns);
        records++;
    }
    return records;
}

static void tables(void)
{
    struct fixture f;
    size_t rows;
    size_t columns = 0;

    fixture_init(&f);
    process(&f, 100, 1, "nginx", "nginx: master process /usr/sbin/nginx", "", 0);
    process(&f, 101, 100, "nginx", "nginx: worker process", "", 1000);
    transfer(&f, (struct xfer){.id = 1, .pid = 101, .rate = 400, .path = "/srv/a,b.bin"});
    transfer(&f, (struct xfer){.id = 2, .pid = 101, .rate = 300, .path = "/srv/say \"hi\".bin"});
    transfer(&f, (struct xfer){.id = 3, .pid = 101, .rate = 200, .path = AWKWARD, .ino = 7});
    transfer(&f, (struct xfer){.id = 4, .pid = 101, .rate = 100, .path = "/srv/plain.bin"});
    sample(&f, 0);

    char *text = csv(f.m, FT_TOP_TRANSFERS, &rows);
    CHECK_U64(rows, 4);
    CHECK_U64(csv_records(text, &columns), 5);
    CHECK(starts(text, "id,pid,user,process,comm,script,file,device,inode,size,bytes_sent,"));
    CHECK(has(text, ",remote.address,remote.port,remote.public,remote.host,age_seconds,"));
    CHECK(has(text, ",\"/srv/a,b.bin\","));
    CHECK(has(text, ",\"/srv/say \"\"hi\"\".bin\","));
    CHECK(has(text, ",\"/srv/q\"\"u\\o\nt\xc3\xa9.bin\","));
    CHECK(has(text, ",/srv/plain.bin,"));
    /* An absent value is an empty cell. */
    CHECK(has(text, "tr_4,101,root,nginx: worker process,nginx,,/srv/plain.bin,2049,4,,0,"));
    free(text);

    /* A group is a column; a heading is not a record. */
    ft_top_set_group(f.m, FT_TOP_TRANSFERS, FT_TOP_GROUP_PROCESS);
    text = csv(f.m, FT_TOP_TRANSFERS, &rows);
    CHECK_U64(rows, 4);
    CHECK_U64(csv_records(text, &columns), 5);
    CHECK(starts(text, "group,id,"));
    CHECK(has(text, "\nnginx: worker process,tr_1,"));
    free(text);

    /* The tree has the columns of its processes, folds and transfers, empty where a row lacks. */
    ft_top_set_tree(f.m, true);
    ft_top_toggle_expanded(f.m, FT_TOP_PROCESSES, 1);
    text = csv(f.m, FT_TOP_PROCESSES, &rows);
    CHECK_U64(csv_records(text, &columns), rows + 1);
    CHECK(starts(text, "depth,pid,ppid,user,process,command_line,script,rate,total,files,"));
    CHECK(has(text, ",fold.process,fold.count,fold.pids,fold.rate,"));
    CHECK(has(text, ",transfer.id,transfer.pid,transfer.user,"));
    CHECK(has(text, ",transfer.remote.address,transfer.remote.port,"));
    CHECK(has(text, "\n0,100,1,root,"));
    CHECK(has(text, ",tr_1,101,root,"));
    free(text);

    fixture_free(&f);
}

static void lists(void)
{
    struct fixture f;
    size_t rows;
    size_t columns = 0;

    fixture_init(&f);
    process(&f, 10, 1, "nginx", "nginx", "", 0);
    process(&f, 11, 1, "php-fpm", "php-fpm", "", 0);
    transfer(&f, (struct xfer){.id = 1, .pid = 10, .rate = 400, .ino = 5});
    transfer(&f, (struct xfer){.id = 2, .pid = 11, .rate = 300, .ino = 5});
    sample(&f, 0);

    /* The senders of a file are named in one cell, the points of a trend are all there. */
    char *text = csv(f.m, FT_TOP_FILES, &rows);
    CHECK_U64(rows, 1);
    CHECK_U64(csv_records(text, &columns), 2);
    CHECK(has(text, ",nginx;php-fpm,sendfile,"));
    free(text);
    text = csv(f.m, FT_TOP_DESTINATIONS, &rows);
    CHECK_U64(csv_records(text, &columns), 2);
    CHECK(has(text, ",trend\n"));
    CHECK(has(text, ",0;0;0;0;0;0;0;0;0;0;0;"));
    free(text);
    fixture_free(&f);
}

static void leader(struct ft_rows *rows, uint32_t rank, uint32_t previous, const char *text,
                   uint64_t bytes, const char *sender)
{
    struct ft_row_leader *row = calloc(1, sizeof(*row));

    row->rank = rank;
    row->previous_rank = previous;
    row->bytes = bytes;
    row->bytes_error = 5;
    row->bytes_exact = bytes / 2;
    row->transfers = 10 * rank;
    row->destinations = rank;
    row->files = 3;
    row->file_size = text[0] == '/' && text[strlen(text) - 1] != '/' ? 4096 : 0;
    row->dev = row->file_size ? 2049 : 0;
    row->ino = row->file_size ? rank : 0;
    row->first_wall_ns = WALL;
    row->method = FT_METHOD_SENDFILE;
    row->confidence = FT_CONF_EXACT;
    row->flags = rank == 2 ? FT_LEADER_MORE_SENDERS : 0;
    for (size_t i = 0; i < FT_LEADER_SLOTS; i++)
        row->trend[i] = i;
    ft_strlcpy(row->senders[0].name, sender, sizeof(row->senders[0].name));
    row->senders[0].bytes = bytes;
    row->senders[0].transfers = row->transfers;
    ft_strlcpy(row->text, text, sizeof(row->text));
    if (!row->file_size)
        CHECK(ft_addr_parse("198.51.100.4", &row->remote));
    CHECK(ft_rows_append(rows, row, offsetof(struct ft_row_leader, text) + strlen(text) + 1));
    free(row);
}

static void leaders(void)
{
    struct ft_top_model *m = ft_top_model_create();
    struct ft_rows ranking;
    struct ft_rows directories;
    struct ft_rows destinations;
    struct ft_row_leader_summary summary = {
        .window_ns = 3600 * SECOND,
        .from_wall_ns = WALL - 3600 * SECOND,
        .to_wall_ns = WALL,
        .previous_from_wall_ns = WALL - 7200 * SECOND,
        .bytes = 1000,
        .bytes_exact = 500,
        .top_bytes = 600,
        .flags = FT_LEADERS_SHORT_HISTORY,
    };

    ft_rows_init(&ranking, FT_MSG_ROW_LEADER);
    ft_rows_init(&directories, FT_MSG_ROW_LEADER);
    ft_rows_init(&destinations, FT_MSG_ROW_LEADER);
    leader(&ranking, 1, 2, "/var/lib/kafka/events-7.log", 9'007'199'254'740'993ull, "java");
    leader(&ranking, 2, 0, AWKWARD, 200, "rclone");
    leader(&directories, 1, 0, "/var/lib/kafka/", 400, "java");
    leader(&destinations, 1, 0, "", 300, "nginx");
    ft_top_set_leaders_request(m, FT_WINDOW_1H, FT_LEADER_FILE);
    struct ft_top_leaders_sample sample = {
        .window = FT_WINDOW_1H,
        .key = FT_LEADER_FILE,
        .by = FT_TOP_SORT_BYTES,
        .summary = &summary,
        .ranking = &ranking,
        .directories = &directories,
        .destinations = &destinations,
    };
    CHECK(ft_top_model_leaders(m, &sample));

    char *text = document(m, FT_TOP_LEADERS, true);
    CHECK(json_ok(text));
    CHECK(has(text, "\"mode\": \"leaders\",\n  \"time\": \"2026-09-21T14:13:20.000Z\""));
    CHECK(has(text, "\"window\": \"1h\",\n  \"by\": \"bytes\",\n  \"key\": \"file\","));
    CHECK(has(text, "\"from\": \"2026-09-21T13:13:20.000Z\""));
    CHECK(has(text, "\"previous_from\": \"2026-09-21T12:13:20.000Z\""));
    CHECK(has(text, "\"short_history\": true,\n    \"capped\": false"));
    CHECK(has(text, "\"files\": [\n    {\n      \"rank\": 1,\n      \"previous_rank\": 2,"));
    CHECK(has(text, "\"bytes\": 9007199254740993,"));
    CHECK(has(text, "\"previous_rank\": null,"));
    CHECK(has(text, "\"file\": \"/srv/q\\\"u\\\\o\\nt\xc3\xa9.bin\""));
    CHECK(has(text, "\"trend\": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]"));
    CHECK(has(text, "\"more_senders\": true"));
    CHECK(has(text, "\"senders\": [\n        {\n          \"name\": \"java\","));
    CHECK(has(text, "\"directories\": [\n    {\n      \"rank\": 1,"));
    CHECK(has(text, "\"directory\": \"/var/lib/kafka/\""));
    CHECK(has(text, "\"address\": \"198.51.100.4\""));
    free(text);

    /* The ranking is named after its key and is not given again as the side list. */
    ft_top_set_leaders_request(m, FT_WINDOW_1H, FT_LEADER_DIRECTORY);
    sample.key = FT_LEADER_DIRECTORY;
    sample.ranking = &directories;
    CHECK(ft_top_model_leaders(m, &sample));
    text = document(m, FT_TOP_LEADERS, false);
    CHECK(json_ok(text));
    CHECK(has(text, "\"key\":\"directory\""));
    CHECK(has(text, "\"directories\":[{\"rank\":1,"));
    CHECK(!has(text, "\"files\":["));
    CHECK(has(text, "\"destinations\":[{"));
    free(text);

    ft_rows_free(&ranking);
    ft_rows_free(&directories);
    ft_rows_free(&destinations);
    ft_top_model_destroy(m);
}

static char *printed(const struct ft_canvas *canvas, enum ft_color_depth depth)
{
    char *text = nullptr;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);

    CHECK(out != nullptr);
    if (!out)
        return strdup("");
    ft_top_print_canvas(canvas, depth, out);
    fclose(out);
    return text;
}

static void canvas_lines(void)
{
    struct ft_canvas *c = ft_canvas_create(12, 4);
    struct ft_style bright = {FT_COLOR_BRIGHT, FT_COLOR_DEFAULT, FT_ATTR_BOLD};
    struct ft_style dim = {FT_COLOR_DIM, FT_COLOR_DEFAULT, 0};
    struct ft_style bar = {FT_COLOR_BG, FT_COLOR_GREEN, 0};

    CHECK(c != nullptr);
    ft_canvas_text(c, 0, 0, 12, bright, "ab");
    ft_canvas_text(c, 2, 0, 10, dim, "cd  ");
    /* A wide character takes two cells and is written once. */
    ft_canvas_text(c, 0, 1, 12, dim, "\xe6\x97\xa5\xe6\x9c\xac x");
    ft_canvas_fill(c, (struct ft_rect){0, 2, 12, 1}, ' ', bar);
    ft_canvas_text(c, 0, 2, 12, bar, "HEAD");

    /* Without color the lines end at their last character. */
    char *text = printed(c, FT_DEPTH_NONE);
    CHECK_STR(text, "abcd\n\xe6\x97\xa5\xe6\x9c\xac x\nHEAD\n\n");
    free(text);

    /* A sequence is written where the style changes; a bar keeps its blanks; each line is reset. */
    text = printed(c, FT_DEPTH_TRUECOLOR);
    CHECK(starts(text, "\033[0;1;38;2;240;246;252mab\033[0;38;2;125;133;144mcd\033[0m\n"));
    CHECK(has(text, "\n\033[0;38;2;125;133;144m\xe6\x97\xa5\xe6\x9c\xac x\033[0m\n"));
    CHECK(has(text, "\n\033[0;38;2;11;14;20;48;2;63;185;80mHEAD        \033[0m\n\n"));
    CHECK_U64(count(text, '\033'), 7);
    free(text);
    ft_canvas_destroy(c);
}

static char *table(const struct ft_top_model *m, enum ft_top_mode mode)
{
    struct ft_top_ui ui = {.mode = mode, .full_paths = true};
    char *text = nullptr;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);

    CHECK(out != nullptr);
    if (!out)
        return strdup("");
    CHECK(ft_top_print_table(m, &ui, 174, FT_DEPTH_NONE, out));
    fclose(out);
    return text;
}

static void table_height(void)
{
    struct fixture f;

    fixture_init(&f);
    /* The empty table has its header and one line to say so; otherwise one line per row. */
    char *text = table(f.m, FT_TOP_TRANSFERS);
    CHECK_U64(count(text, '\n'), 2);
    free(text);
    fill(&f);
    text = table(f.m, FT_TOP_TRANSFERS);
    CHECK_U64(count(text, '\n'), 4);
    free(text);
    ft_top_set_group(f.m, FT_TOP_TRANSFERS, FT_TOP_GROUP_SCRIPT);
    text = table(f.m, FT_TOP_TRANSFERS);
    CHECK_U64(count(text, '\n'), 6);
    free(text);
    fixture_free(&f);
}

static void leaders_lines(void)
{
    constexpr uint64_t TO = 1'789'995'544 * SECOND;
    struct ft_top_model *m = ft_top_model_create();
    struct ft_rows ranking;
    struct ft_row_leader_summary summary = {
        .window_ns = 3600 * SECOND,
        .from_wall_ns = TO - 3604 * SECOND,
        .to_wall_ns = TO,
        .previous_from_wall_ns = TO - 7204 * SECOND,
        .bytes = 2'023'000'000'000,
        .bytes_exact = 1'375'640'000'000,
        .transfers = 48'211,
        .files = 12'408,
        .processes = 23,
        .scripts = 9,
        .destinations_public = 41'231,
        .destinations_private = 157,
    };
    struct ft_top_leaders_sample sample = {
        .window = FT_WINDOW_1H,
        .key = FT_LEADER_FILE,
        .by = FT_TOP_SORT_BYTES,
        .summary = &summary,
    };
    const char *zone = getenv("TZ");
    char *saved = zone ? strdup(zone) : nullptr;

    setenv("TZ", "UTC", 1);
    tzset();
    ft_rows_init(&ranking, FT_MSG_ROW_LEADER);
    sample.ranking = &ranking;
    ft_top_set_leaders_request(m, FT_WINDOW_1H, FT_LEADER_FILE);
    CHECK(ft_top_model_leaders(m, &sample));

    char *text = table(m, FT_TOP_LEADERS);
    CHECK(starts(text, "Window 1h, 11:59:00 to 12:59:04, ranked by bytes. "
                       "Compared with the hour before.\n"
                       "Sent 1.84 TB in 48,211 transfers: 68% sendfile, 32% read-write.\n"
                       "12,408 files from 23 processes and 9 scripts to 41,388 destinations "
                       "(41,231 public).\n"));
    CHECK(!has(text, "not full"));
    free(text);

    /* A history shorter than the window is said so; no span before it means no comparison. */
    summary.flags = FT_LEADERS_SHORT_HISTORY;
    summary.previous_from_wall_ns = 0;
    summary.bytes = 0;
    summary.transfers = 1;
    summary.files = 1;
    summary.processes = 1;
    summary.scripts = 0;
    summary.destinations_public = 0;
    summary.destinations_private = 1;
    CHECK(ft_top_model_leaders(m, &sample));
    text = table(m, FT_TOP_LEADERS);
    CHECK(starts(text, "Window 1h, 11:59:00 to 12:59:04, ranked by bytes.\n"
                       "Sent 0 B in 1 transfer.\n"
                       "1 file from 1 process and 0 scripts to 1 destination (0 public).\n"
                       "The agent has been running since 11:59:00; the window is not full.\n"));
    free(text);

    if (saved)
        setenv("TZ", saved, 1);
    else
        unsetenv("TZ");
    tzset();
    free(saved);
    ft_rows_free(&ranking);
    ft_top_model_destroy(m);
}

static char *read_file(const char *path)
{
    FILE *in = fopen(path, "r");
    char *text = nullptr;
    size_t size = 0;
    size_t used = 0;

    if (!in)
        return nullptr;
    for (;;) {
        char *grown = realloc(text, size + 4097);
        CHECK(grown != nullptr);
        text = grown;
        size_t n = fread(text + used, 1, 4096, in);
        used += n;
        size += 4096;
        if (n < 4096)
            break;
    }
    text[used] = '\0';
    fclose(in);
    return text;
}

static size_t entries(const char *dir)
{
    DIR *d = opendir(dir);
    size_t n = 0;

    CHECK(d != nullptr);
    for (struct dirent *e = d ? readdir(d) : nullptr; e; e = readdir(d))
        n += strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0;
    if (d)
        closedir(d);
    return n;
}

static void exports(void)
{
    const char *base = getenv("TMPDIR") && getenv("TMPDIR")[0] ? getenv("TMPDIR") : "/tmp";
    char dir[PATH_MAX];
    char path[PATH_MAX + 16];
    struct ft_error err = {0};
    struct fixture f;
    size_t rows;

    snprintf(dir, sizeof(dir), "%s/ft-top-once-XXXXXX", base);
    CHECK(mkdtemp(dir) != nullptr);
    fixture_init(&f);
    fill(&f);

    /* JSON, unless the name ends in .csv; the document is written whole and nothing else stays. */
    snprintf(path, sizeof(path), "%s/rows.json", dir);
    CHECK(ft_top_export(f.m, FT_TOP_TRANSFERS, path, &rows, &err));
    CHECK_U64(rows, 3);
    char *text = read_file(path);
    CHECK(text && json_ok(text) && has(text, "\"mode\": \"transfers\""));
    free(text);
    CHECK_U64(entries(dir), 1);

    snprintf(path, sizeof(path), "%s/rows.csv", dir);
    CHECK(ft_top_export(f.m, FT_TOP_TRANSFERS, path, &rows, &err));
    CHECK_U64(rows, 3);
    text = read_file(path);
    CHECK(text && starts(text, "id,pid,user,"));
    free(text);
    CHECK_U64(entries(dir), 2);

    /* A file that is there is replaced. */
    snprintf(path, sizeof(path), "%s/rows.json", dir);
    CHECK(ft_top_export(f.m, FT_TOP_DESTINATIONS, path, &rows, &err));
    CHECK_U64(rows, 2);
    text = read_file(path);
    CHECK(text && json_ok(text) && has(text, "\"mode\": \"destinations\""));
    CHECK(text && !has(text, "\"transfers\": ["));
    free(text);
    CHECK_U64(entries(dir), 2);

    /* A failure says why and leaves no file, whole or half. */
    snprintf(path, sizeof(path), "%s/missing/rows.json", dir);
    CHECK(!ft_top_export(f.m, FT_TOP_TRANSFERS, path, &rows, &err));
    CHECK_U64(rows, 0);
    CHECK(starts(err.msg, "Cannot write ") && has(err.msg, "No such file or directory"));
    CHECK_U64(entries(dir), 2);
    snprintf(path, sizeof(path), "%s/folder", dir);
    CHECK(mkdir(path, 0700) == 0);
    CHECK(!ft_top_export(f.m, FT_TOP_TRANSFERS, path, &rows, &err));
    CHECK_U64(entries(dir), 3);
    rmdir(path);
    if (geteuid() != 0) {
        char locked[PATH_MAX + 8];

        snprintf(locked, sizeof(locked), "%s/locked", dir);
        CHECK(mkdir(locked, 0500) == 0);
        snprintf(path, sizeof(path), "%s/locked/rows.json", dir);
        CHECK(!ft_top_export(f.m, FT_TOP_TRANSFERS, path, &rows, &err));
        CHECK(has(err.msg, "Permission denied"));
        CHECK_U64(entries(locked), 0);
        rmdir(locked);
    }
    CHECK(!ft_top_export(f.m, FT_TOP_TRANSFERS, "", &rows, &err));

    snprintf(path, sizeof(path), "%s/rows.json", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/rows.csv", dir);
    unlink(path);
    rmdir(dir);
    fixture_free(&f);
}

void test_top_once(void)
{
    documents();
    grouped_and_tree();
    leaders();
    single_rows();
    tables();
    lists();
    canvas_lines();
    table_height();
    leaders_lines();
    exports();
}
