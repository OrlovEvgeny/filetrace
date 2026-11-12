#include "unit/test.h"

#include "ui/top/document.h"
#include "ui/top/model.h"
#include "ui/top/once.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    ft_top_write_document(m, mode, indent, out);
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

void test_top_once(void)
{
    documents();
}
