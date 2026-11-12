#include "unit/test.h"

#include "ui/top/model.h"

#include <stdlib.h>

static const char *size_text(uint64_t bytes)
{
    static char buf[32];
    ft_top_format_size(bytes, buf, sizeof(buf));
    return buf;
}

static const char *age_text(uint64_t ns)
{
    static char buf[32];
    ft_top_format_age(ns, buf, sizeof(buf));
    return buf;
}

static const char *percent_text(double share)
{
    static char buf[32];
    ft_top_format_percent(share, buf, sizeof(buf));
    return buf;
}

static void units(void)
{
    constexpr uint64_t K = 1024;
    constexpr uint64_t M = K * K;
    constexpr uint64_t G = M * K;
    constexpr uint64_t T = G * K;
    char rate[32];

    CHECK_STR(size_text(0), "0B");
    CHECK_STR(size_text(512), "512B");
    CHECK_STR(size_text(1023), "1023B");
    CHECK_STR(size_text(K), "1K");
    CHECK_STR(size_text(51 * K + 200), "51K");
    CHECK_STR(size_text(922 * K), "922K");
    CHECK_STR(size_text(1023 * K), "1023K");
    /* 1023.5K would print as 1024K, so it is the first size shown in M. */
    CHECK_STR(size_text(1023 * K + 511), "1023K");
    CHECK_STR(size_text(1023 * K + 512), "1.0M");
    CHECK_STR(size_text(38 * M + 400 * K), "38.4M");
    CHECK_STR(size_text(1023 * M), "1023.0M");
    CHECK_STR(size_text(G - 1), "1.0G");
    CHECK_STR(size_text(2 * G + 100 * M), "2.1G");
    CHECK_STR(size_text(1023 * G), "1023.0G");
    CHECK_STR(size_text(T), "1.00T");
    CHECK_STR(size_text(T + 860 * G), "1.84T");

    ft_top_format_rate(72 * M + 300 * K, rate, sizeof(rate));
    CHECK_STR(rate, "72.3M/s");
    ft_top_format_rate(410 * K, rate, sizeof(rate));
    CHECK_STR(rate, "410K/s");

    CHECK_STR(age_text(0), "0.0s");
    CHECK_STR(age_text(300 * FT_NS_PER_MS), "0.3s");
    CHECK_STR(age_text(9 * FT_NS_PER_SEC), "9.0s");
    CHECK_STR(age_text(10 * FT_NS_PER_SEC - 1), "9.9s");
    CHECK_STR(age_text(10 * FT_NS_PER_SEC), "10s");
    CHECK_STR(age_text(21 * FT_NS_PER_SEC + 900 * FT_NS_PER_MS), "21s");
    CHECK_STR(age_text(60 * FT_NS_PER_SEC - 1), "59s");
    CHECK_STR(age_text(60 * FT_NS_PER_SEC), "1:00");
    CHECK_STR(age_text(297 * FT_NS_PER_SEC), "4:57");
    CHECK_STR(age_text(3599 * FT_NS_PER_SEC), "59:59");
    CHECK_STR(age_text(3600 * FT_NS_PER_SEC), "1h00");
    CHECK_STR(age_text(86399 * FT_NS_PER_SEC), "23h59");
    CHECK_STR(age_text(86400 * FT_NS_PER_SEC), "1d00");
    CHECK_STR(age_text((3 * 86400 + 4 * 3600 + 59) * FT_NS_PER_SEC), "3d04");

    CHECK_STR(percent_text(0.0), "  0%");
    CHECK_STR(percent_text(0.05), "  5%");
    CHECK_STR(percent_text(0.634), " 63%");
    CHECK_STR(percent_text(0.996), " 99%");
    CHECK_STR(percent_text(1.0), "100%");
    CHECK_STR(percent_text(1.7), "100%");
    CHECK_STR(percent_text(-0.2), "  0%");
}

constexpr uint64_t SECOND = FT_NS_PER_SEC;
constexpr uint64_t WALL = 1'790'000'000 * FT_NS_PER_SEC;

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
    row->uid = 0;
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
    uint16_t port;
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
    row->remote.port = x.port ? x.port : 443;
    ft_strlcpy(row->comm, "worker", sizeof(row->comm));
    ft_strlcpy(row->path, x.path ? x.path : "/srv/data/file.bin", FT_PATH_MAX);
    size_t lead = strlen(row->path) + 1;
    ft_process_strings_pack(row->path + lead, sizeof(row->path) - lead, &text);
    CHECK(ft_rows_append(&f->transfers, row, ft_row_transfer_size(row)));
    free(row);
}

/* Hands the rows gathered so far to the model as the answers taken at second at. */
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

static const struct ft_top_row *row_at(struct fixture *f, enum ft_top_mode mode, size_t i)
{
    static const struct ft_top_row none;
    const struct ft_top_row *r = ft_top_row_at(f->m, mode, i);
    CHECK(r != nullptr);
    return r ? r : &none;
}

static uint64_t id_at(struct fixture *f, size_t i)
{
    const struct ft_top_row *r = row_at(f, FT_TOP_TRANSFERS, i);
    return r->kind == FT_TOP_ROW_TRANSFER && r->transfer ? r->transfer->id : 0;
}

static void smoothing(void)
{
    struct fixture even;
    struct fixture uneven;
    fixture_init(&even);
    fixture_init(&uneven);

    /* The first sample shows the agent's rate as it is. */
    transfer(&even, (struct xfer){.id = 1, .pid = 7, .rate = 1000});
    sample(&even, 0);
    CHECK_U64(id_at(&even, 0), 1);
    CHECK_U64(row_at(&even, FT_TOP_TRANSFERS, 0)->transfer->rate, 1000);
    transfer(&uneven, (struct xfer){.id = 1, .pid = 7, .rate = 1000});
    sample(&uneven, 0);

    /* A step to 2000 is halfway there after three seconds, however they are split. */
    for (int s = 1; s <= 3; s++) {
        transfer(&even, (struct xfer){.id = 1, .pid = 7, .rate = 2000});
        sample(&even, s);
    }
    static const double times[] = {0.5, 2.0, 3.0};
    for (size_t i = 0; i < FT_ARRAY_LEN(times); i++) {
        transfer(&uneven, (struct xfer){.id = 1, .pid = 7, .rate = 2000});
        sample(&uneven, times[i]);
    }
    CHECK_U64(row_at(&even, FT_TOP_TRANSFERS, 0)->transfer->rate, 1500);
    CHECK_U64(row_at(&uneven, FT_TOP_TRANSFERS, 0)->transfer->rate, 1500);

    /* Six seconds in, three quarters. */
    for (int s = 4; s <= 6; s++) {
        transfer(&even, (struct xfer){.id = 1, .pid = 7, .rate = 2000});
        sample(&even, s);
    }
    CHECK_U64(row_at(&even, FT_TOP_TRANSFERS, 0)->transfer->rate, 1750);
    CHECK_U64(ft_top_totals(even.m)->rate.value, 1750);

    fixture_free(&even);
    fixture_free(&uneven);
}

/* The raw rate that brings a smoothed rate from prev to target in one second. */
static uint64_t raw_for(double prev, double target)
{
    double keep = 0.7937005259840998; /* 2^(-1/3) */
    return (uint64_t)((target - prev * keep) / (1 - keep) + 0.5);
}

static void meters(void)
{
    struct fixture f;
    fixture_init(&f);

    /* The scale rounds the largest rate up to 1, 2 or 5 times a power of ten. */
    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 4800});
    sample(&f, 0);
    CHECK_U64(ft_top_totals(f.m)->rate.scale, 5000);
    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = raw_for(4800, 12000)});
    sample(&f, 1);
    CHECK_U64(ft_top_totals(f.m)->rate.scale, 20000);

    /* Idle, the rate falls under a fifth of the scale at 6 s (3780), and stays there. */
    for (int s = 2; s <= 65; s++) {
        transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 0});
        sample(&f, s);
        if (s == 5)
            CHECK_U64(ft_top_totals(f.m)->rate.value, 4762);
    }
    CHECK_U64(ft_top_totals(f.m)->rate.scale, 20000);
    /* A minute later it shrinks to fit the largest rate seen meanwhile. */
    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 0});
    sample(&f, 66);
    CHECK_U64(ft_top_totals(f.m)->rate.scale, 5000);
    fixture_free(&f);
}

static void order(void)
{
    struct fixture f;
    fixture_init(&f);

    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 1000, .bytes = 5000});
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = 900, .bytes = 5050});
    sample(&f, 0);
    CHECK_U64(id_at(&f, 0), 1);
    CHECK_U64(id_at(&f, 1), 2);

    /* Crossing by 2% keeps the rows where they were. */
    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 1000, .bytes = 5000});
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = raw_for(900, 1020), .bytes = 5050});
    sample(&f, 1);
    CHECK_U64(row_at(&f, FT_TOP_TRANSFERS, 1)->transfer->rate, 1020);
    CHECK_U64(id_at(&f, 0), 1);
    CHECK_U64(id_at(&f, 1), 2);

    /* Still 2% ahead a refresh later: now it moves up. */
    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 1000, .bytes = 5000});
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = 1020, .bytes = 5050});
    sample(&f, 2);
    CHECK_U64(id_at(&f, 0), 2);
    CHECK_U64(id_at(&f, 1), 1);

    /* Crossing by 10% swaps at once. */
    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = raw_for(1000, 1130), .bytes = 5000});
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = 1020, .bytes = 5050});
    sample(&f, 3);
    CHECK_U64(id_at(&f, 0), 1);
    CHECK_U64(id_at(&f, 1), 2);

    /* A new sort key orders at once, however close the values. */
    CHECK(ft_top_set_sort(f.m, FT_TOP_TRANSFERS, FT_TOP_SORT_BYTES, true));
    CHECK_U64(id_at(&f, 0), 2);
    CHECK_U64(id_at(&f, 1), 1);
    CHECK(ft_top_set_sort(f.m, FT_TOP_TRANSFERS, FT_TOP_SORT_PID, true));
    CHECK(!ft_top_set_sort(f.m, FT_TOP_TRANSFERS, FT_TOP_SORT_TOTAL, true));
    fixture_free(&f);
}

static void selection(void)
{
    struct fixture f;
    fixture_init(&f);

    for (uint64_t id = 1; id <= 3; id++)
        transfer(&f, (struct xfer){.id = id, .pid = 7, .rate = 4000 - id * 1000});
    sample(&f, 0);
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 0);
    ft_top_select_by(f.m, FT_TOP_TRANSFERS, 1);
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 1);
    CHECK(row_at(&f, FT_TOP_TRANSFERS, 1)->flags & FT_TOP_ROW_SELECTED);

    /* The selection follows its transfer to the top. */
    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 3000});
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = 90000});
    transfer(&f, (struct xfer){.id = 3, .pid = 7, .rate = 1000});
    sample(&f, 1);
    CHECK_U64(id_at(&f, 0), 2);
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 0);

    /* Once finished it stays two seconds, done, where it was. */
    ft_top_select_by(f.m, FT_TOP_TRANSFERS, 1);
    CHECK_U64(id_at(&f, 1), 1);
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = 90000});
    transfer(&f, (struct xfer){.id = 3, .pid = 7, .rate = 1000});
    sample(&f, 2);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 3);
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 1);
    const struct ft_top_row *done = row_at(&f, FT_TOP_TRANSFERS, 1);
    CHECK_U64(done->transfer->id, 1);
    CHECK(done->flags & FT_TOP_ROW_DONE);
    CHECK(done->transfer->done);
    CHECK_U64(done->transfer->rate, 0);
    CHECK_U64(ft_top_totals(f.m)->transfers, 2);

    /* An unselected transfer goes at once. */
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = 90000});
    sample(&f, 2.5);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 2);
    CHECK_U64(id_at(&f, 1), 1);

    /* It finished with the sample taken at 3 s on the model's clock. */
    CHECK(!ft_top_model_tick(f.m, 4 * SECOND + 990 * FT_NS_PER_MS));
    CHECK(ft_top_model_tick(f.m, 5 * SECOND));
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 1);
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 0);
    CHECK_U64(id_at(&f, 0), 2);
    fixture_free(&f);
}

static void tags(void)
{
    struct fixture f;
    struct ft_error err = {0};
    fixture_init(&f);

    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 3000, .path = "/srv/a.log"});
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = 2000, .path = "/srv/b.log"});
    sample(&f, 0);
    ft_top_tag_toggle(f.m, FT_TOP_TRANSFERS);
    CHECK(row_at(&f, FT_TOP_TRANSFERS, 0)->flags & FT_TOP_ROW_TAGGED);
    CHECK_U64(ft_top_tag_count(f.m, FT_TOP_TRANSFERS), 1);

    CHECK(ft_top_set_filter(f.m, FT_TOP_TRANSFERS, "file:b.log", &err));
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 1);
    CHECK(!(row_at(&f, FT_TOP_TRANSFERS, 0)->flags & FT_TOP_ROW_TAGGED));
    CHECK_U64(ft_top_view_of(f.m, FT_TOP_TRANSFERS)->shown, 1);
    CHECK_U64(ft_top_view_of(f.m, FT_TOP_TRANSFERS)->total, 2);
    CHECK(!ft_top_set_filter(f.m, FT_TOP_TRANSFERS, "usr:x", &err));
    CHECK_STR(ft_top_filter_of(f.m, FT_TOP_TRANSFERS), "file:b.log");

    CHECK(ft_top_set_filter(f.m, FT_TOP_TRANSFERS, "", &err));
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 2);
    CHECK_U64(id_at(&f, 0), 1);
    CHECK(row_at(&f, FT_TOP_TRANSFERS, 0)->flags & FT_TOP_ROW_TAGGED);
    CHECK(!(row_at(&f, FT_TOP_TRANSFERS, 1)->flags & FT_TOP_ROW_TAGGED));
    ft_top_tags_clear(f.m, FT_TOP_TRANSFERS);
    CHECK(!(row_at(&f, FT_TOP_TRANSFERS, 0)->flags & FT_TOP_ROW_TAGGED));
    fixture_free(&f);
}

static void aggregates(void)
{
    struct fixture f;
    struct ft_error err = {0};
    fixture_init(&f);

    process(&f, 100, 1, "nginx", "nginx: master process /usr/sbin/nginx", "", 0);
    for (uint32_t pid = 101; pid <= 104; pid++)
        process(&f, pid, 100, "nginx", "nginx: worker process", "", 1000 * pid);
    process(&f, 200, 1, "php-fpm8.3", "php-fpm: pool www", "/srv/app/public/download.php", 7);
    /* Four workers send one file; one of them twice to one client, on two ports. */
    for (uint32_t pid = 101; pid <= 104; pid++)
        transfer(&f, (struct xfer){.id = pid,
                                   .pid = pid,
                                   .rate = 1000,
                                   .ino = 9,
                                   .path = "/var/www/video.mp4",
                                   .remote = "198.51.100.4",
                                   .port = (uint16_t)(40000 + pid)});
    transfer(&f, (struct xfer){.id = 105,
                               .pid = 101,
                               .rate = 500,
                               .ino = 8,
                               .path = "/var/www/hero.webp",
                               .remote = "198.51.100.4",
                               .port = 40101});
    transfer(&f, (struct xfer){.id = 201,
                               .pid = 200,
                               .rate = 300,
                               .path = "/srv/app/inv.pdf",
                               .remote = "10.0.0.5",
                               .port = 5000,
                               .method = FT_METHOD_READ_SEND});
    sample(&f, 0);

    const struct ft_top_totals *t = ft_top_totals(f.m);
    CHECK_U64(t->rate.value, 4800);
    CHECK_U64(t->transfers, 6);
    CHECK_U64(t->processes.value, 5);
    CHECK_U64(t->destinations, 2);
    CHECK_U64(t->destinations_public, 1);
    CHECK_U64(t->files.value, 3);
    CHECK_U64(t->fanout.value, 4);
    CHECK_U64(t->rate_by_method[FT_METHOD_SENDFILE], 4500);
    CHECK_U64(t->rate.scale, 5000);
    CHECK(t->exact_share > 0.93 && t->exact_share < 0.94);

    /* A process's rate is the sum of its transfers. */
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_PROCESSES), 5);
    const struct ft_top_process *p = row_at(&f, FT_TOP_PROCESSES, 0)->process;
    CHECK_U64(p->pid, 101);
    CHECK_U64(p->rate, 1500);
    CHECK_U64(p->files, 2);
    CHECK_U64(p->destinations, 1);
    CHECK_U64(p->ntransfers, 2);
    CHECK_U64(p->total, 101000);
    CHECK_STR(p->title, "nginx: worker process");
    CHECK_STR(p->head, "nginx: worker");
    CHECK_STR(p->rest, "process");
    CHECK_STR(p->user, "root");
    const struct ft_top_process *php = row_at(&f, FT_TOP_PROCESSES, 4)->process;
    CHECK_STR(php->head, "php-fpm: pool");
    CHECK_STR(php->script_name, "download.php");
    CHECK_U64(php->method, FT_METHOD_READ_SEND);
    CHECK_U64(php->confidence, FT_CONF_INFERRED);

    /* The filter narrows what the aggregates add up. */
    CHECK(ft_top_set_filter(f.m, FT_TOP_PROCESSES, "file:*.mp4", &err));
    p = row_at(&f, FT_TOP_PROCESSES, 0)->process;
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_PROCESSES), 4);
    CHECK_U64(p->rate, 1000);
    CHECK_U64(p->files, 1);
    CHECK_U64(ft_top_view_of(f.m, FT_TOP_PROCESSES)->shown, 4);
    CHECK_U64(ft_top_view_of(f.m, FT_TOP_PROCESSES)->total, 5);
    CHECK(ft_top_set_filter(f.m, FT_TOP_PROCESSES, "dest:private", &err));
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_PROCESSES), 1);
    CHECK_U64(row_at(&f, FT_TOP_PROCESSES, 0)->process->pid, 200);

    /* A destination over two ports is ip:*, one port shows it. */
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_DESTINATIONS), 2);
    const struct ft_top_destination *d = row_at(&f, FT_TOP_DESTINATIONS, 0)->destination;
    CHECK_STR(d->label, "198.51.100.4:*");
    CHECK_U64(d->ports, 4);
    CHECK_U64(d->rate, 4500);
    CHECK_U64(d->files, 2);
    CHECK_U64(d->processes, 4);
    CHECK_U64(d->top_process->pid, 101);
    CHECK(d->is_public);
    CHECK_STR(row_at(&f, FT_TOP_DESTINATIONS, 1)->destination->label, "10.0.0.5:5000");

    /* A file four processes of one name send reads "name ×4". */
    const struct ft_top_file *file = row_at(&f, FT_TOP_FILES, 0)->file;
    CHECK_STR(file->path, "/var/www/video.mp4");
    CHECK_STR(file->path + file->name_offset, "video.mp4");
    CHECK_STR(file->senders, "nginx ×4");
    CHECK_U64(file->active, 4);
    CHECK_U64(file->destinations, 1);
    CHECK_U64(file->nsenders, 4);
    CHECK(file->public_share == 1.0);
    fixture_free(&f);
}

static void tree(void)
{
    struct fixture f;
    fixture_init(&f);

    process(&f, 100, 1, "nginx", "nginx: master process /usr/sbin/nginx", "", 0);
    for (uint32_t pid = 101; pid <= 104; pid++)
        process(&f, pid, 100, "nginx", "nginx: worker process", "", 1000);
    process(&f, 300, 1, "java", "/usr/bin/java -Xmx6g kafka.Kafka", "", 50);
    for (uint32_t pid = 101; pid <= 104; pid++)
        transfer(&f, (struct xfer){.id = pid, .pid = pid, .rate = 100 * (105 - pid)});
    transfer(&f, (struct xfer){.id = 301, .pid = 300, .rate = 50});
    transfer(&f, (struct xfer){.id = 302, .pid = 300, .rate = 40, .remote = "10.0.0.9"});
    /* A parent the agent does not report shows as its pid alone. */
    transfer(&f, (struct xfer){.id = 501, .pid = 501, .rate = 10});
    sample(&f, 0);
    ft_top_set_tree(f.m, true);

    /* The idle master, its first worker, then the other three folded. */
    const struct ft_top_row *r = row_at(&f, FT_TOP_PROCESSES, 0);
    CHECK_U64(r->kind, FT_TOP_ROW_PROCESS);
    CHECK_U64(r->process->pid, 100);
    CHECK_U64(r->process->rate, 1000);
    CHECK_U64(r->process->total, 4000);
    CHECK_U64(r->process->files, 4);
    CHECK_U64(r->depth, 0);
    CHECK_U64(r->node, FT_TOP_NODE_EXPANDED);
    r = row_at(&f, FT_TOP_PROCESSES, 1);
    CHECK_U64(r->process->pid, 101);
    CHECK_U64(r->depth, 1);
    CHECK_U64(r->node, FT_TOP_NODE_COLLAPSED);
    CHECK(!(r->flags & FT_TOP_ROW_LAST));
    r = row_at(&f, FT_TOP_PROCESSES, 2);
    CHECK_U64(r->kind, FT_TOP_ROW_FOLD);
    CHECK_U64(r->fold->count, 3);
    CHECK_U64(r->fold->rate, 600);
    CHECK_U64(r->fold->members[0]->pid, 102);
    CHECK_STR(r->fold->name, "nginx");
    CHECK(r->flags & FT_TOP_ROW_LAST);
    CHECK_U64(r->node, FT_TOP_NODE_COLLAPSED);
    r = row_at(&f, FT_TOP_PROCESSES, 3);
    CHECK_U64(r->process->pid, 300);
    CHECK_STR(r->process->head, "java");
    CHECK_STR(r->process->rest, "-Xmx6g kafka.Kafka");
    CHECK_U64(row_at(&f, FT_TOP_PROCESSES, 4)->process->pid, 501);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_PROCESSES), 5);

    /* Expanding a leaf shows its transfers; expanding the fold lists its members. */
    ft_top_toggle_expanded(f.m, FT_TOP_PROCESSES, 1);
    CHECK_U64(row_at(&f, FT_TOP_PROCESSES, 1)->node, FT_TOP_NODE_EXPANDED);
    r = row_at(&f, FT_TOP_PROCESSES, 2);
    CHECK_U64(r->kind, FT_TOP_ROW_TRANSFER);
    CHECK_U64(r->transfer->id, 101);
    CHECK_U64(r->depth, 2);
    CHECK_U64(r->rails, 1u << 1);
    CHECK(r->flags & FT_TOP_ROW_LAST);
    ft_top_toggle_expanded(f.m, FT_TOP_PROCESSES, 3);
    CHECK_U64(row_at(&f, FT_TOP_PROCESSES, 3)->node, FT_TOP_NODE_EXPANDED);
    CHECK_U64(row_at(&f, FT_TOP_PROCESSES, 4)->process->pid, 102);
    CHECK_U64(row_at(&f, FT_TOP_PROCESSES, 4)->depth, 2);
    CHECK(row_at(&f, FT_TOP_PROCESSES, 6)->flags & FT_TOP_ROW_LAST);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_PROCESSES), 9);

    /* A parent that is not known shows by its pid. */
    process(&f, 100, 1, "nginx", "nginx: master process /usr/sbin/nginx", "", 0);
    process(&f, 101, 100, "nginx", "nginx: worker process", "", 1000);
    process(&f, 600, 77, "bash", "bash", "", 0);
    transfer(&f, (struct xfer){.id = 101, .pid = 101, .rate = 400});
    transfer(&f, (struct xfer){.id = 601, .pid = 600, .rate = 5});
    sample(&f, 1);
    bool placeholder = false;
    for (size_t i = 0; i < ft_top_row_count(f.m, FT_TOP_PROCESSES); i++) {
        r = row_at(&f, FT_TOP_PROCESSES, i);
        if (r->kind == FT_TOP_ROW_PROCESS && r->process->pid == 77) {
            placeholder = !r->process->known && r->process->title[0] == '\0' && r->depth == 0;
            CHECK_U64(r->process->rate, 5);
            CHECK_U64(row_at(&f, FT_TOP_PROCESSES, i + 1)->process->pid, 600);
        }
    }
    CHECK(placeholder);
    fixture_free(&f);
}

static void deep_tree(void)
{
    constexpr uint32_t N = 20'000;
    struct fixture f;
    fixture_init(&f);

    /* Each process the parent of the next, the last one sending. */
    for (uint32_t pid = 2; pid < N + 2; pid++) {
        char command[32];
        snprintf(command, sizeof(command), "job%" PRIu32, pid);
        process(&f, pid, pid - 1, "job", command, "", 0);
    }
    transfer(&f, (struct xfer){.id = 1, .pid = N + 1, .rate = 1000});
    sample(&f, 0);
    ft_top_set_tree(f.m, true);
    ft_top_expand_all(f.m, FT_TOP_PROCESSES);

    bool *listed = calloc(N + 2, sizeof(*listed));
    size_t processes = 0;
    size_t transfers = 0;
    size_t deepest = 0;
    for (size_t i = 0; i < ft_top_row_count(f.m, FT_TOP_PROCESSES); i++) {
        const struct ft_top_row *r = row_at(&f, FT_TOP_PROCESSES, i);
        if (r->depth > deepest)
            deepest = r->depth;
        if (r->kind == FT_TOP_ROW_PROCESS && r->process->pid < N + 2 && !listed[r->process->pid]) {
            listed[r->process->pid] = true;
            processes++;
        }
        transfers += r->kind == FT_TOP_ROW_TRANSFER;
    }
    CHECK_U64(processes, N);
    CHECK_U64(transfers, 1);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_PROCESSES), N + 1);
    CHECK(deepest <= 64);
    free(listed);
    fixture_free(&f);
}

static void groups(void)
{
    struct fixture f;
    fixture_init(&f);

    process(&f, 10, 1, "php-fpm8.3", "php-fpm: pool www", "", 0);
    process(&f, 11, 1, "php-fpm8.3", "php-fpm: pool www", "", 0);
    transfer(&f, (struct xfer){.id = 1,
                               .pid = 10,
                               .rate = 300,
                               .script = "/srv/download.php",
                               .remote = "198.51.100.1"});
    transfer(&f, (struct xfer){.id = 2,
                               .pid = 11,
                               .rate = 200,
                               .script = "/srv/download.php",
                               .remote = "198.51.100.2"});
    transfer(&f, (struct xfer){.id = 3,
                               .pid = 10,
                               .rate = 900,
                               .script = "/srv/export.php",
                               .remote = "198.51.100.3"});
    sample(&f, 0);
    ft_top_set_group(f.m, FT_TOP_TRANSFERS, FT_TOP_GROUP_SCRIPT);

    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 5);
    const struct ft_top_row *r = row_at(&f, FT_TOP_TRANSFERS, 0);
    CHECK_U64(r->kind, FT_TOP_ROW_SECTION);
    CHECK_STR(r->section->title, "/srv/export.php");
    CHECK_U64(r->section->rate, 900);
    r = row_at(&f, FT_TOP_TRANSFERS, 2);
    CHECK_U64(r->kind, FT_TOP_ROW_SECTION);
    CHECK_STR(r->section->title, "/srv/download.php");
    CHECK_U64(r->section->rows, 2);
    CHECK_U64(r->section->processes, 2);
    CHECK_U64(r->section->files, 2);
    CHECK_U64(r->section->destinations, 2);
    CHECK_U64(r->section->rate, 500);
    CHECK_U64(r->node, FT_TOP_NODE_EXPANDED);
    CHECK_U64(id_at(&f, 3), 1);
    CHECK_U64(id_at(&f, 4), 2);

    /* A collapsed group keeps its heading and subtotals. */
    ft_top_select_at(f.m, FT_TOP_TRANSFERS, 4);
    ft_top_toggle_expanded(f.m, FT_TOP_TRANSFERS, 2);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 3);
    CHECK_U64(row_at(&f, FT_TOP_TRANSFERS, 2)->node, FT_TOP_NODE_COLLAPSED);
    CHECK_U64(row_at(&f, FT_TOP_TRANSFERS, 2)->section->rows, 2);
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 2);
    ft_top_expand_all(f.m, FT_TOP_TRANSFERS);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 5);
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 4);

    /* Processes grouped the same way: rows, processes and the summed rate. */
    ft_top_set_group(f.m, FT_TOP_PROCESSES, FT_TOP_GROUP_PROCESS);
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_PROCESSES), 3);
    r = row_at(&f, FT_TOP_PROCESSES, 0);
    CHECK_STR(r->section->title, "php-fpm: pool www");
    CHECK_U64(r->section->rows, 2);
    CHECK_U64(r->section->processes, 2);
    CHECK_U64(r->section->rate, 1400);
    fixture_free(&f);
}

static void search(void)
{
    struct fixture f;
    fixture_init(&f);

    transfer(&f, (struct xfer){.id = 1, .pid = 7, .rate = 300, .path = "/srv/a.log"});
    transfer(&f, (struct xfer){.id = 2, .pid = 7, .rate = 200, .path = "/srv/report.csv"});
    transfer(&f, (struct xfer){.id = 3, .pid = 7, .rate = 100, .path = "/srv/REPORT.pdf"});
    sample(&f, 0);
    ft_top_set_search(f.m, FT_TOP_TRANSFERS, "report");
    CHECK_U64(ft_top_view_of(f.m, FT_TOP_TRANSFERS)->matches, 2);
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 1);
    CHECK(ft_top_search_step(f.m, FT_TOP_TRANSFERS, 1));
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 2);
    CHECK(ft_top_search_step(f.m, FT_TOP_TRANSFERS, 1));
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 1);
    CHECK(ft_top_search_step(f.m, FT_TOP_TRANSFERS, -1));
    CHECK_U64(ft_top_selected(f.m, FT_TOP_TRANSFERS), 2);
    CHECK(!(row_at(&f, FT_TOP_TRANSFERS, 0)->flags & FT_TOP_ROW_MATCH));
    CHECK_U64(ft_top_row_count(f.m, FT_TOP_TRANSFERS), 3);
    ft_top_set_search(f.m, FT_TOP_TRANSFERS, "");
    CHECK(!ft_top_search_step(f.m, FT_TOP_TRANSFERS, 1));
    fixture_free(&f);
}

static void churn(void)
{
    struct fixture f;
    fixture_init(&f);

    /* Transfers come and go every refresh; the tables must keep track of each one. */
    for (uint64_t round = 0; round < 40; round++) {
        for (uint64_t i = 0; i < 300; i++) {
            uint64_t id = i % 10 == round % 10 ? 1000 * (round + 1) + i : i + 1;
            transfer(&f, (struct xfer){.id = id,
                                       .pid = (uint32_t)(10 + i % 7),
                                       .rate = 1000 + i,
                                       .ino = i % 50 + 1});
        }
        sample(&f, (double)round);
        size_t live = 0;
        for (size_t i = 0; i < ft_top_row_count(f.m, FT_TOP_TRANSFERS); i++)
            live += !(row_at(&f, FT_TOP_TRANSFERS, i)->flags & FT_TOP_ROW_DONE);
        CHECK_U64(live, 300);
        CHECK_U64(ft_top_totals(f.m)->transfers, 300);
        CHECK_U64(ft_top_totals(f.m)->files.value, 50);
    }
    fixture_free(&f);
}

/* Rows cut at every length, inside a field too, never grow a table past what was fed. */
static void short_rows(void)
{
    constexpr uint32_t N = 8;
    static const struct ft_row_transfer zero;
    struct ft_row_transfer *t = calloc(1, sizeof(*t));
    struct ft_row_process *p = calloc(1, sizeof(*p));
    struct ft_process_strings text = {"worker --serve", "/srv", "/srv/run.php"};

    ft_strlcpy(t->path, "/srv/data/file.bin", FT_PATH_MAX);
    size_t lead = strlen(t->path) + 1;
    size_t transfer_size = offsetof(struct ft_row_transfer, path) + lead +
                           ft_process_strings_pack(t->path + lead, sizeof(t->path) - lead, &text);
    size_t process_size = offsetof(struct ft_row_process, text) +
                          ft_process_strings_pack(p->text, sizeof(p->text), &text);
    size_t longest = transfer_size > process_size ? transfer_size : process_size;

    for (size_t cut = 0; cut <= longest; cut++) {
        struct fixture f;
        fixture_init(&f);
        /* A row of zeros is known first, so a reader that zeros a cut field counts nothing new. */
        CHECK(ft_rows_append(&f.transfers, &zero, offsetof(struct ft_row_transfer, path) + 1));
        sample(&f, 0);

        for (uint32_t k = 1; k <= N; k++) {
            t->id = k * 0x0101'0101'0101'0101ULL;
            t->pid = k * 0x0101'0101u;
            t->ppid = 1;
            t->rate = 1000 * k;
            t->dev = 2049;
            t->ino = k;
            t->flags =
                FT_XFER_ACTIVE | FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN | FT_XFER_PROCESS_TEXT;
            t->remote.family = 4;
            memset(t->remote.addr, (int)k, sizeof(t->remote.addr));
            CHECK(ft_rows_append(&f.transfers, t, cut < transfer_size ? cut : transfer_size));
            p->pid = t->pid;
            p->ppid = 1;
            CHECK(ft_rows_append(&f.processes, p, cut < process_size ? cut : process_size));
        }
        sample(&f, 1);
        CHECK(ft_top_row_count(f.m, FT_TOP_TRANSFERS) <= N + 1);
        CHECK(ft_top_row_count(f.m, FT_TOP_FILES) <= N + 1);
        CHECK(ft_top_row_count(f.m, FT_TOP_DESTINATIONS) <= N + 1);
        CHECK(ft_top_row_count(f.m, FT_TOP_PROCESSES) <= 2 * N + 2);
        fixture_free(&f);
    }
    free(t);
    free(p);
}

static void leader(struct ft_rows *rows, uint32_t rank, uint32_t previous, const char *path,
                   uint64_t bytes, const char *sender)
{
    struct ft_row_leader *row = calloc(1, sizeof(*row));
    row->rank = rank;
    row->previous_rank = previous;
    row->bytes = bytes;
    row->transfers = 10 * rank;
    row->method = FT_METHOD_SENDFILE;
    ft_strlcpy(row->senders[0].name, sender, sizeof(row->senders[0].name));
    ft_strlcpy(row->text, path, sizeof(row->text));
    CHECK(ft_rows_append(rows, row, offsetof(struct ft_row_leader, text) + strlen(path) + 1));
    free(row);
}

static void leaders(void)
{
    struct ft_top_model *m = ft_top_model_create();
    struct ft_rows ranking;
    struct ft_row_leader_summary summary = {
        .bytes = 1000, .top_bytes = 600, .previous_from_wall_ns = 1};
    struct ft_error err = {0};

    ft_rows_init(&ranking, FT_MSG_ROW_LEADER);
    leader(&ranking, 1, 2, "/var/lib/kafka/events-7.log", 400, "java");
    leader(&ranking, 2, 0, "/srv/backups/base.tar.zst", 200, "rclone");
    leader(&ranking, 3, 3, "/var/www/video.mp4", 100, "nginx");
    ft_top_set_leaders_request(m, FT_WINDOW_1H, FT_LEADER_FILE);
    struct ft_top_leaders_sample s = {
        .window = FT_WINDOW_1H,
        .key = FT_LEADER_FILE,
        .by = FT_TOP_SORT_BYTES,
        .summary = &summary,
        .ranking = &ranking,
    };
    CHECK(ft_top_model_leaders(m, &s));

    const struct ft_top_leaders *view = ft_top_leaders(m);
    CHECK(view->answered);
    CHECK(view->concentration == 0.6);
    CHECK_U64(ft_top_row_count(m, FT_TOP_LEADERS), 3);
    const struct ft_top_leader *l = ft_top_row_at(m, FT_TOP_LEADERS, 0)->leader;
    CHECK_U64(l->rank_change, 1);
    CHECK(!l->is_new);
    CHECK(l->bar == 1.0);
    CHECK(l->share == 0.4);
    CHECK_STR(l->row->text + l->name_offset, "events-7.log");
    l = ft_top_row_at(m, FT_TOP_LEADERS, 1)->leader;
    CHECK(l->is_new);
    CHECK(l->bar == 0.5);
    CHECK_U64(ft_top_row_at(m, FT_TOP_LEADERS, 2)->leader->rank_change, 0);

    /* The selection stays with its file when the ranking changes. */
    ft_top_select_at(m, FT_TOP_LEADERS, 2);
    ft_rows_clear(&ranking);
    leader(&ranking, 1, 3, "/var/www/video.mp4", 500, "nginx");
    leader(&ranking, 2, 1, "/var/lib/kafka/events-7.log", 400, "java");
    CHECK(ft_top_model_leaders(m, &s));
    CHECK_U64(ft_top_selected(m, FT_TOP_LEADERS), 0);

    /* A filter tests what a ranking row has, and refuses what it lacks. */
    CHECK(ft_top_set_filter(m, FT_TOP_LEADERS, "proc:java", &err));
    CHECK_U64(ft_top_row_count(m, FT_TOP_LEADERS), 1);
    CHECK_U64(ft_top_view_of(m, FT_TOP_LEADERS)->total, 2);
    CHECK(!ft_top_set_filter(m, FT_TOP_LEADERS, "pid:1", &err));
    CHECK_STR(err.msg, "'pid:1' does not apply to Leaders");

    /* Another request has no answer until the agent gives one. */
    ft_top_set_leaders_request(m, FT_WINDOW_24H, FT_LEADER_FILE);
    CHECK(!ft_top_leaders(m)->answered);
    CHECK_U64(ft_top_row_count(m, FT_TOP_LEADERS), 0);
    ft_top_set_leaders_request(m, FT_WINDOW_1H, FT_LEADER_FILE);
    CHECK(ft_top_leaders(m)->answered);

    ft_rows_free(&ranking);
    ft_top_model_destroy(m);
}

void test_top_model(void)
{
    units();
    smoothing();
    order();
    meters();
    selection();
    tags();
    aggregates();
    tree();
    deep_tree();
    groups();
    search();
    churn();
    short_rows();
    leaders();
}
