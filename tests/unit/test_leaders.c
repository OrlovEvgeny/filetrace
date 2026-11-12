#include "unit/test.h"

#include "filetrace/clock.h"
#include "filetrace/event.h"
#include "filetrace/leaders.h"

#include <stdlib.h>

constexpr uint64_t SEC = FT_NS_PER_SEC;
constexpr uint64_t MINUTE = 60 * SEC;
/* Seventy days: a multiple of every slot length, so slots start where the tests expect. */
constexpr uint64_t T0 = 6'048'000 * SEC;
constexpr size_t ROWS = 512;

struct answer {
    struct ft_row_leader_summary summary;
    struct ft_row_leader *rows;
    size_t count;
    size_t summaries;
};

static void collect(void *ctx, uint16_t type, const void *row, size_t size)
{
    struct answer *a = ctx;
    if (type == FT_MSG_ROW_LEADER_SUMMARY) {
        memcpy(&a->summary, row, size);
        a->summaries++;
    } else if (type == FT_MSG_ROW_LEADER && a->count < ROWS) {
        memset(&a->rows[a->count], 0, sizeof(a->rows[0]));
        memcpy(&a->rows[a->count++], row, size);
    }
}

static void ask_filtered(struct ft_leaders *l, struct answer *a, enum ft_leader_window window,
                         enum ft_leader_key key, enum ft_sort sort, uint64_t now, const char *path,
                         bool regex)
{
    struct ft_query q;
    struct ft_error err = {0};

    ft_query_init(&q, FT_Q_LEADERS);
    q.window = window;
    q.leader_key = key;
    q.sort = sort;
    q.limit = ROWS;
    ft_strlcpy(q.path, path, sizeof(q.path));
    if (regex)
        q.flags |= FT_QF_PATH_REGEX;
    a->count = 0;
    a->summaries = 0;
    CHECK(ft_leaders_query(l, &q, T0, now, collect, a, &err));
    CHECK_U64(a->summaries, 1);
}

static void ask(struct ft_leaders *l, struct answer *a, enum ft_leader_window window,
                enum ft_leader_key key, enum ft_sort sort, uint64_t now)
{
    ask_filtered(l, a, window, key, sort, now, "", false);
}

static struct ft_leaders *store(size_t entries)
{
    return ft_leaders_create(&(struct ft_leaders_config){.entries = entries});
}

static struct ft_endpoint addr4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    uint8_t raw[16] = {a, b, c, d};
    struct ft_endpoint ep;
    ft_endpoint_set(&ep, false, raw, 443);
    return ep;
}

static struct ft_leader_sample sample(uint64_t ts, uint64_t ino, uint64_t bytes, bool started)
{
    return (struct ft_leader_sample){
        .ts_ns = ts,
        .file = {.dev = 2049, .ino = ino},
        .file_size = ino * 1000,
        .sender = "nginx",
        .method = FT_METHOD_SENDFILE,
        .confidence = FT_CONF_EXACT,
        .bytes = bytes,
        .started = started,
    };
}

static const struct ft_row_leader *row_of(const struct answer *a, uint64_t ino)
{
    for (size_t i = 0; i < a->count; i++) {
        if (a->rows[i].ino == ino)
            return &a->rows[i];
    }
    return nullptr;
}

static const struct ft_row_leader *row_named(const struct answer *a, const char *text)
{
    for (size_t i = 0; i < a->count; i++) {
        if (strcmp(a->rows[i].text, text) == 0)
            return &a->rows[i];
    }
    return nullptr;
}

static uint64_t rng_next(uint64_t *state)
{
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    return *state * 0x2545f4914f6cdd1du;
}

static void below_capacity_is_exact(void)
{
    static const char *const senders[] = {"nginx", "php-fpm", "rsync"};
    static const char *const paths[] = {"/srv/a.mp4", "/srv/b.mp4", "/srv/c.log",
                                        "/srv/d.log", "/srv/e.bin", "/srv/f.bin"};
    struct ft_endpoint remotes[] = {addr4(10, 0, 0, 1), addr4(10, 0, 0, 2), addr4(192, 168, 1, 9),
                                    addr4(203, 0, 113, 7), addr4(198, 51, 100, 3)};
    uint64_t bytes[6] = {0};
    uint64_t exact[6] = {0};
    uint64_t transfers[6] = {0};
    uint8_t lowest[6] = {FT_CONF_EXACT, FT_CONF_EXACT, FT_CONF_EXACT,
                         FT_CONF_EXACT, FT_CONF_EXACT, FT_CONF_EXACT};
    uint64_t by_sender[6][3] = {{0}};
    uint64_t started_by[6][3] = {{0}};
    bool to[6][5] = {{false}};
    uint64_t total = 0;
    uint64_t total_transfers = 0;
    struct ft_leaders *l = store(64);
    struct answer a = {.rows = calloc(ROWS, sizeof(struct ft_row_leader))};

    /* Forty seconds: eight tips folded into every ring, all below the smallest table. */
    for (uint64_t t = 0; t < 40; t++) {
        size_t f = t % 6;
        size_t s = (t / 6) % 3;
        size_t r = (t / 2) % 5;
        struct ft_leader_sample x = sample(T0 + t * SEC, f + 1, 1000 * (f + 1) + t, t % 2 == 0);
        x.path = paths[f];
        x.sender = senders[s];
        x.script = t % 4 == 0 ? "/srv/app/a.php" : t % 4 == 1 ? "/srv/app/b.php" : nullptr;
        if (t % 7 != 3)
            x.remote = remotes[r];
        if (t % 3 == 0) {
            x.method = FT_METHOD_READ_SEND;
            x.confidence = FT_CONF_INFERRED;
        }
        ft_leaders_add(l, &x);

        bytes[f] += x.bytes;
        exact[f] += x.confidence == FT_CONF_EXACT ? x.bytes : 0;
        transfers[f] += x.started;
        if (x.confidence < lowest[f])
            lowest[f] = x.confidence;
        by_sender[f][s] += x.bytes;
        started_by[f][s] += x.started;
        if (x.remote.family)
            to[f][r] = true;
        total += x.bytes;
        total_transfers += x.started;
    }

    enum ft_leader_window windows[] = {FT_WINDOW_LIFETIME, FT_WINDOW_1M, FT_WINDOW_1H};
    for (size_t w = 0; w < FT_ARRAY_LEN(windows); w++) {
        ask(l, &a, windows[w], FT_LEADER_FILE, FT_SORT_BYTES, T0 + 40 * SEC);
        CHECK_U64(a.count, 6);
        CHECK_U64(a.summary.flags & FT_LEADERS_CAPPED, 0);
        CHECK_U64(a.summary.bytes, total);
        CHECK_U64(a.summary.transfers, total_transfers);
        CHECK_U64(a.summary.files, 6);
        CHECK_U64(a.summary.processes, 3);
        CHECK_U64(a.summary.scripts, 2);
        CHECK_U64(a.summary.destinations_private, 3);
        CHECK_U64(a.summary.destinations_public, 2);
        for (size_t f = 0; f < 6; f++) {
            const struct ft_row_leader *row = row_of(&a, f + 1);
            CHECK(row != nullptr);
            if (!row)
                continue;
            CHECK_STR(row->text, paths[f]);
            CHECK_U64(row->rank, 6 - f);
            CHECK_U64(row->bytes, bytes[f]);
            CHECK_U64(row->bytes_error, 0);
            CHECK_U64(row->bytes_exact, exact[f]);
            CHECK_U64(row->transfers, transfers[f]);
            CHECK_U64(row->transfers_error, 0);
            CHECK_U64(row->files, 1);
            CHECK_U64(row->file_size, (f + 1) * 1000);
            CHECK_U64(row->confidence, lowest[f]);
            uint64_t dests = 0;
            for (size_t r = 0; r < 5; r++)
                dests += to[f][r];
            CHECK_U64(row->destinations, dests);
            CHECK_U64(row->flags & FT_LEADER_MORE_SENDERS, 0);
            for (size_t k = 0; k < FT_LEADER_SENDERS; k++) {
                size_t s = 0;
                while (s < 3 && strcmp(senders[s], row->senders[k].name) != 0)
                    s++;
                CHECK(s < 3);
                if (s == 3)
                    continue;
                CHECK_U64(row->senders[k].bytes, by_sender[f][s]);
                CHECK_U64(row->senders[k].transfers, started_by[f][s]);
                CHECK(k == 0 || row->senders[k].bytes <= row->senders[k - 1].bytes);
            }
        }
    }

    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_DESTINATION, FT_SORT_BYTES, T0 + 40 * SEC);
    CHECK_U64(a.count, 5);
    for (size_t i = 0; i < a.count; i++) {
        CHECK_U64(a.rows[i].destinations, 1);
        CHECK_U64(a.rows[i].remote.port, 0);
        CHECK_STR(a.rows[i].text, "");
        CHECK_U64(a.rows[i].bytes_error, 0);
    }

    free(a.rows);
    ft_leaders_destroy(l);
}

struct zipf {
    double *cdf;
    size_t n;
};

/* The i-th most popular of n files is picked with a probability proportional to 1 / i. */
static void zipf_init(struct zipf *z, size_t n)
{
    z->cdf = calloc(n, sizeof(double));
    z->n = n;
    double sum = 0;
    for (size_t i = 0; i < n; i++) {
        sum += 1.0 / (double)(i + 1);
        z->cdf[i] = sum;
    }
    for (size_t i = 0; i < n; i++)
        z->cdf[i] /= sum;
}

static size_t zipf_pick(const struct zipf *z, uint64_t *rng)
{
    double u = (double)(rng_next(rng) >> 11) / (double)(1ull << 53);
    size_t lo = 0;
    size_t hi = z->n - 1;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (z->cdf[mid] < u)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

/* Indices of the k largest values, largest first. */
static void top_of(const uint64_t *values, size_t n, size_t *top, size_t k)
{
    for (size_t j = 0; j < k; j++) {
        size_t best = SIZE_MAX;
        for (size_t i = 0; i < n; i++) {
            bool taken = false;
            for (size_t t = 0; t < j; t++)
                taken = taken || top[t] == i;
            if (!taken && (best == SIZE_MAX || values[i] > values[best]))
                best = i;
        }
        top[j] = best;
    }
}

static void check_bounds(const struct answer *a, const uint64_t *bytes, const uint64_t *transfers)
{
    for (size_t i = 0; i < a->count; i++) {
        const struct ft_row_leader *row = &a->rows[i];
        uint64_t f = row->ino - 1;
        CHECK(row->bytes <= bytes[f] && bytes[f] <= row->bytes + row->bytes_error);
        CHECK(row->transfers <= transfers[f] &&
              transfers[f] <= row->transfers + row->transfers_error);
    }
}

static bool ranked_first(const struct answer *a, const size_t *top, size_t k)
{
    for (size_t j = 0; j < k; j++) {
        bool found = false;
        for (size_t i = 0; i < k && i < a->count; i++)
            found = found || a->rows[i].ino == top[j] + 1;
        if (!found)
            return false;
    }
    return true;
}

static void skewed_stream_keeps_bounds(void)
{
    constexpr size_t FILES = 320; /* ten times what one table of the tip holds */
    constexpr size_t SAMPLES = 60'000;
    uint64_t *bytes = calloc(FILES, sizeof(uint64_t));
    uint64_t *transfers = calloc(FILES, sizeof(uint64_t));
    struct ft_leader_sample *sent = calloc(SAMPLES, sizeof(*sent));
    struct answer a = {.rows = calloc(ROWS, sizeof(struct ft_row_leader))};
    struct ft_leaders *l = store(16);
    struct zipf z;
    uint64_t rng = 0x9e3779b97f4a7c15u;
    uint64_t now = T0 + 600 * SEC;
    size_t top[5];

    zipf_init(&z, FILES);
    for (size_t i = 0; i < SAMPLES; i++) {
        size_t f = zipf_pick(&z, &rng);
        sent[i] = sample(T0 + i * 10 * FT_NS_PER_MS, f + 1, 1000 + rng_next(&rng) % 1000,
                         rng_next(&rng) % 4 == 0);
        ft_leaders_add(l, &sent[i]);
    }

    /* Every window holds the truth of its own span within each row's bounds. */
    enum ft_leader_window windows[] = {FT_WINDOW_LIFETIME, FT_WINDOW_15M, FT_WINDOW_5M,
                                       FT_WINDOW_1M};
    for (size_t w = 0; w < FT_ARRAY_LEN(windows); w++) {
        uint64_t start = ft_leaders_span_start(windows[w], now);
        memset(bytes, 0, FILES * sizeof(uint64_t));
        memset(transfers, 0, FILES * sizeof(uint64_t));
        for (size_t i = 0; i < SAMPLES; i++) {
            if (sent[i].ts_ns < start)
                continue;
            bytes[sent[i].file.ino - 1] += sent[i].bytes;
            transfers[sent[i].file.ino - 1] += sent[i].started;
        }
        top_of(bytes, FILES, top, 5);
        ask(l, &a, windows[w], FT_LEADER_FILE, FT_SORT_BYTES, now);
        CHECK(a.summary.flags & FT_LEADERS_CAPPED);
        check_bounds(&a, bytes, transfers);
        CHECK(ranked_first(&a, top, 5));
        ask(l, &a, windows[w], FT_LEADER_FILE, FT_SORT_TRANSFERS, now);
        check_bounds(&a, bytes, transfers);
    }
    ft_leaders_destroy(l);

    /*
     * Three small files sent very often, four large ones rarely, and many medium ones: the small
     * ones hold the fewest bytes, yet lead by transfers.
     */
    memset(bytes, 0, FILES * sizeof(uint64_t));
    memset(transfers, 0, FILES * sizeof(uint64_t));
    l = store(16);
    for (uint64_t i = 0; i < 60'000; i++) {
        uint64_t pick = rng_next(&rng) % 100;
        size_t f;
        uint64_t size;
        if (pick < 45) {
            f = pick % 3;
            size = 100;
        } else if (pick < 49) {
            f = 3 + pick % 4;
            size = 10'000'000;
        } else {
            f = 7 + rng_next(&rng) % (FILES - 7);
            size = 10'000;
        }
        struct ft_leader_sample x = sample(T0 + i * 10 * FT_NS_PER_MS, f + 1, size, true);
        ft_leaders_add(l, &x);
        bytes[f] += x.bytes;
        transfers[f] += 1;
    }
    top_of(transfers, FILES, top, 3);
    for (size_t j = 0; j < 3; j++)
        CHECK(top[j] < 3);
    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_FILE, FT_SORT_TRANSFERS, T0 + 600 * SEC);
    CHECK(ranked_first(&a, top, 3));
    check_bounds(&a, bytes, transfers);
    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_FILE, FT_SORT_BYTES, T0 + 600 * SEC);
    top_of(bytes, FILES, top, 4);
    CHECK(ranked_first(&a, top, 4));
    check_bounds(&a, bytes, transfers);

    ft_leaders_destroy(l);
    free(z.cdf);
    free(sent);
    free(bytes);
    free(transfers);
    free(a.rows);
}

static void windows_rotate(void)
{
    struct ft_leaders *l = store(64);
    struct answer a = {.rows = calloc(ROWS, sizeof(struct ft_row_leader))};

    /* In the first hour A leads X and Y; then X grows past A and Z appears. */
    for (uint64_t m = 0; m < 126; m++) {
        uint64_t ts = T0 + m * MINUTE + SEC;
        struct ft_leader_sample x = sample(ts, 1, m < 60 ? 10'000 : 2'000, true);
        ft_leaders_add(l, &x);
        x = sample(ts, 2, m < 60 ? 5'000 : 20'000, true);
        ft_leaders_add(l, &x);
        if (m < 60) {
            x = sample(ts, 3, 1'000, true);
            ft_leaders_add(l, &x);
        }
        if (m >= 90) {
            x = sample(ts, 4, 3'000, true);
            ft_leaders_add(l, &x);
        }
    }

    /* The span is the twelve five-minute slots from minute 70; the one before starts at 10. */
    uint64_t now = T0 + 125 * MINUTE + 30 * SEC;
    ask(l, &a, FT_WINDOW_1H, FT_LEADER_FILE, FT_SORT_BYTES, now);
    CHECK_U64(a.summary.window_ns, 3600 * SEC);
    CHECK_U64(a.summary.slot_ns, 300 * SEC);
    CHECK_U64(ft_leaders_span_start(FT_WINDOW_1H, now), T0 + 70 * MINUTE);
    uint64_t from = ft_clock_mono_to_wall(T0 + 70 * MINUTE);
    uint64_t prev = ft_clock_mono_to_wall(T0 + 10 * MINUTE);
    CHECK(a.summary.from_wall_ns + FT_NS_PER_MS > from &&
          a.summary.from_wall_ns < from + FT_NS_PER_MS);
    CHECK(a.summary.previous_from_wall_ns + FT_NS_PER_MS > prev &&
          a.summary.previous_from_wall_ns < prev + FT_NS_PER_MS);
    CHECK_U64(a.summary.flags, 0);
    CHECK_U64(a.summary.bytes, 56 * 2'000 + 56 * 20'000 + 36 * 3'000);
    CHECK_U64(a.summary.transfers, 56 + 56 + 36);
    CHECK_U64(a.count, 3);

    const struct ft_row_leader *x = row_of(&a, 2);
    const struct ft_row_leader *ra = row_of(&a, 1);
    const struct ft_row_leader *z = row_of(&a, 4);
    CHECK(x && ra && z && !row_of(&a, 3));
    if (x && ra && z) {
        CHECK_U64(x->rank, 1);
        CHECK_U64(x->previous_rank, 2);
        CHECK_U64(ra->rank, 2);
        CHECK_U64(ra->previous_rank, 1);
        CHECK_U64(z->rank, 3);
        CHECK_U64(z->previous_rank, 0);
        CHECK_U64(x->bytes, 56 * 20'000);
        uint64_t sum = 0;
        for (size_t k = 0; k < FT_LEADER_SLOTS; k++) {
            CHECK_U64(x->trend[k], k < FT_LEADER_SLOTS - 1 ? 5 * 20'000 : 20'000);
            sum += x->trend[k];
        }
        CHECK_U64(sum, x->bytes);
        sum = 0;
        for (size_t k = 0; k < FT_LEADER_SLOTS; k++)
            sum += z->trend[k];
        CHECK_U64(sum, z->bytes);
        CHECK_U64(z->trend[3], 0);
        CHECK_U64(z->trend[4], 5 * 3'000);
    }

    /* The day window reaches back before the start of observation. */
    ask(l, &a, FT_WINDOW_24H, FT_LEADER_FILE, FT_SORT_BYTES, now);
    CHECK(a.summary.flags & FT_LEADERS_SHORT_HISTORY);
    CHECK_U64(a.summary.previous_from_wall_ns, 0);
    CHECK_U64(a.count, 4);
    for (size_t i = 0; i < a.count; i++)
        CHECK_U64(a.rows[i].previous_rank, 0);

    /* Five days later: every ring starts again, and the lifetime keeps it all. */
    uint64_t later = T0 + 5 * 24 * 3600 * SEC;
    struct ft_leader_sample w = sample(later, 5, 777, true);
    ft_leaders_add(l, &w);
    ask(l, &a, FT_WINDOW_1H, FT_LEADER_FILE, FT_SORT_BYTES, later + SEC);
    CHECK_U64(a.count, 1);
    CHECK_U64(a.summary.bytes, 777);
    CHECK_U64(a.rows[0].previous_rank, 0);
    ask(l, &a, FT_WINDOW_7D, FT_LEADER_FILE, FT_SORT_BYTES, later + SEC);
    CHECK_U64(a.count, 5);
    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_FILE, FT_SORT_BYTES, later + SEC);
    CHECK_U64(a.count, 5);
    CHECK_U64(a.summary.bytes,
              60 * 10'000 + 66 * 2'000 + 60 * 5'000 + 66 * 20'000 + 60 * 1'000 + 36 * 3'000 + 777);
    for (size_t i = 0; i < a.count; i++) {
        CHECK_U64(a.rows[i].bytes_error, 0);
        CHECK_U64(a.rows[i].trend[0], 0);
    }

    /* A jump of a hundred days, which no slot length divides into few steps. */
    uint64_t far = later + 100 * 24 * 3600 * SEC + 7 * SEC;
    ask(l, &a, FT_WINDOW_15M, FT_LEADER_FILE, FT_SORT_BYTES, far);
    CHECK_U64(a.count, 0);
    CHECK_U64(a.summary.bytes, 0);
    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_FILE, FT_SORT_BYTES, far);
    CHECK_U64(a.count, 5);

    free(a.rows);
    ft_leaders_destroy(l);
}

static void destinations_count(void)
{
    struct ft_leaders *l = store(64);
    struct answer a = {.rows = calloc(ROWS, sizeof(struct ft_row_leader))};

    for (uint8_t i = 1; i <= 15; i++) {
        struct ft_leader_sample x = sample(T0 + SEC, 1, 100, true);
        x.remote = addr4(10, 0, 0, i);
        ft_leaders_add(l, &x);
    }
    /* The same ten addresses in two slots. */
    for (uint64_t t = 0; t < 2; t++) {
        for (uint8_t i = 1; i <= 10; i++) {
            struct ft_leader_sample x = sample(T0 + (2 + 10 * t) * SEC, 3, 100'000, true);
            x.remote = addr4(10, 0, 0, i);
            ft_leaders_add(l, &x);
        }
    }
    /* Two thousand public addresses, all of them again in a later slot. */
    for (uint64_t t = 0; t < 2; t++) {
        for (uint32_t i = 0; i < 2000; i++) {
            struct ft_leader_sample x = sample(T0 + (3 + 20 * t) * SEC, 2, 10, true);
            x.remote = addr4(203, (uint8_t)(i >> 8), (uint8_t)i, 9);
            ft_leaders_add(l, &x);
        }
    }

    enum ft_leader_window windows[] = {FT_WINDOW_LIFETIME, FT_WINDOW_1M, FT_WINDOW_5M};
    for (size_t w = 0; w < FT_ARRAY_LEN(windows); w++) {
        ask(l, &a, windows[w], FT_LEADER_FILE, FT_SORT_DESTINATIONS, T0 + 40 * SEC);
        const struct ft_row_leader *one = row_of(&a, 1);
        const struct ft_row_leader *two = row_of(&a, 2);
        const struct ft_row_leader *three = row_of(&a, 3);
        CHECK(one && two && three);
        if (!one || !two || !three)
            continue;
        CHECK_U64(a.rows[0].ino, 2);
        CHECK_U64(one->destinations, 15);
        CHECK_U64(three->destinations, 10);
        CHECK(two->destinations >= 1500 && two->destinations <= 2500);
        CHECK_U64(a.summary.destinations_private, 15);
        CHECK(a.summary.destinations_public >= 1500 && a.summary.destinations_public <= 2500);
    }

    /* 10.0.0.1 received two files and leads by bytes. */
    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_DESTINATION, FT_SORT_BYTES, T0 + 40 * SEC);
    CHECK(a.count > 0);
    char text[64];
    ft_addr_format(&a.rows[0].remote, text, sizeof(text));
    CHECK_STR(text, "10.0.0.1");
    CHECK_U64(a.rows[0].files, 2);
    CHECK_U64(a.rows[0].bytes, 200'100);
    CHECK_U64(a.rows[0].transfers, 3);

    free(a.rows);
    ft_leaders_destroy(l);
}

static void directories_and_extensions(void)
{
    static const struct {
        uint64_t ino;
        const char *path;
        uint64_t bytes;
    } files[] = {
        {1, "/srv/a/x.mp4", 100}, {2, "/srv/a/y.mp4", 200}, {3, "/srv/b/z.log", 50},
        {4, "/srv/b/README", 30}, {5, "/srv/b/.hidden", 5}, {6, nullptr, 7},
    };
    struct ft_leaders *l = store(64);
    struct answer a = {.rows = calloc(ROWS, sizeof(struct ft_row_leader))};

    for (size_t i = 0; i < FT_ARRAY_LEN(files); i++) {
        struct ft_leader_sample x = sample(T0 + SEC, files[i].ino, files[i].bytes, true);
        x.path = files[i].path;
        ft_leaders_add(l, &x);
    }

    uint64_t now = T0 + 2 * SEC;
    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_DIRECTORY, FT_SORT_BYTES, now);
    CHECK_U64(a.count, 3);
    CHECK_STR(a.rows[0].text, "/srv/a/");
    CHECK_U64(a.rows[0].bytes, 300);
    CHECK_U64(a.rows[0].files, 2);
    CHECK_U64(a.rows[0].transfers, 2);
    CHECK_U64(a.rows[0].ino, 0);
    CHECK_STR(a.rows[1].text, "/srv/b/");
    CHECK_U64(a.rows[1].bytes, 85);
    CHECK_U64(a.rows[1].files, 3);
    CHECK_STR(a.rows[2].text, "(unknown)");
    CHECK_U64(a.rows[2].files, 1);

    ask(l, &a, FT_WINDOW_1M, FT_LEADER_EXTENSION, FT_SORT_BYTES, now);
    CHECK_U64(a.count, 4);
    const struct ft_row_leader *mp4 = row_named(&a, ".mp4");
    const struct ft_row_leader *none = row_named(&a, "(none)");
    CHECK(mp4 && none && row_named(&a, ".log") && row_named(&a, "(unknown)"));
    if (mp4 && none) {
        CHECK_U64(mp4->bytes, 300);
        CHECK_U64(mp4->files, 2);
        CHECK_U64(none->bytes, 35);
        CHECK_U64(none->files, 2);
    }

    ask_filtered(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_FILE, FT_SORT_BYTES, now, "/srv/a/*", false);
    CHECK_U64(a.count, 2);
    ask_filtered(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_FILE, FT_SORT_BYTES, now, "\\.log$", true);
    CHECK_U64(a.count, 1);
    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_FILE, FT_SORT_BYTES, now);
    CHECK(row_named(&a, "(device 2049 inode 6)") != nullptr);

    free(a.rows);
    ft_leaders_destroy(l);
}

static void counters_saturate(void)
{
    struct ft_leaders *l = store(16);
    struct answer a = {.rows = calloc(ROWS, sizeof(struct ft_row_leader))};

    struct ft_leader_sample x = sample(T0 + SEC, 1, INT64_MAX - 10, true);
    ft_leaders_add(l, &x);
    x = sample(T0 + 2 * SEC, 1, 100, false);
    ft_leaders_add(l, &x);
    x = sample(T0 + 7 * SEC, 1, 100, false);
    ft_leaders_add(l, &x);

    ask(l, &a, FT_WINDOW_LIFETIME, FT_LEADER_FILE, FT_SORT_BYTES, T0 + 8 * SEC);
    CHECK_U64(a.count, 1);
    CHECK_U64(a.rows[0].bytes, INT64_MAX);
    CHECK_U64(a.rows[0].bytes_exact, INT64_MAX);
    CHECK_U64(a.rows[0].senders[0].bytes, INT64_MAX);
    CHECK_U64(a.summary.bytes, INT64_MAX);
    CHECK_U64(a.summary.top_bytes, INT64_MAX);

    free(a.rows);
    ft_leaders_destroy(l);
}

struct state_rows {
    struct answer leaders;
    struct ft_row_process process;
    size_t processes;
};

static void collect_state(void *ctx, uint16_t type, const void *row, size_t size)
{
    struct state_rows *r = ctx;
    if (type == FT_MSG_ROW_PROCESS) {
        memcpy(&r->process, row, size);
        r->processes++;
        return;
    }
    collect(&r->leaders, type, row, size);
}

static void ingest(struct ft_state *st, struct ft_event *ev, uint64_t now)
{
    ev->ts_ns = now;
    ft_state_ingest(st, ev);
}

static void through_the_state(void)
{
    struct ft_state_config cfg;
    struct state_rows rows = {.leaders.rows = calloc(ROWS, sizeof(struct ft_row_leader))};
    struct ft_msg_end end;
    struct ft_error err = {0};
    struct ft_query q;
    uint64_t now = ft_clock_mono_ns();

    ft_state_config_defaults(&cfg);
    CHECK_U64(cfg.leader_entries, 512);
    struct ft_state *st = ft_state_create(&cfg);
    st->start_ns = now;

    struct ft_event ev = {.type = FT_EVENT_PROCESS_EXEC};
    ev.process.pid = 1842;
    ev.process.ppid = 1;
    ev.process.start_ns = 1000 * SEC;
    ft_strlcpy(ev.process.comm, "nginx", sizeof(ev.process.comm));
    ingest(st, &ev, now);

    ev = (struct ft_event){.type = FT_EVENT_FILE_SEEN};
    ev.file.id = (struct ft_file_id){.dev = 2049, .ino = 928371};
    ev.file.path = "/data/export/report.csv";
    ev.file.size = 148293012;
    ingest(st, &ev, now);

    ev = (struct ft_event){.type = FT_EVENT_SOCKET_STATE};
    ev.socket.sock_id = 0x1001;
    ev.socket.pid = 1842;
    ev.socket.proto = FT_PROTO_TCP;
    ev.socket.state = FT_SOCK_ESTABLISHED;
    ev.socket.remote = addr4(203, 0, 113, 42);
    ingest(st, &ev, now);

    for (uint64_t part = 0; part < 2; part++) {
        ev = (struct ft_event){.type = FT_EVENT_TRANSFER};
        ev.transfer.sock_id = 0x1001;
        ev.transfer.pid = 1842;
        ev.transfer.method = FT_METHOD_SENDFILE;
        ev.transfer.file = (struct ft_file_id){.dev = 2049, .ino = 928371};
        ev.transfer.first_ns = now;
        ev.transfer.bytes = 74146506;
        ev.transfer.ops = 1;
        ingest(st, &ev, now + part * SEC);
    }

    ft_query_init(&q, FT_Q_LEADERS);
    q.window = FT_WINDOW_1H;
    CHECK(ft_state_query(st, &q, now + 2 * SEC, collect_state, &rows, &end, &err));
    CHECK_U64(rows.leaders.summaries, 1);
    CHECK_U64(rows.leaders.count, 1);
    CHECK_U64(end.rows, 1);
    CHECK_U64(rows.leaders.summary.bytes, 148293012);
    CHECK_U64(rows.leaders.summary.bytes_exact, 148293012);
    CHECK_U64(rows.leaders.summary.transfers, 1);
    CHECK_U64(rows.leaders.summary.destinations_public, 1);
    const struct ft_row_leader *row = &rows.leaders.rows[0];
    CHECK_STR(row->text, "/data/export/report.csv");
    CHECK_U64(row->bytes, 148293012);
    CHECK_U64(row->transfers, 1);
    CHECK_U64(row->destinations, 1);
    CHECK_U64(row->method, FT_METHOD_SENDFILE);
    CHECK_U64(row->confidence, FT_CONF_EXACT);
    CHECK_U64(row->file_size, 148293012);
    CHECK_STR(row->senders[0].name, "nginx");
    CHECK_U64(row->senders[0].transfers, 1);

    ev = (struct ft_event){.type = FT_EVENT_FLOW};
    ev.flow.sock_id = 0x1001;
    ev.flow.pid = 1842;
    ev.flow.proto = FT_PROTO_TCP;
    ev.flow.remote = addr4(203, 0, 113, 42);
    ev.flow.tx_bytes = 148300000;
    ingest(st, &ev, now + 2 * SEC);
    ft_query_init(&q, FT_Q_PROCESSES);
    CHECK(ft_state_query(st, &q, now + 2 * SEC, collect_state, &rows, &end, &err));
    CHECK_U64(rows.processes, 1);
    CHECK_U64(rows.process.file_bytes, 148293012);
    CHECK_U64(rows.process.tx_bytes, 148300000);
    ft_state_destroy(st);

    /* With rankings off, a summary of zeros. */
    cfg.leader_entries = 0;
    st = ft_state_create(&cfg);
    rows.leaders.count = 0;
    rows.leaders.summaries = 0;
    ft_query_init(&q, FT_Q_LEADERS);
    CHECK(ft_state_query(st, &q, now, collect_state, &rows, &end, &err));
    CHECK_U64(rows.leaders.summaries, 1);
    CHECK_U64(rows.leaders.count, 0);
    CHECK_U64(rows.leaders.summary.bytes, 0);
    ft_state_destroy(st);
    free(rows.leaders.rows);
}

void test_leaders(void)
{
    below_capacity_is_exact();
    skewed_stream_keeps_bounds();
    windows_rotate();
    destinations_count();
    directories_and_extensions();
    counters_saturate();
    through_the_state();
}
