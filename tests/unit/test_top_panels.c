#include "unit/test.h"

#include "ui/top/views.h"

#include <stdlib.h>

constexpr uint64_t SECOND = FT_NS_PER_SEC;
constexpr uint64_t WALL = 1'790'000'000 * FT_NS_PER_SEC;
constexpr uint64_t MIB = 1024 * 1024;
constexpr uint32_t UNTOUCHED = U'§';

struct fixture {
    struct ft_top_model *m;
    struct ft_rows transfers;
    struct ft_rows processes;
    struct ft_rows ranking;
    struct ft_rows directories;
    struct ft_rows destinations;
    struct ft_row_stats stats;
    struct ft_row_leader_summary summary;
    struct ft_top_ui ui;
};

static void process(struct fixture *f, uint32_t pid, uint32_t ppid, const char *comm,
                    const char *command_line, const char *script)
{
    struct ft_row_process *row = calloc(1, sizeof(*row));
    struct ft_process_strings text = {command_line, "/srv", script};

    row->pid = pid;
    row->ppid = ppid;
    row->file_bytes = 10 * MIB;
    ft_strlcpy(row->comm, comm, sizeof(row->comm));
    size_t size = offsetof(struct ft_row_process, text) +
                  ft_process_strings_pack(row->text, sizeof(row->text), &text);
    CHECK(ft_rows_append(&f->processes, row, size));
    free(row);
}

static void transfer(struct fixture *f, uint64_t id, uint32_t pid, uint64_t rate, uint64_t ino,
                     const char *path, const char *remote, const char *script)
{
    struct ft_row_transfer *row = calloc(1, sizeof(*row));
    struct ft_process_strings text = {"", "/srv", script};

    row->id = id;
    row->pid = pid;
    row->rate = rate;
    row->bytes = 100 * MIB;
    row->file_size = 400 * MIB;
    row->dev = 2049;
    row->ino = ino;
    row->first_wall_ns = WALL;
    row->method = script[0] ? FT_METHOD_READ_SEND : FT_METHOD_SENDFILE;
    row->confidence = script[0] ? FT_CONF_INFERRED : FT_CONF_EXACT;
    row->flags = FT_XFER_ACTIVE | FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN | FT_XFER_PROCESS_TEXT;
    CHECK(ft_addr_parse(remote, &row->remote));
    row->remote.port = 443;
    ft_strlcpy(row->comm, "worker", sizeof(row->comm));
    ft_strlcpy(row->path, path, FT_PATH_MAX);
    size_t lead = strlen(row->path) + 1;
    ft_process_strings_pack(row->path + lead, sizeof(row->path) - lead, &text);
    CHECK(ft_rows_append(&f->transfers, row, ft_row_transfer_size(row)));
    free(row);
}

static void leader(struct ft_rows *rows, uint32_t rank, const char *text, uint64_t bytes,
                   const char *remote)
{
    struct ft_row_leader *row = calloc(1, sizeof(*row));

    row->rank = rank;
    row->previous_rank = rank;
    row->bytes = bytes;
    row->transfers = 10 * rank;
    row->destinations = 3;
    row->file_size = 100;
    row->method = FT_METHOD_SENDFILE;
    row->confidence = FT_CONF_EXACT;
    if (remote)
        CHECK(ft_addr_parse(remote, &row->remote));
    ft_strlcpy(row->senders[0].name, "nginx", sizeof(row->senders[0].name));
    row->senders[0].bytes = bytes;
    ft_strlcpy(row->text, text, sizeof(row->text));
    CHECK(ft_rows_append(rows, row, offsetof(struct ft_row_leader, text) + strlen(text) + 1));
    free(row);
}

/* Four workers under one master, so that the tree folds three, and a ranking of three files. */
static void fixture_init(struct fixture *f)
{
    *f = (struct fixture){.m = ft_top_model_create()};
    CHECK(f->m != nullptr);
    ft_rows_init(&f->transfers, FT_MSG_ROW_TRANSFER);
    ft_rows_init(&f->processes, FT_MSG_ROW_PROCESS);
    ft_rows_init(&f->ranking, FT_MSG_ROW_LEADER);
    ft_rows_init(&f->directories, FT_MSG_ROW_LEADER);
    ft_rows_init(&f->destinations, FT_MSG_ROW_LEADER);

    process(f, 100, 1, "nginx", "nginx: master process /usr/sbin/nginx", "");
    for (uint32_t pid = 101; pid <= 104; pid++)
        process(f, pid, 100, "nginx", "nginx: worker process", "");
    process(f, 200, 1, "php-fpm8.3", "php-fpm: pool www", "");
    transfer(f, 1, 101, 30 * MIB, 1, "/var/www/video/launch.mp4", "81.2.69.144", "");
    transfer(f, 2, 102, 20 * MIB, 1, "/var/www/video/launch.mp4", "62.45.88.170", "");
    transfer(f, 3, 103, 10 * MIB, 3, "/var/www/video/trailer.mp4", "81.2.69.145", "");
    transfer(f, 4, 104, 5 * MIB, 4, "/var/www/img/hero.webp", "10.0.5.22", "");
    transfer(f, 5, 200, 1 * MIB, 5, "/srv/app/storage/INV-1.pdf", "92.68.14.201",
             "/srv/app/public/download.php");
    f->stats.now_wall_ns = WALL;
    struct ft_top_sample s = {
        .mono_ns = SECOND,
        .stats = &f->stats,
        .transfers = &f->transfers,
        .processes = &f->processes,
    };
    CHECK(ft_top_model_sample(f->m, &s));

    leader(&f->ranking, 1, "/var/lib/kafka/data/events-7/00000000000184220311.log", 1000, nullptr);
    leader(&f->ranking, 2, "/srv/backups/pg/base-2026-11-12.tar.zst", 500, nullptr);
    leader(&f->ranking, 3, "/var/log/nginx/access.log", 1, nullptr);
    leader(&f->directories, 1, "/var/lib/kafka/data/", 1000, nullptr);
    leader(&f->directories, 2, "/srv/backups/pg/", 500, nullptr);
    leader(&f->destinations, 1, "", 1000, "10.0.5.22");
    leader(&f->destinations, 2, "", 500, "81.2.69.144");
    f->summary = (struct ft_row_leader_summary){
        .bytes = 1501, .bytes_exact = 1000, .top_bytes = 1501, .files = 3, .processes = 1};
    ft_top_set_leaders_request(f->m, FT_WINDOW_1H, FT_LEADER_FILE);
    struct ft_top_leaders_sample ls = {
        .window = FT_WINDOW_1H,
        .key = FT_LEADER_FILE,
        .by = FT_TOP_SORT_BYTES,
        .summary = &f->summary,
        .ranking = &f->ranking,
        .directories = &f->directories,
        .destinations = &f->destinations,
    };
    CHECK(ft_top_model_leaders(f->m, &ls));

    f->ui = (struct ft_top_ui){
        .full_paths = true,
        .window = FT_WINDOW_1H,
        .key = FT_LEADER_FILE,
        .by = FT_TOP_SORT_BYTES,
    };
}

static void fixture_free(struct fixture *f)
{
    ft_top_model_destroy(f->m);
    ft_rows_free(&f->transfers);
    ft_rows_free(&f->processes);
    ft_rows_free(&f->ranking);
    ft_rows_free(&f->directories);
    ft_rows_free(&f->destinations);
}

static struct ft_canvas *canvas(int cols, int rows)
{
    struct ft_canvas *c = ft_canvas_create(cols, rows);
    CHECK(c != nullptr);
    ft_canvas_fill(c, (struct ft_rect){0, 0, cols, rows}, UNTOUCHED, (struct ft_style){0});
    return c;
}

static struct ft_top_draw drawing(struct fixture *f, struct ft_canvas *c)
{
    return (struct ft_top_draw){
        .canvas = c,
        .depth = FT_DEPTH_TRUECOLOR,
        .model = f->m,
        .ui = &f->ui,
        .cursor_x = -1,
    };
}

static bool inside(struct ft_rect r, int x, int y)
{
    return x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
}

/* Every cell outside the rectangles still holds what the canvas was filled with. */
static bool untouched_outside(const struct ft_canvas *c, const struct ft_rect *rects, size_t n)
{
    for (int y = 0; y < ft_canvas_rows(c); y++) {
        for (int x = 0; x < ft_canvas_cols(c); x++) {
            bool in = false;
            for (size_t i = 0; i < n && !in; i++)
                in = inside(rects[i], x, y);
            if (!in && ft_canvas_at(c, x, y)->rune != UNTOUCHED) {
                fprintf(stderr, "cell %d,%d was drawn outside its rectangles\n", x, y);
                return false;
            }
        }
    }
    return true;
}

static size_t put_utf8(char *out, uint32_t r)
{
    if (r < 0x80) {
        out[0] = (char)r;
        return 1;
    }
    if (r < 0x800) {
        out[0] = (char)(0xc0 | (r >> 6));
        out[1] = (char)(0x80 | (r & 0x3f));
        return 2;
    }
    out[0] = (char)(0xe0 | (r >> 12));
    out[1] = (char)(0x80 | ((r >> 6) & 0x3f));
    out[2] = (char)(0x80 | (r & 0x3f));
    return 3;
}

/* The text of n cells from (x, y). */
static const char *text_at(const struct ft_canvas *c, int x, int y, int n)
{
    static char buf[1024];
    size_t len = 0;
    for (int i = 0; i < n && len + 4 < sizeof(buf); i++) {
        const struct ft_cell *cell = ft_canvas_at(c, x + i, y);
        if (cell && cell->rune)
            len += put_utf8(buf + len, cell->rune);
    }
    buf[len] = '\0';
    return buf;
}

/* The column where text starts in row y, or -1. */
static int find_text(const struct ft_canvas *c, int y, const char *text)
{
    int cols = ft_canvas_cols(c);
    int width = ft_text_columns(text);
    for (int x = 0; x + width <= cols; x++) {
        if (strcmp(text_at(c, x, y, width), text) == 0)
            return x;
    }
    return -1;
}

static int count_runes(const struct ft_canvas *c, int x, int y, int n, uint32_t rune)
{
    int count = 0;
    for (int i = 0; i < n; i++)
        count += ft_canvas_at(c, x + i, y)->rune == rune;
    return count;
}

struct leaders_frame {
    struct ft_rect cards;
    struct ft_rect header;
    struct ft_rect rows;
    struct ft_rect side;
};

static struct leaders_frame leaders_frame(int cols, int rows)
{
    return (struct leaders_frame){
        .cards = {0, 0, cols, 5},
        .header = {0, 6, cols - 46, 1},
        .rows = {0, 7, cols - 46, rows - 10},
        .side = {cols - 44, 6, 44, rows - 7},
    };
}

static void draw_leaders(struct fixture *f, struct ft_canvas *c, const struct leaders_frame *l)
{
    struct ft_top_draw d = drawing(f, c);
    ft_top_draw_leaders_cards(&d, l->cards);
    ft_top_draw_leaders_table(&d, l->header, l->rows, 0);
    ft_top_draw_leaders_side(&d, l->side);
}

static void leaders_wide(void)
{
    struct fixture f;
    fixture_init(&f);
    f.ui.mode = FT_TOP_LEADERS;
    struct ft_canvas *c = canvas(174, 44);
    struct leaders_frame l = leaders_frame(174, 44);
    draw_leaders(&f, c, &l);

    const struct ft_rect rects[] = {l.cards, l.header, l.rows, l.side};
    CHECK(untouched_outside(c, rects, FT_ARRAY_LEN(rects)));
    int y = l.header.y;
    CHECK_U64(find_text(c, y, "FILE"), 9);
    CHECK_U64(find_text(c, y, "BYTES"), 65);
    CHECK_U64(find_text(c, y, "SHARE"), 71);
    CHECK_U64(find_text(c, y, "XFERS"), 89);
    CHECK_U64(find_text(c, y, "DESTS"), 96);
    CHECK_U64(find_text(c, y, "TOP SENDER"), 102);
    CHECK_U64(find_text(c, y, "TREND 1h"), 116);
    CHECK(ft_canvas_at(c, 62, y)->bg == FT_COLOR_CYAN);
    CHECK(ft_canvas_at(c, 70, y)->bg == FT_COLOR_CYAN);
    CHECK(ft_canvas_at(c, 61, y)->bg == FT_COLOR_GREEN);
    CHECK(ft_canvas_at(c, 71, y)->bg == FT_COLOR_GREEN);
    CHECK(ft_canvas_at(c, 127, y)->bg == FT_COLOR_GREEN);
    CHECK_STR(text_at(c, 130, y, 16), " Top directories");

    /* The largest row fills the bar, a row at half fills half, a tiny one shows. */
    CHECK_U64(count_runes(c, 71, 7, 15, U'█'), 15);
    CHECK_U64(count_runes(c, 71, 8, 15, U'█'), 8);
    CHECK_U64(count_runes(c, 71, 8, 15, U'░'), 7);
    CHECK_U64(count_runes(c, 71, 9, 15, U'█'), 1);
    CHECK_U64(count_runes(c, 71, 9, 15, U'░'), 14);
    CHECK(ft_canvas_at(c, 86, 7)->rune != U'█');

    ft_canvas_destroy(c);
    fixture_free(&f);
}

static void leaders_narrow(void)
{
    struct fixture f;
    fixture_init(&f);
    f.ui.mode = FT_TOP_LEADERS;
    struct leaders_frame l = leaders_frame(120, 30);
    const struct ft_rect rects[] = {l.cards, l.header, l.rows, l.side};

    struct ft_canvas *c = canvas(120, 30);
    draw_leaders(&f, c, &l);
    CHECK(untouched_outside(c, rects, FT_ARRAY_LEN(rects)));
    int y = l.header.y;
    CHECK_U64(find_text(c, y, "BYTES"), 44);
    CHECK_U64(find_text(c, y, "XFERS"), 68);
    CHECK(find_text(c, y, "DESTS") < 0);
    CHECK(find_text(c, y, "TREND") < 0);
    CHECK(ft_canvas_at(c, 45, y)->bg == FT_COLOR_CYAN);
    CHECK(ft_canvas_at(c, 68, y)->bg == FT_COLOR_GREEN);
    ft_canvas_destroy(c);

    /* The ranked measure keeps its column when the narrow ranking drops the others. */
    ft_top_set_sort(f.m, FT_TOP_LEADERS, FT_TOP_SORT_DESTINATIONS, true);
    struct ft_top_leaders_sample ls = {
        .window = FT_WINDOW_1H,
        .key = FT_LEADER_FILE,
        .by = FT_TOP_SORT_DESTINATIONS,
        .summary = &f.summary,
        .ranking = &f.ranking,
        .directories = &f.directories,
        .destinations = &f.destinations,
    };
    CHECK(ft_top_model_leaders(f.m, &ls));
    c = canvas(120, 30);
    draw_leaders(&f, c, &l);
    CHECK(untouched_outside(c, rects, FT_ARRAY_LEN(rects)));
    int dests = find_text(c, y, "DESTS");
    CHECK(dests > 0);
    CHECK(find_text(c, y, "XFERS") < 0);
    CHECK(dests > 0 && ft_canvas_at(c, dests, y)->bg == FT_COLOR_CYAN);
    ft_canvas_destroy(c);
    fixture_free(&f);
}

/* Selects the first row of the mode that is of the kind. */
static bool select_kind(struct fixture *f, enum ft_top_mode mode, enum ft_top_row_kind kind)
{
    size_t n = ft_top_row_count(f->m, mode);
    for (size_t i = 0; i < n; i++) {
        if (ft_top_row_at(f->m, mode, i)->kind == kind) {
            ft_top_select_at(f->m, mode, i);
            return true;
        }
    }
    return false;
}

static void inspect_one(struct fixture *f, enum ft_top_mode mode, const char *title)
{
    struct ft_canvas *c = canvas(174, 44);
    struct ft_top_draw d = drawing(f, c);
    struct ft_rect r = {0, 36, 174, 7};

    f->ui.mode = mode;
    ft_top_draw_inspect(&d, r);
    CHECK(untouched_outside(c, &r, 1));
    const char *shown = text_at(c, 1, r.y, ft_text_columns(title));
    if (strcmp(shown, title) != 0)
        fprintf(stderr, "inspect title \"%s\", expected \"%s\"\n", shown, title);
    CHECK(strcmp(shown, title) == 0);
    CHECK_STR(text_at(c, 164, r.y, 9), "Esc close");
    CHECK(ft_canvas_at(c, 0, r.y + 3)->rune == U'│');
    CHECK(ft_canvas_at(c, 173, r.y + 6)->rune == U'┘');
    ft_canvas_destroy(c);
}

static void inspect(void)
{
    struct fixture f;
    fixture_init(&f);

    CHECK(select_kind(&f, FT_TOP_TRANSFERS, FT_TOP_ROW_TRANSFER));
    inspect_one(&f, FT_TOP_TRANSFERS, "F8 Inspect · process 101 nginx: worker process");
    CHECK(select_kind(&f, FT_TOP_PROCESSES, FT_TOP_ROW_PROCESS));
    inspect_one(&f, FT_TOP_PROCESSES, "F8 Inspect · process");
    CHECK(select_kind(&f, FT_TOP_DESTINATIONS, FT_TOP_ROW_DESTINATION));
    inspect_one(&f, FT_TOP_DESTINATIONS, "F8 Inspect · destination ");
    CHECK(select_kind(&f, FT_TOP_FILES, FT_TOP_ROW_FILE));
    inspect_one(&f, FT_TOP_FILES, "F8 Inspect · file /var/www/video/launch.mp4");
    CHECK(select_kind(&f, FT_TOP_LEADERS, FT_TOP_ROW_LEADER));
    inspect_one(&f, FT_TOP_LEADERS, "F8 Inspect · file /var/lib/kafka/data/events-7/");

    ft_top_set_group(f.m, FT_TOP_TRANSFERS, FT_TOP_GROUP_PROCESS);
    CHECK(select_kind(&f, FT_TOP_TRANSFERS, FT_TOP_ROW_SECTION));
    inspect_one(&f, FT_TOP_TRANSFERS, "F8 Inspect · process ");

    ft_top_set_tree(f.m, true);
    ft_top_expand_all(f.m, FT_TOP_PROCESSES);
    CHECK(select_kind(&f, FT_TOP_PROCESSES, FT_TOP_ROW_FOLD));
    inspect_one(&f, FT_TOP_PROCESSES, "F8 Inspect · 3 more nginx: worker process");
    fixture_free(&f);
}

/* The panel lists the mode's sort keys in order, the one in effect marked. */
static void panel_sorts(struct fixture *f, enum ft_top_mode mode)
{
    struct ft_canvas *c = canvas(174, 44);
    struct ft_top_draw d = drawing(f, c);
    struct ft_rect r = {0, 1, 24, 40};
    size_t n;
    const struct ft_top_sort_option *sorts = ft_top_mode_sorts(mode, &n);
    enum ft_top_sort key;
    bool descending;

    f->ui.mode = mode;
    f->ui.panel = FT_TOP_PANEL_SORT;
    ft_top_sort_of(f->m, mode, &key, &descending);
    ft_top_draw_panel(&d, r);
    CHECK(untouched_outside(c, &r, 1));
    CHECK_STR(text_at(c, 1, 1, 7), "Sort by");
    for (size_t i = 0; i < n; i++) {
        char expected[64];
        snprintf(expected, sizeof(expected), "%s%s", sorts[i].key == key ? "▶ " : "  ",
                 sorts[i].label);
        CHECK_STR(text_at(c, 1, 2 + (int)i, ft_text_columns(expected)), expected);
    }
    CHECK(ft_canvas_at(c, 3, 2 + (int)n)->rune == UNTOUCHED);
    ft_canvas_destroy(c);
}

static void panel(void)
{
    struct fixture f;
    fixture_init(&f);
    for (int mode = 0; mode < FT_TOP_LEADERS; mode++)
        panel_sorts(&f, (enum ft_top_mode)mode);
    CHECK(ft_top_set_sort(f.m, FT_TOP_TRANSFERS, FT_TOP_SORT_AGE, true));
    panel_sorts(&f, FT_TOP_TRANSFERS);

    size_t n;
    const enum ft_top_group *groups = ft_top_mode_groups(FT_TOP_TRANSFERS, &n);
    CHECK_U64(n, 6);
    CHECK(groups[0] == FT_TOP_GROUP_NONE && groups[5] == FT_TOP_GROUP_SUBNET);
    ft_top_mode_groups(FT_TOP_LEADERS, &n);
    CHECK_U64(n, 1);
    fixture_free(&f);
}

/* In every column of key groups the descriptions start together, clear of the longest key. */
static void help_columns(const struct ft_canvas *c)
{
    int cols = ft_canvas_cols(c);
    int width = (cols - 10) / 3;

    for (int col = 0; col < 3; col++) {
        int gx = 2 + col * (width + 3);
        int key_end = -1;
        int text_start = -1;
        int keys = 0;
        for (int y = 0; y < ft_canvas_rows(c); y++) {
            const struct ft_cell *first = ft_canvas_at(c, gx, y);
            if (first->fg != FT_COLOR_CYAN || first->rune == ' ')
                continue;
            keys++;
            int x = gx;
            int last = gx;
            for (; x < gx + width && ft_canvas_at(c, x, y)->fg != FT_COLOR_TEXT; x++) {
                if (ft_canvas_at(c, x, y)->rune != ' ')
                    last = x;
            }
            key_end = last > key_end ? last : key_end;
            CHECK(text_start < 0 || text_start == x);
            text_start = x;
        }
        CHECK(keys >= 12);
        CHECK(text_start >= key_end + 2);
    }
}

static void help(void)
{
    struct fixture f;
    fixture_init(&f);

    struct ft_canvas *c = canvas(120, 30);
    struct ft_top_draw d = drawing(&f, c);
    ft_canvas_clear(c, (struct ft_style){0});
    ft_top_draw_help(&d);
    help_columns(c);
    CHECK(find_text(c, 1, "filetrace top") == 2);
    CHECK(find_text(c, 29, "Press any key to return") > 0);
    for (int y = 0; y < 30; y++)
        CHECK(find_text(c, y, "$ sudo") < 0);
    ft_canvas_destroy(c);

    c = canvas(174, 44);
    d = drawing(&f, c);
    ft_canvas_clear(c, (struct ft_style){0});
    ft_top_draw_help(&d);
    help_columns(c);
    int commands = 0;
    for (int y = 0; y < 44; y++)
        commands += find_text(c, y, "$ sudo filetrace top") == 2;
    CHECK_U64(commands, 6);
    ft_canvas_destroy(c);
    fixture_free(&f);
}

static void overlay(void)
{
    static char storage[200][16];
    static const char *lines[200];
    struct fixture f;
    fixture_init(&f);
    for (size_t i = 0; i < FT_ARRAY_LEN(lines); i++) {
        snprintf(storage[i], sizeof(storage[i]), "line %zu", i + 1);
        lines[i] = storage[i];
    }
    f.ui.overlay = FT_TOP_OVERLAY_EVENTS;
    f.ui.overlay_text = (struct ft_top_text){.title = "Events", .lines = lines, .count = 200};
    struct ft_rect r = {0, 7, 174, 39};

    f.ui.overlay_text.scroll = 20;
    struct ft_canvas *c = canvas(174, 46);
    struct ft_top_draw d = drawing(&f, c);
    ft_top_draw_overlay(&d, r);
    CHECK(untouched_outside(c, &r, 1));
    CHECK(find_text(c, 7, "lines 21–58 of 200   Esc close") > 0);
    CHECK_STR(text_at(c, 1, 8, 7), "line 21");
    ft_canvas_destroy(c);

    /* Past the end it shows the last page. */
    f.ui.overlay_text.scroll = 190;
    c = canvas(174, 46);
    d = drawing(&f, c);
    ft_top_draw_overlay(&d, r);
    CHECK(find_text(c, 7, "lines 163–200 of 200   Esc close") > 0);
    CHECK_STR(text_at(c, 1, 45, 8), "line 200");
    ft_canvas_destroy(c);
    fixture_free(&f);
}

void test_top_panels(void)
{
    leaders_wide();
    leaders_narrow();
    inspect();
    panel();
    help();
    overlay();
}
