#include "unit/test.h"

#include "ui/top/views.h"

#include <stdlib.h>

constexpr uint64_t SECOND = FT_NS_PER_SEC;
constexpr uint64_t WALL = 1'790'000'000 * FT_NS_PER_SEC;

struct fixture {
    struct ft_top_model *m;
    struct ft_rows transfers;
    struct ft_rows processes;
    struct ft_row_stats stats;
};

static void process(struct fixture *f, uint32_t pid, uint32_t ppid, const char *comm,
                    const char *command_line, const char *script)
{
    struct ft_row_process *row = calloc(1, sizeof(*row));
    struct ft_process_strings text = {command_line, "/srv", script};

    row->pid = pid;
    row->ppid = ppid;
    row->file_bytes = 1000;
    ft_strlcpy(row->comm, comm, sizeof(row->comm));
    size_t size = offsetof(struct ft_row_process, text) +
                  ft_process_strings_pack(row->text, sizeof(row->text), &text);
    CHECK(ft_rows_append(&f->processes, row, size));
    free(row);
}

static void transfer(struct fixture *f, uint64_t id, uint32_t pid, uint64_t rate, const char *path,
                     const char *remote)
{
    struct ft_row_transfer *row = calloc(1, sizeof(*row));
    struct ft_process_strings text = {"", "/srv", ""};

    row->id = id;
    row->pid = pid;
    row->rate = rate;
    row->bytes = rate;
    row->file_size = 4 * rate;
    row->dev = 2049;
    row->ino = id;
    row->first_wall_ns = WALL;
    row->method = FT_METHOD_SENDFILE;
    row->confidence = FT_CONF_EXACT;
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

/* An nginx master with four workers, and java sending two files of its own. */
static void fixture_init(struct fixture *f)
{
    *f = (struct fixture){.m = ft_top_model_create()};
    CHECK(f->m != nullptr);
    ft_rows_init(&f->transfers, FT_MSG_ROW_TRANSFER);
    ft_rows_init(&f->processes, FT_MSG_ROW_PROCESS);

    process(f, 100, 1, "nginx", "nginx: master process /usr/sbin/nginx", "");
    for (uint32_t pid = 101; pid <= 104; pid++)
        process(f, pid, 100, "nginx", "nginx: worker process", "");
    process(f, 300, 1, "java", "/usr/bin/java -Xmx6g kafka.Kafka", "");
    for (uint32_t pid = 101; pid <= 104; pid++)
        transfer(f, pid, pid, 1'000'000 * (105 - pid), "/var/www/cdn/video/launch.mp4",
                 "81.2.69.144");
    transfer(f, 301, 300, 60'000'000, "/var/lib/kafka/data/events-7/00000000000184220311.log",
             "10.0.5.22");
    transfer(f, 302, 300, 50'000'000, "/var/lib/kafka/data/events-3/00000000000183990127.log",
             "10.0.5.23");

    f->stats.now_wall_ns = WALL;
    struct ft_top_sample s = {
        .mono_ns = SECOND,
        .stats = &f->stats,
        .transfers = &f->transfers,
        .processes = &f->processes,
    };
    CHECK(ft_top_model_sample(f->m, &s));
}

static void fixture_free(struct fixture *f)
{
    ft_top_model_destroy(f->m);
    ft_rows_free(&f->transfers);
    ft_rows_free(&f->processes);
}

static size_t encode(uint32_t r, char *out)
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

/* The text of cells [x, x + n) of row y. */
static const char *cells(const struct ft_canvas *c, int x, int y, int n)
{
    static char buf[2048];
    size_t len = 0;

    for (int i = x; i < x + n && len + 4 < sizeof(buf); i++) {
        const struct ft_cell *cell = ft_canvas_at(c, i, y);
        if (cell && cell->rune)
            len += encode(cell->rune, buf + len);
    }
    buf[len] = '\0';
    return buf;
}

static bool shows(const struct ft_canvas *c, int x, int y, const char *text)
{
    return strcmp(cells(c, x, y, ft_text_columns(text)), text) == 0;
}

/* Whether a label stands alone in the row, not as part of a longer word. */
static bool has_label(const struct ft_canvas *c, int y, const char *label)
{
    const char *row = cells(c, 0, y, ft_canvas_cols(c));
    size_t len = strlen(label);

    for (const char *p = strstr(row, label); p; p = strstr(p + 1, label)) {
        bool start = p == row || p[-1] == ' ';
        bool end = p[len] == ' ' || p[len] == '\0';
        if (start && end)
            return true;
    }
    return false;
}

static struct ft_top_draw drawer(struct ft_canvas *c, struct fixture *f, struct ft_top_ui *ui)
{
    return (struct ft_top_draw){
        .canvas = c,
        .depth = FT_DEPTH_TRUECOLOR,
        .model = f->m,
        .ui = ui,
        .cursor_x = -1,
        .cursor_y = -1,
    };
}

static bool inside(struct ft_rect r, int x, int y)
{
    return x >= r.x && x < r.x + r.w && y >= r.y && y < r.y + r.h;
}

static void live_mode(struct fixture *f, enum ft_top_mode mode, int cols, int rows)
{
    static const char *const tabs[] = {"1 Transfers", "2 Processes", "3 Destinations", "4 Files"};
    static const int tab_x[] = {1, 14, 27, 43};
    struct ft_top_ui ui = {.mode = mode, .full_paths = true, .delay_ns = SECOND};
    struct ft_canvas *c = ft_canvas_create(cols, rows);
    struct ft_top_draw d = drawer(c, f, &ui);
    struct ft_top_layout l;
    bool stray = false;

    ft_top_set_mode(f->m, mode);
    ft_top_select_at(f->m, mode, 1);
    ft_top_layout(&ui, cols, rows, &l);

    /* The table alone touches nothing beyond its header and rows. */
    ft_canvas_fill(c, (struct ft_rect){0, 0, cols, rows}, '#', (struct ft_style){0});
    ft_top_draw_table(&d, mode, l.header, l.table, 0);
    for (int y = 0; y < rows; y++) {
        for (int x = 0; x < cols; x++) {
            bool table = inside(l.header, x, y) || inside(l.table, x, y);
            stray |= !table && ft_canvas_at(c, x, y)->rune != '#';
        }
    }
    CHECK(!stray);

    ft_top_draw(&d);
    CHECK(shows(c, tab_x[mode], l.tabs.y, tabs[mode]));
    CHECK_U64(ft_canvas_at(c, tab_x[mode], l.tabs.y)->bg, FT_COLOR_CYAN);
    CHECK_U64(ft_canvas_at(c, tab_x[(mode + 1) % 4], l.tabs.y)->bg, FT_COLOR_PANEL);
    switch (mode) {
    case FT_TOP_TRANSFERS:
        CHECK(shows(c, 3, l.header.y, "PID"));
        CHECK(shows(c, cols >= 174 ? 35 : 25, l.header.y, "FILE"));
        break;
    case FT_TOP_PROCESSES:
        CHECK(shows(c, 7, l.header.y, "USER"));
        CHECK(shows(c, 59, l.header.y, "COMMAND"));
        break;
    case FT_TOP_DESTINATIONS:
        CHECK(shows(c, 0, l.header.y, "DESTINATION"));
        CHECK(shows(c, 29, l.header.y, "rDNS"));
        break;
    default:
        /* FILE takes the design's 52 columns, and less on a narrower screen. */
        CHECK(shows(c, cols >= 174 ? 55 : 43, l.header.y, "SIZE"));
        break;
    }
    bool bar = true;
    for (int x = 0; x < cols; x++)
        bar &= ft_canvas_at(c, x, l.table.y + 1)->bg == FT_COLOR_CYAN;
    CHECK(bar);
    CHECK(ft_canvas_at(c, 0, l.table.y)->bg != FT_COLOR_CYAN);
    CHECK_U64(ft_canvas_at(c, 0, l.header.y)->bg, FT_COLOR_GREEN);
    CHECK_U64(ft_canvas_at(c, 0, l.keys.y)->rune, 'F');
    ft_canvas_destroy(c);
}

static void live_modes(void)
{
    struct fixture f;
    fixture_init(&f);
    for (int mode = FT_TOP_TRANSFERS; mode <= FT_TOP_FILES; mode++) {
        live_mode(&f, (enum ft_top_mode)mode, 174, 44);
        live_mode(&f, (enum ft_top_mode)mode, 120, 30);
    }
    fixture_free(&f);
}

static void transfer_columns(void)
{
    struct fixture f;
    struct ft_top_ui ui = {.mode = FT_TOP_TRANSFERS, .full_paths = true};
    fixture_init(&f);
    ft_top_set_mode(f.m, FT_TOP_TRANSFERS);

    static const struct {
        int width;
        bool user, progress, age, conf;
        int file_x;
        int destination_x;
    } cases[] = {
        {174, true, true, true, true, 35, 79},
        {159, true, true, true, true, 35, 65},
        {140, false, true, true, false, 25, 56},
        {120, false, false, false, false, 25, 58},
    };
    for (size_t i = 0; i < FT_ARRAY_LEN(cases); i++) {
        int w = cases[i].width;
        struct ft_canvas *c = ft_canvas_create(w, 3);
        struct ft_top_draw d = drawer(c, &f, &ui);
        ft_top_draw_table(&d, FT_TOP_TRANSFERS, (struct ft_rect){0, 0, w, 1},
                          (struct ft_rect){0, 1, w, 2}, 0);
        CHECK(has_label(c, 0, "PID"));
        CHECK(has_label(c, 0, "PROCESS"));
        CHECK(has_label(c, 0, "METHOD"));
        CHECK(has_label(c, 0, "SENT/SIZE"));
        CHECK(has_label(c, 0, "USER") == cases[i].user);
        CHECK(has_label(c, 0, "PROGRESS") == cases[i].progress);
        CHECK(has_label(c, 0, "AGE") == cases[i].age);
        CHECK(has_label(c, 0, "CONF") == cases[i].conf);
        CHECK(shows(c, cases[i].file_x, 0, "FILE"));
        CHECK(shows(c, cases[i].destination_x, 0, "DESTINATION"));
        ft_canvas_destroy(c);
    }

    /* The SCRIPT column goes before DESTINATION shrinks. */
    ui.script_column = true;
    struct ft_canvas *c = ft_canvas_create(174, 2);
    struct ft_top_draw d = drawer(c, &f, &ui);
    ft_top_draw_table(&d, FT_TOP_TRANSFERS, (struct ft_rect){0, 0, 174, 1},
                      (struct ft_rect){0, 1, 174, 1}, 0);
    CHECK(has_label(c, 0, "SCRIPT"));
    CHECK(!has_label(c, 0, "CONF"));
    CHECK(has_label(c, 0, "USER"));
    ft_canvas_destroy(c);
    fixture_free(&f);
}

/* Every cell belongs to exactly one block, the gutters beside the panels to none. */
static void covers(const struct ft_top_layout *l)
{
    const struct ft_rect blocks[] = {
        l->head,    l->tabs,   l->panel,   l->header, l->table, l->side,    l->rule,
        l->context, l->status, l->inspect, l->prompt, l->keys,  l->overlay,
    };
    int *count = calloc((size_t)(l->cols * l->rows), sizeof(*count));
    bool outside = false;
    bool once = true;

    CHECK(count != nullptr);
    if (!count)
        return;
    for (size_t b = 0; b < FT_ARRAY_LEN(blocks); b++) {
        struct ft_rect r = blocks[b];
        if (r.h <= 0 || r.w <= 0)
            continue;
        outside |= r.x < 0 || r.y < 0 || r.x + r.w > l->cols || r.y + r.h > l->rows;
        for (int y = r.y; y < r.y + r.h && y < l->rows; y++) {
            for (int x = r.x; x < r.x + r.w && x < l->cols; x++)
                count[y * l->cols + x]++;
        }
    }
    for (int y = 0; y < l->rows; y++) {
        for (int x = 0; x < l->cols; x++) {
            bool panel_gutter = l->panel.h > 0 && inside(l->panel, x - 2, y) && x >= 24;
            bool side_gutter = l->side.h > 0 && inside(l->side, x + 2, y) && x < l->side.x;
            int expected = panel_gutter || side_gutter ? 0 : 1;
            once &= count[y * l->cols + x] == expected;
        }
    }
    CHECK(!outside);
    CHECK(once);
    free(count);
}

static void layout(void)
{
    struct ft_top_ui ui = {.mode = FT_TOP_TRANSFERS};
    struct ft_top_layout l;

    ft_top_layout(&ui, 174, 44, &l);
    covers(&l);
    CHECK(!l.too_small);
    CHECK_U64(l.head.h, 6); /* five rows of summary and the blank row */
    CHECK_U64(l.tabs.y, 6);
    CHECK_U64(l.header.y, 7);
    CHECK_U64(l.table.y, 8);
    CHECK_U64(l.table.h, 32);
    CHECK_U64(l.rule.y, 40);
    CHECK_U64(l.context.y, 41);
    CHECK_U64(l.status.y, 42);
    CHECK_U64(l.keys.y, 43);

    ui.prompt = FT_TOP_PROMPT_FILTER;
    ft_top_layout(&ui, 174, 44, &l);
    covers(&l);
    CHECK_U64(l.prompt.y, 41);
    CHECK_U64(l.prompt.h, 2);
    CHECK_U64(l.status.y, 40);
    CHECK_U64(l.table.h, 30);

    ui.prompt = FT_TOP_PROMPT_SEARCH;
    ui.panel = FT_TOP_PANEL_SORT;
    ft_top_layout(&ui, 174, 44, &l);
    covers(&l);
    CHECK_U64(l.head.h, 0);
    CHECK_U64(l.tabs.y, 0);
    CHECK_U64(l.panel.x, 0);
    CHECK_U64(l.panel.y, 1);
    CHECK_U64(l.panel.w, 24);
    CHECK_U64(l.panel.y + l.panel.h, l.prompt.y);
    CHECK_U64(l.header.x, 26);
    CHECK_U64(l.header.w, 148);
    CHECK_U64(l.status.x, 26);

    ui = (struct ft_top_ui){.mode = FT_TOP_PROCESSES, .inspect = true};
    ft_top_layout(&ui, 174, 44, &l);
    covers(&l);
    CHECK_U64(l.head.h, 3);
    CHECK_U64(l.inspect.y, 36);
    CHECK_U64(l.inspect.h, 7);
    CHECK_U64(l.status.h, 0);
    CHECK_U64(l.context.h, 0);
    CHECK_U64(l.rule.h, 0);
    CHECK_U64(l.table.y + l.table.h, 36);

    ui.prompt = FT_TOP_PROMPT_FILTER;
    ft_top_layout(&ui, 120, 30, &l);
    covers(&l);
    CHECK_U64(l.inspect.y + l.inspect.h, l.prompt.y);
    CHECK_U64(l.prompt.y + l.prompt.h, 29);

    /* Under 36 rows the blank row and the rule give their rows to the table. */
    ui = (struct ft_top_ui){.mode = FT_TOP_TRANSFERS};
    ft_top_layout(&ui, 120, 30, &l);
    covers(&l);
    CHECK_U64(l.head.h, 5);
    CHECK_U64(l.tabs.y, 5);
    CHECK_U64(l.rule.h, 0);
    CHECK_U64(l.table.y, 7);
    CHECK_U64(l.table.h, 20);
    CHECK_U64(l.context.y, 27);

    ui = (struct ft_top_ui){.mode = FT_TOP_LEADERS};
    ft_top_layout(&ui, 174, 44, &l);
    covers(&l);
    CHECK_U64(l.head.h, 6);
    CHECK_U64(l.header.w, 128);
    CHECK_U64(l.side.x, 130);
    CHECK_U64(l.side.y, l.header.y);
    CHECK_U64(l.rule.y, 41);
    CHECK_U64(l.context.y, 42);
    CHECK_U64(l.status.h, 0);

    ui = (struct ft_top_ui){.mode = FT_TOP_TRANSFERS, .overlay = FT_TOP_OVERLAY_JSON};
    ft_top_layout(&ui, 120, 30, &l);
    covers(&l);
    CHECK_U64(l.overlay.y, l.tabs.y + 1);
    CHECK_U64(l.table.h, 0);

    ui = (struct ft_top_ui){.mode = FT_TOP_TRANSFERS};
    ft_top_layout(&ui, 119, 30, &l);
    CHECK(l.too_small);
    CHECK_U64(l.table.h + l.keys.h + l.tabs.h + l.head.h, 0);
    ft_top_layout(&ui, 120, 29, &l);
    CHECK(l.too_small);
}

/* The COMMAND column of a row, from its tree guides on. */
static const char *command(struct fixture *f, size_t row)
{
    struct ft_top_ui ui = {.mode = FT_TOP_PROCESSES, .full_paths = true};
    struct ft_canvas *c = ft_canvas_create(174, 1);
    struct ft_top_draw d = drawer(c, f, &ui);

    ft_top_draw_table(&d, FT_TOP_PROCESSES, (struct ft_rect){0, 0, 174, 0},
                      (struct ft_rect){0, 0, 174, 1}, row);
    const char *text = cells(c, 59, 0, 60);
    ft_canvas_destroy(c);
    return text;
}

static bool starts(const char *text, const char *prefix)
{
    bool ok = strncmp(text, prefix, strlen(prefix)) == 0;
    if (!ok)
        fprintf(stderr, "  \"%s\" does not start with \"%s\"\n", text, prefix);
    return ok;
}

static void tree_guides(void)
{
    struct fixture f;
    fixture_init(&f);
    ft_top_set_mode(f.m, FT_TOP_PROCESSES);
    ft_top_set_tree(f.m, true);

    /* Java, then the master, its first worker and the other three folded. */
    CHECK(starts(command(&f, 0), "+ java -Xmx6g kafka.Kafka"));
    CHECK(starts(command(&f, 1), "- nginx: master process /usr/sbin/nginx"));
    CHECK(starts(command(&f, 2), "  ├─ + nginx: worker process"));
    CHECK(starts(command(&f, 3), "  └─ + 3 more nginx 102 103 104"));

    ft_top_expand_all(f.m, FT_TOP_PROCESSES);
    CHECK(starts(command(&f, 0), "- java -Xmx6g kafka.Kafka"));
    CHECK(starts(command(&f, 1), "  ├─ /var/lib/kafka/data/events-7/"));
    CHECK(starts(command(&f, 2), "  └─ /var/lib/kafka/data/events-3/"));
    CHECK(starts(command(&f, 4), "  ├─ - nginx: worker process"));
    CHECK(starts(command(&f, 5), "  │  └─ /var/www/cdn/video/launch.mp4 → 81.2.69.144:443"));
    CHECK(starts(command(&f, 6), "  └─ - 3 more nginx"));
    CHECK(starts(command(&f, 7), "     ├─ - nginx: worker process"));
    CHECK(starts(command(&f, 8), "     │  └─ /var/www/cdn/video/launch.mp4"));
    CHECK(starts(command(&f, 11), "     └─ - nginx: worker process"));
    CHECK(starts(command(&f, 12), "        └─ /var/www/cdn/video/launch.mp4"));

    /* The list has neither guides nor marks. */
    ft_top_set_tree(f.m, false);
    CHECK(starts(command(&f, 0), "java -Xmx6g kafka.Kafka"));
    fixture_free(&f);
}

void test_top_views(void)
{
    live_modes();
    transfer_columns();
    layout();
    tree_guides();
}
