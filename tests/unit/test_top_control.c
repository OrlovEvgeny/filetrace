#include "unit/test.h"

#include "ui/top/control.h"
#include "ui/top/presets.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

constexpr uint64_t SECOND = FT_NS_PER_SEC;
constexpr uint64_t WALL = 1'790'000'000 * FT_NS_PER_SEC;
constexpr int TABLE_ROWS = 5;

struct rig {
    struct ft_top_controller *c;
    struct ft_top_model *m;
    struct ft_top_frame frame;
    uint64_t at; /* seconds since the start, of the next frame */
};

/* As the loop does it: the source has the request the state calls for. */
static void sent(struct rig *r)
{
    struct ft_top_request *req = malloc(sizeof(*req));

    CHECK(req != nullptr);
    if (!req)
        return;
    ft_top_control_request(r->c, req);
    ft_top_control_sent(r->c, req, r->c->sent_serial + 1);
    free(req);
}

static bool rig_open(struct rig *r, enum ft_top_mode mode)
{
    struct ft_top_options opt;
    struct ft_error err = {0};

    ft_top_options_defaults(&opt);
    opt.mode = mode;
    *r = (struct rig){.m = ft_top_model_create(), .c = calloc(1, sizeof(*r->c))};
    ft_top_frame_init(&r->frame);
    if (!r->m || !r->c || !ft_top_control_init(r->c, r->m, &opt, nullptr, &err))
        return false;
    r->c->layout.table = (struct ft_rect){0, 8, 174, TABLE_ROWS};
    r->c->layout.overlay = (struct ft_rect){0, 7, 174, 20};
    sent(r);
    return true;
}

static void rig_close(struct rig *r)
{
    if (r->c)
        ft_top_control_free(r->c);
    free(r->c);
    ft_top_model_destroy(r->m);
    ft_top_frame_free(&r->frame);
}

/* Transfers 1..n, the lower ids the faster; odd ids send "odd-" files, even ids "even-" ones. */
static void fill(struct rig *r, uint64_t n)
{
    struct ft_row_transfer *row = calloc(1, sizeof(*row));
    struct ft_process_strings text = {"", "/srv", ""};

    CHECK(row != nullptr);
    for (uint64_t id = 1; row && id <= n; id++) {
        memset(row, 0, sizeof(*row));
        row->id = id;
        row->pid = 100 + (uint32_t)(id % 3);
        row->rate = (n + 1 - id) * 1000 * 1000;
        row->bytes = 1000;
        row->file_size = 4000;
        row->dev = 2049;
        row->ino = id;
        row->first_wall_ns = WALL;
        row->method = FT_METHOD_SENDFILE;
        row->confidence = FT_CONF_EXACT;
        row->flags =
            FT_XFER_ACTIVE | FT_XFER_FILE_KNOWN | FT_XFER_PATH_KNOWN | FT_XFER_PROCESS_TEXT;
        CHECK(ft_addr_parse("203.0.113.7", &row->remote));
        row->remote.port = (uint16_t)(1000 + id);
        ft_strlcpy(row->comm, "worker", sizeof(row->comm));
        snprintf(row->path, FT_PATH_MAX, "/srv/a/%s-%" PRIu64, id % 2 ? "odd" : "even", id);
        size_t lead = strlen(row->path) + 1;
        ft_process_strings_pack(row->path + lead, sizeof(row->path) - lead, &text);
        CHECK(ft_rows_append(&r->frame.transfers, row, ft_row_transfer_size(row)));
    }
    free(row);
}

/* Hands the rows filled so far to the controller as the answer to the latest request. */
static unsigned deliver(struct rig *r)
{
    struct ft_top_frame *f = &r->frame;

    f->code = FT_EXIT_OK;
    f->request_serial = r->c->sent_serial;
    f->mono_ns = (r->at + 1) * SECOND;
    f->stats.now_wall_ns = WALL + r->at * SECOND;
    r->at++;
    r->c->now_ns = f->mono_ns;
    unsigned bits = ft_top_control_frame(r->c, f);
    /* The controller may have kept the frame and handed back the one it held. */
    ft_rows_clear(&f->transfers);
    ft_rows_clear(&f->processes);
    f->has_totals = false;
    f->has_leaders = false;
    f->has_events = false;
    return bits;
}

static unsigned press(struct rig *r, enum ft_key key)
{
    struct ft_input in = {.kind = FT_INPUT_KEY, .key = key};
    return ft_top_control(r->c, &in);
}

static unsigned type(struct rig *r, const char *text)
{
    unsigned bits = 0;

    for (const char *p = text; *p; p++) {
        struct ft_input in = {
            .kind = FT_INPUT_KEY,
            .key = *p == ' ' ? FT_KEY_SPACE : FT_KEY_CHAR,
            .rune = (uint32_t)*p,
        };
        bits |= ft_top_control(r->c, &in);
    }
    return bits;
}

static unsigned click(struct rig *r, int x, int y)
{
    struct ft_input in = {.kind = FT_INPUT_MOUSE, .mouse = FT_MOUSE_LEFT, .x = x, .y = y};
    return ft_top_control(r->c, &in);
}

static size_t selected(struct rig *r)
{
    return ft_top_selected(r->m, r->c->ui.mode);
}

static uint64_t selected_id(struct rig *r)
{
    const struct ft_top_row *row = ft_top_row_at(r->m, r->c->ui.mode, selected(r));
    return row && row->kind == FT_TOP_ROW_TRANSFER ? row->transfer->id : 0;
}

static size_t scroll(struct rig *r)
{
    return r->c->ui.scroll[r->c->ui.mode];
}

static void esc_ladder(void)
{
    struct rig r;
    struct ft_top_ui *ui = &r.c->ui;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    ui = &r.c->ui;
    fill(&r, 8);
    deliver(&r);

    /* A search left highlighting, the sort panel, a filter being typed and Inspect over it. */
    press(&r, FT_KEY_F3);
    type(&r, "odd");
    press(&r, FT_KEY_ENTER);
    press(&r, FT_KEY_F6);
    press(&r, FT_KEY_F4);
    type(&r, "pid:101");
    press(&r, FT_KEY_F8);
    CHECK(ui->inspect);
    CHECK_U64(ui->prompt, FT_TOP_PROMPT_FILTER);
    CHECK_U64(ui->panel, FT_TOP_PANEL_SORT);
    CHECK_STR(ft_top_filter_of(r.m, FT_TOP_TRANSFERS), "pid:101");
    CHECK_STR(ft_top_search_of(r.m, FT_TOP_TRANSFERS), "odd");

    press(&r, FT_KEY_ESC);
    CHECK(!ui->inspect);
    CHECK_U64(ui->prompt, FT_TOP_PROMPT_FILTER);
    press(&r, FT_KEY_ESC);
    CHECK_U64(ui->prompt, FT_TOP_PROMPT_NONE);
    CHECK_STR(ft_top_filter_of(r.m, FT_TOP_TRANSFERS), "");
    CHECK_U64(ui->panel, FT_TOP_PANEL_SORT);
    press(&r, FT_KEY_ESC);
    CHECK_U64(ui->panel, FT_TOP_PANEL_NONE);
    CHECK_STR(ft_top_search_of(r.m, FT_TOP_TRANSFERS), "odd");
    press(&r, FT_KEY_ESC);
    CHECK_STR(ft_top_search_of(r.m, FT_TOP_TRANSFERS), "");
    CHECK_U64(press(&r, FT_KEY_ESC) & FT_TOP_DO_REDRAW, 0);
    CHECK_U64(ui->mode, FT_TOP_TRANSFERS);

    /* An overlay closes back to the Inspect panel it came from; the help waits for both. */
    press(&r, FT_KEY_F8);
    press(&r, FT_KEY_F1);
    CHECK(!ui->help);
    type(&r, "j");
    CHECK_U64(ui->overlay, FT_TOP_OVERLAY_JSON);
    press(&r, FT_KEY_ESC);
    CHECK_U64(ui->overlay, FT_TOP_OVERLAY_NONE);
    CHECK(ui->inspect);
    press(&r, FT_KEY_ESC);
    CHECK(!ui->inspect);

    /* The help opens over a prompt and closes before it. */
    press(&r, FT_KEY_F3);
    type(&r, "x");
    press(&r, FT_KEY_F1);
    CHECK(ui->help);
    press(&r, FT_KEY_ESC);
    CHECK(!ui->help);
    CHECK_U64(ui->prompt, FT_TOP_PROMPT_SEARCH);
    CHECK_STR(ui->edit.text, "x");
    press(&r, FT_KEY_ESC);
    CHECK_U64(ui->prompt, FT_TOP_PROMPT_NONE);
    CHECK_STR(ft_top_search_of(r.m, FT_TOP_TRANSFERS), "");

    /* Leaders goes back to the mode it was entered from. */
    type(&r, "3L");
    CHECK_U64(ui->mode, FT_TOP_LEADERS);
    press(&r, FT_KEY_ESC);
    CHECK_U64(ui->mode, FT_TOP_DESTINATIONS);
    rig_close(&r);
}

static void prompt_keeps_keys(void)
{
    struct rig r;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    fill(&r, 4);
    deliver(&r);

    press(&r, FT_KEY_F3);
    unsigned bits = type(&r, "q2Lzp");
    CHECK_U64(bits & FT_TOP_DO_QUIT, 0);
    CHECK_U64(r.c->ui.mode, FT_TOP_TRANSFERS);
    CHECK(!r.c->ui.paused);
    CHECK(r.c->ui.full_paths);
    CHECK_STR(r.c->ui.edit.text, "q2Lzp");
    CHECK_STR(ft_top_search_of(r.m, FT_TOP_TRANSFERS), "q2Lzp");

    /* Once the prompt is closed the same key acts. */
    press(&r, FT_KEY_ENTER);
    CHECK(type(&r, "q") & FT_TOP_DO_QUIT);
    rig_close(&r);
}

static void next_match_or_host_names(void)
{
    struct rig r;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    fill(&r, 8);
    deliver(&r);

    type(&r, "n");
    CHECK(ft_top_resolve_of(r.m));
    type(&r, "n");
    CHECK(!ft_top_resolve_of(r.m));

    press(&r, FT_KEY_F3);
    type(&r, "odd");
    press(&r, FT_KEY_ENTER);
    CHECK_U64(selected_id(&r), 1);
    type(&r, "n");
    CHECK_U64(selected_id(&r), 3);
    type(&r, "n");
    CHECK_U64(selected_id(&r), 5);
    type(&r, "N");
    CHECK_U64(selected_id(&r), 3);
    CHECK(!ft_top_resolve_of(r.m));

    /* Without the highlighting it is the host names again. */
    press(&r, FT_KEY_ESC);
    type(&r, "n");
    CHECK(ft_top_resolve_of(r.m));
    CHECK_U64(selected_id(&r), 3);
    rig_close(&r);
}

static void names_or_addresses(void)
{
    struct rig r;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    fill(&r, 2);
    deliver(&r);

    /* Names by default; a switches every mode with destination cells, but not Leaders. */
    CHECK(!r.c->ui.addresses);
    CHECK(type(&r, "a") & FT_TOP_DO_REDRAW);
    CHECK(r.c->ui.addresses);
    type(&r, "3a");
    CHECK(!r.c->ui.addresses);
    type(&r, "L");
    CHECK_U64(type(&r, "a") & FT_TOP_DO_REDRAW, 0);
    CHECK(!r.c->ui.addresses);
    rig_close(&r);
}

static void modes(void)
{
    struct rig r;
    struct ft_top_ui *ui;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    ui = &r.c->ui;

    type(&r, "2");
    CHECK_U64(ui->mode, FT_TOP_PROCESSES);
    static const enum ft_top_mode order[] = {FT_TOP_DESTINATIONS, FT_TOP_FILES, FT_TOP_LEADERS,
                                             FT_TOP_TRANSFERS, FT_TOP_PROCESSES};
    for (size_t i = 0; i < FT_ARRAY_LEN(order); i++) {
        press(&r, FT_KEY_TAB);
        CHECK_U64(ui->mode, order[i]);
    }
    press(&r, FT_KEY_F2);
    CHECK_U64(ui->mode, FT_TOP_DESTINATIONS);

    /* In Leaders F2 changes the window and Tab still changes the mode. */
    type(&r, "4l");
    CHECK_U64(ui->mode, FT_TOP_LEADERS);
    CHECK_U64(ui->window, FT_WINDOW_1H);
    press(&r, FT_KEY_F2);
    CHECK_U64(ui->mode, FT_TOP_LEADERS);
    CHECK_U64(ui->window, FT_WINDOW_24H);
    press(&r, FT_KEY_F2);
    press(&r, FT_KEY_F2);
    CHECK_U64(ui->window, FT_WINDOW_1M);
    press(&r, FT_KEY_ESC);
    CHECK_U64(ui->mode, FT_TOP_FILES);
    type(&r, "L");
    press(&r, FT_KEY_TAB);
    CHECK_U64(ui->mode, FT_TOP_TRANSFERS);

    /* F5 elsewhere goes to the process tree; in Processes it turns the tree off. */
    press(&r, FT_KEY_F5);
    CHECK_U64(ui->mode, FT_TOP_PROCESSES);
    CHECK(ft_top_tree_of(r.m));
    press(&r, FT_KEY_F5);
    CHECK(!ft_top_tree_of(r.m));
    rig_close(&r);
}

static void selection_and_scroll(void)
{
    struct rig r;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    fill(&r, 20);
    deliver(&r);
    CHECK_U64(selected(&r), 0);

    for (int i = 0; i < 4; i++)
        press(&r, FT_KEY_DOWN);
    CHECK_U64(selected(&r), 4);
    CHECK_U64(scroll(&r), 0);
    press(&r, FT_KEY_DOWN);
    CHECK_U64(selected(&r), 5);
    CHECK_U64(scroll(&r), 1);
    press(&r, FT_KEY_PGDN);
    CHECK_U64(selected(&r), 5 + TABLE_ROWS - 1);
    CHECK_U64(scroll(&r), 5);
    press(&r, FT_KEY_END);
    CHECK_U64(selected(&r), 19);
    CHECK_U64(scroll(&r), 15);
    press(&r, FT_KEY_PGUP);
    CHECK_U64(selected(&r), 15);
    CHECK_U64(scroll(&r), 15);
    press(&r, FT_KEY_UP);
    CHECK_U64(selected(&r), 14);
    CHECK_U64(scroll(&r), 14);
    press(&r, FT_KEY_HOME);
    CHECK_U64(selected(&r), 0);
    CHECK_U64(scroll(&r), 0);
    press(&r, FT_KEY_UP);
    CHECK_U64(selected(&r), 0);
    type(&r, "jjk");
    CHECK_U64(selected(&r), 1);

    struct ft_input wheel = {.kind = FT_INPUT_MOUSE, .mouse = FT_MOUSE_WHEEL_DOWN};
    ft_top_control(r.c, &wheel);
    CHECK_U64(selected(&r), 4);
    CHECK_U64(scroll(&r), 0);

    /* A shorter table after a resize brings the selection back into view. */
    r.c->layout.table.h = 3;
    ft_top_control_clamp(r.c);
    CHECK_U64(scroll(&r), 2);
    press(&r, FT_KEY_PGDN);
    CHECK_U64(selected(&r), 6);
    CHECK_U64(scroll(&r), 4);

    /* The table never scrolls past its last full page. */
    press(&r, FT_KEY_END);
    CHECK_U64(scroll(&r), 17);
    r.c->layout.table.h = 30;
    ft_top_control_clamp(r.c);
    CHECK_U64(scroll(&r), 0);

    /* Space tags and moves on; c copies the tagged rows. */
    press(&r, FT_KEY_HOME);
    type(&r, "  ");
    CHECK_U64(selected(&r), 2);
    CHECK_U64(ft_top_tag_count(r.m, FT_TOP_TRANSFERS), 2);
    unsigned bits = type(&r, "c");
    CHECK(bits & FT_TOP_DO_COPY);
    CHECK_STR(r.c->copy ? r.c->copy : "", "/srv/a/odd-1\n/srv/a/even-2");
    CHECK_STR(r.c->ui.message, "Sent 2 paths to the clipboard");
    rig_close(&r);
}

static void pause_holds_frames(void)
{
    struct rig r;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    fill(&r, 3);
    deliver(&r);
    CHECK_U64(ft_top_row_count(r.m, FT_TOP_TRANSFERS), 3);

    press(&r, FT_KEY_F9);
    CHECK(r.c->ui.paused);
    fill(&r, 5);
    deliver(&r);
    fill(&r, 6);
    deliver(&r);
    CHECK_U64(ft_top_row_count(r.m, FT_TOP_TRANSFERS), 3);

    /* Moving and sorting work on the frozen rows. */
    press(&r, FT_KEY_DOWN);
    CHECK_U64(selected_id(&r), 2);
    type(&r, "<");
    CHECK_U64(ft_top_row_count(r.m, FT_TOP_TRANSFERS), 3);

    r.c->now_ns = 10 * SECOND;
    press(&r, FT_KEY_F9);
    CHECK(!r.c->ui.paused);
    CHECK_U64(ft_top_row_count(r.m, FT_TOP_TRANSFERS), 6);
    CHECK_U64(r.c->ui.skipped_ns, 2 * SECOND);
    r.c->now_ns = 12 * SECOND;
    CHECK(ft_top_control_tick(r.c) & FT_TOP_DO_REDRAW);
    CHECK_U64(r.c->ui.skipped_ns, 0);
    rig_close(&r);
}

static void agent_that_stops_answering(void)
{
    struct rig r;
    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    struct ft_top_ui *ui = &r.c->ui;
    uint64_t stale = 2 * ui->delay_ns;

    fill(&r, 3);
    deliver(&r);
    uint64_t shown = r.c->now_ns;

    /* A frame up to twice the delay late is nothing to show. */
    r.c->now_ns = shown + stale;
    ft_top_control_tick(r.c);
    CHECK_U64(ui->lag_ns, 0);
    CHECK_U64(ft_top_control_deadline(r.c), shown + stale + 1);

    /* Later the lag counts from the frame shown, the loop waking every second to show it. */
    r.c->now_ns = shown + stale + SECOND / 2;
    CHECK(ft_top_control_tick(r.c) & FT_TOP_DO_REDRAW);
    CHECK_U64(ui->lag_ns, stale + SECOND / 2);
    CHECK_U64(ft_top_control_deadline(r.c), r.c->now_ns + SECOND);

    /* Paused, the screen is meant to stand still. */
    press(&r, FT_KEY_F9);
    r.c->now_ns += 5 * SECOND;
    ft_top_control_tick(r.c);
    CHECK_U64(ui->lag_ns, stale + SECOND / 2);
    CHECK(ft_top_control_deadline(r.c) > r.c->now_ns + SECOND);
    press(&r, FT_KEY_F9);
    ft_top_control_tick(r.c);
    CHECK_U64(ui->lag_ns, r.c->now_ns - shown);

    /* A frame that comes ends it. */
    r.at = r.c->now_ns / SECOND;
    fill(&r, 3);
    deliver(&r);
    ft_top_control_tick(r.c);
    CHECK_U64(ui->lag_ns, 0);
    rig_close(&r);
}

static unsigned fail_frame(struct rig *r, int code)
{
    r->frame.code = code;
    ft_strlcpy(r->frame.error, "The connection to the agent was lost.", sizeof(r->frame.error));
    r->frame.request_serial = r->c->sent_serial;
    return ft_top_control_frame(r->c, &r->frame);
}

static void collector_session(void)
{
    struct rig r;
    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    struct ft_top_ui *ui = &r.c->ui;
    uint64_t start = 10 * SECOND;
    uint64_t moment = 300 * FT_NS_PER_MS;

    /* The wait is shown only once it has lasted a moment. */
    r.c->now_ns = start;
    ft_top_control_start(r.c, true, false);
    CHECK(ui->session_only);
    CHECK_U64(ft_top_control_deadline(r.c), start + moment);
    r.c->now_ns = start + moment - 1;
    ft_top_control_tick(r.c);
    CHECK(!ui->starting);
    r.c->now_ns = start + moment;
    CHECK(ft_top_control_tick(r.c) & FT_TOP_DO_REDRAW);
    CHECK(ui->starting);
    r.c->now_ns = start + 3 * SECOND;
    ft_top_control_tick(r.c);
    CHECK_U64(ui->starting_ns, 3 * SECOND);

    /* A collector that could not attach ends the run with its reason. */
    CHECK(fail_frame(&r, FT_EXIT_PERMISSION) & FT_TOP_DO_QUIT);
    CHECK_U64(r.c->exit_code, FT_EXIT_PERMISSION);
    CHECK(!ui->starting);
    rig_close(&r);

    /* One that stops later leaves the last data on the screen. */
    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    ui = &r.c->ui;
    ft_top_control_start(r.c, true, false);
    fill(&r, 3);
    r.frame.stats.start_wall_ns = WALL;
    CHECK(!(deliver(&r) & FT_TOP_DO_QUIT));
    CHECK_U64(ui->since_wall_ns, WALL);
    CHECK(!(fail_frame(&r, FT_EXIT_NO_AGENT) & FT_TOP_DO_QUIT));
    CHECK(ui->collector_lost);
    CHECK_U64(r.c->exit_code, FT_EXIT_OK);
    CHECK_U64(ft_top_row_count(r.m, FT_TOP_TRANSFERS), 3);
    rig_close(&r);

    /* An agent that fails is retried, never a reason to end. */
    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    ft_top_control_start(r.c, false, false);
    CHECK(!(fail_frame(&r, FT_EXIT_NO_AGENT) & FT_TOP_DO_QUIT));
    CHECK(!r.c->ui.collector_lost);
    rig_close(&r);
}

static void filter_that_does_not_parse(void)
{
    struct rig r;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    fill(&r, 6);
    deliver(&r);

    press(&r, FT_KEY_F4);
    type(&r, "pid:101");
    CHECK_STR(r.c->ui.prompt_error, "");
    CHECK_U64(ft_top_row_count(r.m, FT_TOP_TRANSFERS), 2);
    press(&r, FT_KEY_ENTER);
    CHECK_U64(r.c->ui.prompt, FT_TOP_PROMPT_NONE);

    /* F4 holds the filter in effect; a bad pid leaves it in effect and says why. */
    press(&r, FT_KEY_F4);
    CHECK_STR(r.c->ui.edit.text, "pid:101");
    type(&r, "x");
    CHECK(strstr(r.c->ui.prompt_error, "pid:101x") != nullptr);
    CHECK_STR(ft_top_filter_of(r.m, FT_TOP_TRANSFERS), "pid:101");
    CHECK_U64(ft_top_row_count(r.m, FT_TOP_TRANSFERS), 2);
    press(&r, FT_KEY_ENTER);
    CHECK_U64(r.c->ui.prompt, FT_TOP_PROMPT_FILTER);

    press(&r, FT_KEY_BACKSPACE);
    CHECK_STR(r.c->ui.prompt_error, "");
    press(&r, FT_KEY_ENTER);
    CHECK_U64(r.c->ui.prompt, FT_TOP_PROMPT_NONE);

    /* Esc on the plain screen leaves the filter alone. */
    press(&r, FT_KEY_ESC);
    CHECK_STR(ft_top_filter_of(r.m, FT_TOP_TRANSFERS), "pid:101");
    rig_close(&r);
}

static void clicks_act_as_keys(void)
{
    struct rig r;
    struct ft_top_hits *hits;

    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    hits = &r.c->hits;
    fill(&r, 8);
    deliver(&r);
    ft_top_hits_add(hits, (struct ft_rect){0, 7, 14, 1}, FT_TOP_TARGET_TAB, FT_TOP_TRANSFERS);
    ft_top_hits_add(hits, (struct ft_rect){14, 7, 15, 1}, FT_TOP_TARGET_TAB, FT_TOP_PROCESSES);
    ft_top_hits_add(hits, (struct ft_rect){0, 8, 7, 1}, FT_TOP_TARGET_HEADER, FT_TOP_SORT_PID);
    for (int i = 0; i < TABLE_ROWS; i++)
        ft_top_hits_add(hits, (struct ft_rect){0, 9 + i, 174, 1}, FT_TOP_TARGET_ROW, (uint32_t)i);
    ft_top_hits_add_key(hits, (struct ft_rect){18, 43, 9, 1}, FT_KEY_F3, 0);
    ft_top_hits_add_key(hits, (struct ft_rect){100, 43, 9, 1}, FT_KEY_CHAR, 'q');

    click(&r, 40, 11);
    CHECK_U64(selected(&r), 2);
    CHECK(!r.c->ui.inspect);
    click(&r, 40, 11);
    CHECK(r.c->ui.inspect);
    press(&r, FT_KEY_ESC);

    enum ft_top_sort key;
    bool descending;
    click(&r, 3, 8);
    ft_top_sort_of(r.m, FT_TOP_TRANSFERS, &key, &descending);
    CHECK_U64(key, FT_TOP_SORT_PID);
    CHECK(descending);
    click(&r, 3, 8);
    ft_top_sort_of(r.m, FT_TOP_TRANSFERS, &key, &descending);
    CHECK_U64(key, FT_TOP_SORT_PID);
    CHECK(!descending);

    click(&r, 20, 43);
    CHECK_U64(r.c->ui.prompt, FT_TOP_PROMPT_SEARCH);
    /* The item replays its key, so with the search prompt open it closes the prompt. */
    click(&r, 20, 43);
    CHECK_U64(r.c->ui.prompt, FT_TOP_PROMPT_NONE);

    click(&r, 20, 7);
    CHECK_U64(r.c->ui.mode, FT_TOP_PROCESSES);
    CHECK_U64(click(&r, 5, 30), 0);
    CHECK(click(&r, 101, 43) & FT_TOP_DO_QUIT);
    rig_close(&r);
}

static void requests(void)
{
    struct rig r;
    struct ft_top_request *req = malloc(sizeof(*req));

    CHECK(req != nullptr);
    if (!req)
        return;
    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    ft_top_control_request(r.c, req);
    CHECK(req->live);
    CHECK(!req->totals);
    CHECK(!req->leaders);
    CHECK_U64(req->delay_ns, SECOND);

    /* Destinations needs the totals; Leaders the ranking of the window. */
    CHECK(type(&r, "3") & FT_TOP_DO_REQUEST);
    ft_top_control_request(r.c, req);
    CHECK(req->totals);
    sent(&r);
    CHECK(type(&r, "L") & FT_TOP_DO_REQUEST);
    ft_top_control_request(r.c, req);
    CHECK(req->live);
    CHECK(!req->totals);
    CHECK(req->leaders);
    CHECK_U64(req->window, FT_WINDOW_1H);
    CHECK_U64(req->key, FT_LEADER_FILE);
    CHECK_U64(req->by, FT_SORT_BYTES);
    CHECK_U64(req->limit, 50);
    sent(&r);

    /* A change of window waits for its answer and shows it is waiting after a moment. */
    r.c->now_ns = 50 * SECOND;
    CHECK(type(&r, "w") & FT_TOP_DO_REQUEST);
    ft_top_control_request(r.c, req);
    CHECK_U64(req->window, FT_WINDOW_24H);
    sent(&r);
    CHECK_U64(ft_top_control_deadline(r.c), 50 * SECOND + 100 * FT_NS_PER_MS);
    r.c->now_ns += 150 * FT_NS_PER_MS;
    ft_top_control_tick(r.c);
    CHECK(r.c->ui.waiting);
    r.frame.has_leaders = true;
    deliver(&r);
    CHECK(!r.c->ui.waiting);
    CHECK(!r.c->ui.leaders_unsupported);

    /* The ranking follows a single file glob of the Leaders filter. */
    press(&r, FT_KEY_F4);
    type(&r, "file:/srv/*.pdf");
    press(&r, FT_KEY_ENTER);
    ft_top_control_request(r.c, req);
    CHECK_STR(req->leader_path, "/srv/*.pdf");
    sent(&r);

    /* A pid typed into the filter goes to the agent with the next frame, or when kept. */
    type(&r, "1");
    press(&r, FT_KEY_F4);
    CHECK_U64(type(&r, "pid:42") & FT_TOP_DO_REQUEST, 0);
    CHECK(deliver(&r) & FT_TOP_DO_REQUEST);
    CHECK(press(&r, FT_KEY_ENTER) & FT_TOP_DO_REQUEST);
    ft_top_control_request(r.c, req);
    CHECK_U64(req->scope.pid, 42);
    CHECK(!req->leaders);
    sent(&r);

    /* The scope is the mode's own: Processes has no filter. */
    CHECK(type(&r, "2") & FT_TOP_DO_REQUEST);
    ft_top_control_request(r.c, req);
    CHECK_U64(req->scope.pid, 0);
    sent(&r);
    CHECK_U64(type(&r, "m") & FT_TOP_DO_REQUEST, 0);

    CHECK(type(&r, "d") & FT_TOP_DO_REQUEST);
    ft_top_control_request(r.c, req);
    CHECK_U64(req->delay_ns, 2 * SECOND);
    rig_close(&r);
    free(req);
}

static void presets(void)
{
    char dir[] = "/tmp/ft_top_presets.XXXXXX";
    char config[64];
    char home[64];
    char path[96];
    char expression[64];
    const char *old = getenv("XDG_CONFIG_HOME");
    char *saved = old ? strdup(old) : nullptr;
    struct ft_error err = {0};
    struct ft_top_presets p;
    struct stat st;

    CHECK(mkdtemp(dir) != nullptr);
    snprintf(config, sizeof(config), "%s/config", dir);
    snprintf(home, sizeof(home), "%s/filetrace", config);
    snprintf(path, sizeof(path), "%s/top-presets", home);
    setenv("XDG_CONFIG_HOME", config, 1);

    /* No file yet: no presets, and an unknown name says so. */
    CHECK(ft_top_presets_load(&p, &err));
    CHECK_U64(p.count, 0);
    CHECK(!ft_top_presets_find("invoices", expression, sizeof(expression), &err));
    CHECK_U64(err.code, FT_EXIT_USAGE);
    CHECK(strstr(err.msg, "none are saved") != nullptr);

    CHECK(ft_top_presets_save("invoices", "file:*.pdf dest:public", &err));
    CHECK(ft_top_presets_save("mine", "user:evgenii", &err));
    CHECK(ft_top_presets_save("invoices", "file:INV-*.pdf", &err));
    CHECK(stat(home, &st) == 0 && (st.st_mode & 0777) == 0700);

    CHECK(ft_top_presets_load(&p, &err));
    CHECK_U64(p.count, 2);
    if (p.count == 2) {
        CHECK_STR(p.items[0].name, "invoices");
        CHECK_STR(p.items[0].expression, "file:INV-*.pdf");
        CHECK_STR(p.items[1].name, "mine");
    }
    ft_top_presets_free(&p);

    CHECK(ft_top_presets_find("mine", expression, sizeof(expression), &err));
    CHECK_STR(expression, "user:evgenii");
    CHECK(!ft_top_presets_find("nope", expression, sizeof(expression), &err));
    CHECK_U64(err.code, FT_EXIT_USAGE);
    CHECK(strstr(err.msg, "invoices, mine") != nullptr);
    CHECK(!ft_top_presets_save("a\tb", "pid:1", &err));
    CHECK(!ft_top_presets_save("my logs", "file:*.log", &err));
    CHECK_U64(err.code, FT_EXIT_USAGE);
    CHECK(strstr(err.msg, "space") != nullptr);

    /* "@name" ends at a space or a tab; the terms after it follow the preset's own. */
    static const char *const expansions[][2] = {
        {"@mine", "user:evgenii"},
        {"@mine dest:public", "user:evgenii dest:public"},
        {"@mine\tdest:public", "user:evgenii dest:public"},
        {"pid:1 @mine", "pid:1 @mine"},
    };
    for (size_t i = 0; i < FT_ARRAY_LEN(expansions); i++) {
        char *expanded = ft_top_presets_expand(expansions[i][0], &err);
        CHECK_STR(expanded ? expanded : "(failed)", expansions[i][1]);
        free(expanded);
    }
    CHECK(!ft_top_presets_expand("@", &err));
    CHECK_U64(err.code, FT_EXIT_USAGE);
    CHECK(!ft_top_presets_expand("@my logs", &err));
    CHECK(strstr(err.msg, "'my'") != nullptr);

    /* Ctrl-S in the filter prompt saves; the arrows bring presets and earlier filters back. */
    struct rig r;
    CHECK(rig_open(&r, FT_TOP_TRANSFERS));
    press(&r, FT_KEY_F4);
    type(&r, "pid:7");
    press(&r, FT_KEY_CTRL_S);
    CHECK_U64(r.c->ui.prompt, FT_TOP_PROMPT_PRESET);
    type(&r, "seven");
    press(&r, FT_KEY_ENTER);
    CHECK_U64(r.c->ui.prompt, FT_TOP_PROMPT_NONE);
    CHECK(ft_top_presets_find("seven", expression, sizeof(expression), &err));
    CHECK_STR(expression, "pid:7");
    CHECK_STR(ft_top_filter_of(r.m, FT_TOP_TRANSFERS), "pid:7");

    press(&r, FT_KEY_F4);
    press(&r, FT_KEY_UP);
    CHECK_STR(r.c->ui.edit.text, "pid:7");
    press(&r, FT_KEY_UP);
    CHECK_STR(r.c->ui.edit.text, "user:evgenii");
    CHECK_STR(ft_top_filter_of(r.m, FT_TOP_TRANSFERS), "user:evgenii");
    press(&r, FT_KEY_DOWN);
    press(&r, FT_KEY_DOWN);
    CHECK_STR(r.c->ui.edit.text, "pid:7");

    /* A name the filter could not call up is refused, and its prompt stays open. */
    press(&r, FT_KEY_CTRL_S);
    type(&r, "my logs");
    press(&r, FT_KEY_ENTER);
    CHECK_U64(r.c->ui.prompt, FT_TOP_PROMPT_PRESET);
    CHECK(strstr(r.c->ui.message, "space") != nullptr);
    rig_close(&r);

    /* Saving keeps every other line byte for byte, one holding a NUL too. */
    static const char held[] = "junk\0more\nmine\tdest:private\n";
    char back[64];
    FILE *f = fopen(path, "wb");
    CHECK(f && fwrite(held, 1, sizeof(held) - 1, f) == sizeof(held) - 1);
    if (f)
        fclose(f);
    CHECK(ft_top_presets_save("other", "pid:1", &err));
    f = fopen(path, "rb");
    size_t n = f ? fread(back, 1, sizeof(back), f) : 0;
    if (f)
        fclose(f);
    CHECK(n > sizeof(held) - 1 && memcmp(back, held, sizeof(held) - 1) == 0);
    CHECK(ft_top_presets_find("mine", expression, sizeof(expression), &err));
    CHECK_STR(expression, "dest:private");

    unlink(path);
    rmdir(home);
    rmdir(config);
    rmdir(dir);
    if (saved)
        setenv("XDG_CONFIG_HOME", saved, 1);
    else
        unsetenv("XDG_CONFIG_HOME");
    free(saved);
}

void test_top_control(void)
{
    esc_ladder();
    prompt_keeps_keys();
    next_match_or_host_names();
    names_or_addresses();
    modes();
    selection_and_scroll();
    pause_holds_frames();
    agent_that_stops_answering();
    collector_session();
    filter_that_does_not_parse();
    clicks_act_as_keys();
    requests();
    presets();
}
