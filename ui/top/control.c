#include "ui/top/control.h"

#include "filetrace/event.h"
#include "filetrace/format.h"
#include "ui/top/once.h"
#include "ui/top/presets.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <time.h>

constexpr uint64_t MESSAGE_NS = 3 * FT_NS_PER_SEC;
constexpr uint64_t SKIPPED_NS = 2 * FT_NS_PER_SEC;
constexpr uint64_t SPINNER_NS = 100 * FT_NS_PER_MS;
constexpr long WHEEL_ROWS = 3;

static const uint64_t delays[] = {
    500 * FT_NS_PER_MS, FT_NS_PER_SEC, 2 * FT_NS_PER_SEC, 5 * FT_NS_PER_SEC, 10 * FT_NS_PER_SEC,
};

static const enum ft_leader_window windows[] = {
    FT_WINDOW_1M, FT_WINDOW_5M, FT_WINDOW_15M, FT_WINDOW_1H, FT_WINDOW_24H, FT_WINDOW_7D,
};

static const enum ft_leader_key groupings[] = {
    FT_LEADER_FILE,
    FT_LEADER_DIRECTORY,
    FT_LEADER_EXTENSION,
};

static const struct {
    enum ft_top_sort top;
    enum ft_sort wire;
} measures[] = {
    {FT_TOP_SORT_BYTES, FT_SORT_BYTES},
    {FT_TOP_SORT_TRANSFERS, FT_SORT_TRANSFERS},
    {FT_TOP_SORT_DESTINATIONS, FT_SORT_DESTINATIONS},
};

static enum ft_top_sort top_measure(enum ft_sort by)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(measures); i++) {
        if (measures[i].wire == by)
            return measures[i].top;
    }
    return FT_TOP_SORT_BYTES;
}

static enum ft_sort wire_measure(enum ft_top_sort by)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(measures); i++) {
        if (measures[i].top == by)
            return measures[i].wire;
    }
    return FT_SORT_BYTES;
}

[[gnu::format(printf, 3, 4)]]
static void say(struct ft_top_controller *c, enum ft_top_message kind, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(c->ui.message, sizeof(c->ui.message), fmt, ap);
    va_end(ap);
    c->ui.message_kind = kind;
    c->message_until_ns = c->now_ns + MESSAGE_NS;
}

/* Text as one line: control characters would split it or move the terminal's cursor. */
static void put_text(FILE *out, const char *text)
{
    for (const char *p = text ? text : ""; *p; p++)
        fputc((unsigned char)*p < 0x20 || *p == 0x7f ? '?' : *p, out);
}

static void lines_free(struct ft_top_lines *l)
{
    free(l->text);
    free(l->lines);
    *l = (struct ft_top_lines){0};
}

/* Takes text, which malloc gave, and splits it at its newlines; a last empty line is dropped. */
static bool lines_take(struct ft_top_lines *l, char *text)
{
    size_t n = 1;

    lines_free(l);
    for (const char *p = text; *p; p++)
        n += *p == '\n';
    l->lines = calloc(n, sizeof(*l->lines));
    if (!l->lines) {
        free(text);
        return false;
    }
    l->text = text;
    for (char *p = text; *p;) {
        l->lines[l->count++] = p;
        char *nl = strchr(p, '\n');
        if (!nl)
            break;
        *nl = '\0';
        p = nl + 1;
    }
    return true;
}

static void overlay_show(struct ft_top_controller *c)
{
    c->ui.overlay_text.lines = c->overlay.lines;
    c->ui.overlay_text.count = c->overlay.count;
}

static void overlay_say(struct ft_top_controller *c, const char *line)
{
    char *text = strdup(line);

    if (text)
        lines_take(&c->overlay, text);
    overlay_show(c);
}

static void close_overlay(struct ft_top_controller *c)
{
    c->ui.overlay = FT_TOP_OVERLAY_NONE;
    c->ui.overlay_text = (struct ft_top_text){0};
    c->events_serial = 0;
    c->events_ask = false;
    lines_free(&c->overlay);
}

static const struct ft_top_row *selected_row(const struct ft_top_controller *c)
{
    size_t i = ft_top_selected(c->model, c->ui.mode);
    return i == SIZE_MAX ? nullptr : ft_top_row_at(c->model, c->ui.mode, i);
}

static size_t table_height(const struct ft_top_controller *c)
{
    return c->layout.table.h > 0 ? (size_t)c->layout.table.h : 1;
}

static size_t overlay_page(const struct ft_top_controller *c)
{
    /* The first row of the overlay is its title. */
    return c->layout.overlay.h > 1 ? (size_t)c->layout.overlay.h - 1 : 1;
}

static void keep_in_view(struct ft_top_controller *c)
{
    enum ft_top_mode mode = c->ui.mode;
    size_t rows = ft_top_row_count(c->model, mode);
    size_t height = table_height(c);
    size_t selected = ft_top_selected(c->model, mode);
    size_t *scroll = &c->ui.scroll[mode];

    if (selected != SIZE_MAX) {
        if (selected < *scroll)
            *scroll = selected;
        else if (selected - *scroll >= height)
            *scroll = selected - height + 1;
    }
    size_t last = rows > height ? rows - height : 0;
    if (*scroll > last)
        *scroll = last;
}

static void keep_overlay(struct ft_top_controller *c)
{
    struct ft_top_text *t = &c->ui.overlay_text;
    size_t page = overlay_page(c);
    size_t last = t->count > page ? t->count - page : 0;

    if (t->scroll > last)
        t->scroll = last;
}

void ft_top_control_clamp(struct ft_top_controller *c)
{
    keep_in_view(c);
    keep_overlay(c);
}

static void scroll_overlay(struct ft_top_controller *c, long delta)
{
    size_t *scroll = &c->ui.overlay_text.scroll;

    if (delta < 0)
        *scroll = (size_t)-delta > *scroll ? 0 : *scroll - (size_t)-delta;
    else
        *scroll = (size_t)delta > SIZE_MAX - *scroll ? SIZE_MAX : *scroll + (size_t)delta;
    keep_overlay(c);
}

static long page_rows(const struct ft_top_controller *c)
{
    size_t height = table_height(c);
    return height > 1 ? (long)height - 1 : 1;
}

static unsigned move(struct ft_top_controller *c, long delta)
{
    ft_top_select_by(c->model, c->ui.mode, delta);
    return FT_TOP_DO_REDRAW;
}

static bool plain_char(const struct ft_input *in)
{
    return in->key == FT_KEY_CHAR && !(in->mods & (FT_MOD_ALT | FT_MOD_CTRL));
}

/* The keys that move the selection; false for any other. Shift on an arrow is ignored. */
static bool movement(struct ft_top_controller *c, const struct ft_input *in, unsigned *bits)
{
    switch (in->key) {
    case FT_KEY_UP:
        *bits = move(c, -1);
        return true;
    case FT_KEY_DOWN:
        *bits = move(c, 1);
        return true;
    case FT_KEY_PGUP:
        *bits = move(c, -page_rows(c));
        return true;
    case FT_KEY_PGDN:
        *bits = move(c, page_rows(c));
        return true;
    case FT_KEY_HOME:
        ft_top_select_at(c->model, c->ui.mode, 0);
        *bits = FT_TOP_DO_REDRAW;
        return true;
    case FT_KEY_END:
        ft_top_select_at(c->model, c->ui.mode, SIZE_MAX);
        *bits = FT_TOP_DO_REDRAW;
        return true;
    default:
        break;
    }
    if (plain_char(in) && (in->rune == 'k' || in->rune == 'j')) {
        *bits = move(c, in->rune == 'k' ? -1 : 1);
        return true;
    }
    return false;
}

/* What the selected row stands for in the Inspect panel and its actions. */
enum subject_kind : uint8_t {
    SUBJECT_NONE,
    SUBJECT_PROCESS,
    SUBJECT_DESTINATION,
    SUBJECT_FILE, /* or a directory or an extension of Leaders */
};

struct subject {
    enum subject_kind kind;
    const struct ft_top_process *process;
    const struct ft_top_destination *destination;
    const char *path;
    bool path_known;
    enum ft_leader_key key;
};

static struct subject subject_of(const struct ft_top_controller *c, const struct ft_top_row *r)
{
    struct subject s = {.key = FT_LEADER_FILE};

    if (!r)
        return s;
    switch (r->kind) {
    case FT_TOP_ROW_TRANSFER:
        s.kind = SUBJECT_PROCESS;
        s.process = r->transfer->process;
        break;
    case FT_TOP_ROW_PROCESS:
        s.kind = SUBJECT_PROCESS;
        s.process = r->process;
        break;
    case FT_TOP_ROW_DESTINATION:
        s.kind = SUBJECT_DESTINATION;
        s.destination = r->destination;
        break;
    case FT_TOP_ROW_FILE:
        s.kind = SUBJECT_FILE;
        s.path = r->file->path;
        s.path_known = r->file->path_known;
        break;
    case FT_TOP_ROW_LEADER:
        if (r->leader->row->remote.family)
            break;
        s.kind = SUBJECT_FILE;
        s.path = r->leader->row->text;
        s.path_known = s.path[0] != '\0';
        s.key = c->sent.leaders ? c->sent.key : c->ui.key;
        break;
    default:
        break;
    }
    return s;
}

/* "key:value", the value quoted when the filter language needs it; false when it does not fit. */
static bool filter_term(char *buf, size_t size, const char *key, const char *value)
{
    bool quote = strpbrk(value, " \"") != nullptr;
    int n = snprintf(buf, size, "%s:%s", key, quote ? "\"" : "");
    size_t len = n > 0 ? (size_t)n : 0;

    for (const char *p = value; *p; p++) {
        if (len + 3 >= size)
            return false;
        if (quote && (*p == '"' || *p == '\\'))
            buf[len++] = '\\';
        buf[len++] = *p;
    }
    if (len + 2 >= size)
        return false;
    if (quote)
        buf[len++] = '"';
    buf[len] = '\0';
    return true;
}

/* The expression without the term when it holds it, else with the term added. */
static bool toggle_term(const char *text, const char *term, char *out, size_t size)
{
    size_t term_len = strlen(term);
    size_t len = 0;
    bool found = false;

    out[0] = '\0';
    for (const char *p = text; *p;) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        const char *start = p;
        bool quoted = false;
        while (*p && (quoted || *p != ' ')) {
            if (*p == '"')
                quoted = !quoted;
            else if (quoted && *p == '\\' && p[1])
                p++;
            p++;
        }
        size_t n = (size_t)(p - start);
        if (n == term_len && memcmp(start, term, n) == 0) {
            found = true;
            continue;
        }
        if (len + n + 2 > size)
            return false;
        if (len)
            out[len++] = ' ';
        memcpy(out + len, start, n);
        len += n;
        out[len] = '\0';
    }
    if (found)
        return true;
    if (len + term_len + 2 > size)
        return false;
    if (len)
        out[len++] = ' ';
    memcpy(out + len, term, term_len + 1);
    return true;
}

static bool set_filter_text(struct ft_top_controller *c, enum ft_top_mode mode, const char *text)
{
    struct ft_error err = {0};

    if (ft_top_set_filter(c->model, mode, text, &err))
        return true;
    say(c, FT_TOP_MESSAGE_ERROR, "%s", err.msg);
    return false;
}

static void recall_free(struct ft_top_recall *r)
{
    for (size_t i = 0; i < r->count; i++)
        free(r->items[i]);
    free(r->items);
    *r = (struct ft_top_recall){0};
}

/* Adds a text at the newest end; one that is there already moves there. */
static void recall_add(char ***items, size_t *count, const char *text)
{
    if (!text || !text[0])
        return;
    for (size_t i = 0; i < *count; i++) {
        if (strcmp((*items)[i], text) == 0) {
            char *same = (*items)[i];
            memmove(&(*items)[i], &(*items)[i + 1], (*count - i - 1) * sizeof(**items));
            (*items)[*count - 1] = same;
            return;
        }
    }
    char **grown = realloc(*items, (*count + 1) * sizeof(*grown));
    char *copy = strdup(text);
    if (grown)
        *items = grown;
    if (!grown || !copy) {
        free(copy);
        return;
    }
    (*items)[(*count)++] = copy;
}

static void recall_build(struct ft_top_controller *c)
{
    struct ft_top_recall *r = &c->recall;
    struct ft_top_presets presets;
    struct ft_error err = {0};

    recall_free(r);
    if (ft_top_presets_load(&presets, &err)) {
        for (size_t i = 0; i < presets.count; i++)
            recall_add(&r->items, &r->count, presets.items[i].expression);
        ft_top_presets_free(&presets);
    }
    for (size_t i = 0; i < c->nhistory; i++)
        recall_add(&r->items, &r->count, c->history[i]);
    r->at = r->count;
}

static void apply_filter_prompt(struct ft_top_controller *c)
{
    struct ft_error err = {0};

    if (ft_top_set_filter(c->model, c->ui.mode, c->ui.edit.text, &err))
        c->ui.prompt_error[0] = '\0';
    else
        ft_strlcpy(c->ui.prompt_error, err.msg, sizeof(c->ui.prompt_error));
}

static unsigned recall_step(struct ft_top_controller *c, int step)
{
    struct ft_top_recall *r = &c->recall;

    if (step < 0) {
        if (r->at == 0)
            return 0;
        if (r->at == r->count)
            ft_strlcpy(r->typed, c->ui.edit.text, sizeof(r->typed));
        r->at--;
        ft_lineedit_set(&c->ui.edit, r->items[r->at]);
    } else {
        if (r->at >= r->count)
            return 0;
        r->at++;
        ft_lineedit_set(&c->ui.edit, r->at == r->count ? r->typed : r->items[r->at]);
    }
    apply_filter_prompt(c);
    return FT_TOP_DO_REDRAW;
}

/* Closes the prompt keeping what it applied: a search keeps highlighting, the filter stays. */
static void leave_prompt(struct ft_top_controller *c)
{
    struct ft_top_ui *ui = &c->ui;

    if (ui->prompt == FT_TOP_PROMPT_FILTER || ui->prompt == FT_TOP_PROMPT_PRESET) {
        recall_add(&c->history, &c->nhistory, ft_top_filter_of(c->model, ui->mode));
        recall_free(&c->recall);
    }
    ui->prompt = FT_TOP_PROMPT_NONE;
    ui->prompt_error[0] = '\0';
}

static unsigned open_prompt(struct ft_top_controller *c, enum ft_top_prompt prompt)
{
    struct ft_top_ui *ui = &c->ui;
    char name[160];

    leave_prompt(c);
    ui->prompt = prompt;
    switch (prompt) {
    case FT_TOP_PROMPT_SEARCH:
        ft_lineedit_set(&ui->edit, ft_top_search_of(c->model, ui->mode));
        break;
    case FT_TOP_PROMPT_FILTER:
        ft_lineedit_set(&ui->edit, ft_top_filter_of(c->model, ui->mode));
        recall_build(c);
        break;
    case FT_TOP_PROMPT_EXPORT: {
        time_t now = time(nullptr);
        struct tm tm;
        char stamp[32] = "";
        if (localtime_r(&now, &tm))
            strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tm);
        snprintf(name, sizeof(name), "filetrace-top-%s-%s.json", ft_top_mode_name(ui->mode), stamp);
        ft_lineedit_set(&ui->edit, name);
        break;
    }
    default:
        ft_lineedit_set(&ui->edit, "");
        break;
    }
    return FT_TOP_DO_REDRAW;
}

static unsigned export_view(struct ft_top_controller *c)
{
    struct ft_error err = {0};
    size_t rows = 0;
    const char *path = c->ui.edit.text;

    if (!ft_top_export(c->model, c->ui.mode, path, &rows, &err)) {
        say(c, FT_TOP_MESSAGE_ERROR, "%s", err.msg);
        return FT_TOP_DO_REDRAW;
    }
    say(c, FT_TOP_MESSAGE_INFO, "Exported %zu %s to %s", rows, rows == 1 ? "row" : "rows", path);
    c->ui.prompt = FT_TOP_PROMPT_NONE;
    return FT_TOP_DO_REDRAW;
}

static unsigned save_preset(struct ft_top_controller *c)
{
    struct ft_error err = {0};
    char name[sizeof(c->ui.edit.text)];
    const char *start = c->ui.edit.text;
    size_t len;

    while (*start == ' ')
        start++;
    len = strlen(start);
    while (len && start[len - 1] == ' ')
        len--;
    memcpy(name, start, len);
    name[len] = '\0';
    if (!ft_top_presets_save(name, c->filter_edit.text, &err)) {
        say(c, FT_TOP_MESSAGE_ERROR, "%s", err.msg);
        return FT_TOP_DO_REDRAW;
    }
    say(c, FT_TOP_MESSAGE_INFO, "Saved preset \"%s\" · --filter @%s starts with it", name, name);
    leave_prompt(c);
    return FT_TOP_DO_REDRAW;
}

static unsigned prompt_enter(struct ft_top_controller *c)
{
    switch (c->ui.prompt) {
    case FT_TOP_PROMPT_SEARCH:
        c->ui.prompt = FT_TOP_PROMPT_NONE;
        return FT_TOP_DO_REDRAW;
    case FT_TOP_PROMPT_FILTER:
        if (c->ui.prompt_error[0])
            return 0;
        leave_prompt(c);
        return FT_TOP_DO_REDRAW;
    case FT_TOP_PROMPT_EXPORT:
        return export_view(c);
    case FT_TOP_PROMPT_PRESET:
        return save_preset(c);
    default:
        return 0;
    }
}

static unsigned prompt_cancel(struct ft_top_controller *c)
{
    struct ft_top_ui *ui = &c->ui;
    struct ft_error err = {0};

    switch (ui->prompt) {
    case FT_TOP_PROMPT_SEARCH:
        ft_top_set_search(c->model, ui->mode, "");
        break;
    case FT_TOP_PROMPT_FILTER:
        ft_top_set_filter(c->model, ui->mode, "", &err);
        recall_free(&c->recall);
        break;
    case FT_TOP_PROMPT_PRESET:
        ui->prompt = FT_TOP_PROMPT_FILTER;
        ui->edit = c->filter_edit;
        return FT_TOP_DO_REDRAW;
    default:
        break;
    }
    ui->prompt = FT_TOP_PROMPT_NONE;
    ui->prompt_error[0] = '\0';
    return FT_TOP_DO_REDRAW;
}

static void prompt_edited(struct ft_top_controller *c)
{
    switch (c->ui.prompt) {
    case FT_TOP_PROMPT_SEARCH:
        ft_top_set_search(c->model, c->ui.mode, c->ui.edit.text);
        break;
    case FT_TOP_PROMPT_FILTER:
        c->recall.at = c->recall.count;
        apply_filter_prompt(c);
        break;
    default:
        break;
    }
}

static bool function_key(enum ft_key key)
{
    return key >= FT_KEY_F1 && key <= FT_KEY_F12;
}

/* Everything but the F-keys and Ctrl-L stays in an open prompt. */
static bool prompt_key(struct ft_top_controller *c, const struct ft_input *in, unsigned *bits)
{
    struct ft_top_ui *ui = &c->ui;

    *bits = FT_TOP_DO_REDRAW;
    if ((in->key == FT_KEY_F3 && ui->prompt == FT_TOP_PROMPT_SEARCH) ||
        (in->key == FT_KEY_F4 && ui->prompt == FT_TOP_PROMPT_FILTER)) {
        *bits = prompt_enter(c);
        return true;
    }
    if (function_key(in->key) || in->key == FT_KEY_CTRL_L)
        return false;

    switch (in->key) {
    case FT_KEY_ENTER:
        *bits = prompt_enter(c);
        return true;
    case FT_KEY_UP:
    case FT_KEY_DOWN: {
        int step = in->key == FT_KEY_UP ? -1 : 1;
        if (ui->prompt == FT_TOP_PROMPT_SEARCH)
            ft_top_search_step(c->model, ui->mode, step);
        else if (ui->prompt == FT_TOP_PROMPT_FILTER)
            *bits = recall_step(c, step);
        return true;
    }
    case FT_KEY_CTRL_S:
        if (ui->prompt == FT_TOP_PROMPT_FILTER && ui->edit.len && !ui->prompt_error[0]) {
            c->filter_edit = ui->edit;
            ui->prompt = FT_TOP_PROMPT_PRESET;
            ft_lineedit_set(&ui->edit, "");
        }
        return true;
    default:
        break;
    }
    if (ft_lineedit_key(&ui->edit, in))
        prompt_edited(c);
    return true;
}

static unsigned set_mode(struct ft_top_controller *c, enum ft_top_mode mode)
{
    struct ft_top_ui *ui = &c->ui;

    if (mode >= FT_TOP_MODE_COUNT || mode == ui->mode)
        return 0;
    leave_prompt(c);
    ui->panel = FT_TOP_PANEL_NONE;
    if (mode == FT_TOP_LEADERS)
        ui->previous_mode = ui->mode;
    ui->mode = mode;
    ft_top_set_mode(c->model, mode);
    return FT_TOP_DO_REDRAW;
}

static enum ft_top_mode next_mode(enum ft_top_mode mode, int step)
{
    return (enum ft_top_mode)((mode + FT_TOP_MODE_COUNT + step) % FT_TOP_MODE_COUNT);
}

static unsigned ranking_changed(struct ft_top_controller *c)
{
    ft_top_set_leaders_request(c->model, c->ui.window, c->ui.key);
    ft_top_set_sort(c->model, FT_TOP_LEADERS, c->ui.by, true);
    c->await_next = true;
    return FT_TOP_DO_REDRAW;
}

static unsigned set_window(struct ft_top_controller *c, enum ft_leader_window window)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(windows); i++) {
        if (windows[i] == window && window != c->ui.window) {
            c->ui.window = window;
            return ranking_changed(c);
        }
    }
    return 0;
}

static unsigned next_window(struct ft_top_controller *c)
{
    size_t i = 0;

    while (i < FT_ARRAY_LEN(windows) && windows[i] != c->ui.window)
        i++;
    return set_window(c, windows[(i + 1) % FT_ARRAY_LEN(windows)]);
}

static unsigned set_rank_by(struct ft_top_controller *c, enum ft_top_sort by)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(measures); i++) {
        if (measures[i].top == by && by != c->ui.by) {
            c->ui.by = by;
            return ranking_changed(c);
        }
    }
    return 0;
}

static unsigned next_rank_by(struct ft_top_controller *c)
{
    size_t i = 0;

    while (i < FT_ARRAY_LEN(measures) && measures[i].top != c->ui.by)
        i++;
    return set_rank_by(c, measures[(i + 1) % FT_ARRAY_LEN(measures)].top);
}

static unsigned next_grouping(struct ft_top_controller *c)
{
    size_t i = 0;

    while (i < FT_ARRAY_LEN(groupings) && groupings[i] != c->ui.key)
        i++;
    c->ui.key = groupings[(i + 1) % FT_ARRAY_LEN(groupings)];
    return ranking_changed(c);
}

static const struct ft_top_sort_option *sort_option(enum ft_top_mode mode, enum ft_top_sort key,
                                                    size_t *index)
{
    size_t n;
    const struct ft_top_sort_option *sorts = ft_top_mode_sorts(mode, &n);

    for (size_t i = 0; i < n; i++) {
        if (sorts[i].key == key) {
            if (index)
                *index = i;
            return &sorts[i];
        }
    }
    return nullptr;
}

/* A key of the mode in its own direction; in Leaders the measure of the ranking. */
static unsigned choose_sort(struct ft_top_controller *c, enum ft_top_sort key)
{
    enum ft_top_mode mode = c->ui.mode;

    if (mode == FT_TOP_LEADERS)
        return set_rank_by(c, key);
    const struct ft_top_sort_option *opt = sort_option(mode, key, nullptr);
    if (!opt)
        return 0;
    ft_top_set_sort(c->model, mode, key, opt->descending);
    return FT_TOP_DO_REDRAW;
}

static unsigned step_sort(struct ft_top_controller *c, int step)
{
    enum ft_top_sort key;
    bool descending;
    size_t n;
    size_t i = 0;
    const struct ft_top_sort_option *sorts = ft_top_mode_sorts(c->ui.mode, &n);

    ft_top_sort_of(c->model, c->ui.mode, &key, &descending);
    sort_option(c->ui.mode, key, &i);
    return choose_sort(c, sorts[step < 0 ? (i + n - 1) % n : (i + 1) % n].key);
}

static unsigned invert_sort(struct ft_top_controller *c)
{
    enum ft_top_sort key;
    bool descending;

    if (c->ui.mode == FT_TOP_LEADERS)
        return 0;
    ft_top_sort_of(c->model, c->ui.mode, &key, &descending);
    ft_top_set_sort(c->model, c->ui.mode, key, !descending);
    return FT_TOP_DO_REDRAW;
}

static unsigned header_click(struct ft_top_controller *c, enum ft_top_sort key)
{
    enum ft_top_sort current;
    bool descending;

    ft_top_sort_of(c->model, c->ui.mode, &current, &descending);
    if (key == current)
        return invert_sort(c);
    return choose_sort(c, key);
}

static size_t panel_size(const struct ft_top_controller *c, enum ft_top_panel list)
{
    size_t n = 0;

    if (list == FT_TOP_PANEL_SORT)
        ft_top_mode_sorts(c->ui.mode, &n);
    else
        ft_top_mode_groups(c->ui.mode, &n);
    return n;
}

static size_t panel_current(const struct ft_top_controller *c, enum ft_top_panel list)
{
    size_t index = 0;
    size_t n;

    if (list == FT_TOP_PANEL_SORT) {
        enum ft_top_sort key;
        bool descending;
        ft_top_sort_of(c->model, c->ui.mode, &key, &descending);
        sort_option(c->ui.mode, key, &index);
        return index;
    }
    const enum ft_top_group *groups = ft_top_mode_groups(c->ui.mode, &n);
    enum ft_top_group group = ft_top_group_of(c->model, c->ui.mode);
    for (size_t i = 0; i < n; i++) {
        if (groups[i] == group)
            index = i;
    }
    return index;
}

static void panel_list(struct ft_top_controller *c, enum ft_top_panel list)
{
    c->ui.panel = list;
    c->ui.panel_cursor = panel_current(c, list);
}

static unsigned open_panel(struct ft_top_controller *c, enum ft_top_panel list)
{
    if (c->ui.mode == FT_TOP_LEADERS)
        return list == FT_TOP_PANEL_SORT ? next_rank_by(c) : next_grouping(c);
    leave_prompt(c);
    panel_list(c, list);
    return FT_TOP_DO_REDRAW;
}

static unsigned panel_apply(struct ft_top_controller *c, enum ft_top_panel list, size_t index)
{
    enum ft_top_mode mode = c->ui.mode;
    size_t n;

    if (mode == FT_TOP_LEADERS)
        return 0;
    if (list == FT_TOP_PANEL_SORT) {
        const struct ft_top_sort_option *sorts = ft_top_mode_sorts(mode, &n);
        enum ft_top_sort key;
        bool descending;
        if (index >= n)
            return 0;
        ft_top_sort_of(c->model, mode, &key, &descending);
        if (sorts[index].key != key)
            descending = sorts[index].descending;
        ft_top_set_sort(c->model, mode, sorts[index].key, descending);
    } else {
        const enum ft_top_group *groups = ft_top_mode_groups(mode, &n);
        if (index >= n)
            return 0;
        ft_top_set_group(c->model, mode, groups[index]);
    }
    c->ui.panel = FT_TOP_PANEL_NONE;
    return FT_TOP_DO_REDRAW;
}

static enum ft_top_panel other_list(enum ft_top_panel list)
{
    return list == FT_TOP_PANEL_SORT ? FT_TOP_PANEL_GROUP : FT_TOP_PANEL_SORT;
}

/* Moving past either end of a list goes on in the other one. */
static void panel_step(struct ft_top_controller *c, int step)
{
    struct ft_top_ui *ui = &c->ui;
    size_t n = panel_size(c, ui->panel);

    if (step > 0 && ui->panel_cursor + 1 >= n) {
        ui->panel = other_list(ui->panel);
        ui->panel_cursor = 0;
    } else if (step < 0 && ui->panel_cursor == 0) {
        ui->panel = other_list(ui->panel);
        size_t m = panel_size(c, ui->panel);
        ui->panel_cursor = m ? m - 1 : 0;
    } else {
        ui->panel_cursor = step > 0 ? ui->panel_cursor + 1 : ui->panel_cursor - 1;
    }
}

static bool panel_key(struct ft_top_controller *c, const struct ft_input *in, unsigned *bits)
{
    struct ft_top_ui *ui = &c->ui;
    size_t n = panel_size(c, ui->panel);

    *bits = FT_TOP_DO_REDRAW;
    switch (in->key) {
    case FT_KEY_UP:
        panel_step(c, -1);
        return true;
    case FT_KEY_DOWN:
        panel_step(c, 1);
        return true;
    case FT_KEY_HOME:
    case FT_KEY_PGUP:
        ui->panel_cursor = 0;
        return true;
    case FT_KEY_END:
    case FT_KEY_PGDN:
        ui->panel_cursor = n ? n - 1 : 0;
        return true;
    case FT_KEY_TAB:
        panel_list(c, other_list(ui->panel));
        return true;
    case FT_KEY_ENTER:
        *bits = panel_apply(c, ui->panel, ui->panel_cursor);
        return true;
    case FT_KEY_F6:
        panel_list(c, FT_TOP_PANEL_SORT);
        return true;
    case FT_KEY_F7:
        panel_list(c, FT_TOP_PANEL_GROUP);
        return true;
    default:
        break;
    }
    if (plain_char(in) && (in->rune == 'k' || in->rune == 'j')) {
        panel_step(c, in->rune == 'k' ? -1 : 1);
        return true;
    }
    if (plain_char(in) && in->rune == 'I') {
        *bits = invert_sort(c);
        return true;
    }
    return false;
}

static const char *shown_path(const struct ft_top_controller *c, const char *path, uint32_t name)
{
    return c->ui.full_paths ? path : path + name;
}

/* What c copies of a row: a path, an address or an executable; nullptr for nothing. */
static const char *row_path(const struct ft_top_row *r)
{
    switch (r->kind) {
    case FT_TOP_ROW_TRANSFER:
        return r->transfer->path_known ? r->transfer->path : nullptr;
    case FT_TOP_ROW_PROCESS:
        return r->process->exe;
    case FT_TOP_ROW_DESTINATION:
        return r->destination->text;
    case FT_TOP_ROW_FILE:
        return r->file->path_known ? r->file->path : nullptr;
    case FT_TOP_ROW_LEADER:
        return r->leader->row->remote.family ? r->leader->remote_text : r->leader->row->text;
    default:
        return nullptr;
    }
}

static void cell(FILE *out, bool *first, const char *text)
{
    if (!*first)
        fputc('\t', out);
    *first = false;
    put_text(out, text);
}

[[gnu::format(printf, 3, 4)]]
static void cellf(FILE *out, bool *first, const char *fmt, ...)
{
    char buf[128];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    cell(out, first, buf);
}

static void size_cell(FILE *out, bool *first, uint64_t bytes)
{
    char buf[32];
    ft_top_format_size(bytes, buf, sizeof(buf));
    cell(out, first, buf);
}

static void rate_cell(FILE *out, bool *first, uint64_t rate)
{
    char buf[32];
    ft_top_format_rate(rate, buf, sizeof(buf));
    cell(out, first, buf);
}

static void transfer_columns(const struct ft_top_controller *c, FILE *out,
                             const struct ft_top_transfer *t)
{
    char sent[32];
    char size[32] = "?";
    char progress[16] = "";
    char age[32];
    bool first = true;

    ft_top_format_size(t->bytes, sent, sizeof(sent));
    if (t->size)
        ft_top_format_size(t->size, size, sizeof(size));
    if (t->progress >= 0)
        ft_top_format_percent(t->progress, progress, sizeof(progress));
    ft_top_format_age(t->age_ns, age, sizeof(age));

    cellf(out, &first, "%" PRIu32, t->pid);
    cell(out, &first, t->process->user);
    cell(out, &first, t->process->title);
    if (c->ui.script_column && c->ui.mode == FT_TOP_TRANSFERS)
        cell(out, &first, t->script_name);
    cell(out, &first, shown_path(c, t->path, t->name_offset));
    if (t->destination && t->destination->host_state == FT_TOP_HOST_NAMED)
        cellf(out, &first, "%s:%u", t->destination->host, t->remote.port);
    else
        cell(out, &first, t->remote_text);
    if (t->done)
        cell(out, &first, "done");
    else
        rate_cell(out, &first, t->rate);
    cellf(out, &first, "%s/%s", sent, size);
    cell(out, &first, progress + strspn(progress, " "));
    cell(out, &first, ft_top_method_word(t->method));
    cell(out, &first, ft_top_confidence_word(t->confidence, t->incomplete));
    cell(out, &first, age);
}

static void leader_columns(const struct ft_top_controller *c, FILE *out,
                           const struct ft_top_leader *l)
{
    const struct ft_row_leader *row = l->row;
    bool first = true;

    cellf(out, &first, "%" PRIu32, row->rank);
    if (l->is_new)
        cell(out, &first, "NEW");
    else if (l->rank_change > 0)
        cellf(out, &first, "▲%" PRId32, l->rank_change);
    else if (l->rank_change < 0)
        cellf(out, &first, "▼%" PRId32, -l->rank_change);
    else
        cell(out, &first, "=");
    cell(out, &first,
         row->remote.family ? l->remote_text : shown_path(c, row->text, l->name_offset));
    size_cell(out, &first, row->bytes);
    cellf(out, &first, "%.0f%%", l->share * 100.0);
    cellf(out, &first, "%" PRIu64, row->transfers);
    cellf(out, &first, "%" PRIu64, row->destinations);
    cell(out, &first, row->senders[0].name);
}

/* The text of a row's columns, tab-separated; false for a row with none. */
static bool row_columns(const struct ft_top_controller *c, FILE *out, const struct ft_top_row *r)
{
    bool first = true;

    switch (r->kind) {
    case FT_TOP_ROW_TRANSFER:
        transfer_columns(c, out, r->transfer);
        return true;
    case FT_TOP_ROW_PROCESS: {
        const struct ft_top_process *p = r->process;
        cellf(out, &first, "%" PRIu32, p->pid);
        cell(out, &first, p->user);
        rate_cell(out, &first, p->rate);
        size_cell(out, &first, p->total);
        cellf(out, &first, "%" PRIu32, p->files);
        cellf(out, &first, "%" PRIu32, p->destinations);
        cell(out, &first, ft_top_method_word(p->method));
        cell(out, &first, p->command_line[0] ? p->command_line : p->title);
        return true;
    }
    case FT_TOP_ROW_DESTINATION: {
        const struct ft_top_destination *d = r->destination;
        cell(out, &first, d->label);
        cell(out, &first, d->is_public ? "public" : "private");
        cell(out, &first, d->host_state == FT_TOP_HOST_NAMED ? d->host : "");
        rate_cell(out, &first, d->rate);
        size_cell(out, &first, d->total);
        cellf(out, &first, "%" PRIu32, d->files);
        cellf(out, &first, "%" PRIu32, d->processes);
        cell(out, &first, d->top_process ? d->top_process->title : "");
        cell(out, &first, d->top ? shown_path(c, d->top->path, d->top->name_offset) : "");
        return true;
    }
    case FT_TOP_ROW_FILE: {
        const struct ft_top_file *f = r->file;
        cell(out, &first, shown_path(c, f->path, f->name_offset));
        size_cell(out, &first, f->size);
        rate_cell(out, &first, f->rate);
        cellf(out, &first, "%" PRIu32, f->active);
        cellf(out, &first, "%" PRIu32, f->destinations);
        cell(out, &first, f->senders);
        cell(out, &first, ft_top_method_word(f->method));
        cellf(out, &first, "%.0f%% public", f->public_share * 100.0);
        return true;
    }
    case FT_TOP_ROW_LEADER:
        leader_columns(c, out, r->leader);
        return true;
    case FT_TOP_ROW_SECTION:
        cell(out, &first, r->section->title);
        cellf(out, &first, "%" PRIu32, r->section->rows);
        rate_cell(out, &first, r->section->rate);
        return true;
    case FT_TOP_ROW_FOLD:
        cell(out, &first, r->fold->title);
        cellf(out, &first, "%zu", r->fold->count);
        rate_cell(out, &first, r->fold->rate);
        return true;
    default:
        return false;
    }
}

static unsigned send_copy(struct ft_top_controller *c, char *text, size_t count, const char *noun,
                          const char *nouns)
{
    if (count == 0) {
        free(text);
        return 0;
    }
    free(c->copy);
    c->copy = text;
    say(c, FT_TOP_MESSAGE_INFO, "Sent %zu %s to the clipboard", count, count == 1 ? noun : nouns);
    return FT_TOP_DO_REDRAW | FT_TOP_DO_COPY;
}

/* The tagged rows, or the selected one when none is tagged. */
static unsigned copy_rows(struct ft_top_controller *c, bool columns)
{
    enum ft_top_mode mode = c->ui.mode;
    size_t n = ft_top_row_count(c->model, mode);
    uint8_t wanted = ft_top_tag_count(c->model, mode) ? FT_TOP_ROW_TAGGED : FT_TOP_ROW_SELECTED;
    char *text = nullptr;
    size_t size = 0;
    size_t count = 0;
    FILE *out = open_memstream(&text, &size);

    if (!out) {
        say(c, FT_TOP_MESSAGE_ERROR, "Out of memory");
        return FT_TOP_DO_REDRAW;
    }
    for (size_t i = 0; i < n; i++) {
        const struct ft_top_row *r = ft_top_row_at(c->model, mode, i);
        if (!(r->flags & wanted))
            continue;
        if (columns) {
            if (!row_columns(c, out, r))
                continue;
        } else {
            const char *path = row_path(r);
            if (!path || !path[0])
                continue;
            put_text(out, path);
        }
        fputc('\n', out);
        count++;
    }
    fclose(out);
    if (text && size && text[size - 1] == '\n')
        text[size - 1] = '\0';
    if (columns)
        return send_copy(c, text, count, "row", "rows");
    if (mode == FT_TOP_DESTINATIONS)
        return send_copy(c, text, count, "address", "addresses");
    return send_copy(c, text, count, "path", "paths");
}

static void describe(const struct ft_top_controller *c, const struct ft_top_row *r, char *buf,
                     size_t size)
{
    static const char *const leader_kinds[] = {
        [FT_LEADER_FILE] = "file",
        [FT_LEADER_DIRECTORY] = "directory",
        [FT_LEADER_EXTENSION] = "extension",
        [FT_LEADER_DESTINATION] = "destination",
    };

    switch (r->kind) {
    case FT_TOP_ROW_TRANSFER:
        snprintf(buf, size, "transfer %s → %s", r->transfer->path, r->transfer->remote_text);
        break;
    case FT_TOP_ROW_PROCESS:
        snprintf(buf, size, "process %" PRIu32 " %s", r->process->pid, r->process->title);
        break;
    case FT_TOP_ROW_DESTINATION:
        snprintf(buf, size, "destination %s", r->destination->label);
        break;
    case FT_TOP_ROW_FILE:
        snprintf(buf, size, "file %s", r->file->path);
        break;
    case FT_TOP_ROW_LEADER: {
        struct subject s = subject_of(c, r);
        snprintf(buf, size, "%s %s", leader_kinds[s.key < FT_LEADER_KEY_COUNT ? s.key : 0],
                 r->leader->row->remote.family ? r->leader->remote_text : r->leader->row->text);
        break;
    }
    case FT_TOP_ROW_SECTION:
        snprintf(buf, size, "group %s", r->section->title);
        break;
    case FT_TOP_ROW_FOLD:
        snprintf(buf, size, "%s", r->fold->title);
        break;
    default:
        buf[0] = '\0';
        break;
    }
}

static bool subject_filter(const struct subject *s, char *buf, size_t size)
{
    switch (s->kind) {
    case SUBJECT_PROCESS:
        snprintf(buf, size, "pid:%" PRIu32, s->process->pid);
        return true;
    case SUBJECT_DESTINATION:
        return filter_term(buf, size, "dest", s->destination->text);
    case SUBJECT_FILE:
        return s->path_known && filter_term(buf, size, "file", s->path);
    default:
        return false;
    }
}

static unsigned follow(struct ft_top_controller *c)
{
    struct subject s = subject_of(c, selected_row(c));
    char term[FT_PATH_MAX + 16];

    if (!subject_filter(&s, term, sizeof(term)) || !set_filter_text(c, c->ui.mode, term))
        return FT_TOP_DO_REDRAW;
    c->ui.inspect = false;
    say(c, FT_TOP_MESSAGE_INFO, "Following %s · F4 then Esc shows everything again", term);
    return FT_TOP_DO_REDRAW;
}

static unsigned copy_subject(struct ft_top_controller *c)
{
    struct subject s = subject_of(c, selected_row(c));
    const char *text = nullptr;
    const char *noun = "path";

    switch (s.kind) {
    case SUBJECT_PROCESS:
        text = s.process->script[0] ? s.process->script : s.process->exe;
        break;
    case SUBJECT_DESTINATION:
        text = s.destination->text;
        noun = "address";
        break;
    case SUBJECT_FILE:
        text = s.path_known ? s.path : nullptr;
        break;
    default:
        break;
    }
    if (!text || !text[0])
        return 0;
    char *copy = strdup(text);
    if (!copy) {
        say(c, FT_TOP_MESSAGE_ERROR, "Out of memory");
        return FT_TOP_DO_REDRAW;
    }
    return send_copy(c, copy, 1, noun, noun);
}

static unsigned open_events(struct ft_top_controller *c)
{
    struct subject s = subject_of(c, selected_row(c));
    struct ft_top_text *t = &c->ui.overlay_text;

    c->events_pid = 0;
    c->events_remote = (struct ft_endpoint){0};
    c->events_path[0] = '\0';
    switch (s.kind) {
    case SUBJECT_PROCESS:
        c->events_pid = s.process->pid;
        snprintf(t->title, sizeof(t->title), "Events · process %" PRIu32 " %s", s.process->pid,
                 s.process->title);
        break;
    case SUBJECT_DESTINATION:
        c->events_remote = s.destination->address;
        snprintf(t->title, sizeof(t->title), "Events · destination %s", s.destination->text);
        break;
    case SUBJECT_FILE:
        if (!s.path_known) {
            say(c, FT_TOP_MESSAGE_ERROR, "The path of this file is not known");
            return FT_TOP_DO_REDRAW;
        }
        snprintf(c->events_path, sizeof(c->events_path),
                 s.key == FT_LEADER_DIRECTORY   ? "%s*"
                 : s.key == FT_LEADER_EXTENSION ? "*%s"
                                                : "%s",
                 s.path);
        snprintf(t->title, sizeof(t->title), "Events · file %s", s.path);
        break;
    default:
        return 0;
    }
    c->ui.overlay = FT_TOP_OVERLAY_EVENTS;
    t->scroll = 0;
    overlay_say(c, "Asking the agent for the latest events…");
    c->events_ask = true;
    c->force = true;
    return FT_TOP_DO_REDRAW;
}

static unsigned open_json(struct ft_top_controller *c)
{
    size_t index = ft_top_selected(c->model, c->ui.mode);
    struct ft_top_text *t = &c->ui.overlay_text;
    char *text = nullptr;
    size_t size = 0;
    char what[120];

    if (index == SIZE_MAX)
        return 0;
    FILE *out = open_memstream(&text, &size);
    if (!out) {
        say(c, FT_TOP_MESSAGE_ERROR, "Out of memory");
        return FT_TOP_DO_REDRAW;
    }
    ft_top_row_json(c->model, c->ui.mode, index, out);
    fclose(out);
    describe(c, ft_top_row_at(c->model, c->ui.mode, index), what, sizeof(what));
    bool taken = text && lines_take(&c->overlay, text);
    overlay_show(c);
    if (!taken) {
        say(c, FT_TOP_MESSAGE_ERROR, "Out of memory");
        return FT_TOP_DO_REDRAW;
    }
    snprintf(t->title, sizeof(t->title), "JSON · %s", what);
    t->scroll = 0;
    c->ui.overlay = FT_TOP_OVERLAY_JSON;
    return FT_TOP_DO_REDRAW;
}

static unsigned open_in_leaders(struct ft_top_controller *c)
{
    struct subject s = subject_of(c, selected_row(c));
    char search[FT_PATH_MAX] = "";

    if (s.kind == SUBJECT_NONE || c->ui.mode == FT_TOP_LEADERS)
        return 0;
    if (s.kind == SUBJECT_PROCESS)
        ft_strlcpy(search, s.process->name, sizeof(search));
    else if (s.kind == SUBJECT_FILE && s.path_known)
        ft_strlcpy(search, s.path, sizeof(search));
    c->ui.inspect = false;
    set_mode(c, FT_TOP_LEADERS);
    if (search[0])
        ft_top_set_search(c->model, FT_TOP_LEADERS, search);
    return FT_TOP_DO_REDRAW;
}

static unsigned destinations_of(struct ft_top_controller *c)
{
    struct subject s = subject_of(c, selected_row(c));
    char term[FT_PATH_MAX + 16];

    if (s.kind != SUBJECT_FILE || !subject_filter(&s, term, sizeof(term)) ||
        !set_filter_text(c, FT_TOP_DESTINATIONS, term))
        return s.kind == SUBJECT_FILE ? FT_TOP_DO_REDRAW : 0;
    c->ui.inspect = false;
    set_mode(c, FT_TOP_DESTINATIONS);
    say(c, FT_TOP_MESSAGE_INFO, "Destinations of %s · F4 then Esc shows them all", s.path);
    return FT_TOP_DO_REDRAW;
}

/* The panel's own keys and the movement keys; the help waits until it closes. */
static bool inspect_key(struct ft_top_controller *c, const struct ft_input *in, unsigned *bits)
{
    *bits = 0;
    if (in->key == FT_KEY_ENTER || in->key == FT_KEY_F8) {
        c->ui.inspect = false;
        *bits = FT_TOP_DO_REDRAW;
        return true;
    }
    if (in->key == FT_KEY_F1)
        return true;
    if (!plain_char(in))
        return movement(c, in, bits);
    switch (in->rune) {
    case 'f':
        *bits = follow(c);
        return true;
    case 'c':
        *bits = copy_subject(c);
        return true;
    case 'e':
        *bits = open_events(c);
        return true;
    case 'o':
        *bits = open_in_leaders(c);
        return true;
    case 'd':
        *bits = destinations_of(c);
        return true;
    case 'j':
        *bits = open_json(c);
        return true;
    case '?':
    case 'h':
        return true;
    default:
        return movement(c, in, bits);
    }
}

static unsigned inspect(struct ft_top_controller *c, bool enter)
{
    const struct ft_top_row *r = selected_row(c);

    if (!r)
        return 0;
    if (enter && (r->kind == FT_TOP_ROW_SECTION || r->kind == FT_TOP_ROW_FOLD) &&
        r->node != FT_TOP_NODE_LEAF) {
        ft_top_toggle_expanded(c->model, c->ui.mode, ft_top_selected(c->model, c->ui.mode));
        return FT_TOP_DO_REDRAW;
    }
    c->ui.inspect = true;
    return FT_TOP_DO_REDRAW;
}

static void event_line(FILE *out, const struct ft_row_event *e)
{
    const char *name = ft_record_type_name((enum ft_record_type)e->type);
    char type[32];
    char clock[16];
    char buf[96];
    size_t i = 0;

    for (; name[i] && i + 1 < sizeof(type); i++)
        type[i] = (char)toupper((unsigned char)name[i]);
    type[i] = '\0';
    ft_format_clock_local(e->time_ns, clock, sizeof(clock));
    /* As wide as the longest kind, SOCKET_ESTABLISHED. */
    fprintf(out, "%s.%03u %-18s", clock, (unsigned)(e->time_ns % FT_NS_PER_SEC / FT_NS_PER_MS),
            type);

    if (e->pid)
        fprintf(out, " pid=%" PRIu32, e->pid);
    if (e->comm[0]) {
        fputs(" process=", out);
        put_text(out, e->comm);
    }
    if (e->type >= FT_REC_PROCESS_EXEC && e->type <= FT_REC_PROCESS_EXIT && e->text[0]) {
        fputs(" executable=", out);
        put_text(out, e->text);
    }
    if (e->type == FT_REC_PROCESS_EXIT) {
        if (WIFSIGNALED(e->exit_status))
            fprintf(out, " signal=%d", WTERMSIG(e->exit_status));
        else
            fprintf(out, " exit_status=%d", WEXITSTATUS(e->exit_status));
    }
    if (e->type == FT_REC_NETWORK_SEND || e->type == FT_REC_NETWORK_RECEIVE ||
        e->type == FT_REC_FILE_TRANSFER)
        fprintf(out, " bytes=%" PRIu64, e->bytes);
    if (e->type == FT_REC_FILE_SEEN || e->type == FT_REC_FILE_TRANSFER) {
        if (e->text[0]) {
            fputs(" file=", out);
            put_text(out, e->text);
        } else {
            fprintf(out, " inode=%" PRIu64, e->ino);
        }
    }
    if (e->sock_id) {
        if (e->remote.family == 0 && e->remote.port == 0)
            ft_strlcpy(buf, "*", sizeof(buf));
        else
            ft_endpoint_format(&e->remote, buf, sizeof(buf));
        fprintf(out, " remote=%s", buf);
    }
    if (e->type == FT_REC_FILE_TRANSFER)
        fprintf(out, " method=%s confidence=%s", ft_method_name((enum ft_method)e->method),
                (e->flags & FT_EVENT_HAS_CONFIDENCE)
                    ? ft_confidence_name((enum ft_confidence)e->confidence)
                    : "pending");
    if (e->type == FT_REC_EVENT_LOSS)
        fprintf(out, " events=%" PRIu64 " cause=%s", e->bytes,
                e->loss_kind == FT_EVENT_LOSS_READER
                    ? "this reader fell behind"
                    : ft_loss_kind_name((enum ft_loss_kind)e->loss_kind));
    fputc('\n', out);
}

static void show_events(struct ft_top_controller *c, const struct ft_top_frame *f)
{
    struct ft_row_event *row = malloc(sizeof(*row));
    char *text = nullptr;
    size_t size = 0;
    FILE *out = row ? open_memstream(&text, &size) : nullptr;

    if (!out) {
        free(row);
        overlay_say(c, "Out of memory");
        return;
    }
    for (size_t i = 0; i < f->events.count; i++) {
        ft_rows_get(&f->events, i, row, sizeof(*row));
        row->comm[sizeof(row->comm) - 1] = '\0';
        row->text[sizeof(row->text) - 1] = '\0';
        event_line(out, row);
    }
    if (f->events.count == 0)
        fputs("The agent's event log holds no events of this.\n", out);
    fclose(out);
    free(row);
    if (!text || !lines_take(&c->overlay, text)) {
        overlay_say(c, "Out of memory");
        return;
    }
    overlay_show(c);
    /* The newest events come last, so the overlay opens at its end. */
    c->ui.overlay_text.scroll = SIZE_MAX;
    keep_overlay(c);
}

static unsigned overlay_key(struct ft_top_controller *c, const struct ft_input *in)
{
    long page = (long)overlay_page(c);

    switch (in->key) {
    case FT_KEY_UP:
        scroll_overlay(c, -1);
        return FT_TOP_DO_REDRAW;
    case FT_KEY_DOWN:
        scroll_overlay(c, 1);
        return FT_TOP_DO_REDRAW;
    case FT_KEY_PGUP:
        scroll_overlay(c, -page);
        return FT_TOP_DO_REDRAW;
    case FT_KEY_PGDN:
        scroll_overlay(c, page);
        return FT_TOP_DO_REDRAW;
    case FT_KEY_HOME:
        c->ui.overlay_text.scroll = 0;
        return FT_TOP_DO_REDRAW;
    case FT_KEY_END:
        scroll_overlay(c, LONG_MAX);
        return FT_TOP_DO_REDRAW;
    case FT_KEY_F10:
        return FT_TOP_DO_QUIT;
    case FT_KEY_CTRL_L:
        return FT_TOP_DO_REDRAW | FT_TOP_DO_REPAINT;
    default:
        break;
    }
    if (plain_char(in) && (in->rune == 'k' || in->rune == 'j')) {
        scroll_overlay(c, in->rune == 'k' ? -1 : 1);
        return FT_TOP_DO_REDRAW;
    }
    if (plain_char(in) && in->rune == 'q')
        return FT_TOP_DO_QUIT;
    return 0;
}

/* Esc: the innermost thing open closes, or else the screen steps back. */
static unsigned step_back(struct ft_top_controller *c)
{
    struct ft_top_ui *ui = &c->ui;

    if (ui->overlay) {
        close_overlay(c);
        return FT_TOP_DO_REDRAW;
    }
    if (ui->inspect) {
        ui->inspect = false;
        return FT_TOP_DO_REDRAW;
    }
    if (ui->help) {
        ui->help = false;
        return FT_TOP_DO_REDRAW;
    }
    if (ui->prompt)
        return prompt_cancel(c);
    if (ui->panel) {
        ui->panel = FT_TOP_PANEL_NONE;
        return FT_TOP_DO_REDRAW;
    }
    if (ft_top_search_of(c->model, ui->mode)[0]) {
        ft_top_set_search(c->model, ui->mode, "");
        return FT_TOP_DO_REDRAW;
    }
    if (ui->mode == FT_TOP_LEADERS)
        return set_mode(c, ui->previous_mode);
    return 0;
}

static void sample_live(struct ft_top_controller *c, const struct ft_top_frame *f);
static void sample_ranking(struct ft_top_controller *c, const struct ft_top_frame *f);
static bool answers_ranking(const struct ft_top_controller *c, const struct ft_top_frame *f);

static unsigned toggle_pause(struct ft_top_controller *c)
{
    struct ft_top_ui *ui = &c->ui;

    ui->paused = !ui->paused;
    if (!ui->paused && c->held_live) {
        uint64_t shown = c->shown_mono_ns;
        c->held_live = false;
        sample_live(c, &c->held);
        ui->skipped_ns = c->held.mono_ns > shown ? c->held.mono_ns - shown : 0;
        c->skipped_until_ns = ui->skipped_ns ? c->now_ns + SKIPPED_NS : 0;
    }
    return FT_TOP_DO_REDRAW;
}

static unsigned toggle_freeze(struct ft_top_controller *c)
{
    c->ui.frozen = !c->ui.frozen;
    if (!c->ui.frozen && c->held_leaders) {
        c->held_leaders = false;
        if (answers_ranking(c, &c->held))
            sample_ranking(c, &c->held);
    }
    return FT_TOP_DO_REDRAW;
}

static unsigned next_delay(struct ft_top_controller *c)
{
    uint64_t next = delays[0];

    for (size_t i = 0; i < FT_ARRAY_LEN(delays); i++) {
        if (delays[i] > c->ui.delay_ns) {
            next = delays[i];
            break;
        }
    }
    c->ui.delay_ns = next;
    say(c, FT_TOP_MESSAGE_INFO, "Refreshing every %.1f s", (double)next / (double)FT_NS_PER_SEC);
    return FT_TOP_DO_REDRAW;
}

static const char *row_user(const struct ft_top_row *r)
{
    switch (r ? r->kind : FT_TOP_ROW_SECTION) {
    case FT_TOP_ROW_TRANSFER:
        return r->transfer->process->user;
    case FT_TOP_ROW_PROCESS:
        return r->process->user;
    case FT_TOP_ROW_DESTINATION:
        return r->destination->top_process ? r->destination->top_process->user : nullptr;
    case FT_TOP_ROW_FILE:
        return r->file->top ? r->file->top->process->user : nullptr;
    default:
        return nullptr;
    }
}

static unsigned toggle_user(struct ft_top_controller *c)
{
    const char *user = row_user(selected_row(c));
    char term[300];
    char text[1024];

    if (c->ui.mode == FT_TOP_LEADERS || !user || !user[0] ||
        !filter_term(term, sizeof(term), "user", user))
        return 0;
    if (!toggle_term(ft_top_filter_of(c->model, c->ui.mode), term, text, sizeof(text))) {
        say(c, FT_TOP_MESSAGE_ERROR, "The filter is too long to add %s", term);
        return FT_TOP_DO_REDRAW;
    }
    set_filter_text(c, c->ui.mode, text);
    return FT_TOP_DO_REDRAW;
}

static unsigned tree(struct ft_top_controller *c)
{
    if (c->ui.mode == FT_TOP_PROCESSES) {
        ft_top_set_tree(c->model, !ft_top_tree_of(c->model));
        return FT_TOP_DO_REDRAW;
    }
    ft_top_set_tree(c->model, true);
    return set_mode(c, FT_TOP_PROCESSES) | FT_TOP_DO_REDRAW;
}

static unsigned expand(struct ft_top_controller *c, bool on)
{
    size_t i = ft_top_selected(c->model, c->ui.mode);

    if (i == SIZE_MAX)
        return 0;
    ft_top_set_expanded(c->model, c->ui.mode, i, on);
    return FT_TOP_DO_REDRAW;
}

static bool searching(const struct ft_top_controller *c)
{
    return ft_top_search_of(c->model, c->ui.mode)[0] != '\0';
}

static unsigned open_help(struct ft_top_controller *c)
{
    if (c->ui.inspect || c->ui.overlay)
        return 0;
    c->ui.help = true;
    return FT_TOP_DO_REDRAW;
}

static unsigned char_key(struct ft_top_controller *c, uint32_t rune)
{
    struct ft_top_ui *ui = &c->ui;
    bool leaders = ui->mode == FT_TOP_LEADERS;

    switch (rune) {
    case '1':
    case '2':
    case '3':
    case '4':
        return set_mode(c, (enum ft_top_mode)(FT_TOP_TRANSFERS + (rune - '1')));
    case 'L':
    case 'l':
        return set_mode(c, FT_TOP_LEADERS);
    case '?':
    case 'h':
        return open_help(c);
    case '/':
        return open_prompt(c, FT_TOP_PROMPT_SEARCH);
    case '\\':
        return open_prompt(c, FT_TOP_PROMPT_FILTER);
    case 'n':
        if (searching(c)) {
            ft_top_search_step(c->model, ui->mode, 1);
            return FT_TOP_DO_REDRAW;
        }
        ft_top_set_resolve(c->model, !ft_top_resolve_of(c->model));
        return FT_TOP_DO_REDRAW;
    case 'N':
        if (!searching(c))
            return 0;
        ft_top_search_step(c->model, ui->mode, -1);
        return FT_TOP_DO_REDRAW;
    case 't':
        return tree(c);
    case '>':
    case '.':
        return step_sort(c, 1);
    case '<':
    case ',':
        return step_sort(c, -1);
    case 'I':
        return invert_sort(c);
    case 'P':
        return choose_sort(c, FT_TOP_SORT_RATE);
    case 'B':
        return choose_sort(c, FT_TOP_SORT_BYTES);
    case 'T':
        return choose_sort(c, FT_TOP_SORT_AGE);
    case 'g':
        return open_panel(c, FT_TOP_PANEL_GROUP);
    case 'z':
        return leaders ? toggle_freeze(c) : toggle_pause(c);
    case 'q':
        return FT_TOP_DO_QUIT;
    case 'U':
        ft_top_tags_clear(c->model, ui->mode);
        return FT_TOP_DO_REDRAW;
    case '+':
    case '=':
        return expand(c, true);
    case '-':
        return expand(c, false);
    case '*':
        ft_top_expand_all(c->model, ui->mode);
        return FT_TOP_DO_REDRAW;
    case 'w':
        return leaders ? next_window(c) : 0;
    case 'r':
        return leaders ? next_rank_by(c) : 0;
    case 'e':
        return open_prompt(c, FT_TOP_PROMPT_EXPORT);
    case 'c':
        return copy_rows(c, false);
    case 'C':
        return copy_rows(c, true);
    case 'm':
        ui->color_by_method = !ui->color_by_method;
        return FT_TOP_DO_REDRAW;
    case 'u':
        return toggle_user(c);
    case 'p':
        ui->full_paths = !ui->full_paths;
        return FT_TOP_DO_REDRAW;
    case 's':
        if (ui->mode != FT_TOP_TRANSFERS)
            return 0;
        ui->script_column = !ui->script_column;
        return FT_TOP_DO_REDRAW;
    case 'd':
        return next_delay(c);
    default:
        return 0;
    }
}

static unsigned screen_key(struct ft_top_controller *c, const struct ft_input *in)
{
    struct ft_top_ui *ui = &c->ui;
    bool leaders = ui->mode == FT_TOP_LEADERS;
    unsigned bits = 0;

    if (movement(c, in, &bits))
        return bits;
    switch (in->key) {
    case FT_KEY_TAB:
        return set_mode(c, next_mode(ui->mode, 1));
    case FT_KEY_BACKTAB:
        return set_mode(c, next_mode(ui->mode, -1));
    case FT_KEY_F1:
        return open_help(c);
    case FT_KEY_F2:
        return leaders ? next_window(c) : set_mode(c, next_mode(ui->mode, 1));
    case FT_KEY_F3:
        return open_prompt(c, FT_TOP_PROMPT_SEARCH);
    case FT_KEY_F4:
        return open_prompt(c, FT_TOP_PROMPT_FILTER);
    case FT_KEY_F5:
        return tree(c);
    case FT_KEY_F6:
        return open_panel(c, FT_TOP_PANEL_SORT);
    case FT_KEY_F7:
        return open_panel(c, FT_TOP_PANEL_GROUP);
    case FT_KEY_F8:
        return inspect(c, false);
    case FT_KEY_ENTER:
        return inspect(c, true);
    case FT_KEY_F9:
        return leaders ? toggle_freeze(c) : toggle_pause(c);
    case FT_KEY_F10:
        return FT_TOP_DO_QUIT;
    case FT_KEY_SPACE:
        ft_top_tag_toggle(c->model, ui->mode);
        return move(c, 1);
    case FT_KEY_CTRL_L:
        return FT_TOP_DO_REDRAW | FT_TOP_DO_REPAINT;
    default:
        break;
    }
    return plain_char(in) ? char_key(c, in->rune) : 0;
}

static unsigned key(struct ft_top_controller *c, const struct ft_input *in)
{
    struct ft_top_ui *ui = &c->ui;
    unsigned bits = 0;

    if (in->key == FT_KEY_CTRL_C)
        return FT_TOP_DO_QUIT;
    /* The help covers everything and any key takes it away. */
    if (ui->help) {
        ui->help = false;
        return FT_TOP_DO_REDRAW;
    }
    if (in->key == FT_KEY_ESC)
        return step_back(c);
    if (ui->overlay)
        return overlay_key(c, in);
    if (ui->prompt && prompt_key(c, in, &bits))
        return bits;
    if (ui->inspect && inspect_key(c, in, &bits))
        return bits;
    if (ui->panel && panel_key(c, in, &bits))
        return bits;
    return screen_key(c, in);
}

static unsigned click_row(struct ft_top_controller *c, size_t index)
{
    if (index == ft_top_selected(c->model, c->ui.mode)) {
        c->ui.inspect = true;
        return FT_TOP_DO_REDRAW;
    }
    ft_top_select_at(c->model, c->ui.mode, index);
    return FT_TOP_DO_REDRAW;
}

static unsigned close_innermost(struct ft_top_controller *c)
{
    if (c->ui.overlay) {
        close_overlay(c);
    } else if (c->ui.inspect) {
        c->ui.inspect = false;
    } else if (c->ui.panel) {
        c->ui.panel = FT_TOP_PANEL_NONE;
    } else {
        return 0;
    }
    return FT_TOP_DO_REDRAW;
}

static unsigned click(struct ft_top_controller *c, const struct ft_top_hit *hit)
{
    enum ft_top_mode mode = c->ui.mode;

    if (c->ui.overlay && hit->target != FT_TOP_TARGET_CLOSE && hit->target != FT_TOP_TARGET_KEY)
        return 0;
    switch (hit->target) {
    case FT_TOP_TARGET_ROW:
        return click_row(c, hit->arg);
    case FT_TOP_TARGET_TOGGLE:
        ft_top_toggle_expanded(c->model, mode, hit->arg);
        return FT_TOP_DO_REDRAW;
    case FT_TOP_TARGET_HEADER:
        return header_click(c, (enum ft_top_sort)hit->arg);
    case FT_TOP_TARGET_TAB:
        return set_mode(c, (enum ft_top_mode)hit->arg);
    case FT_TOP_TARGET_KEY: {
        struct ft_input k = {.kind = FT_INPUT_KEY, .key = (enum ft_key)hit->arg, .rune = hit->rune};
        return ft_top_control(c, &k);
    }
    case FT_TOP_TARGET_WINDOW:
        return mode == FT_TOP_LEADERS ? set_window(c, (enum ft_leader_window)hit->arg) : 0;
    case FT_TOP_TARGET_RANK_BY:
        return mode == FT_TOP_LEADERS ? set_rank_by(c, (enum ft_top_sort)hit->arg) : 0;
    case FT_TOP_TARGET_SORT:
        return panel_apply(c, FT_TOP_PANEL_SORT, hit->arg);
    case FT_TOP_TARGET_GROUP:
        return panel_apply(c, FT_TOP_PANEL_GROUP, hit->arg);
    case FT_TOP_TARGET_CLOSE:
        return close_innermost(c);
    default:
        return 0;
    }
}

static unsigned mouse(struct ft_top_controller *c, const struct ft_input *in)
{
    struct ft_top_ui *ui = &c->ui;

    if (in->mouse == FT_MOUSE_RELEASE)
        return 0;
    if (ui->help) {
        if (in->mouse != FT_MOUSE_LEFT && in->mouse != FT_MOUSE_MIDDLE &&
            in->mouse != FT_MOUSE_RIGHT)
            return 0;
        ui->help = false;
        return FT_TOP_DO_REDRAW;
    }
    if (in->mouse == FT_MOUSE_WHEEL_UP || in->mouse == FT_MOUSE_WHEEL_DOWN) {
        long delta = in->mouse == FT_MOUSE_WHEEL_UP ? -WHEEL_ROWS : WHEEL_ROWS;
        if (!ui->overlay)
            return move(c, delta);
        scroll_overlay(c, delta);
        return FT_TOP_DO_REDRAW;
    }
    if (in->mouse != FT_MOUSE_LEFT)
        return 0;
    const struct ft_top_hit *hit = ft_top_hits_at(&c->hits, in->x, in->y);
    return hit ? click(c, hit) : 0;
}

void ft_top_control_request(const struct ft_top_controller *c, struct ft_top_request *req)
{
    const struct ft_top_ui *ui = &c->ui;

    ft_top_request_init(req);
    req->delay_ns = ui->delay_ns;
    req->live = true;
    req->totals = ui->mode == FT_TOP_DESTINATIONS;
    if (ui->mode == FT_TOP_LEADERS) {
        req->leaders = true;
        req->window = ui->window;
        req->key = ui->key;
        req->by = wire_measure(ui->by);
        req->limit = c->limit;
        ft_top_filter_leader_path(ft_top_filter_of(c->model, FT_TOP_LEADERS), req->leader_path,
                                  sizeof(req->leader_path));
    } else {
        /* One scope narrows every mode, so only the mode on screen may set it. */
        ft_top_filter_pushdown(ft_top_filter_get(c->model, ui->mode), &req->scope);
    }
    if (ui->overlay == FT_TOP_OVERLAY_EVENTS) {
        req->events = true;
        req->events_pid = c->events_pid;
        req->events_remote = c->events_remote;
        ft_strlcpy(req->events_path, c->events_path, sizeof(req->events_path));
    }
}

/*
 * Whether the source must hear of the request. It asks for the events once per request, so a
 * request that only drops them changes nothing; the events fields come last in the request.
 */
static bool request_differs(const struct ft_top_request *want, const struct ft_top_request *sent)
{
    size_t n = want->events ? sizeof(*want) : offsetof(struct ft_top_request, events);
    return memcmp(want, sent, n) != 0;
}

void ft_top_control_sent(struct ft_top_controller *c, const struct ft_top_request *req,
                         uint64_t serial)
{
    const struct ft_top_request *old = &c->sent;
    bool ranking = req->window != old->window || req->key != old->key || req->by != old->by ||
                   req->limit != old->limit || strcmp(req->leader_path, old->leader_path) != 0;

    if (req->leaders && !old->leaders)
        c->leaders_from = serial;
    if (req->leaders && (ranking || !old->leaders))
        c->leaders_serial = serial;
    if (req->leaders && c->await_next) {
        c->await_serial = serial;
        c->await_ns = c->now_ns;
        c->ui.waiting = false;
    }
    c->await_next = false;
    if (req->events && c->events_ask)
        c->events_serial = serial;
    c->events_ask = false;
    c->force = false;
    c->sent = *req;
    c->sent_serial = serial;
}

/* A scope typed into the filter prompt waits for the next frame, so typing does not flood. */
static unsigned finish(struct ft_top_controller *c, unsigned bits, bool frame)
{
    struct ft_top_request req;

    ft_top_control_request(c, &req);
    if (c->force ||
        (request_differs(&req, &c->sent) && (frame || c->ui.prompt != FT_TOP_PROMPT_FILTER)))
        bits |= FT_TOP_DO_REQUEST;
    keep_in_view(c);
    keep_overlay(c);
    return bits;
}

unsigned ft_top_control(struct ft_top_controller *c, const struct ft_input *in)
{
    unsigned bits = 0;

    switch (in->kind) {
    case FT_INPUT_KEY:
        bits = key(c, in);
        break;
    case FT_INPUT_MOUSE:
        bits = mouse(c, in);
        break;
    case FT_INPUT_RESIZE:
        bits = FT_TOP_DO_REDRAW;
        break;
    default:
        break;
    }
    return finish(c, bits, false);
}

/* The finished row under the cursor goes when its time is up. */
static void note_linger(struct ft_top_controller *c, uint64_t mono_ns)
{
    const struct ft_top_row *r = selected_row(c);

    if (!r || !(r->flags & FT_TOP_ROW_DONE))
        c->linger_ns = 0;
    else if (!c->linger_ns)
        c->linger_ns = mono_ns + FT_TOP_DONE_NS;
}

static void sample_live(struct ft_top_controller *c, const struct ft_top_frame *f)
{
    struct ft_top_sample s = {
        .mono_ns = f->mono_ns,
        .stats = &f->stats,
        .transfers = &f->transfers,
        .processes = &f->processes,
        .destinations = f->has_totals ? &f->destination_totals : nullptr,
    };

    if (!ft_top_model_sample(c->model, &s))
        say(c, FT_TOP_MESSAGE_ERROR, "Out of memory: the screen shows older data");
    c->shown_mono_ns = f->mono_ns;
    note_linger(c, f->mono_ns);
}

static bool answers_ranking(const struct ft_top_controller *c, const struct ft_top_frame *f)
{
    return c->sent.leaders && f->has_leaders && f->request_serial >= c->leaders_serial;
}

static void sample_ranking(struct ft_top_controller *c, const struct ft_top_frame *f)
{
    struct ft_top_leaders_sample s = {
        .window = c->sent.window,
        .key = c->sent.key,
        .by = top_measure(c->sent.by),
        .summary = &f->leader_summary,
        .ranking = &f->leaders,
        .directories = &f->leader_directories,
        .destinations = &f->leader_destinations,
    };

    if (!ft_top_model_leaders(c->model, &s))
        say(c, FT_TOP_MESSAGE_ERROR, "Out of memory: the ranking shows older data");
}

static void hold(struct ft_top_controller *c, struct ft_top_frame *f, bool ranking)
{
    struct ft_top_frame *h = &c->held;

    /* Only some frames carry the totals; a newer frame takes over those of the one it replaces. */
    if (c->held_live && h->has_totals && !f->has_totals) {
        struct ft_rows totals = f->destination_totals;
        f->destination_totals = h->destination_totals;
        h->destination_totals = totals;
        f->has_totals = true;
    }
    struct ft_top_frame t = *h;
    *h = *f;
    *f = t;
    c->held_live = c->ui.paused;
    c->held_leaders = c->ui.frozen && ranking;
}

unsigned ft_top_control_frame(struct ft_top_controller *c, struct ft_top_frame *frame)
{
    struct ft_top_ui *ui = &c->ui;

    ui->agent_code = frame->code;
    ft_strlcpy(ui->agent_error, frame->code == FT_EXIT_OK ? "" : frame->error,
               sizeof(ui->agent_error));
    ui->lag_ns = frame->code == FT_EXIT_OK && frame->took_ns > ui->delay_ns
                     ? frame->took_ns - ui->delay_ns
                     : 0;
    if (c->await_serial && frame->request_serial >= c->await_serial) {
        c->await_serial = 0;
        ui->waiting = false;
    }
    if (frame->code != FT_EXIT_OK)
        return finish(c, FT_TOP_DO_REDRAW, true);
    if (frame->has_events && c->events_serial && frame->request_serial >= c->events_serial &&
        ui->overlay == FT_TOP_OVERLAY_EVENTS) {
        c->events_serial = 0;
        show_events(c, frame);
    }
    if (c->sent.leaders && frame->request_serial >= c->leaders_from)
        ui->leaders_unsupported = !frame->has_leaders;

    bool ranking = answers_ranking(c, frame);
    if (!ui->paused)
        sample_live(c, frame);
    if (ranking && !ui->frozen)
        sample_ranking(c, frame);
    if (ui->paused || (ui->frozen && ranking))
        hold(c, frame, ranking);
    return finish(c, FT_TOP_DO_REDRAW, true);
}

unsigned ft_top_control_tick(struct ft_top_controller *c)
{
    struct ft_top_ui *ui = &c->ui;
    uint64_t now = c->now_ns;
    unsigned bits = 0;

    if (c->message_until_ns && now >= c->message_until_ns) {
        c->message_until_ns = 0;
        ui->message[0] = '\0';
        ui->message_kind = FT_TOP_MESSAGE_NONE;
        bits |= FT_TOP_DO_REDRAW;
    }
    if (c->skipped_until_ns && now >= c->skipped_until_ns) {
        c->skipped_until_ns = 0;
        ui->skipped_ns = 0;
        bits |= FT_TOP_DO_REDRAW;
    }
    if (c->await_serial && !ui->waiting && now >= c->await_ns + SPINNER_NS) {
        ui->waiting = true;
        c->spin_ns = now + SPINNER_NS;
        bits |= FT_TOP_DO_REDRAW;
    } else if (c->await_serial && ui->waiting && now >= c->spin_ns) {
        ui->spinner++;
        c->spin_ns = now + SPINNER_NS;
        bits |= FT_TOP_DO_REDRAW;
    }
    if (!ui->paused) {
        if (ft_top_model_tick(c->model, now))
            bits |= FT_TOP_DO_REDRAW;
        if (c->linger_ns && now >= c->linger_ns) {
            c->linger_ns = 0;
            bits |= FT_TOP_DO_REDRAW;
        }
        if (c->shown_mono_ns && now > c->shown_mono_ns + 2 * ui->delay_ns) {
            ui->lag_ns = now - c->shown_mono_ns;
            bits |= FT_TOP_DO_REDRAW;
        }
    }
    return bits;
}

static void sooner(uint64_t *next, uint64_t at)
{
    if (at && at < *next)
        *next = at;
}

uint64_t ft_top_control_deadline(const struct ft_top_controller *c)
{
    uint64_t next = UINT64_MAX;

    sooner(&next, c->message_until_ns);
    sooner(&next, c->skipped_until_ns);
    if (c->await_serial)
        sooner(&next, c->ui.waiting ? c->spin_ns : c->await_ns + SPINNER_NS);
    if (!c->ui.paused)
        sooner(&next, c->linger_ns);
    if (!c->ui.paused && c->shown_mono_ns) {
        uint64_t stale_ns = c->shown_mono_ns + 2 * c->ui.delay_ns + 1;
        sooner(&next, c->now_ns < stale_ns ? stale_ns : c->now_ns + FT_NS_PER_SEC);
    }
    return next;
}

bool ft_top_control_init(struct ft_top_controller *c, struct ft_top_model *m,
                         const struct ft_top_options *opt, const char *filter, struct ft_error *err)
{
    struct ft_top_ui *ui = &c->ui;
    enum ft_top_mode mode = opt->mode < FT_TOP_MODE_COUNT ? opt->mode : FT_TOP_TRANSFERS;

    memset(c, 0, sizeof(*c));
    c->model = m;
    ft_top_frame_init(&c->held);
    ui->mode = mode;
    ui->previous_mode = FT_TOP_TRANSFERS;
    ui->full_paths = true;
    ui->delay_ns = opt->delay_ns < FT_TOP_DELAY_MIN_NS   ? FT_TOP_DELAY_MIN_NS
                   : opt->delay_ns > FT_TOP_DELAY_MAX_NS ? FT_TOP_DELAY_MAX_NS
                                                         : opt->delay_ns;
    ui->window = FT_WINDOW_1H;
    for (size_t i = 0; i < FT_ARRAY_LEN(windows); i++) {
        if (windows[i] == opt->window)
            ui->window = opt->window;
    }
    ui->key = FT_LEADER_FILE;
    ui->by = top_measure(opt->by);
    c->limit = opt->limit ? opt->limit : 50;

    ft_top_set_mode(m, mode);
    ft_top_set_tree(m, opt->tree);
    ft_top_set_leaders_request(m, ui->window, ui->key);
    ft_top_set_sort(m, FT_TOP_LEADERS, ui->by, true);
    if (mode != FT_TOP_LEADERS) {
        size_t n;
        enum ft_top_sort key =
            opt->sort == FT_TOP_SORT_DEFAULT ? ft_top_mode_sorts(mode, &n)[0].key : opt->sort;
        const struct ft_top_sort_option *sort = sort_option(mode, key, nullptr);
        if (!sort) {
            ft_error_set(err, FT_EXIT_USAGE, "--sort %s does not apply to the %s mode",
                         ft_top_sort_name(key), ft_top_mode_name(mode));
            return false;
        }
        ft_top_set_sort(m, mode, key, sort->descending != opt->reverse);
        ft_top_set_group(m, mode, opt->group);
    }
    if (filter && filter[0] && !ft_top_set_filter(m, mode, filter, err))
        return false;
    ft_top_set_resolve(m, opt->resolve);
    return true;
}

void ft_top_control_free(struct ft_top_controller *c)
{
    ft_top_frame_free(&c->held);
    lines_free(&c->overlay);
    recall_free(&c->recall);
    for (size_t i = 0; i < c->nhistory; i++)
        free(c->history[i]);
    free(c->history);
    free(c->copy);
    c->history = nullptr;
    c->nhistory = 0;
    c->copy = nullptr;
}
