#ifndef FILETRACE_TOP_VIEWS_H
#define FILETRACE_TOP_VIEWS_H

#include "filetrace/sysinfo.h"
#include "ui/top/model.h"
#include "ui/tui/canvas.h"
#include "ui/tui/lineedit.h"
#include "ui/tui/theme.h"

/* The smallest terminal the screen is drawn in. */
constexpr int FT_TOP_MIN_COLS = 120;
constexpr int FT_TOP_MIN_ROWS = 30;

enum ft_top_prompt : uint8_t {
    FT_TOP_PROMPT_NONE,
    FT_TOP_PROMPT_SEARCH,
    FT_TOP_PROMPT_FILTER,
    FT_TOP_PROMPT_EXPORT,
    FT_TOP_PROMPT_PRESET, /* the name a filter is saved under */
};

enum ft_top_overlay : uint8_t {
    FT_TOP_OVERLAY_NONE,
    FT_TOP_OVERLAY_EVENTS,
    FT_TOP_OVERLAY_JSON,
};

enum ft_top_panel : uint8_t {
    FT_TOP_PANEL_NONE,
    FT_TOP_PANEL_SORT,  /* the Sort/Group panel with its cursor in the sort list */
    FT_TOP_PANEL_GROUP, /* the same panel with its cursor in the group list */
};

enum ft_top_message : uint8_t {
    FT_TOP_MESSAGE_NONE,
    FT_TOP_MESSAGE_INFO,
    FT_TOP_MESSAGE_ERROR,
};

/* Lines of text shown in place of the table; the controller fills them. */
struct ft_top_text {
    char title[160];
    const char *const *lines;
    size_t count;
    size_t scroll; /* index of the first line shown */
};

/*
 * What is on screen besides the model's rows. The controller owns and changes it; the drawing
 * code only reads it.
 */
struct ft_top_ui {
    enum ft_top_mode mode;
    enum ft_top_mode previous_mode;   /* where Esc returns from Leaders */
    size_t scroll[FT_TOP_MODE_COUNT]; /* index of the first table row shown */

    bool help;
    bool inspect;
    enum ft_top_overlay overlay;
    struct ft_top_text overlay_text;
    enum ft_top_panel panel;
    size_t panel_cursor; /* index in the list the cursor is in */
    enum ft_top_prompt prompt;
    struct ft_lineedit edit;
    char prompt_error[200]; /* why the text of the filter prompt does not parse; "" when it does */

    bool paused;
    uint64_t skipped_ns; /* shown for a moment after resuming; 0: nothing to show */
    bool script_column;
    bool full_paths;
    bool color_by_method; /* false: destinations carry the color, by egress */
    bool no_selection;    /* a table printed outside the screen has no cursor to show */
    uint64_t delay_ns;

    /* Leaders. */
    enum ft_leader_window window;
    enum ft_leader_key key;
    enum ft_top_sort by; /* FT_TOP_SORT_BYTES, _TRANSFERS or _DESTINATIONS */
    bool frozen;
    bool waiting;             /* an answer has been awaited for longer than a moment */
    unsigned spinner;         /* advances while waiting */
    bool leaders_unsupported; /* the agent does not keep rankings */

    enum ft_top_message message_kind;
    char message[240]; /* replaces the status row while set */

    /* The agent, as the source last reported it. */
    int agent_code;        /* FT_EXIT_OK, or why there is no fresh data */
    char agent_error[256]; /* "" when fine */
    uint64_t lag_ns;       /* how late the latest data is beyond one refresh; 0 when on time */
};

/* What a click lands on. */
enum ft_top_target : uint8_t {
    FT_TOP_TARGET_NONE,
    FT_TOP_TARGET_ROW,     /* arg: the row's index in the mode */
    FT_TOP_TARGET_TOGGLE,  /* arg: the row whose group or tree node opens and closes */
    FT_TOP_TARGET_HEADER,  /* arg: enum ft_top_sort of the column */
    FT_TOP_TARGET_TAB,     /* arg: enum ft_top_mode */
    FT_TOP_TARGET_KEY,     /* arg: enum ft_key the item stands for, rune its character */
    FT_TOP_TARGET_WINDOW,  /* arg: enum ft_leader_window */
    FT_TOP_TARGET_RANK_BY, /* arg: enum ft_top_sort */
    FT_TOP_TARGET_SORT,    /* arg: index in the panel's sort list */
    FT_TOP_TARGET_GROUP,   /* arg: index in the panel's group list */
    FT_TOP_TARGET_CLOSE,   /* the "Esc close" of a panel or overlay */
};

struct ft_top_hit {
    struct ft_rect rect;
    enum ft_top_target target;
    uint32_t arg;
    uint32_t rune; /* FT_TOP_TARGET_KEY with FT_KEY_CHAR */
};

constexpr size_t FT_TOP_HITS_MAX = 4096;

/* The clickable areas of the frame last drawn, later ones on top. */
struct ft_top_hits {
    struct ft_top_hit items[FT_TOP_HITS_MAX];
    size_t count;
};

void ft_top_hits_add(struct ft_top_hits *hits, struct ft_rect rect, enum ft_top_target target,
                     uint32_t arg);
void ft_top_hits_add_key(struct ft_top_hits *hits, struct ft_rect rect, enum ft_key key,
                         uint32_t rune);
/* The topmost area holding the cell, or nullptr. */
const struct ft_top_hit *ft_top_hits_at(const struct ft_top_hits *hits, int x, int y);

/* Where each block of the screen is; a block that is not shown has no height. */
struct ft_top_layout {
    int cols;
    int rows;
    bool too_small;
    struct ft_rect head; /* meters and summary, or the cards of Leaders */
    struct ft_rect tabs;
    struct ft_rect panel;   /* the Sort/Group panel */
    struct ft_rect header;  /* the table's header row */
    struct ft_rect table;   /* the table's rows */
    struct ft_rect side;    /* Leaders: the side panel, from the header row down */
    struct ft_rect rule;    /* the line above the context row or the legend */
    struct ft_rect context; /* the selected row's details; in Leaders the legend */
    struct ft_rect status;
    struct ft_rect inspect;
    struct ft_rect prompt;
    struct ft_rect keys;
    struct ft_rect overlay; /* where an overlay's title and lines go */
};

void ft_top_layout(const struct ft_top_ui *ui, int cols, int rows, struct ft_top_layout *out);

/* Everything one frame is drawn from. */
struct ft_top_draw {
    struct ft_canvas *canvas;
    enum ft_color_depth depth;
    const struct ft_top_model *model;
    const struct ft_top_ui *ui;
    const struct ft_host_info *host;
    struct ft_top_hits *hits; /* filled while drawing; nullptr when clicks are of no interest */
    /* Where the terminal cursor belongs, set while drawing a prompt; x < 0 hides it. */
    int cursor_x;
    int cursor_y;
};

/* Draws the whole screen for the canvas's size. */
void ft_top_draw(struct ft_top_draw *d);

/*
 * The pieces of the screen. ft_top_draw calls them with the rectangles of ft_top_layout; the
 * table is also drawn alone, for output that is not a screen.
 */

/* The header row and the rows from index first of a live mode's table. */
void ft_top_draw_table(struct ft_top_draw *d, enum ft_top_mode mode, struct ft_rect header,
                       struct ft_rect rows, size_t first);

void ft_top_draw_leaders_cards(struct ft_top_draw *d, struct ft_rect r);
/* The window and rank-by words after the tabs, and the span at the right. */
void ft_top_draw_leaders_bar(struct ft_top_draw *d, struct ft_rect r, int x);
void ft_top_draw_leaders_table(struct ft_top_draw *d, struct ft_rect header, struct ft_rect rows,
                               size_t first);
void ft_top_draw_leaders_side(struct ft_top_draw *d, struct ft_rect r);
void ft_top_draw_leaders_legend(struct ft_top_draw *d, struct ft_rect r);

void ft_top_draw_panel(struct ft_top_draw *d, struct ft_rect r);
void ft_top_draw_inspect(struct ft_top_draw *d, struct ft_rect r);
void ft_top_draw_overlay(struct ft_top_draw *d, struct ft_rect r);
void ft_top_draw_help(struct ft_top_draw *d);

/* The groupings a mode offers, in the order the panel lists them. */
const enum ft_top_group *ft_top_mode_groups(enum ft_top_mode mode, size_t *count);

/* Styles and words the screens share. */

/* A foreground on the cell's own background. */
struct ft_style ft_top_fg(enum ft_color fg, bool bold);
/* Dark text on a bar of the given color. */
struct ft_style ft_top_on(enum ft_color bar, bool bold);

struct ft_style ft_top_rate_style(uint64_t bytes_per_second);
enum ft_color ft_top_method_color(uint8_t method);
enum ft_color ft_top_egress_color(bool is_public);
const char *ft_top_method_word(uint8_t method);
/* "EXACT", "INFERRED"; with a "*" when events were lost. */
const char *ft_top_confidence_word(uint8_t confidence, bool incomplete);

/* A bar across r: reverse video without color, else the bar color under dark text. */
void ft_top_bar_row(struct ft_top_draw *d, struct ft_rect r, enum ft_color bar);
/* The selection: every cell of r dark on cyan, or reversed without color. */
void ft_top_select_row(struct ft_top_draw *d, struct ft_rect r);
/* A title on a bar, with text at its right end; either may be nullptr. */
void ft_top_title_row(struct ft_top_draw *d, struct ft_rect r, enum ft_color bar, const char *left,
                      const char *right);

/* One cell of a column: text within [x, x + width - 1), right-aligned or cut at its end. */
int ft_top_cell(struct ft_top_draw *d, int x, int y, int width, bool right, struct ft_style s,
                const char *text);
/* The text ft_top_path_cell draws: the path, or its file name when full paths are off. */
const char *ft_top_path_text(const struct ft_top_draw *d, const char *path, uint32_t name_offset);
/* A path in a column, cut from its start: directory dim, the name in its style. */
void ft_top_path_cell(struct ft_top_draw *d, int x, int y, int width, const char *path,
                      uint32_t name_offset, struct ft_style name);
/*
 * Marks, in a cell of this width drawn from text with this cut, what the mode's search finds and
 * what its filter asks of the field; FT_TOP_FIELD_ANY for a column no filter key names.
 */
void ft_top_mark_matches(struct ft_top_draw *d, int x, int y, int width, const char *text,
                         enum ft_cut cut, enum ft_top_field field, bool selected);

#endif
