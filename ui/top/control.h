#ifndef FILETRACE_TOP_CONTROL_H
#define FILETRACE_TOP_CONTROL_H

#include "ui/top/source.h"
#include "ui/top/views.h"

/*
 * The state machine of filetrace top: keys, clicks, frames and the passing of time go in, changes
 * of the screen state and of the model come out, with bits that say what the loop must do. It
 * touches neither the terminal nor the source.
 */

/* What the loop must do after a call. */
#define FT_TOP_DO_REDRAW 0x01u
#define FT_TOP_DO_REQUEST 0x02u /* send ft_top_control_request() to the source */
#define FT_TOP_DO_COPY 0x04u    /* put the controller's copy text on the clipboard */
#define FT_TOP_DO_REPAINT 0x08u /* write every cell at the next present */
#define FT_TOP_DO_QUIT 0x10u

/* Texts the filter prompt steps through with the arrow keys. */
struct ft_top_recall {
    char **items; /* the saved presets' expressions, then this run's filters, oldest first */
    size_t count;
    size_t at;       /* count while the typed text is shown */
    char typed[512]; /* the text as typed, while a recalled one is shown */
};

/* Lines of text with the memory that holds them. */
struct ft_top_lines {
    char *text;
    const char **lines;
    size_t count;
};

struct ft_top_controller {
    struct ft_top_ui ui;
    struct ft_top_model *model;
    struct ft_top_layout layout; /* of the frame drawn last */
    struct ft_top_hits hits;     /* of the frame drawn last */
    uint64_t now_ns;             /* the monotonic clock; the caller sets it before each call */
    char *copy;                  /* what FT_TOP_DO_COPY puts on the clipboard */

    /* What the source was asked for. */
    struct ft_top_request sent; /* the request last sent */
    uint64_t sent_serial;
    uint64_t leaders_serial; /* the first request for the ranking as it is now asked for */
    uint64_t leaders_from;   /* the first request of those asking for a ranking without a break */
    uint64_t events_serial;  /* the request the events overlay waits for; 0: none */
    bool events_ask;         /* the next request asks for the events */
    bool force;              /* the next request goes out even if it is the same */
    uint32_t limit;          /* rows of the ranking */
    uint32_t events_pid;     /* what the events overlay shows */
    struct ft_endpoint events_remote;
    char events_path[FT_PATH_MAX];

    /* Frames held back while paused or frozen; the newest only. */
    struct ft_top_frame held;
    bool held_live;
    bool held_leaders;
    uint64_t shown_mono_ns; /* when the refresh shown in the live modes began */

    /* Timed things on the monotonic clock; 0 when nothing waits. */
    uint64_t message_until_ns;
    uint64_t skipped_until_ns;
    uint64_t await_serial; /* the Leaders answer waited for */
    uint64_t await_ns;
    bool await_next; /* the next request starts a wait */
    uint64_t spin_ns;
    uint64_t linger_ns; /* the selected finished row goes */

    /* Prompts. */
    struct ft_lineedit filter_edit; /* the filter prompt while a preset name is typed */
    struct ft_top_recall recall;
    char **history; /* filters kept with Enter in this run, oldest first */
    size_t nhistory;

    struct ft_top_lines overlay;

    uint64_t start_ns; /* when the first request went out; 0 when no wait for it is shown */
    bool answered;     /* a frame has come */
    int exit_code;     /* why the run ends with FT_TOP_DO_QUIT by itself; FT_EXIT_OK for a key */
};

/* Sets up the state the options ask for; false with err set when the filter does not apply. */
bool ft_top_control_init(struct ft_top_controller *c, struct ft_top_model *m,
                         const struct ft_top_options *opt, const char *filter,
                         struct ft_error *err);
void ft_top_control_free(struct ft_top_controller *c);

/* Records where the data comes from and that the first request went out at now_ns. */
void ft_top_control_start(struct ft_top_controller *c, bool session_only, bool mode_overridden);

/* Applies one input to the state and the model; says what the loop must do next. */
unsigned ft_top_control(struct ft_top_controller *c, const struct ft_input *in);

/* Takes a frame into the model, or swaps it into the controller while paused or frozen. */
unsigned ft_top_control_frame(struct ft_top_controller *c, struct ft_top_frame *frame);

/* Ends what has run its time by now_ns. */
unsigned ft_top_control_tick(struct ft_top_controller *c);

/* When the next timed change is due on the monotonic clock; UINT64_MAX when none is. */
uint64_t ft_top_control_deadline(const struct ft_top_controller *c);

/* The request the state calls for. */
void ft_top_control_request(const struct ft_top_controller *c, struct ft_top_request *req);
/* Records that the request went out under the serial the source gave it. */
void ft_top_control_sent(struct ft_top_controller *c, const struct ft_top_request *req,
                         uint64_t serial);

/* Scrolls the current mode's table and the overlay of the layout to keep the selection shown. */
void ft_top_control_clamp(struct ft_top_controller *c);

#endif
