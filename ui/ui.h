#ifndef FILETRACE_UI_H
#define FILETRACE_UI_H

#include "cmd/cli.h"

/* Whether styled output suits the stream: a terminal, and NO_COLOR unset. */
bool ft_term_styled(FILE *stream);
void ft_term_size(int *rows, int *cols);

bool ft_term_raw_enter(void);
void ft_term_raw_leave(void);

#define FT_STYLE_BOLD "\033[1m"
#define FT_STYLE_DIM "\033[2m"
#define FT_STYLE_RESET "\033[0m"

struct ft_column_spec {
    const char *title;
    bool right;
};

/* Returns the text of one cell; may use buf for storage. */
typedef const char *ft_cell_fn(void *ctx, size_t row, size_t col, char *buf, size_t size);

void ft_table_print(FILE *out, const struct ft_column_spec *cols, size_t ncols, size_t nrows,
                    ft_cell_fn *cell, void *ctx, bool styled);

/* What a column gives up, and when, if its table is wider than the room for it. */
struct ft_column_fit {
    uint8_t cut;   /* turn in which its cells are cut, from 1; 0: never */
    size_t least;  /* the narrowest a cut leaves them, and never narrower than the title */
    bool keep_end; /* a cut keeps the end of the text, as of a path, rather than its start */
    uint8_t leave; /* turn in which the column is left out whole, from 1; 0: never */
};

/*
 * Prints a table as ft_table_print does, no wider than width. A wider one has its cells cut with
 * "...", the cut columns in turn, each no further than needed nor below its least width. If that
 * is not enough, whole columns are left out in turn, the rest cut afresh each time. Returns false
 * if the table is still too wide, and prints it at its narrowest.
 */
bool ft_table_print_fit(FILE *out, const struct ft_column_spec *cols,
                        const struct ft_column_fit *fit, size_t ncols, size_t nrows,
                        ft_cell_fn *cell, void *ctx, bool styled, size_t width);

/* Display width of UTF-8 text, counting each code point as one column. */
size_t ft_text_width(const char *s);

enum ft_watch_direction : uint8_t {
    FT_WATCH_OUTBOUND,
    FT_WATCH_INBOUND,
    FT_WATCH_BOTH,
};

struct ft_watch_options {
    uint64_t interval_ns;
    enum ft_watch_direction direction; /* which traffic ranks processes and connections */
    bool plain;                        /* append snapshots instead of drawing a dashboard */
    bool timestamps;                   /* head each appended snapshot with its time */
    bool resolve;                      /* show remote addresses by host name */

    /* Filters of every view; its sort orders the transfers, its limit caps each table. */
    struct ft_query filter;
};

int ft_watch_run(struct ft_session *s, const struct ft_watch_options *opt);

/* What the network view asks the agent for: the open connections the filters leave. */
void ft_watch_connections_query(const struct ft_watch_options *opt, uint32_t limit,
                                struct ft_query *q);

#endif
