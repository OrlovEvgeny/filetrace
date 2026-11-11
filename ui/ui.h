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

    /* The filters shared by every view, the order of the transfers, and the rows per
       table (limit 0: as many as fit). */
    struct ft_query filter;
};

int ft_watch_run(struct ft_session *s, const struct ft_watch_options *opt);

#endif
