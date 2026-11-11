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

struct ft_watch_options {
    uint64_t interval_ns;
    uint32_t pid;
    uint16_t proto;
    uint32_t limit;
    bool inbound; /* rank processes by received bytes */
    bool plain;   /* append snapshots instead of drawing a dashboard */
    char process[64];
};

int ft_watch_run(struct ft_session *s, const struct ft_watch_options *opt);

#endif
