#ifndef FILETRACE_LEADERS_H
#define FILETRACE_LEADERS_H

#include "filetrace/state.h"

/* Rankings of the most sent files and remote addresses over sliding windows, in bounded memory. */
struct ft_leaders;

struct ft_leaders_config {
    size_t entries; /* the lifetime's tables hold twice this; a window's a half to a sixteenth */
};

/* What one counted part of a transfer adds to the rankings. */
struct ft_leader_sample {
    uint64_t ts_ns;
    struct ft_file_id file;
    const char *path; /* borrowed; nullptr while unknown */
    uint64_t file_size;
    bool deleted;
    const char *sender;        /* the process name, borrowed */
    const char *script;        /* borrowed; nullptr or "" when none */
    struct ft_endpoint remote; /* family 0 when unknown; the port is ignored */
    enum ft_method method;
    enum ft_confidence confidence;
    uint64_t bytes; /* counted since the previous sample of this transfer */
    bool started;   /* this sample is the transfer's first */
};

struct ft_leaders *ft_leaders_create(const struct ft_leaders_config *cfg);
void ft_leaders_destroy(struct ft_leaders *l);

void ft_leaders_add(struct ft_leaders *l, const struct ft_leader_sample *s);

/* Where the current span of a window starts at now_ns; 0 for the lifetime window. */
uint64_t ft_leaders_span_start(enum ft_leader_window window, uint64_t now_ns);

/* The summary, then the rows; no span starts before since_ns; a null store gives FT_LEADERS_OFF. */
bool ft_leaders_query(struct ft_leaders *l, const struct ft_query *q, uint64_t since_ns,
                      uint64_t now_ns, ft_row_fn *emit, void *ctx, struct ft_error *err);

/* Bytes the store has allocated. */
size_t ft_leaders_memory(const struct ft_leaders *l);

#endif
