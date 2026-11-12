#ifndef FILETRACE_TOP_FILTER_H
#define FILETRACE_TOP_FILTER_H

#include "filetrace/wire.h"

/*
 * The filter language: space-separated terms that must all hold, "!" negates a term,
 * "key:value" tests one field and a bare word tests every field as a substring:
 *
 *   file:*.pdf dest:public !user:root rate:>1M php
 */
struct ft_top_filter;

enum ft_top_field : uint8_t {
    FT_TOP_FIELD_PID,
    FT_TOP_FIELD_USER,
    FT_TOP_FIELD_PROC,
    FT_TOP_FIELD_SCRIPT,
    FT_TOP_FIELD_FILE,
    FT_TOP_FIELD_DEST,
    FT_TOP_FIELD_METHOD,
    FT_TOP_FIELD_CONF,
    FT_TOP_FIELD_RATE,
    FT_TOP_FIELD_ANY, /* a bare word */
    FT_TOP_FIELD_COUNT,
};

#define FT_TOP_FIELD_BIT(field) (1u << (field))

/* What a filter tests of one transfer. */
struct ft_top_subject {
    uint32_t pid;
    const char *pid_text;
    uint32_t uid;
    bool uid_known;
    const char *user; /* "" when unknown */
    const char *title;
    const char *comm;
    const char *script; /* "" when none */
    const char *path;
    const struct ft_endpoint *remote;
    const char *remote_text; /* the address and port as printed */
    const char *host;        /* nullptr when no name is known */
    bool is_public;
    uint8_t method;     /* enum ft_method */
    uint8_t confidence; /* enum ft_confidence */
    uint64_t rate;      /* bytes per second */
};

/* What a filter tests of one row of a leaders ranking. */
struct ft_top_leader_subject {
    const char *text; /* path, directory or extension */
    const char *const *senders;
    size_t nsenders;
    const struct ft_endpoint *remote; /* family 0 unless the ranking is by destination */
    const char *remote_text;
    const char *host;
    uint8_t method;
    uint8_t confidence;
};

/* An empty expression compiles to a filter that passes everything. */
struct ft_top_filter *ft_top_filter_compile(const char *expression, struct ft_error *err);
void ft_top_filter_free(struct ft_top_filter *f);

const char *ft_top_filter_text(const struct ft_top_filter *f);
bool ft_top_filter_empty(const struct ft_top_filter *f);

/* FT_TOP_FIELD_BIT of every field the terms test. */
uint32_t ft_top_filter_fields(const struct ft_top_filter *f);

/* Fails, naming the first term, when a term tests a field outside allowed. */
bool ft_top_filter_restrict(const struct ft_top_filter *f, uint32_t allowed, const char *where,
                            struct ft_error *err);

bool ft_top_filter_match(const struct ft_top_filter *f, const struct ft_top_subject *s);

/* Fields other than file, proc, dest, method, conf and bare words hold for every row. */
bool ft_top_filter_match_leader(const struct ft_top_filter *f,
                                const struct ft_top_leader_subject *s);

/* Copies into q the terms the agent applies with the same meaning; the rest stay client-side. */
void ft_top_filter_pushdown(const struct ft_top_filter *f, struct ft_query *q);

/* The text of the first positive term on field, or on any field, to highlight; nullptr if none. */
const char *ft_top_filter_needle(const struct ft_top_filter *f, enum ft_top_field field,
                                 size_t *len);

/* Finds needle in text ignoring ASCII case; sets the byte range [*start, *end). */
bool ft_top_find(const char *text, const char *needle, size_t needle_len, size_t *start,
                 size_t *end);

#endif
