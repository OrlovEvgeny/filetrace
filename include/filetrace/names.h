#ifndef FILETRACE_NAMES_H
#define FILETRACE_NAMES_H

#include "filetrace/model.h"

#define FT_RESOLVED_NAMES 4 /* looked-up names kept for one address or connection */

enum ft_name_kind : uint8_t {
    FT_NAME_HOST,
    FT_NAME_ADDRESS, /* an address in one of its numeric forms, or nothing at all */
    FT_NAME_REFUSED, /* too long, or with a byte that no host name has */
};

/* Writes a host name as names are kept and compared: in lower case, without a trailing dot. */
enum ft_name_kind ft_name_normalise(const char *text, char out[static FT_NAME_MAX]);

/*
 * Writes a pattern for names, where '*' stands for any run of characters, as names are kept.
 * False for text that could match no name, and for digits without a letter: a mistyped address
 * would otherwise list nothing, which reads as nothing having gone there.
 */
bool ft_name_pattern(const char *text, char out[static FT_NAME_MAX]);

/* Whether a kept name matches the pattern; the pattern's case does not count. */
bool ft_name_matches(const char *pattern, const char *name);

/* How a process came to use a name for a connection. */
enum ft_name_source : uint8_t {
    FT_NAME_SOURCE_NONE = 0,
    FT_NAME_SOURCE_LOOKUP = 1,     /* it looked the name up and got the remote address */
    FT_NAME_SOURCE_TLS = 2,        /* it asked for the name as the TLS server name */
    FT_NAME_SOURCE_LOOKUP_TLS = 3, /* both */
};

/* "lookup", "tls" or "lookup+tls"; "" for none. */
const char *ft_name_source_name(enum ft_name_source source);

/* The names of a connection's remote end, as kept. */
struct ft_remote_names {
    const char *tls;                         /* "" when no TLS server name was seen */
    const char *resolved[FT_RESOLVED_NAMES]; /* the connecting thread's latest first */
    uint32_t listed;                         /* how many of resolved are set */
    uint32_t count; /* names the process looked up to the address: listed or more */
};

/* The name the connection was opened for: its TLS server name, else the first looked up. */
const char *ft_remote_name(const struct ft_remote_names *n);
enum ft_name_source ft_remote_name_source(const struct ft_remote_names *n);

/* What a table shows: "name", "name (+2)" for several looked up, "name via looked-up". */
void ft_remote_name_format(const struct ft_remote_names *n, char *buf, size_t size);

/*
 * What a cell with no room for both shows in place of the address: the name, followed by the
 * port only where the process looked that name up to the address, so that "name:port" is true
 * of it. A port of 0 is left out. "" when the remote end has no name.
 */
void ft_remote_name_cell(const struct ft_remote_names *n, uint16_t port, char *buf, size_t size);

#define FT_ADDRESS_NAMES 16 /* distinct names kept for one address */

struct ft_name_use {
    const char *name;
    uint64_t bytes;                        /* carried by the connections opened for it */
    const struct ft_remote_names *used_by; /* the first of them; nullptr when none was */
    uint32_t met;                          /* its place in the order the names were met */
};

/*
 * The names behind one address, gathered from the connections to it: each distinct name a
 * connection was opened for or its process looked up to the address. Start from a zeroed one.
 * The names and connections given stay the caller's and must outlive it.
 */
struct ft_address_names {
    struct ft_name_use names[FT_ADDRESS_NAMES];
    size_t count;
    size_t more; /* names met after the room was taken; one name may be counted twice here */
};

void ft_address_names_add(struct ft_address_names *a, const struct ft_remote_names *n,
                          uint64_t bytes);

/* Puts the name whose connections carried the most bytes first, the rest after it likewise. */
void ft_address_names_sort(struct ft_address_names *a);

/*
 * What a view of the address shows, once sorted: what the connection that used the first name
 * shows when that says every name, else "first (+N)" for the N other names. "" for none.
 */
void ft_address_names_format(const struct ft_address_names *a, char *buf, size_t size);

/*
 * Host names in a fixed number of slots. A held name keeps its slot. A name nobody holds stays
 * until a new name needs the slot of the one unused the longest; a reference to it then no
 * longer resolves.
 */
struct ft_names;

struct ft_name_ref {
    uint32_t id; /* 0: no name */
    uint32_t generation;
};

struct ft_names *ft_names_create(size_t capacity);
void ft_names_destroy(struct ft_names *n);

/* Finds the name or keeps it, as its latest use. No id: not a host name, or every slot is held. */
struct ft_name_ref ft_names_intern(struct ft_names *n, const char *text);

/* The id of the name the reference was made for, or 0 once its slot went to another. */
uint32_t ft_names_resolve(const struct ft_names *n, struct ft_name_ref ref);

void ft_names_hold(struct ft_names *n, uint32_t id);
void ft_names_release(struct ft_names *n, uint32_t id);

const char *ft_names_text(const struct ft_names *n, uint32_t id);
uint64_t ft_names_hash(const struct ft_names *n, uint32_t id);

size_t ft_names_count(const struct ft_names *n);
size_t ft_names_capacity(const struct ft_names *n);
uint64_t ft_names_forgotten(const struct ft_names *n);
uint64_t ft_names_invalid(const struct ft_names *n); /* refused: not host names */
uint64_t ft_names_refused(const struct ft_names *n); /* refused: every slot was held */

#endif
