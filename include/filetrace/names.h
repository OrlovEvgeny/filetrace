#ifndef FILETRACE_NAMES_H
#define FILETRACE_NAMES_H

#include "filetrace/model.h"

enum ft_name_kind : uint8_t {
    FT_NAME_HOST,
    FT_NAME_ADDRESS, /* an address in one of its numeric forms, or nothing at all */
    FT_NAME_REFUSED, /* too long, or with a byte that no host name has */
};

/* Writes a host name as names are kept and compared: in lower case, without a trailing dot. */
enum ft_name_kind ft_name_normalise(const char *text, char out[static FT_NAME_MAX]);

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

size_t ft_names_count(const struct ft_names *n);
size_t ft_names_capacity(const struct ft_names *n);
uint64_t ft_names_forgotten(const struct ft_names *n);
uint64_t ft_names_invalid(const struct ft_names *n); /* refused: not host names */
uint64_t ft_names_refused(const struct ft_names *n); /* refused: every slot was held */

#endif
