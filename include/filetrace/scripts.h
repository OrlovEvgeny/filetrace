#ifndef FILETRACE_SCRIPTS_H
#define FILETRACE_SCRIPTS_H

#include "filetrace/base.h"

/*
 * The paths of PHP request scripts by the id the kernel gave each, in a fixed number of slots.
 * The kernel keeps an id for a path for as long as the path stays in use, so an id that loses
 * its slot must also be forgotten there, or the path would stay nameless.
 */
struct ft_script_names;

struct ft_script_names *ft_script_names_create(size_t slots);
void ft_script_names_destroy(struct ft_script_names *n);

/*
 * Keeps path under id. Returns true when that takes the slot of another id, with the hash the
 * kernel knows that id's path by in *evicted, for the caller to make the kernel forget it.
 */
bool ft_script_names_put(struct ft_script_names *n, uint32_t id, uint64_t hash, const char *path,
                         uint64_t *evicted);

/* The path kept for id, or nullptr. */
const char *ft_script_names_get(const struct ft_script_names *n, uint32_t id);

#endif
