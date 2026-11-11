#ifndef FILETRACE_TABLE_H
#define FILETRACE_TABLE_H

#include "filetrace/base.h"

/* All memory is reserved at creation; a full table evicts its least recently used entry. */
struct ft_table;

typedef void ft_table_evict_fn(void *value, void *ctx);

struct ft_table *ft_table_create(size_t capacity, size_t key_size, size_t value_size);
void ft_table_destroy(struct ft_table *t);

/* Called for every entry that is evicted, removed or cleared. */
void ft_table_on_evict(struct ft_table *t, ft_table_evict_fn *fn, void *ctx);

void *ft_table_find(const struct ft_table *t, const void *key);

/* Also marks the entry as most recently used. */
void *ft_table_touch(struct ft_table *t, const void *key);

/* Finds or creates the entry; a created value is zero-filled. */
void *ft_table_insert(struct ft_table *t, const void *key, bool *created);

void ft_table_remove(struct ft_table *t, const void *key);
void ft_table_clear(struct ft_table *t);

const void *ft_table_key(const struct ft_table *t, const void *value);

/* Iteration from most to least recently used. */
void *ft_table_first(const struct ft_table *t);
void *ft_table_next(const struct ft_table *t, const void *value);

size_t ft_table_count(const struct ft_table *t);
size_t ft_table_capacity(const struct ft_table *t);
uint64_t ft_table_evictions(const struct ft_table *t);

#endif
