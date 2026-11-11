#ifndef FILETRACE_ARENA_H
#define FILETRACE_ARENA_H

#include "filetrace/base.h"

/* Memory for a message under construction: handed out piecewise, released all at once. */
struct ft_arena {
    struct ft_arena_chunk *chunks;
    bool failed; /* an allocation was refused; what was built is incomplete */
};

/* Zero-filled and aligned for any type; nullptr when memory runs out. */
void *ft_arena_alloc(struct ft_arena *a, size_t size);

/* A copy of s that is valid UTF-8, as a protobuf string must be; never nullptr. */
char *ft_arena_text(struct ft_arena *a, const char *s);

void ft_arena_release(struct ft_arena *a);

#endif
