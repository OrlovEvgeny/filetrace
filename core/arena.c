#include "filetrace/arena.h"

#include "filetrace/format.h"

#include <stdlib.h>
#include <string.h>

struct ft_arena_chunk {
    struct ft_arena_chunk *next;
    size_t used;
    size_t size;
    max_align_t data[];
};

void *ft_arena_alloc(struct ft_arena *a, size_t size)
{
    constexpr size_t CHUNK_BYTES = 64 * 1024;
    struct ft_arena_chunk *c = a->chunks;

    size = (size + alignof(max_align_t) - 1) & ~(alignof(max_align_t) - 1);
    if (!c || c->size - c->used < size) {
        size_t room = size > CHUNK_BYTES ? size : CHUNK_BYTES;
        c = malloc(sizeof(*c) + room);
        if (!c) {
            a->failed = true;
            return nullptr;
        }
        c->next = a->chunks;
        c->used = 0;
        c->size = room;
        a->chunks = c;
    }
    void *p = (unsigned char *)c->data + c->used;
    c->used += size;
    memset(p, 0, size);
    return p;
}

char *ft_arena_text(struct ft_arena *a, const char *s)
{
    static char empty[1];
    size_t size = strlen(s) + 1;
    char *copy = ft_arena_alloc(a, size);

    if (!copy)
        return empty;
    ft_utf8_copy(copy, s, size);
    return copy;
}

void ft_arena_release(struct ft_arena *a)
{
    while (a->chunks) {
        struct ft_arena_chunk *next = a->chunks->next;
        free(a->chunks);
        a->chunks = next;
    }
}
