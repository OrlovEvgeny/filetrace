#include "filetrace/scripts.h"

#include <stdlib.h>
#include <string.h>

struct slot {
    uint32_t id;
    uint64_t hash;
    char *path;
};

struct ft_script_names {
    size_t count;
    struct slot slots[];
};

struct ft_script_names *ft_script_names_create(size_t slots)
{
    if (!slots)
        return nullptr;
    struct ft_script_names *n = calloc(1, sizeof(*n) + slots * sizeof(struct slot));
    if (n)
        n->count = slots;
    return n;
}

void ft_script_names_destroy(struct ft_script_names *n)
{
    if (!n)
        return;
    for (size_t i = 0; i < n->count; i++)
        free(n->slots[i].path);
    free(n);
}

bool ft_script_names_put(struct ft_script_names *n, uint32_t id, uint64_t hash, const char *path,
                         uint64_t *evicted)
{
    struct slot *s = &n->slots[id % n->count];
    char *copy = strdup(path);
    if (!copy)
        return false;
    bool replaced = s->path && s->id != id;
    if (replaced)
        *evicted = s->hash;
    free(s->path);
    s->id = id;
    s->hash = hash;
    s->path = copy;
    return replaced;
}

const char *ft_script_names_get(const struct ft_script_names *n, uint32_t id)
{
    if (!n || !id)
        return nullptr;
    const struct slot *s = &n->slots[id % n->count];
    return s->path && s->id == id ? s->path : nullptr;
}
