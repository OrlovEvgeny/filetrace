#include "cmd/cli.h"

#include "exporters/exporters.h"

#include <stdlib.h>
#include <string.h>

struct ft_kept_name {
    struct ft_kept_name *next;
    uint64_t bytes;
    struct ft_remote_names names; /* points into text */
    char text[];
};

static const char *copy_name(char **at, const char *name)
{
    char *copy = *at;
    size_t size = strlen(name) + 1;

    memcpy(copy, name, size);
    *at += size;
    return copy;
}

bool ft_kept_names_add(struct ft_kept_names *list, const struct ft_remote_names *n, uint64_t bytes)
{
    size_t size = strlen(n->tls) + 1;

    if (ft_remote_name_source(n) == FT_NAME_SOURCE_NONE)
        return true;
    for (uint32_t i = 0; i < n->listed; i++)
        size += strlen(n->resolved[i]) + 1;

    struct ft_kept_name *k = malloc(sizeof(*k) + size);
    if (!k)
        return false;
    char *at = k->text;
    k->next = nullptr;
    k->bytes = bytes;
    k->names = (struct ft_remote_names){
        .tls = copy_name(&at, n->tls), .listed = n->listed, .count = n->count};
    for (uint32_t i = 0; i < n->listed; i++)
        k->names.resolved[i] = copy_name(&at, n->resolved[i]);

    if (list->last)
        list->last->next = k;
    else
        list->first = k;
    list->last = k;
    return true;
}

void ft_kept_names_join(struct ft_kept_names *into, struct ft_kept_names *from)
{
    if (!from->first)
        return;
    if (into->last)
        into->last->next = from->first;
    else
        into->first = from->first;
    into->last = from->last;
    *from = (struct ft_kept_names){0};
}

void ft_kept_names_gather(const struct ft_kept_names *list, struct ft_address_names *a)
{
    for (const struct ft_kept_name *k = list->first; k; k = k->next)
        ft_address_names_add(a, &k->names, k->bytes);
}

void ft_kept_names_behind(const struct ft_kept_names *list, struct ft_address_names *out)
{
    *out = (struct ft_address_names){0};
    ft_kept_names_gather(list, out);
    ft_address_names_sort(out);
}

void ft_kept_names_format(const struct ft_kept_names *list, char *buf, size_t size)
{
    struct ft_address_names behind;

    ft_kept_names_behind(list, &behind);
    ft_address_names_format(&behind, buf, size);
}

void ft_kept_names_free(struct ft_kept_names *list)
{
    struct ft_kept_name *k = list->first;

    while (k) {
        struct ft_kept_name *next = k->next;
        free(k);
        k = next;
    }
    *list = (struct ft_kept_names){0};
}

void ft_json_names(FILE *o, const char *key, const struct ft_address_names *a)
{
    if (a->count == 0)
        return;
    fprintf(o, ",\"%s\":[", key);
    for (size_t i = 0; i < a->count; i++) {
        if (i)
            fputc(',', o);
        ft_json_string(o, a->names[i].name);
    }
    fputc(']', o);
}
