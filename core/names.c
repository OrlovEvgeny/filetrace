#include "filetrace/names.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static bool is_hex(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'f');
}

/* The resolver reads a name whose last label is a number as an address: 127.1, 0x7f.1. */
static bool ends_in_number(const char *name, size_t len)
{
    size_t start = len;
    while (start > 0 && name[start - 1] != '.')
        start--;

    bool hex = len - start >= 2 && name[start] == '0' && name[start + 1] == 'x';
    if (hex)
        start += 2;
    else if (start == len)
        return false;
    for (size_t i = start; i < len; i++) {
        if (hex ? !is_hex(name[i]) : !is_digit(name[i]))
            return false;
    }
    return true;
}

enum ft_name_kind ft_name_normalise(const char *text, char out[static FT_NAME_MAX])
{
    size_t len = 0;
    bool refused = false;

    out[0] = '\0';
    for (; text[len]; len++) {
        char c = text[len];
        if (c == ':') {
            out[0] = '\0';
            return FT_NAME_ADDRESS;
        }
        if (len >= FT_NAME_MAX) {
            refused = true;
            continue;
        }
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
        if (!(c >= 'a' && c <= 'z') && !is_digit(c) && c != '-' && c != '_' && c != '.')
            refused = true;
        out[len] = c;
    }
    if (!refused && len > 0 && out[len - 1] == '.')
        len--;
    if (refused || len > FT_NAME_MAX - 1) {
        out[0] = '\0';
        return FT_NAME_REFUSED;
    }
    out[len] = '\0';
    if (len == 0 || ends_in_number(out, len)) {
        out[0] = '\0';
        return FT_NAME_ADDRESS;
    }
    return FT_NAME_HOST;
}

static char lower(char c)
{
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}

bool ft_name_pattern(const char *text, char out[static FT_NAME_MAX])
{
    bool letter = false;
    bool digit = false;
    size_t len = 0;

    for (; text[len]; len++) {
        char c = lower(text[len]);
        bool part = (c >= 'a' && c <= 'z') || is_digit(c) || c == '-' || c == '_' || c == '.';
        if (len >= FT_NAME_MAX - 1 || (!part && c != '*')) {
            out[0] = '\0';
            return false;
        }
        letter = letter || (c >= 'a' && c <= 'z');
        digit = digit || is_digit(c);
        out[len] = c;
    }
    if (len > 1 && out[len - 1] == '.')
        len--;
    out[len] = '\0';
    if (len == 0 || (digit && !letter))
        out[0] = '\0';
    return out[0] != '\0';
}

bool ft_name_matches(const char *pattern, const char *name)
{
    const char *after_star = nullptr;
    const char *retry = nullptr;

    while (*name) {
        if (*pattern == '*') {
            after_star = ++pattern;
            retry = name;
        } else if (lower(*pattern) == *name) {
            pattern++;
            name++;
        } else if (after_star) {
            pattern = after_star;
            name = ++retry;
        } else {
            return false;
        }
    }
    while (*pattern == '*')
        pattern++;
    return *pattern == '\0';
}

const char *ft_name_source_name(enum ft_name_source source)
{
    switch (source) {
    case FT_NAME_SOURCE_LOOKUP:
        return "lookup";
    case FT_NAME_SOURCE_TLS:
        return "tls";
    case FT_NAME_SOURCE_LOOKUP_TLS:
        return "lookup+tls";
    default:
        return "";
    }
}

const char *ft_remote_name(const struct ft_remote_names *n)
{
    if (n->tls[0])
        return n->tls;
    return n->listed ? n->resolved[0] : "";
}

enum ft_name_source ft_remote_name_source(const struct ft_remote_names *n)
{
    if (!n->tls[0])
        return n->listed ? FT_NAME_SOURCE_LOOKUP : FT_NAME_SOURCE_NONE;
    for (uint32_t i = 0; i < n->listed; i++) {
        if (strcmp(n->resolved[i], n->tls) == 0)
            return FT_NAME_SOURCE_LOOKUP_TLS;
    }
    return FT_NAME_SOURCE_TLS;
}

void ft_remote_name_format(const struct ft_remote_names *n, char *buf, size_t size)
{
    uint32_t others = n->count > 1 ? n->count - 1 : 0;

    switch (ft_remote_name_source(n)) {
    case FT_NAME_SOURCE_LOOKUP:
        if (others)
            snprintf(buf, size, "%s (+%u)", n->resolved[0], others);
        else
            snprintf(buf, size, "%s", n->resolved[0]);
        break;
    case FT_NAME_SOURCE_TLS:
        if (!n->listed)
            snprintf(buf, size, "%s", n->tls);
        else if (others)
            snprintf(buf, size, "%s via %s (+%u)", n->tls, n->resolved[0], others);
        else
            snprintf(buf, size, "%s via %s", n->tls, n->resolved[0]);
        break;
    case FT_NAME_SOURCE_LOOKUP_TLS:
        snprintf(buf, size, "%s", n->tls);
        break;
    default:
        snprintf(buf, size, "%s", "");
        break;
    }
}

/* Ids count from 1, so that 0 can stand for no name and for the end of a list. */
struct entry {
    uint64_t hash;
    uint32_t holders;
    uint32_t generation;
    uint32_t chain;
    uint32_t newer; /* among the names nobody holds */
    uint32_t older;
    char text[FT_NAME_MAX];
};

struct ft_names {
    size_t capacity;
    size_t count;
    uint64_t forgotten;
    uint64_t invalid;
    uint64_t refused;
    uint32_t mask;
    uint32_t used; /* slots handed out at least once */
    uint32_t newest;
    uint32_t oldest;
    uint32_t *buckets;
    struct entry *entries;
};

struct ft_names *ft_names_create(size_t capacity)
{
    if (capacity == 0 || capacity >= UINT32_MAX / 2)
        return nullptr;

    struct ft_names *n = calloc(1, sizeof(*n));
    if (!n)
        return nullptr;

    size_t nbuckets = 16;
    while (nbuckets < capacity * 2)
        nbuckets *= 2;
    n->capacity = capacity;
    n->mask = (uint32_t)(nbuckets - 1);
    n->buckets = calloc(nbuckets, sizeof(*n->buckets));
    n->entries = calloc(capacity, sizeof(*n->entries));
    if (!n->buckets || !n->entries) {
        ft_names_destroy(n);
        return nullptr;
    }
    return n;
}

void ft_names_destroy(struct ft_names *n)
{
    if (!n)
        return;
    free(n->buckets);
    free(n->entries);
    free(n);
}

static struct entry *entry_of(const struct ft_names *n, uint32_t id)
{
    return &n->entries[id - 1];
}

static uint64_t hash_name(const char *name)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (const char *p = name; *p; p++) {
        h ^= (unsigned char)*p;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static void unused_unlink(struct ft_names *n, uint32_t id)
{
    struct entry *e = entry_of(n, id);
    if (e->newer)
        entry_of(n, e->newer)->older = e->older;
    else
        n->newest = e->older;
    if (e->older)
        entry_of(n, e->older)->newer = e->newer;
    else
        n->oldest = e->newer;
}

static void unused_push(struct ft_names *n, uint32_t id)
{
    struct entry *e = entry_of(n, id);
    e->newer = 0;
    e->older = n->newest;
    if (n->newest)
        entry_of(n, n->newest)->newer = id;
    else
        n->oldest = id;
    n->newest = id;
}

/* Takes the slot of the name unused the longest; 0 when every name is held. */
static uint32_t forget_oldest(struct ft_names *n)
{
    uint32_t id = n->oldest;
    if (!id)
        return 0;

    struct entry *e = entry_of(n, id);
    uint32_t *link = &n->buckets[e->hash & n->mask];
    while (*link != id)
        link = &entry_of(n, *link)->chain;
    *link = e->chain;
    unused_unlink(n, id);
    n->count--;
    n->forgotten++;
    return id;
}

struct ft_name_ref ft_names_intern(struct ft_names *n, const char *text)
{
    char name[FT_NAME_MAX];
    enum ft_name_kind kind = ft_name_normalise(text, name);

    if (kind == FT_NAME_REFUSED)
        n->invalid++;
    if (kind != FT_NAME_HOST)
        return (struct ft_name_ref){0};

    uint64_t hash = hash_name(name);
    for (uint32_t id = n->buckets[hash & n->mask]; id; id = entry_of(n, id)->chain) {
        struct entry *e = entry_of(n, id);
        if (e->hash != hash || strcmp(e->text, name) != 0)
            continue;
        if (e->holders == 0 && n->newest != id) {
            unused_unlink(n, id);
            unused_push(n, id);
        }
        return (struct ft_name_ref){.id = id, .generation = e->generation};
    }

    uint32_t id = n->used < n->capacity ? ++n->used : forget_oldest(n);
    if (!id) {
        n->refused++;
        return (struct ft_name_ref){0};
    }

    struct entry *e = entry_of(n, id);
    e->hash = hash;
    e->holders = 0;
    e->generation++;
    e->chain = n->buckets[hash & n->mask];
    n->buckets[hash & n->mask] = id;
    ft_strlcpy(e->text, name, sizeof(e->text));
    unused_push(n, id);
    n->count++;
    return (struct ft_name_ref){.id = id, .generation = e->generation};
}

uint32_t ft_names_resolve(const struct ft_names *n, struct ft_name_ref ref)
{
    if (ref.id == 0 || ref.id > n->used)
        return 0;
    return entry_of(n, ref.id)->generation == ref.generation ? ref.id : 0;
}

void ft_names_hold(struct ft_names *n, uint32_t id)
{
    if (entry_of(n, id)->holders++ == 0)
        unused_unlink(n, id);
}

void ft_names_release(struct ft_names *n, uint32_t id)
{
    if (--entry_of(n, id)->holders == 0)
        unused_push(n, id);
}

const char *ft_names_text(const struct ft_names *n, uint32_t id)
{
    return entry_of(n, id)->text;
}

uint64_t ft_names_hash(const struct ft_names *n, uint32_t id)
{
    return entry_of(n, id)->hash;
}

size_t ft_names_count(const struct ft_names *n)
{
    return n->count;
}

size_t ft_names_capacity(const struct ft_names *n)
{
    return n->capacity;
}

uint64_t ft_names_forgotten(const struct ft_names *n)
{
    return n->forgotten;
}

uint64_t ft_names_invalid(const struct ft_names *n)
{
    return n->invalid;
}

uint64_t ft_names_refused(const struct ft_names *n)
{
    return n->refused;
}
