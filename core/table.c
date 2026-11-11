#include "filetrace/table.h"

#include <stdckdint.h>
#include <stdlib.h>
#include <string.h>

constexpr uint32_t NIL = UINT32_MAX;

struct slot {
    uint32_t chain; /* next slot in the same bucket, or next free slot */
    uint32_t newer;
    uint32_t older;
    uint32_t hash;
};

struct ft_table {
    size_t capacity;
    size_t key_size;
    size_t value_size;
    size_t key_offset;
    size_t value_offset;
    size_t slot_size;
    size_t count;
    uint64_t evictions;
    uint32_t mask;
    uint32_t free_head;
    uint32_t unused; /* slots [unused, capacity) were never handed out */
    uint32_t newest;
    uint32_t oldest;
    uint32_t *buckets;
    unsigned char *slots;
    ft_table_evict_fn *evict;
    void *evict_ctx;
};

static size_t align8(size_t n)
{
    return (n + 7) & ~(size_t)7;
}

static uint32_t hash_key(const void *key, size_t size)
{
    const unsigned char *p = key;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < size; i++) {
        h ^= p[i];
        h *= 0x100000001b3ULL;
    }
    return (uint32_t)(h ^ (h >> 32));
}

static struct slot *slot_at(const struct ft_table *t, uint32_t index)
{
    return (struct slot *)(void *)(t->slots + (size_t)index * t->slot_size);
}

static void *slot_key(const struct ft_table *t, struct slot *s)
{
    return (unsigned char *)s + t->key_offset;
}

static void *slot_value(const struct ft_table *t, struct slot *s)
{
    return (unsigned char *)s + t->value_offset;
}

static uint32_t value_index(const struct ft_table *t, const void *value)
{
    size_t offset = (size_t)((const unsigned char *)value - t->slots) - t->value_offset;
    return (uint32_t)(offset / t->slot_size);
}

struct ft_table *ft_table_create(size_t capacity, size_t key_size, size_t value_size)
{
    if (capacity == 0 || capacity >= NIL / 2 || key_size == 0)
        return nullptr;

    struct ft_table *t = calloc(1, sizeof(*t));
    if (!t)
        return nullptr;

    t->capacity = capacity;
    t->key_size = key_size;
    t->value_size = value_size;
    t->key_offset = align8(sizeof(struct slot));
    t->value_offset = t->key_offset + align8(key_size);
    t->slot_size = t->value_offset + align8(value_size);

    size_t nbuckets = 16;
    while (nbuckets < capacity * 2)
        nbuckets *= 2;
    t->mask = (uint32_t)(nbuckets - 1);

    size_t slots_bytes;
    if (ckd_mul(&slots_bytes, capacity, t->slot_size)) {
        free(t);
        return nullptr;
    }
    t->buckets = malloc(nbuckets * sizeof(uint32_t));
    /* calloc keeps untouched slots out of resident memory until first use. */
    t->slots = calloc(1, slots_bytes);
    if (!t->buckets || !t->slots) {
        ft_table_destroy(t);
        return nullptr;
    }
    memset(t->buckets, 0xff, nbuckets * sizeof(uint32_t));
    t->free_head = NIL;
    t->newest = NIL;
    t->oldest = NIL;
    return t;
}

void ft_table_destroy(struct ft_table *t)
{
    if (!t)
        return;
    if (t->slots && t->evict) {
        for (void *v = ft_table_first(t); v; v = ft_table_next(t, v))
            t->evict(v, t->evict_ctx);
    }
    free(t->buckets);
    free(t->slots);
    free(t);
}

void ft_table_on_evict(struct ft_table *t, ft_table_evict_fn *fn, void *ctx)
{
    t->evict = fn;
    t->evict_ctx = ctx;
}

static uint32_t find_index(const struct ft_table *t, const void *key, uint32_t hash)
{
    for (uint32_t i = t->buckets[hash & t->mask]; i != NIL;) {
        struct slot *s = slot_at(t, i);
        if (s->hash == hash && memcmp(slot_key(t, s), key, t->key_size) == 0)
            return i;
        i = s->chain;
    }
    return NIL;
}

static void lru_unlink(struct ft_table *t, uint32_t index)
{
    struct slot *s = slot_at(t, index);
    if (s->newer != NIL)
        slot_at(t, s->newer)->older = s->older;
    else
        t->newest = s->older;
    if (s->older != NIL)
        slot_at(t, s->older)->newer = s->newer;
    else
        t->oldest = s->newer;
}

static void lru_push(struct ft_table *t, uint32_t index)
{
    struct slot *s = slot_at(t, index);
    s->newer = NIL;
    s->older = t->newest;
    if (t->newest != NIL)
        slot_at(t, t->newest)->newer = index;
    else
        t->oldest = index;
    t->newest = index;
}

static void release(struct ft_table *t, uint32_t index)
{
    struct slot *s = slot_at(t, index);
    uint32_t *link = &t->buckets[s->hash & t->mask];

    while (*link != index)
        link = &slot_at(t, *link)->chain;
    *link = s->chain;

    lru_unlink(t, index);
    if (t->evict)
        t->evict(slot_value(t, s), t->evict_ctx);
    s->chain = t->free_head;
    t->free_head = index;
    t->count--;
}

void *ft_table_find(const struct ft_table *t, const void *key)
{
    uint32_t i = find_index(t, key, hash_key(key, t->key_size));
    return i == NIL ? nullptr : slot_value(t, slot_at(t, i));
}

void *ft_table_touch(struct ft_table *t, const void *key)
{
    uint32_t i = find_index(t, key, hash_key(key, t->key_size));
    if (i == NIL)
        return nullptr;
    if (t->newest != i) {
        lru_unlink(t, i);
        lru_push(t, i);
    }
    return slot_value(t, slot_at(t, i));
}

void *ft_table_insert(struct ft_table *t, const void *key, bool *created)
{
    void *existing = ft_table_touch(t, key);
    if (created)
        *created = existing == nullptr;
    if (existing)
        return existing;

    uint32_t index;
    if (t->free_head != NIL) {
        index = t->free_head;
        t->free_head = slot_at(t, index)->chain;
    } else if (t->unused < t->capacity) {
        index = t->unused++;
    } else {
        index = t->oldest;
        release(t, index);
        t->free_head = slot_at(t, index)->chain;
        t->evictions++;
    }

    struct slot *s = slot_at(t, index);
    s->hash = hash_key(key, t->key_size);
    s->chain = t->buckets[s->hash & t->mask];
    t->buckets[s->hash & t->mask] = index;
    memcpy(slot_key(t, s), key, t->key_size);
    memset(slot_value(t, s), 0, t->value_size);
    lru_push(t, index);
    t->count++;
    return slot_value(t, s);
}

void ft_table_remove(struct ft_table *t, const void *key)
{
    uint32_t i = find_index(t, key, hash_key(key, t->key_size));
    if (i != NIL)
        release(t, i);
}

void ft_table_clear(struct ft_table *t)
{
    while (t->newest != NIL)
        release(t, t->newest);
}

const void *ft_table_key(const struct ft_table *t, const void *value)
{
    return slot_key(t, slot_at(t, value_index(t, value)));
}

void *ft_table_first(const struct ft_table *t)
{
    return t->newest == NIL ? nullptr : slot_value(t, slot_at(t, t->newest));
}

void *ft_table_next(const struct ft_table *t, const void *value)
{
    uint32_t older = slot_at(t, value_index(t, value))->older;
    return older == NIL ? nullptr : slot_value(t, slot_at(t, older));
}

size_t ft_table_count(const struct ft_table *t)
{
    return t->count;
}

size_t ft_table_capacity(const struct ft_table *t)
{
    return t->capacity;
}

uint64_t ft_table_evictions(const struct ft_table *t)
{
    return t->evictions;
}
