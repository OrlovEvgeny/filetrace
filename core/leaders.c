#include "filetrace/leaders.h"

#include "filetrace/clock.h"
#include "filetrace/format.h"

#include <inttypes.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The tip, the open five-second slot, takes every sample and is folded into each ring and the
 * lifetime slot when it closes. Slots keep Space-Saving tables: a count never falls below the
 * truth, a key a table lacks counted at most the table's smallest count (its floor), and what an
 * entry counted since it was created never exceeds the truth.
 */

constexpr uint32_t NONE = UINT32_MAX;
constexpr uint64_t COUNT_MAX = INT64_MAX;
constexpr uint64_t TIP_NS = 5 * FT_NS_PER_SEC;
constexpr size_t RINGS = FT_WINDOW_COUNT - 1;
constexpr size_t RING_SLOTS = 2 * FT_LEADER_SLOTS; /* the span and the one before it */
constexpr uint32_t MIN_TABLE = 8;
constexpr uint32_t MAX_ENTRIES = 1u << 20;
constexpr uint32_t DEFAULT_LIMIT = 50;
constexpr uint32_t PREVIOUS_RANKS = 50;
constexpr size_t TOP_FILES = 10;
/* Path bytes the store keeps for each configured entry; a file past the budget has no path. */
constexpr size_t PATH_BYTES_PER_ENTRY = 8 * 1024;

static const uint64_t slot_lengths[RINGS] = {
    5 * FT_NS_PER_SEC,   25 * FT_NS_PER_SEC,   75 * FT_NS_PER_SEC,
    300 * FT_NS_PER_SEC, 7200 * FT_NS_PER_SEC, 50400 * FT_NS_PER_SEC,
};

/* Short slots see few distinct files, so they get smaller tables than the configured size. */
static const unsigned table_shifts[RINGS] = {4, 4, 3, 2, 1, 1};

enum measure : uint8_t {
    BY_BYTES,
    BY_TRANSFERS,
    MEASURES,
};

constexpr uint8_t SKETCH = 0xff;
constexpr unsigned ENTRY_SET_BITS = 7; /* 128 registers: about 9% standard error */
constexpr unsigned WIDE_SET_BITS = 10; /* 1024 registers: about 3% */
constexpr unsigned RANK_MAX = 15;      /* registers are four bits wide */

/* Distinct hashes: exact up to FT_LEADER_EXACT_DESTINATIONS, then a HyperLogLog. */
struct set {
    union {
        uint32_t exact[FT_LEADER_EXACT_DESTINATIONS];
        uint8_t regs[(1u << ENTRY_SET_BITS) / 2];
    };
    uint8_t n; /* hashes held in exact, or SKETCH */
};

struct wide_set {
    union {
        uint32_t exact[FT_LEADER_EXACT_DESTINATIONS];
        uint8_t regs[(1u << WIDE_SET_BITS) / 2];
    };
    uint8_t n;
};

struct set_view {
    uint8_t *n;
    uint32_t *exact;
    uint8_t *regs;
    unsigned bits;
};

static struct set_view entry_view(struct set *s)
{
    return (struct set_view){&s->n, s->exact, s->regs, ENTRY_SET_BITS};
}

static struct set_view wide_view(struct wide_set *s)
{
    return (struct set_view){&s->n, s->exact, s->regs, WIDE_SET_BITS};
}

static uint64_t mix64(uint64_t h)
{
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdu;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53u;
    h ^= h >> 33;
    return h;
}

static uint32_t hash_bytes(const void *data, size_t size)
{
    const unsigned char *p = data;
    uint64_t h = 0xcbf29ce484222325u;
    for (size_t i = 0; i < size; i++) {
        h ^= p[i];
        h *= 0x100000001b3u;
    }
    return (uint32_t)(mix64(h) >> 32);
}

/* Natural logarithm of x >= 1, so the store needs no math library. */
static double log_of(double x)
{
    int halvings = 0;
    while (x >= 2.0) {
        x /= 2.0;
        halvings++;
    }
    /* ln(x) = 2 atanh(z) with z = (x - 1) / (x + 1), at most 1/3 here. */
    double z = (x - 1.0) / (x + 1.0);
    double term = z;
    double sum = 0.0;
    for (int i = 1; i < 40; i += 2) {
        sum += term / i;
        term *= z * z;
    }
    return 2.0 * sum + halvings * 0.69314718055994531;
}

static unsigned reg_get(const uint8_t *regs, uint32_t i)
{
    return (regs[i / 2] >> ((i & 1) * 4)) & 0xfu;
}

static void sketch_add(uint8_t *regs, unsigned bits, uint32_t h)
{
    uint32_t i = h >> (32 - bits);
    uint32_t rest = h << bits;
    unsigned rank = rest ? (unsigned)__builtin_clz(rest) + 1 : RANK_MAX;
    if (rank > RANK_MAX)
        rank = RANK_MAX;
    unsigned shift = (i & 1) * 4;
    if (rank > reg_get(regs, i))
        regs[i / 2] = (uint8_t)((regs[i / 2] & ~(0xfu << shift)) | (rank << shift));
}

static void set_to_sketch(struct set_view v)
{
    uint32_t held[FT_LEADER_EXACT_DESTINATIONS];
    uint8_t n = *v.n;

    memcpy(held, v.exact, n * sizeof(held[0]));
    memset(v.regs, 0, (1u << v.bits) / 2);
    for (uint8_t i = 0; i < n; i++)
        sketch_add(v.regs, v.bits, held[i]);
    *v.n = SKETCH;
}

static void set_add(struct set_view v, uint32_t h)
{
    if (*v.n != SKETCH) {
        for (uint8_t i = 0; i < *v.n; i++) {
            if (v.exact[i] == h)
                return;
        }
        if (*v.n < FT_LEADER_EXACT_DESTINATIONS) {
            v.exact[(*v.n)++] = h;
            return;
        }
        set_to_sketch(v);
    }
    sketch_add(v.regs, v.bits, h);
}

/* Both sides have the same number of registers. */
static void set_merge(struct set_view d, uint8_t n, const uint32_t *exact, const uint8_t *regs)
{
    if (n != SKETCH) {
        for (uint8_t i = 0; i < n; i++)
            set_add(d, exact[i]);
        return;
    }
    if (*d.n != SKETCH)
        set_to_sketch(d);
    for (size_t i = 0; i < (1u << d.bits) / 2; i++) {
        unsigned a = d.regs[i];
        unsigned b = regs[i];
        unsigned lo = (a & 0xfu) > (b & 0xfu) ? a & 0xfu : b & 0xfu;
        unsigned hi = (a >> 4) > (b >> 4) ? a >> 4 : b >> 4;
        d.regs[i] = (uint8_t)(hi << 4 | lo);
    }
}

static uint64_t set_count(uint8_t n, const uint8_t *regs, unsigned bits)
{
    if (n != SKETCH)
        return n;

    uint32_t m = 1u << bits;
    uint32_t zeros = 0;
    double sum = 0.0;
    for (uint32_t i = 0; i < m; i++) {
        unsigned r = reg_get(regs, i);
        sum += 1.0 / (double)(1u << r);
        if (r == 0)
            zeros++;
    }
    double estimate = 0.7213 / (1.0 + 1.079 / m) * m * m / sum;
    if (estimate <= 2.5 * m && zeros)
        estimate = m * log_of((double)m / zeros);
    uint64_t count = (uint64_t)(estimate + 0.5);
    /* It became a sketch on its first hash past the exact ones. */
    return count > FT_LEADER_EXACT_DESTINATIONS ? count : FT_LEADER_EXACT_DESTINATIONS + 1;
}

static uint64_t sat_sum(uint64_t a, uint64_t b)
{
    return a >= COUNT_MAX || b >= COUNT_MAX - a ? COUNT_MAX : a + b;
}

static void sat_add(uint64_t *c, uint64_t v)
{
    *c = sat_sum(*c, v);
}

static uint64_t sat_diff(uint64_t a, uint64_t b)
{
    return a > b ? a - b : 0;
}

struct record {
    uint32_t hash;
    uint32_t next; /* in its hash chain, or the next free record */
    uint32_t refs; /* 0: free */
    uint32_t pad;
};

struct file_record {
    struct record r;
    struct ft_file_id id;
    char *path; /* the first one seen; nullptr while unknown */
    uint64_t size;
    bool deleted;
};

struct addr_record {
    struct record r;
    struct ft_endpoint addr; /* port 0 */
};

struct name_record {
    struct record r;
    char name[FT_COMM_MAX];
};

static_assert(offsetof(struct file_record, id) == sizeof(struct record));
static_assert(offsetof(struct addr_record, addr) == sizeof(struct record));
static_assert(offsetof(struct name_record, name) == sizeof(struct record));

/* Interned files, remote addresses or process names, shared by every slot. */
struct registry {
    unsigned char *recs;
    uint32_t *buckets;
    size_t rec_size;
    size_t key_size;
    uint32_t used; /* records handed out: [0, used) */
    uint32_t cap;
    uint32_t nbuckets; /* a power of two */
    uint32_t free_head;
    bool paths; /* records are struct file_record */
};

struct stats {
    uint64_t bytes; /* what was counted for this entry itself */
    uint64_t bytes_exact;
    uint64_t transfers;
    uint64_t first_ns;
    uint64_t last_ns;
    uint64_t sender_bytes[FT_LEADER_SENDERS];
    uint64_t sender_transfers[FT_LEADER_SENDERS];
    uint32_t sender[FT_LEADER_SENDERS]; /* name records, or NONE */
    uint8_t confidence;                 /* FT_CONF_ANY until something is counted */
    uint8_t exact_method;
    uint8_t other_method;
    bool more_senders;
    struct set set; /* remote addresses of a file, or files sent to an address */
};

struct entry {
    uint32_t key;             /* record in the pool's registry; NONE when the entry is free */
    uint32_t next;            /* in its hash chain, or the next free entry */
    uint32_t pos[MEASURES];   /* place in each table's heap; NONE when the table lacks it */
    uint64_t count[MEASURES]; /* the Space-Saving figure while in that table */
    struct stats s;
};

/* Tables of one kind of key, one per measure, over one set of entries. */
struct pool {
    struct registry *keys;
    struct entry *e;
    uint32_t *buckets;
    uint32_t *heap[MEASURES]; /* min-heaps of entries by count */
    uint32_t len[MEASURES];
    uint32_t hcap[MEASURES];
    uint32_t used; /* entries handed out: [0, used) */
    uint32_t ecap;
    uint32_t nbuckets;
    uint32_t free_head;
    uint32_t table; /* entries one table holds at most */
    uint8_t measures;
    bool capped[MEASURES]; /* the table dropped a key */
};

struct totals {
    uint64_t bytes;
    uint64_t bytes_exact;
    uint64_t transfers;
    uint64_t addressed_transfers; /* of transfers, those with a known remote address */
    struct wide_set files;
    struct wide_set public_addrs;
    struct wide_set private_addrs;
    struct wide_set senders;
    struct wide_set scripts;
};

struct slot {
    struct pool files;     /* by bytes and by transfers */
    struct pool addrs;     /* by bytes */
    struct totals *totals; /* nullptr until something is counted */
};

struct ring {
    uint64_t slot_ns;
    uint64_t head; /* absolute index of the open slot, which is slots[head % RING_SLOTS] */
    struct slot slots[RING_SLOTS];
};

struct ft_leaders {
    struct registry files;
    struct registry addrs;
    struct registry names;
    struct slot tip;
    uint64_t tip_index; /* absolute index of the tip's five seconds */
    struct ring rings[RINGS];
    struct slot lifetime;
    uint64_t first_ns; /* 0 until the store has seen a time */
    uint64_t latest_ns;
    uint32_t *scratch; /* entries of the tip waiting for a place in a table */
    uint32_t scratch_cap;
    size_t memory;
    size_t path_bytes;
    size_t path_budget;
};

static void *mem_resize(struct ft_leaders *l, void *p, size_t old_size, size_t new_size)
{
    void *q = realloc(p, new_size);
    if (q)
        l->memory = l->memory - old_size + new_size;
    return q;
}

static void mem_free(struct ft_leaders *l, void *p, size_t size)
{
    if (!p)
        return;
    free(p);
    l->memory -= size;
}

static void path_free(struct ft_leaders *l, struct file_record *f)
{
    if (!f->path)
        return;
    size_t size = strlen(f->path) + 1;
    mem_free(l, f->path, size);
    l->path_bytes -= size;
    f->path = nullptr;
}

static struct record *rec_at(const struct registry *g, uint32_t i)
{
    return (struct record *)(void *)(g->recs + (size_t)i * g->rec_size);
}

static const struct file_record *file_at(const struct ft_leaders *l, uint32_t i)
{
    return (const struct file_record *)rec_at(&l->files, i);
}

static void reg_init(struct registry *g, size_t rec_size, size_t key_size, bool paths)
{
    *g = (struct registry){
        .rec_size = rec_size, .key_size = key_size, .free_head = NONE, .paths = paths};
}

static uint32_t reg_find(const struct registry *g, const void *key, uint32_t hash)
{
    if (!g->nbuckets)
        return NONE;
    for (uint32_t i = g->buckets[hash & (g->nbuckets - 1)]; i != NONE;) {
        const struct record *r = rec_at(g, i);
        if (r->hash == hash && memcmp(r + 1, key, g->key_size) == 0)
            return i;
        i = r->next;
    }
    return NONE;
}

static bool reg_grow(struct ft_leaders *l, struct registry *g)
{
    if (g->cap >= UINT32_MAX / 4)
        return false;
    uint32_t cap = g->cap ? g->cap * 2 : 64;

    if (cap > g->nbuckets) {
        uint32_t *buckets = mem_resize(l, nullptr, 0, cap * sizeof(uint32_t));
        if (!buckets)
            return false;
        mem_free(l, g->buckets, g->nbuckets * sizeof(uint32_t));
        memset(buckets, 0xff, cap * sizeof(uint32_t));
        g->buckets = buckets;
        g->nbuckets = cap;
        for (uint32_t i = 0; i < g->used; i++) {
            struct record *r = rec_at(g, i);
            if (r->refs == 0)
                continue;
            uint32_t *head = &g->buckets[r->hash & (cap - 1)];
            r->next = *head;
            *head = i;
        }
    }
    unsigned char *recs = mem_resize(l, g->recs, g->cap * g->rec_size, cap * g->rec_size);
    if (!recs)
        return false;
    g->recs = recs;
    g->cap = cap;
    return true;
}

/* Finds or adds the record and takes a reference to it; NONE when memory runs out. */
static uint32_t reg_acquire(struct ft_leaders *l, struct registry *g, const void *key,
                            uint32_t hash)
{
    uint32_t i = reg_find(g, key, hash);

    if (i == NONE) {
        if (g->free_head != NONE) {
            i = g->free_head;
            g->free_head = rec_at(g, i)->next;
        } else {
            if (g->used == g->cap && !reg_grow(l, g))
                return NONE;
            i = g->used++;
        }
        struct record *r = rec_at(g, i);
        memset(r, 0, g->rec_size);
        memcpy(r + 1, key, g->key_size);
        r->hash = hash;
        uint32_t *head = &g->buckets[hash & (g->nbuckets - 1)];
        r->next = *head;
        *head = i;
    }
    rec_at(g, i)->refs++;
    return i;
}

static void reg_ref(struct registry *g, uint32_t i)
{
    rec_at(g, i)->refs++;
}

static void reg_release(struct ft_leaders *l, struct registry *g, uint32_t i)
{
    struct record *r = rec_at(g, i);
    if (--r->refs)
        return;

    uint32_t *link = &g->buckets[r->hash & (g->nbuckets - 1)];
    while (*link != i)
        link = &rec_at(g, *link)->next;
    *link = r->next;
    if (g->paths)
        path_free(l, (struct file_record *)r);
    r->next = g->free_head;
    g->free_head = i;
}

static void reg_destroy(struct ft_leaders *l, struct registry *g)
{
    for (uint32_t i = 0; g->paths && i < g->used; i++) {
        struct file_record *f = (struct file_record *)rec_at(g, i);
        if (f->r.refs)
            path_free(l, f);
    }
    mem_free(l, g->recs, g->cap * g->rec_size);
    mem_free(l, g->buckets, g->nbuckets * sizeof(uint32_t));
}

static void stats_init(struct stats *s)
{
    memset(s, 0, sizeof(*s));
    s->first_ns = UINT64_MAX;
    s->confidence = FT_CONF_ANY;
    for (size_t k = 0; k < FT_LEADER_SENDERS; k++)
        s->sender[k] = NONE;
}

static void stats_release(struct ft_leaders *l, struct stats *s)
{
    for (size_t k = 0; k < FT_LEADER_SENDERS; k++) {
        if (s->sender[k] != NONE)
            reg_release(l, &l->names, s->sender[k]);
    }
}

/* What one sample adds to an entry. */
struct counted {
    uint64_t ts_ns;
    uint64_t bytes;
    uint32_t sender;
    uint32_t item; /* the hash it adds to the entry's set */
    bool has_item;
    bool started;
    bool exact;
    uint8_t method;
    uint8_t confidence;
};

static void senders_count(struct ft_leaders *l, struct stats *s, const struct counted *c)
{
    uint64_t transfers = c->started ? 1u : 0u;

    for (size_t k = 0; k < FT_LEADER_SENDERS; k++) {
        if (s->sender[k] == c->sender) {
            sat_add(&s->sender_bytes[k], c->bytes);
            sat_add(&s->sender_transfers[k], transfers);
            return;
        }
    }
    size_t k = 0;
    while (k < FT_LEADER_SENDERS && s->sender[k] != NONE)
        k++;
    if (k == FT_LEADER_SENDERS) {
        /* Full: a name that sent more than the smallest one listed takes its place. */
        s->more_senders = true;
        k = 0;
        for (size_t j = 1; j < FT_LEADER_SENDERS; j++) {
            if (s->sender_bytes[j] < s->sender_bytes[k])
                k = j;
        }
        if (c->bytes <= s->sender_bytes[k])
            return;
        reg_release(l, &l->names, s->sender[k]);
    }
    reg_ref(&l->names, c->sender);
    s->sender[k] = c->sender;
    s->sender_bytes[k] = c->bytes;
    s->sender_transfers[k] = transfers;
}

static void stats_count(struct ft_leaders *l, struct stats *s, const struct counted *c)
{
    sat_add(&s->bytes, c->bytes);
    if (c->exact) {
        sat_add(&s->bytes_exact, c->bytes);
        s->exact_method = c->method;
    } else {
        s->other_method = c->method;
    }
    if (c->started)
        sat_add(&s->transfers, 1);
    if (c->ts_ns < s->first_ns)
        s->first_ns = c->ts_ns;
    if (c->ts_ns > s->last_ns)
        s->last_ns = c->ts_ns;
    if (s->confidence == FT_CONF_ANY || c->confidence < s->confidence)
        s->confidence = c->confidence;
    senders_count(l, s, c);
    if (c->has_item)
        set_add(entry_view(&s->set), c->item);
}

/* With owned set, the names an entry keeps hold references. */
static void senders_merge(struct ft_leaders *l, struct stats *d, const struct stats *s, bool owned)
{
    struct {
        uint32_t name;
        uint64_t bytes;
        uint64_t transfers;
    } all[2 * FT_LEADER_SENDERS];
    size_t n = 0;

    for (size_t k = 0; k < FT_LEADER_SENDERS; k++) {
        if (d->sender[k] != NONE)
            all[n++] = (typeof(all[0])){d->sender[k], d->sender_bytes[k], d->sender_transfers[k]};
    }
    for (size_t k = 0; k < FT_LEADER_SENDERS; k++) {
        if (s->sender[k] == NONE)
            continue;
        size_t j = 0;
        while (j < n && all[j].name != s->sender[k])
            j++;
        if (j < n) {
            sat_add(&all[j].bytes, s->sender_bytes[k]);
            sat_add(&all[j].transfers, s->sender_transfers[k]);
            continue;
        }
        all[n++] = (typeof(all[0])){s->sender[k], s->sender_bytes[k], s->sender_transfers[k]};
        if (owned)
            reg_ref(&l->names, s->sender[k]);
    }
    for (size_t i = 1; i < n; i++) {
        for (size_t j = i; j > 0 && all[j].bytes > all[j - 1].bytes; j--) {
            typeof(all[0]) t = all[j];
            all[j] = all[j - 1];
            all[j - 1] = t;
        }
    }
    if (n > FT_LEADER_SENDERS) {
        d->more_senders = true;
        for (size_t k = FT_LEADER_SENDERS; owned && k < n; k++)
            reg_release(l, &l->names, all[k].name);
    }
    for (size_t k = 0; k < FT_LEADER_SENDERS; k++) {
        d->sender[k] = k < n ? all[k].name : NONE;
        d->sender_bytes[k] = k < n ? all[k].bytes : 0;
        d->sender_transfers[k] = k < n ? all[k].transfers : 0;
    }
}

static void stats_merge(struct ft_leaders *l, struct stats *d, const struct stats *s, bool owned)
{
    sat_add(&d->bytes, s->bytes);
    sat_add(&d->bytes_exact, s->bytes_exact);
    sat_add(&d->transfers, s->transfers);
    if (s->first_ns < d->first_ns)
        d->first_ns = s->first_ns;
    if (s->last_ns > d->last_ns)
        d->last_ns = s->last_ns;
    if (d->confidence == FT_CONF_ANY || s->confidence < d->confidence)
        d->confidence = s->confidence;
    if (!d->exact_method)
        d->exact_method = s->exact_method;
    if (!d->other_method)
        d->other_method = s->other_method;
    d->more_senders = d->more_senders || s->more_senders;
    senders_merge(l, d, s, owned);
    set_merge(entry_view(&d->set), s->set.n, s->set.exact, s->set.regs);
}

static void stats_copy(struct ft_leaders *l, struct stats *d, const struct stats *s)
{
    *d = *s;
    for (size_t k = 0; k < FT_LEADER_SENDERS; k++) {
        if (d->sender[k] != NONE)
            reg_ref(&l->names, d->sender[k]);
    }
}

static void pool_init(struct pool *p, struct registry *keys, uint32_t table, uint8_t measures)
{
    *p = (struct pool){.keys = keys, .free_head = NONE, .table = table, .measures = measures};
}

static uint32_t pool_bucket(const struct pool *p, uint32_t key)
{
    uint32_t h = key * 0x9e3779b1u;
    return (h ^ (h >> 16)) & (p->nbuckets - 1);
}

static uint32_t pool_find(const struct pool *p, uint32_t key)
{
    if (!p->nbuckets)
        return NONE;
    for (uint32_t i = p->buckets[pool_bucket(p, key)]; i != NONE; i = p->e[i].next) {
        if (p->e[i].key == key)
            return i;
    }
    return NONE;
}

static bool in_any_table(const struct pool *p, uint32_t i)
{
    for (size_t m = 0; m < p->measures; m++) {
        if (p->e[i].pos[m] != NONE)
            return true;
    }
    return false;
}

static bool pool_grow(struct ft_leaders *l, struct pool *p)
{
    uint32_t most = p->table * p->measures;
    uint32_t cap = p->ecap ? 2 * p->ecap : 16;
    if (cap > most)
        cap = most;
    if (cap <= p->ecap)
        return false;

    uint32_t nbuckets = 16;
    while (nbuckets < cap)
        nbuckets *= 2;
    if (nbuckets > p->nbuckets) {
        uint32_t *buckets = mem_resize(l, nullptr, 0, nbuckets * sizeof(uint32_t));
        if (!buckets)
            return false;
        mem_free(l, p->buckets, p->nbuckets * sizeof(uint32_t));
        memset(buckets, 0xff, nbuckets * sizeof(uint32_t));
        p->buckets = buckets;
        p->nbuckets = nbuckets;
        for (uint32_t i = 0; i < p->used; i++) {
            if (p->e[i].key == NONE)
                continue;
            uint32_t *head = &p->buckets[pool_bucket(p, p->e[i].key)];
            p->e[i].next = *head;
            *head = i;
        }
    }
    struct entry *e = mem_resize(l, p->e, p->ecap * sizeof(*e), cap * sizeof(*e));
    if (!e)
        return false;
    p->e = e;
    p->ecap = cap;
    return true;
}

static uint32_t entry_alloc(struct ft_leaders *l, struct pool *p, uint32_t key)
{
    uint32_t i;

    if (p->free_head != NONE) {
        i = p->free_head;
        p->free_head = p->e[i].next;
    } else {
        if (p->used == p->ecap && !pool_grow(l, p))
            return NONE;
        i = p->used++;
    }
    struct entry *e = &p->e[i];
    e->key = key;
    for (size_t m = 0; m < MEASURES; m++) {
        e->pos[m] = NONE;
        e->count[m] = 0;
    }
    stats_init(&e->s);
    uint32_t *head = &p->buckets[pool_bucket(p, key)];
    e->next = *head;
    *head = i;
    reg_ref(p->keys, key);
    return i;
}

static void entry_free(struct ft_leaders *l, struct pool *p, uint32_t i)
{
    struct entry *e = &p->e[i];
    uint32_t *link = &p->buckets[pool_bucket(p, e->key)];

    while (*link != i)
        link = &p->e[*link].next;
    *link = e->next;
    stats_release(l, &e->s);
    reg_release(l, p->keys, e->key);
    e->key = NONE;
    e->next = p->free_head;
    p->free_head = i;
}

static void heap_set(struct pool *p, size_t m, uint32_t pos, uint32_t i)
{
    p->heap[m][pos] = i;
    p->e[i].pos[m] = pos;
}

static void sift_up(struct pool *p, size_t m, uint32_t pos)
{
    uint32_t i = p->heap[m][pos];
    uint64_t c = p->e[i].count[m];

    while (pos > 0) {
        uint32_t parent = (pos - 1) / 2;
        uint32_t j = p->heap[m][parent];
        if (p->e[j].count[m] <= c)
            break;
        heap_set(p, m, pos, j);
        pos = parent;
    }
    heap_set(p, m, pos, i);
}

static void sift_down(struct pool *p, size_t m, uint32_t pos)
{
    uint32_t i = p->heap[m][pos];
    uint64_t c = p->e[i].count[m];

    for (;;) {
        uint32_t child = 2 * pos + 1;
        if (child >= p->len[m])
            break;
        if (child + 1 < p->len[m] &&
            p->e[p->heap[m][child + 1]].count[m] < p->e[p->heap[m][child]].count[m])
            child++;
        uint32_t j = p->heap[m][child];
        if (p->e[j].count[m] >= c)
            break;
        heap_set(p, m, pos, j);
        pos = child;
    }
    heap_set(p, m, pos, i);
}

static bool heap_push(struct ft_leaders *l, struct pool *p, size_t m, uint32_t i)
{
    if (p->len[m] == p->hcap[m]) {
        uint32_t cap = p->hcap[m] ? 2 * p->hcap[m] : 16;
        if (cap > p->table)
            cap = p->table;
        uint32_t *heap = cap > p->hcap[m] ? mem_resize(l, p->heap[m], p->hcap[m] * sizeof(uint32_t),
                                                       cap * sizeof(uint32_t))
                                          : nullptr;
        if (!heap)
            return false;
        p->heap[m] = heap;
        p->hcap[m] = cap;
    }
    uint32_t pos = p->len[m]++;
    heap_set(p, m, pos, i);
    sift_up(p, m, pos);
    return true;
}

/* The count a key absent from the table may have reached. */
static uint64_t table_floor(const struct pool *p, size_t m)
{
    return p->capped[m] && p->len[m] ? p->e[p->heap[m][0]].count[m] : 0;
}

static uint64_t table_min(const struct pool *p, size_t m)
{
    return p->e[p->heap[m][0]].count[m];
}

/* Returns the count of the entry it takes out, and frees the entry when no table holds it. */
static uint64_t evict_min(struct ft_leaders *l, struct pool *p, size_t m)
{
    uint32_t i = p->heap[m][0];
    uint64_t c = p->e[i].count[m];

    p->e[i].pos[m] = NONE;
    p->capped[m] = true;
    if (--p->len[m] > 0) {
        heap_set(p, m, 0, p->heap[m][p->len[m]]);
        sift_down(p, m, 0);
    }
    if (!in_any_table(p, i))
        entry_free(l, p, i);
    return c;
}

/* Puts an entry the table lacks into it with the given count, if it ranks high enough. */
static void table_offer(struct ft_leaders *l, struct pool *p, size_t m, uint32_t i, uint64_t count)
{
    if (p->len[m] == p->table) {
        if (table_min(p, m) >= count) {
            p->capped[m] = true;
            return;
        }
        evict_min(l, p, m);
    }
    p->e[i].count[m] = count;
    if (!heap_push(l, p, m, i))
        p->capped[m] = true;
}

static void pool_clear(struct ft_leaders *l, struct pool *p)
{
    for (uint32_t i = 0; i < p->used; i++) {
        struct entry *e = &p->e[i];
        if (e->key == NONE)
            continue;
        stats_release(l, &e->s);
        reg_release(l, p->keys, e->key);
    }
    mem_free(l, p->e, p->ecap * sizeof(*p->e));
    mem_free(l, p->buckets, p->nbuckets * sizeof(uint32_t));
    for (size_t m = 0; m < MEASURES; m++)
        mem_free(l, p->heap[m], p->hcap[m] * sizeof(uint32_t));
    pool_init(p, p->keys, p->table, p->measures);
}

/* The Space-Saving update: a key a full table lacks replaces the entry with the smallest count. */
static void pool_count(struct ft_leaders *l, struct pool *p, uint32_t key, const struct counted *c)
{
    uint64_t weight[MEASURES] = {[BY_BYTES] = c->bytes, [BY_TRANSFERS] = c->started ? 1u : 0u};
    uint32_t i = pool_find(p, key);

    if (i == NONE) {
        uint64_t base[MEASURES] = {0};
        bool any = false;
        for (size_t m = 0; m < p->measures; m++) {
            if (!weight[m])
                continue;
            any = true;
            base[m] = p->len[m] == p->table ? evict_min(l, p, m) : table_floor(p, m);
        }
        if (!any || (i = entry_alloc(l, p, key)) == NONE)
            return;
        for (size_t m = 0; m < p->measures; m++) {
            if (!weight[m])
                continue;
            p->e[i].count[m] = sat_sum(base[m], weight[m]);
            if (!heap_push(l, p, m, i))
                p->capped[m] = true;
        }
        if (!in_any_table(p, i)) {
            entry_free(l, p, i);
            return;
        }
    } else {
        for (size_t m = 0; m < p->measures; m++) {
            if (!weight[m])
                continue;
            if (p->e[i].pos[m] != NONE) {
                sat_add(&p->e[i].count[m], weight[m]);
                sift_down(p, m, p->e[i].pos[m]);
                continue;
            }
            uint64_t base = p->len[m] == p->table ? evict_min(l, p, m) : table_floor(p, m);
            p->e[i].count[m] = sat_sum(base, weight[m]);
            if (!heap_push(l, p, m, i))
                p->capped[m] = true;
        }
    }
    stats_count(l, &p->e[i].s, c);
}

/* A key of s that d's table lacks takes a place in it if its count ranks high enough. */
static void fold_offer(struct ft_leaders *l, struct pool *d, size_t m, const struct entry *src,
                       uint64_t count)
{
    uint32_t i = pool_find(d, src->key);

    if (i != NONE) {
        table_offer(l, d, m, i, count);
        return;
    }
    if (d->len[m] == d->table) {
        if (table_min(d, m) >= count) {
            d->capped[m] = true;
            return;
        }
        evict_min(l, d, m);
    }
    i = entry_alloc(l, d, src->key);
    if (i == NONE) {
        d->capped[m] = true;
        return;
    }
    stats_copy(l, &d->e[i].s, &src->s);
    d->e[i].count[m] = count;
    if (!heap_push(l, d, m, i)) {
        d->capped[m] = true;
        entry_free(l, d, i);
    }
}

/*
 * Merges the tables of s into those of d and keeps the largest counts that fit. A key one side
 * lacks is taken to have counted that side's floor there, so every count stays above the truth.
 */
static void pool_fold(struct ft_leaders *l, struct pool *d, const struct pool *s)
{
    uint64_t dfloor[MEASURES] = {0};
    uint64_t sfloor[MEASURES] = {0};

    for (size_t m = 0; m < d->measures; m++) {
        dfloor[m] = table_floor(d, m);
        sfloor[m] = table_floor(s, m);
    }

    /* Every key d holds takes its part from s before any of them can be evicted. */
    for (uint32_t j = 0; j < d->used; j++) {
        if (d->e[j].key == NONE)
            continue;
        uint32_t k = pool_find(s, d->e[j].key);
        if (k != NONE)
            stats_merge(l, &d->e[j].s, &s->e[k].s, true);
        for (size_t m = 0; m < d->measures; m++) {
            if (d->e[j].pos[m] == NONE)
                continue;
            uint64_t part = k != NONE && s->e[k].pos[m] != NONE ? s->e[k].count[m] : sfloor[m];
            if (!part)
                continue;
            sat_add(&d->e[j].count[m], part);
            sift_down(d, m, d->e[j].pos[m]);
        }
    }

    /* Then the keys a table of d lacks compete for its places, listed before any is taken. */
    for (size_t m = 0; m < d->measures; m++) {
        uint32_t n = 0;
        for (uint32_t k = 0; k < s->used && n < l->scratch_cap; k++) {
            const struct entry *src = &s->e[k];
            if (src->key == NONE || src->pos[m] == NONE)
                continue;
            uint32_t j = pool_find(d, src->key);
            if (j == NONE || d->e[j].pos[m] == NONE)
                l->scratch[n++] = k;
        }
        for (uint32_t i = 0; i < n; i++) {
            const struct entry *src = &s->e[l->scratch[i]];
            fold_offer(l, d, m, src, sat_sum(dfloor[m], src->count[m]));
        }
        d->capped[m] = d->capped[m] || s->capped[m];
    }
}

static void slot_init(struct ft_leaders *l, struct slot *s, uint32_t table)
{
    pool_init(&s->files, &l->files, table, 2);
    pool_init(&s->addrs, &l->addrs, table / 2 > MIN_TABLE ? table / 2 : MIN_TABLE, 1);
    s->totals = nullptr;
}

static struct totals *slot_totals(struct ft_leaders *l, struct slot *s)
{
    if (!s->totals) {
        s->totals = mem_resize(l, nullptr, 0, sizeof(*s->totals));
        if (s->totals)
            memset(s->totals, 0, sizeof(*s->totals));
    }
    return s->totals;
}

static void slot_clear(struct ft_leaders *l, struct slot *s)
{
    pool_clear(l, &s->files);
    pool_clear(l, &s->addrs);
    mem_free(l, s->totals, sizeof(*s->totals));
    s->totals = nullptr;
}

static void totals_merge(struct totals *d, const struct totals *s)
{
    sat_add(&d->bytes, s->bytes);
    sat_add(&d->bytes_exact, s->bytes_exact);
    sat_add(&d->transfers, s->transfers);
    sat_add(&d->addressed_transfers, s->addressed_transfers);
    struct wide_set *ds[] = {&d->files, &d->public_addrs, &d->private_addrs, &d->senders,
                             &d->scripts};
    const struct wide_set *ss[] = {&s->files, &s->public_addrs, &s->private_addrs, &s->senders,
                                   &s->scripts};
    for (size_t i = 0; i < FT_ARRAY_LEN(ds); i++)
        set_merge(wide_view(ds[i]), ss[i]->n, ss[i]->exact, ss[i]->regs);
}

static void slot_fold(struct ft_leaders *l, struct slot *d, const struct slot *s)
{
    struct totals *t = slot_totals(l, d);
    if (!t)
        return;
    totals_merge(t, s->totals);
    pool_fold(l, &d->files, &s->files);
    pool_fold(l, &d->addrs, &s->addrs);
}

static void ring_rotate(struct ft_leaders *l, struct ring *r, uint64_t head)
{
    if (head <= r->head)
        return;
    /* After a long pause every slot is cleared once, however much time passed. */
    uint64_t steps = head - r->head < RING_SLOTS ? head - r->head : RING_SLOTS;
    for (uint64_t k = head - steps + 1; k <= head; k++)
        slot_clear(l, &r->slots[k % RING_SLOTS]);
    r->head = head;
}

static void close_tip(struct ft_leaders *l)
{
    if (!l->tip.totals)
        return;
    for (size_t i = 0; i < RINGS; i++) {
        struct ring *r = &l->rings[i];
        slot_fold(l, &r->slots[r->head % RING_SLOTS], &l->tip);
    }
    slot_fold(l, &l->lifetime, &l->tip);
    slot_clear(l, &l->tip);
}

/* Moves every slot forward to t; a time before the latest one changes nothing. */
static void advance(struct ft_leaders *l, uint64_t t)
{
    if (l->first_ns == 0) {
        l->first_ns = t ? t : 1;
        l->latest_ns = t;
        l->tip_index = t / TIP_NS;
        for (size_t i = 0; i < RINGS; i++)
            l->rings[i].head = t / l->rings[i].slot_ns;
        return;
    }
    if (t <= l->latest_ns)
        return;
    l->latest_ns = t;
    if (t / TIP_NS != l->tip_index) {
        close_tip(l);
        l->tip_index = t / TIP_NS;
    }
    for (size_t i = 0; i < RINGS; i++)
        ring_rotate(l, &l->rings[i], t / l->rings[i].slot_ns);
}

struct ft_leaders *ft_leaders_create(const struct ft_leaders_config *cfg)
{
    if (cfg->entries == 0)
        return nullptr;
    struct ft_leaders *l = calloc(1, sizeof(*l));
    if (!l)
        return nullptr;

    uint32_t entries = cfg->entries < MAX_ENTRIES ? (uint32_t)cfg->entries : MAX_ENTRIES;
    l->memory = sizeof(*l);
    l->path_budget = entries * PATH_BYTES_PER_ENTRY;
    reg_init(&l->files, sizeof(struct file_record), sizeof(struct ft_file_id), true);
    reg_init(&l->addrs, sizeof(struct addr_record), sizeof(struct ft_endpoint), false);
    reg_init(&l->names, sizeof(struct name_record), FT_COMM_MAX, false);
    slot_init(l, &l->tip, 2 * entries);
    slot_init(l, &l->lifetime, 2 * entries);
    l->scratch_cap = l->tip.files.table;
    l->scratch = mem_resize(l, nullptr, 0, l->scratch_cap * sizeof(uint32_t));
    if (!l->scratch) {
        free(l);
        return nullptr;
    }
    for (size_t i = 0; i < RINGS; i++) {
        struct ring *r = &l->rings[i];
        uint32_t table = entries >> table_shifts[i];
        r->slot_ns = slot_lengths[i];
        for (size_t k = 0; k < RING_SLOTS; k++)
            slot_init(l, &r->slots[k], table > MIN_TABLE ? table : MIN_TABLE);
    }
    return l;
}

void ft_leaders_destroy(struct ft_leaders *l)
{
    if (!l)
        return;
    slot_clear(l, &l->tip);
    slot_clear(l, &l->lifetime);
    for (size_t i = 0; i < RINGS; i++) {
        for (size_t k = 0; k < RING_SLOTS; k++)
            slot_clear(l, &l->rings[i].slots[k]);
    }
    reg_destroy(l, &l->files);
    reg_destroy(l, &l->addrs);
    reg_destroy(l, &l->names);
    mem_free(l, l->scratch, l->scratch_cap * sizeof(uint32_t));
    free(l);
}

size_t ft_leaders_memory(const struct ft_leaders *l)
{
    return l ? l->memory : 0;
}

static void file_describe(struct ft_leaders *l, uint32_t i, const struct ft_leader_sample *s)
{
    struct file_record *f = (struct file_record *)rec_at(&l->files, i);

    f->size = s->file_size;
    f->deleted = s->deleted;
    if (!f->path && s->path && s->path[0]) {
        size_t size = strnlen(s->path, FT_PATH_MAX - 1) + 1;
        if (size > l->path_budget - l->path_bytes)
            return;
        f->path = mem_resize(l, nullptr, 0, size);
        if (f->path) {
            ft_strlcpy(f->path, s->path, size);
            l->path_bytes += size;
        }
    }
}

void ft_leaders_add(struct ft_leaders *l, const struct ft_leader_sample *s)
{
    if (!l || (!s->started && s->bytes == 0))
        return;
    advance(l, s->ts_ns);
    struct totals *t = slot_totals(l, &l->tip);
    if (!t)
        return;

    /* A sample older than the tip is counted as if it had just happened. */
    uint64_t tip_start = l->tip_index * TIP_NS;
    struct counted c = {
        .ts_ns = s->ts_ns > tip_start ? s->ts_ns : tip_start,
        .bytes = s->bytes,
        .started = s->started,
        .exact = s->confidence == FT_CONF_EXACT,
        .method = s->method,
        .confidence = s->confidence,
    };
    sat_add(&t->bytes, s->bytes);
    if (c.exact)
        sat_add(&t->bytes_exact, s->bytes);
    if (s->started)
        sat_add(&t->transfers, 1);

    struct ft_file_id id = {.dev = s->file.dev, .ino = s->file.ino, .instance = s->file.instance};
    uint32_t file_hash = hash_bytes(&id, sizeof(id));
    char name[FT_COMM_MAX] = {0};
    ft_strlcpy(name, s->sender ? s->sender : "", sizeof(name));
    uint32_t name_hash = hash_bytes(name, sizeof(name));
    set_add(wide_view(&t->files), file_hash);
    set_add(wide_view(&t->senders), name_hash);
    if (s->script && s->script[0])
        set_add(wide_view(&t->scripts), hash_bytes(s->script, strlen(s->script)));

    struct ft_endpoint addr = {.family = s->remote.family};
    uint32_t addr_hash = 0;
    if (addr.family) {
        memcpy(addr.addr, s->remote.addr, sizeof(addr.addr));
        addr_hash = hash_bytes(&addr, sizeof(addr));
        set_add(wide_view(ft_addr_is_private(&addr) ? &t->private_addrs : &t->public_addrs),
                addr_hash);
        if (s->started)
            sat_add(&t->addressed_transfers, 1);
    }

    uint32_t file = reg_acquire(l, &l->files, &id, file_hash);
    uint32_t sender = reg_acquire(l, &l->names, name, name_hash);
    uint32_t to = addr.family ? reg_acquire(l, &l->addrs, &addr, addr_hash) : NONE;
    if (file != NONE && sender != NONE) {
        file_describe(l, file, s);
        c.sender = sender;
        c.item = addr_hash;
        c.has_item = addr.family != 0;
        pool_count(l, &l->tip.files, file, &c);
        if (to != NONE) {
            c.item = file_hash;
            c.has_item = true;
            pool_count(l, &l->tip.addrs, to, &c);
        }
    }
    if (file != NONE)
        reg_release(l, &l->files, file);
    if (sender != NONE)
        reg_release(l, &l->names, sender);
    if (to != NONE)
        reg_release(l, &l->addrs, to);
}

uint64_t ft_leaders_span_start(enum ft_leader_window window, uint64_t now_ns)
{
    if (window == FT_WINDOW_LIFETIME || window >= FT_WINDOW_COUNT)
        return 0;
    uint64_t slot_ns = slot_lengths[window - 1];
    uint64_t head = now_ns / slot_ns;
    return head >= FT_LEADER_SLOTS - 1 ? (head - (FT_LEADER_SLOTS - 1)) * slot_ns : 0;
}

/* The slots a span is made of, each with its place in the trend, or -1. */
struct span {
    struct slot *slot[FT_LEADER_SLOTS + 1];
    int trend[FT_LEADER_SLOTS + 1];
    size_t n;
};

static void span_add(struct span *sp, struct slot *s, int trend)
{
    sp->slot[sp->n] = s;
    sp->trend[sp->n] = trend;
    sp->n++;
}

/* The current span ends with the tip, which is not folded into the rings yet. */
static void span_of(struct ft_leaders *l, enum ft_leader_window w, bool previous, struct span *sp)
{
    sp->n = 0;
    if (w == FT_WINDOW_LIFETIME) {
        if (!previous) {
            span_add(sp, &l->lifetime, -1);
            span_add(sp, &l->tip, -1);
        }
        return;
    }
    struct ring *r = &l->rings[w - 1];
    uint64_t back = previous ? RING_SLOTS - 1 : FT_LEADER_SLOTS - 1;
    for (uint64_t k = 0; k < FT_LEADER_SLOTS; k++) {
        if (r->head + k < back)
            continue;
        span_add(sp, &r->slots[(r->head + k - back) % RING_SLOTS], (int)k);
    }
    if (!previous)
        span_add(sp, &l->tip, FT_LEADER_SLOTS - 1);
}

/* One row in the making: a file, an address, or files merged under a directory or extension. */
struct agg {
    uint32_t key; /* record of a file or address; for a group, where its text starts */
    uint32_t next;
    uint32_t hash;
    uint32_t files;
    uint64_t above[MEASURES]; /* how far its counts rose above the floors of its tables */
    uint64_t error[MEASURES];
    uint64_t trend[FT_LEADER_SLOTS];
    struct stats s;
};

struct aggs {
    struct agg *a;
    uint32_t *buckets;
    uint32_t n;
    uint32_t cap;
    uint32_t nbuckets;
    uint64_t floor[MEASURES]; /* sum of the floors of the tables gathered */
    uint64_t lost_transfers;  /* addresses: transfers no entry counted */
    char *text;
    size_t text_len;
    size_t text_cap;
};

static void aggs_free(struct aggs *g)
{
    free(g->a);
    free(g->buckets);
    free(g->text);
}

static bool aggs_grow(struct aggs *g)
{
    uint32_t cap = g->cap ? 2 * g->cap : 64;
    struct agg *a = realloc(g->a, cap * sizeof(*a));
    if (!a)
        return false;
    g->a = a;
    g->cap = cap;

    uint32_t *buckets = malloc(cap * sizeof(uint32_t));
    if (!buckets)
        return false;
    free(g->buckets);
    memset(buckets, 0xff, cap * sizeof(uint32_t));
    g->buckets = buckets;
    g->nbuckets = cap;
    for (uint32_t i = 0; i < g->n; i++) {
        uint32_t *head = &g->buckets[g->a[i].hash & (cap - 1)];
        g->a[i].next = *head;
        *head = i;
    }
    return true;
}

static const char *agg_text(const struct aggs *g, const struct agg *a)
{
    return g->text + a->key;
}

/* Finds or adds the row for a key, or for a text when text is set; NONE when memory runs out. */
static uint32_t aggs_find(struct aggs *g, uint32_t hash, uint32_t key, const char *text)
{
    for (uint32_t i = g->nbuckets ? g->buckets[hash & (g->nbuckets - 1)] : NONE; i != NONE;
         i = g->a[i].next) {
        if (g->a[i].hash == hash &&
            (text ? strcmp(agg_text(g, &g->a[i]), text) == 0 : g->a[i].key == key))
            return i;
    }
    if (g->n == g->cap && !aggs_grow(g))
        return NONE;
    if (text) {
        size_t size = strlen(text) + 1;
        if (g->text_len + size > g->text_cap) {
            size_t cap = g->text_cap ? 2 * g->text_cap : 4096;
            while (cap < g->text_len + size)
                cap *= 2;
            char *grown = cap <= UINT32_MAX ? realloc(g->text, cap) : nullptr;
            if (!grown)
                return NONE;
            g->text = grown;
            g->text_cap = cap;
        }
        memcpy(g->text + g->text_len, text, size);
        key = (uint32_t)g->text_len;
        g->text_len += size;
    }
    uint32_t i = g->n++;
    struct agg *a = &g->a[i];
    memset(a, 0, sizeof(*a));
    a->key = key;
    a->hash = hash;
    stats_init(&a->s);
    uint32_t *head = &g->buckets[hash & (g->nbuckets - 1)];
    a->next = *head;
    *head = i;
    return i;
}

static bool gather(struct ft_leaders *l, struct aggs *g, const struct slot *slot, bool addrs,
                   int trend)
{
    const struct pool *p = addrs ? &slot->addrs : &slot->files;
    uint64_t floor[MEASURES] = {0};
    uint64_t counted_transfers = 0;

    for (size_t m = 0; m < p->measures; m++) {
        floor[m] = table_floor(p, m);
        sat_add(&g->floor[m], floor[m]);
    }
    for (uint32_t k = 0; k < p->used; k++) {
        const struct entry *e = &p->e[k];
        if (e->key == NONE)
            continue;
        uint32_t i = aggs_find(g, e->key * 0x9e3779b1u, e->key, nullptr);
        if (i == NONE)
            return false;
        struct agg *a = &g->a[i];
        stats_merge(l, &a->s, &e->s, false);
        for (size_t m = 0; m < p->measures; m++) {
            if (e->pos[m] != NONE)
                sat_add(&a->above[m], sat_diff(e->count[m], floor[m]));
        }
        if (trend >= 0)
            sat_add(&a->trend[trend], e->s.bytes);
        sat_add(&counted_transfers, e->s.transfers);
    }
    if (addrs && slot->totals)
        sat_add(&g->lost_transfers, sat_diff(slot->totals->addressed_transfers, counted_transfers));
    return true;
}

/* A row's figure may fall short of the truth by its count above the floors, plus the floors. */
static void aggs_settle(struct aggs *g, bool addrs)
{
    for (uint32_t i = 0; i < g->n; i++) {
        struct agg *a = &g->a[i];
        a->files = 1;
        a->error[BY_BYTES] = sat_diff(sat_sum(g->floor[BY_BYTES], a->above[BY_BYTES]), a->s.bytes);
        a->error[BY_TRANSFERS] =
            addrs
                ? g->lost_transfers
                : sat_diff(sat_sum(g->floor[BY_TRANSFERS], a->above[BY_TRANSFERS]), a->s.transfers);
    }
}

static void group_text(enum ft_leader_key key, const char *path, char *buf, size_t size)
{
    const char *slash = path ? strrchr(path, '/') : nullptr;

    if (!slash) {
        ft_strlcpy(buf, "(unknown)", size);
    } else if (key == FT_LEADER_DIRECTORY) {
        size_t len = (size_t)(slash - path) + 1;
        ft_strlcpy(buf, path, len < size ? len + 1 : size);
    } else {
        const char *dot = strrchr(slash + 1, '.');
        ft_strlcpy(buf, dot && dot != slash + 1 && dot[1] ? dot : "(none)", size);
    }
}

static bool group_files(struct ft_leaders *l, enum ft_leader_key key, const struct aggs *files,
                        struct aggs *groups)
{
    char text[FT_PATH_MAX];

    for (uint32_t k = 0; k < files->n; k++) {
        const struct agg *f = &files->a[k];
        group_text(key, file_at(l, f->key)->path, text, sizeof(text));
        uint32_t i = aggs_find(groups, hash_bytes(text, strlen(text)), 0, text);
        if (i == NONE)
            return false;
        struct agg *g = &groups->a[i];
        stats_merge(l, &g->s, &f->s, false);
        for (size_t m = 0; m < MEASURES; m++)
            sat_add(&g->error[m], f->error[m]);
        for (size_t t = 0; t < FT_LEADER_SLOTS; t++)
            sat_add(&g->trend[t], f->trend[t]);
        g->files++;
    }
    return true;
}

struct ranked {
    uint64_t primary;
    uint64_t secondary;
    const char *text; /* compared when the figures are equal */
    uint64_t tie[2];
    uint32_t index;
};

static int compare_ranked(const void *a, const void *b)
{
    const struct ranked *x = a;
    const struct ranked *y = b;

    if (x->primary != y->primary)
        return x->primary > y->primary ? -1 : 1;
    if (x->secondary != y->secondary)
        return x->secondary > y->secondary ? -1 : 1;
    if (x->text && y->text) {
        int order = strcmp(x->text, y->text);
        if (order)
            return order;
    } else if (x->text || y->text) {
        return x->text ? -1 : 1;
    }
    for (size_t i = 0; i < 2; i++) {
        if (x->tie[i] != y->tie[i])
            return x->tie[i] < y->tie[i] ? -1 : 1;
    }
    return 0;
}

struct filter {
    const char *glob; /* nullptr: every row */
    regex_t regex;
    bool by_regex;
};

static bool filter_match(const struct filter *f, const char *text)
{
    if (!f->glob)
        return true;
    return f->by_regex ? regexec(&f->regex, text, 0, nullptr, 0) == 0
                       : ft_glob_match(f->glob, text);
}

struct ranking {
    enum ft_leader_key key;
    struct aggs files;
    struct aggs addrs;
    struct aggs groups;
    struct aggs *rows;
    struct ranked *order;
    uint32_t count;
};

static void ranking_free(struct ranking *rk)
{
    aggs_free(&rk->files);
    aggs_free(&rk->addrs);
    aggs_free(&rk->groups);
    free(rk->order);
}

static const char *row_text(const struct ft_leaders *l, const struct ranking *rk,
                            const struct agg *a, char *buf, size_t size)
{
    switch (rk->key) {
    case FT_LEADER_FILE: {
        const struct file_record *f = file_at(l, a->key);
        if (f->path)
            return f->path;
        snprintf(buf, size, "(device %" PRIu64 " inode %" PRIu64 ")", f->id.dev, f->id.ino);
        return buf;
    }
    case FT_LEADER_DESTINATION:
        ft_addr_format(&((const struct addr_record *)rec_at(&l->addrs, a->key))->addr, buf, size);
        return buf;
    default:
        return agg_text(&rk->groups, a);
    }
}

static uint64_t agg_destinations(const struct ranking *rk, const struct agg *a)
{
    return rk->key == FT_LEADER_DESTINATION ? 1
                                            : set_count(a->s.set.n, a->s.set.regs, ENTRY_SET_BITS);
}

static void rank_figures(const struct ft_query *q, const struct ranking *rk, const struct agg *a,
                         struct ranked *r)
{
    switch (q->sort) {
    case FT_SORT_TRANSFERS:
        r->primary = a->s.transfers;
        r->secondary = a->s.bytes;
        break;
    case FT_SORT_DESTINATIONS:
        r->primary = agg_destinations(rk, a);
        r->secondary = a->s.bytes;
        break;
    default:
        r->primary = a->s.bytes;
        r->secondary = a->s.transfers;
        break;
    }
}

static void rank_ties(const struct ft_leaders *l, const struct ranking *rk, const struct agg *a,
                      struct ranked *r)
{
    if (rk->key == FT_LEADER_FILE) {
        const struct file_record *f = file_at(l, a->key);
        r->text = f->path;
        r->tie[0] = f->id.dev;
        r->tie[1] = f->id.ino;
    } else if (rk->key == FT_LEADER_DESTINATION) {
        const uint8_t *addr = ((const struct addr_record *)rec_at(&l->addrs, a->key))->addr.addr;
        for (size_t i = 0; i < 16; i++)
            r->tie[i / 8] = r->tie[i / 8] << 8 | addr[i];
    } else {
        r->text = agg_text(&rk->groups, a);
    }
}

/* Gathers a span into rows of the query's key, keeps those that pass the filter, and sorts them. */
static bool rank_span(struct ft_leaders *l, const struct ft_query *q, const struct span *sp,
                      const struct filter *f, bool with_files, struct ranking *rk)
{
    char buf[FT_PATH_MAX];
    bool by_addr = rk->key == FT_LEADER_DESTINATION;

    with_files = with_files || !by_addr;
    for (size_t i = 0; i < sp->n; i++) {
        if (with_files && !gather(l, &rk->files, sp->slot[i], false, sp->trend[i]))
            return false;
        if (by_addr && !gather(l, &rk->addrs, sp->slot[i], true, sp->trend[i]))
            return false;
    }
    aggs_settle(&rk->files, false);
    aggs_settle(&rk->addrs, true);
    if (rk->key == FT_LEADER_DIRECTORY || rk->key == FT_LEADER_EXTENSION) {
        if (!group_files(l, rk->key, &rk->files, &rk->groups))
            return false;
        rk->rows = &rk->groups;
    } else {
        rk->rows = by_addr ? &rk->addrs : &rk->files;
    }

    rk->order = malloc((rk->rows->n ? rk->rows->n : 1) * sizeof(*rk->order));
    if (!rk->order)
        return false;
    for (uint32_t i = 0; i < rk->rows->n; i++) {
        const struct agg *a = &rk->rows->a[i];
        if (!filter_match(f, row_text(l, rk, a, buf, sizeof(buf))))
            continue;
        struct ranked *r = &rk->order[rk->count++];
        *r = (struct ranked){.index = i};
        rank_figures(q, rk, a, r);
        rank_ties(l, rk, a, r);
    }
    qsort(rk->order, rk->count, sizeof(*rk->order), compare_ranked);
    return true;
}

static uint32_t previous_rank(const struct ranking *now, const struct agg *a,
                              const struct ranking *before)
{
    uint32_t n = before->count < PREVIOUS_RANKS ? before->count : PREVIOUS_RANKS;
    bool by_text = now->rows == &now->groups;

    for (uint32_t r = 0; r < n; r++) {
        const struct agg *b = &before->rows->a[before->order[r].index];
        if (by_text ? strcmp(agg_text(&now->groups, a), agg_text(&before->groups, b)) == 0
                    : a->key == b->key)
            return r + 1;
    }
    return 0;
}

static uint8_t main_method(const struct stats *s)
{
    uint64_t other = sat_diff(s->bytes, s->bytes_exact);
    if (s->exact_method && (s->bytes_exact >= other || !s->other_method))
        return s->exact_method;
    return s->other_method;
}

static void fill_row(const struct ft_leaders *l, const struct ranking *rk, const struct agg *a,
                     struct ft_row_leader *row)
{
    char buf[64];

    memset(row, 0, offsetof(struct ft_row_leader, text) + 1);
    row->bytes = a->s.bytes;
    row->bytes_error = a->error[BY_BYTES];
    row->bytes_exact = a->s.bytes_exact;
    row->transfers = a->s.transfers;
    row->transfers_error = a->error[BY_TRANSFERS];
    row->destinations = agg_destinations(rk, a);
    row->files = a->files;
    row->first_wall_ns = a->s.first_ns == UINT64_MAX ? 0 : ft_clock_mono_to_wall(a->s.first_ns);
    row->last_wall_ns = ft_clock_mono_to_wall(a->s.last_ns);
    memcpy(row->trend, a->trend, sizeof(row->trend));
    row->confidence = a->s.confidence == FT_CONF_ANY ? FT_CONF_UNKNOWN : a->s.confidence;
    row->method = main_method(&a->s);
    if (a->s.more_senders)
        row->flags |= FT_LEADER_MORE_SENDERS;

    uint32_t order[FT_LEADER_SENDERS];
    for (uint32_t i = 0; i < FT_LEADER_SENDERS; i++)
        order[i] = i;
    for (size_t i = 1; i < FT_LEADER_SENDERS; i++) {
        for (size_t j = i; j > 0 && a->s.sender_bytes[order[j]] > a->s.sender_bytes[order[j - 1]];
             j--) {
            uint32_t t = order[j];
            order[j] = order[j - 1];
            order[j - 1] = t;
        }
    }
    size_t n = 0;
    for (size_t i = 0; i < FT_LEADER_SENDERS; i++) {
        uint32_t k = order[i];
        if (a->s.sender[k] == NONE)
            continue;
        struct ft_leader_sender *out = &row->senders[n++];
        out->bytes = a->s.sender_bytes[k];
        out->transfers = a->s.sender_transfers[k];
        ft_strlcpy(out->name, ((const struct name_record *)rec_at(&l->names, a->s.sender[k]))->name,
                   sizeof(out->name));
    }

    switch (rk->key) {
    case FT_LEADER_FILE: {
        const struct file_record *f = file_at(l, a->key);
        row->file_size = f->size;
        row->dev = f->id.dev;
        row->ino = f->id.ino;
        if (f->deleted)
            row->flags |= FT_LEADER_DELETED;
        break;
    }
    case FT_LEADER_DESTINATION:
        row->remote = ((const struct addr_record *)rec_at(&l->addrs, a->key))->addr;
        row->files = set_count(a->s.set.n, a->s.set.regs, ENTRY_SET_BITS);
        return;
    default:
        break;
    }
    ft_strlcpy(row->text, row_text(l, rk, a, buf, sizeof(buf)), sizeof(row->text));
}

static void summarize(const struct span *sp, const struct ranking *rk,
                      struct ft_row_leader_summary *sum)
{
    struct wide_set *sets = calloc(5, sizeof(*sets));
    uint64_t top[TOP_FILES] = {0};

    for (size_t i = 0; i < sp->n; i++) {
        const struct slot *s = sp->slot[i];
        if (!s->totals)
            continue;
        sat_add(&sum->bytes, s->totals->bytes);
        sat_add(&sum->bytes_exact, s->totals->bytes_exact);
        sat_add(&sum->transfers, s->totals->transfers);
        const struct wide_set *from[] = {&s->totals->files, &s->totals->public_addrs,
                                         &s->totals->private_addrs, &s->totals->senders,
                                         &s->totals->scripts};
        for (size_t k = 0; sets && k < 5; k++)
            set_merge(wide_view(&sets[k]), from[k]->n, from[k]->exact, from[k]->regs);
    }
    if (sets) {
        uint64_t counts[5];
        for (size_t k = 0; k < 5; k++)
            counts[k] = set_count(sets[k].n, sets[k].regs, WIDE_SET_BITS);
        sum->files = counts[0];
        sum->destinations_public = counts[1];
        sum->destinations_private = counts[2];
        sum->processes = (uint32_t)(counts[3] < UINT32_MAX ? counts[3] : UINT32_MAX);
        sum->scripts = (uint32_t)(counts[4] < UINT32_MAX ? counts[4] : UINT32_MAX);
        free(sets);
    }

    /* The ten largest files, kept in descending order. */
    for (uint32_t i = 0; i < rk->files.n; i++) {
        uint64_t b = rk->files.a[i].s.bytes;
        for (size_t k = 0; k < TOP_FILES; k++) {
            if (b <= top[k])
                continue;
            memmove(&top[k + 1], &top[k], (TOP_FILES - k - 1) * sizeof(top[0]));
            top[k] = b;
            break;
        }
    }
    for (size_t k = 0; k < TOP_FILES; k++)
        sat_add(&sum->top_bytes, top[k]);
}

static bool span_capped(const struct span *sp)
{
    for (size_t i = 0; i < sp->n; i++) {
        const struct slot *s = sp->slot[i];
        if (s->files.capped[BY_BYTES] || s->files.capped[BY_TRANSFERS] || s->addrs.capped[BY_BYTES])
            return true;
    }
    return false;
}

static bool answer(struct ft_leaders *l, const struct ft_query *q, const struct filter *f,
                   uint64_t since_ns, uint64_t now_ns, ft_row_fn *emit, void *ctx)
{
    enum ft_leader_window w = (enum ft_leader_window)q->window;
    struct ft_row_leader_summary sum = {.to_wall_ns = ft_clock_mono_to_wall(now_ns)};
    struct ranking now = {.key = (enum ft_leader_key)q->leader_key};
    struct ranking before = {.key = now.key};
    struct span sp;
    struct span prev = {.n = 0};
    bool ok = false;

    uint64_t from_ns = since_ns;
    if (w != FT_WINDOW_LIFETIME) {
        uint64_t slot_ns = slot_lengths[w - 1];
        uint64_t start = ft_leaders_span_start(w, now_ns);
        uint64_t prev_start =
            start >= FT_LEADER_SLOTS * slot_ns ? start - FT_LEADER_SLOTS * slot_ns : 0;
        sum.window_ns = FT_LEADER_SLOTS * slot_ns;
        sum.slot_ns = slot_ns;
        if (since_ns > start)
            sum.flags |= FT_LEADERS_SHORT_HISTORY;
        else
            from_ns = start;
        if (since_ns < start) {
            sum.previous_from_wall_ns =
                ft_clock_mono_to_wall(since_ns > prev_start ? since_ns : prev_start);
            span_of(l, w, true, &prev);
        }
    }
    sum.from_wall_ns = ft_clock_mono_to_wall(from_ns);

    span_of(l, w, false, &sp);
    if (!rank_span(l, q, &sp, f, true, &now))
        goto out;
    if (prev.n && !rank_span(l, q, &prev, f, false, &before))
        goto out;
    summarize(&sp, &now, &sum);
    if (span_capped(&sp) || span_capped(&prev))
        sum.flags |= FT_LEADERS_CAPPED;
    emit(ctx, FT_MSG_ROW_LEADER_SUMMARY, &sum, sizeof(sum));

    uint32_t limit = q->limit ? q->limit : DEFAULT_LIMIT;
    uint32_t n = now.count < limit ? now.count : limit;
    struct ft_row_leader *row = malloc(sizeof(*row));
    if (!row)
        goto out;
    for (uint32_t r = 0; r < n; r++) {
        const struct agg *a = &now.rows->a[now.order[r].index];
        fill_row(l, &now, a, row);
        row->rank = r + 1;
        row->previous_rank = prev.n ? previous_rank(&now, a, &before) : 0;
        emit(ctx, FT_MSG_ROW_LEADER, row, ft_row_leader_size(row));
    }
    free(row);
    ok = true;
out:
    ranking_free(&now);
    ranking_free(&before);
    return ok;
}

bool ft_leaders_query(struct ft_leaders *l, const struct ft_query *q, uint64_t since_ns,
                      uint64_t now_ns, ft_row_fn *emit, void *ctx, struct ft_error *err)
{
    struct filter f = {.glob = q->path[0] ? q->path : nullptr};

    if (q->window >= FT_WINDOW_COUNT) {
        ft_error_set(err, FT_EXIT_USAGE, "Unknown ranking window %u", q->window);
        return false;
    }
    if (q->leader_key >= FT_LEADER_KEY_COUNT) {
        ft_error_set(err, FT_EXIT_USAGE, "Unknown ranking key %u", q->leader_key);
        return false;
    }
    if (!l) {
        struct ft_row_leader_summary sum = {.flags = FT_LEADERS_OFF};
        emit(ctx, FT_MSG_ROW_LEADER_SUMMARY, &sum, sizeof(sum));
        return true;
    }
    if (f.glob && (q->flags & FT_QF_PATH_REGEX)) {
        int rc = regcomp(&f.regex, q->path, REG_EXTENDED | REG_NOSUB);
        if (rc != 0) {
            char reason[128];
            regerror(rc, &f.regex, reason, sizeof(reason));
            ft_error_set(err, FT_EXIT_USAGE, "Invalid path expression '%s': %s", q->path, reason);
            return false;
        }
        f.by_regex = true;
    }

    advance(l, now_ns);
    if (l->latest_ns > now_ns)
        now_ns = l->latest_ns;
    if (since_ns == 0 || since_ns > now_ns)
        since_ns = l->first_ns ? l->first_ns : now_ns;

    bool ok = answer(l, q, &f, since_ns, now_ns, emit, ctx);
    if (f.by_regex)
        regfree(&f.regex);
    if (!ok)
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
    return ok;
}
