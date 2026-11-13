#include "ui/top/model_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

constexpr double HOLD_SHARE = 0.05; /* rows closer than this keep their order */
constexpr uint32_t POSITION_MASK = 0xffffffu;
constexpr uint32_t EXPLICIT_COLLAPSED = 1;
constexpr uint32_t EXPLICIT_EXPANDED = 2;
constexpr unsigned FOLD_AT = 3;    /* siblings sharing a title from which all but the first fold */
constexpr size_t TREE_LEVELS = 64; /* a deeper process shows as a root */

enum key_type : uint8_t {
    BY_VALUE,
    BY_TEXT,
    BY_ADDRESS,
};

struct order {
    enum key_type type;
    bool descending;
    bool hysteresis;
};

/* What a tree node shows below itself. */
enum shows : uint8_t {
    SHOWS_NOTHING,
    SHOWS_CHILDREN,
    SHOWS_ALL,
};

static struct ft_top_process_entry *process_entry(const struct ft_top_process *p)
{
    return (struct ft_top_process_entry *)(void *)p;
}

static struct ft_top_transfer_entry *transfer_entry(const struct ft_top_transfer *t)
{
    return (struct ft_top_transfer_entry *)(void *)t;
}

static int sign(int c)
{
    return (c > 0) - (c < 0);
}

static int compare_addresses(const struct ft_endpoint *a, const struct ft_endpoint *b)
{
    if (a->family != b->family)
        return a->family < b->family ? -1 : 1;
    int c = memcmp(a->addr, b->addr, sizeof(a->addr));
    if (c)
        return sign(c);
    return (a->port > b->port) - (a->port < b->port);
}

static int compare_items(const struct ft_top_item *x, const struct ft_top_item *y,
                         const struct order *o)
{
    int c;
    switch (o->type) {
    case BY_TEXT:
        c = sign(strcmp(x->text ? x->text : "", y->text ? y->text : ""));
        break;
    case BY_ADDRESS: {
        static const struct ft_endpoint none;
        c = compare_addresses(x->addr ? x->addr : &none, y->addr ? y->addr : &none);
        break;
    }
    default:
        c = (x->value > y->value) - (x->value < y->value);
        break;
    }
    if (c)
        return o->descending ? -c : c;
    if (x->rate != y->rate)
        return x->rate > y->rate ? -1 : 1;
    if (x->key.kind != y->key.kind)
        return x->key.kind < y->key.kind ? -1 : 1;
    if (x->key.a != y->key.a)
        return x->key.a < y->key.a ? -1 : 1;
    return (x->key.b > y->key.b) - (x->key.b < y->key.b);
}

/* Stable; the result ends up in a. */
static void merge_sort(struct ft_top_item *a, struct ft_top_item *tmp, size_t n,
                       const struct order *o)
{
    struct ft_top_item *from = a;
    struct ft_top_item *to = tmp;

    for (size_t width = 1; width < n; width *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * width) {
            size_t mid = lo + width < n ? lo + width : n;
            size_t hi = lo + 2 * width < n ? lo + 2 * width : n;
            size_t i = lo;
            size_t j = mid;
            size_t k = lo;
            while (i < mid && j < hi)
                to[k++] = compare_items(&from[j], &from[i], o) < 0 ? from[j++] : from[i++];
            while (i < mid)
                to[k++] = from[i++];
            while (j < hi)
                to[k++] = from[j++];
        }
        struct ft_top_item *swap = from;
        from = to;
        to = swap;
    }
    if (from != a)
        memcpy(a, from, n * sizeof(*a));
}

static double magnitude(double v)
{
    return v < 0 ? -v : v;
}

/* Whether x, just below y, takes y's place in this build. */
static bool may_pass(struct ft_top_item *x, const struct ft_top_item *y, const struct order *o)
{
    if (compare_items(x, y, o) >= 0)
        return false;
    if (x->prev == FT_TOP_NONE || y->prev == FT_TOP_NONE || x->value == y->value)
        return true;
    double larger =
        magnitude(x->value) > magnitude(y->value) ? magnitude(x->value) : magnitude(y->value);
    if (magnitude(x->value - y->value) > HOLD_SHARE * larger || x->due >= 1)
        return true;
    x->held = true;
    return false;
}

static bool reserve_items(struct ft_top_mode_state *ms, size_t n)
{
    size_t caps[4] = {ms->items_cap, ms->items_cap, ms->items_cap, ms->items_cap};
    if (n <= ms->items_cap)
        return true;
    bool ok = ft_top_reserve(&ms->items, &caps[0], n, sizeof(*ms->items)) &&
              ft_top_reserve(&ms->spare, &caps[1], n, sizeof(*ms->spare)) &&
              ft_top_reserve(&ms->indices, &caps[2], n, sizeof(*ms->indices)) &&
              ft_top_reserve(&ms->indices_spare, &caps[3], n, sizeof(*ms->indices_spare));
    if (!ok)
        return false;
    ms->items_cap = caps[0];
    for (size_t i = 1; i < FT_ARRAY_LEN(caps); i++)
        ms->items_cap = caps[i] < ms->items_cap ? caps[i] : ms->items_cap;
    return true;
}

/* Stable sort of indices into items by the row each had before. */
static void sort_by_previous(uint32_t *a, uint32_t *tmp, size_t n, const struct ft_top_item *items)
{
    uint32_t *from = a;
    uint32_t *to = tmp;

    for (size_t width = 1; width < n; width *= 2) {
        for (size_t lo = 0; lo < n; lo += 2 * width) {
            size_t mid = lo + width < n ? lo + width : n;
            size_t hi = lo + 2 * width < n ? lo + 2 * width : n;
            size_t i = lo;
            size_t j = mid;
            size_t k = lo;
            while (i < mid && j < hi)
                to[k++] = items[from[j]].prev < items[from[i]].prev ? from[j++] : from[i++];
            while (i < mid)
                to[k++] = from[i++];
            while (j < hi)
                to[k++] = from[j++];
        }
        uint32_t *swap = from;
        from = to;
        to = swap;
    }
    if (from != a)
        memcpy(a, from, n * sizeof(*a));
}

/*
 * Sorts items, then lets a row move past the one above it only when their keys differ by more
 * than HOLD_SHARE, or when it was held back in the previous build too.
 */
static void order_items(struct ft_top_mode_state *ms, struct ft_top_item *items, size_t n,
                        const struct order *o)
{
    const struct ft_top_map *memory = &ms->memory[ms->memory_now];

    for (size_t i = 0; i < n; i++) {
        uint32_t *seen = o->hysteresis ? ft_top_map_find(memory, items[i].key) : nullptr;
        items[i].prev = seen ? *seen & POSITION_MASK : FT_TOP_NONE;
        items[i].due = seen ? (uint8_t)(*seen >> 24) : 0;
        items[i].held = false;
    }
    merge_sort(items, ms->spare, n, o);
    if (!o->hysteresis || n < 2)
        return;

    /* Rows in the order of the previous build, each new one after the row it follows now. */
    uint32_t *old = ms->indices;
    size_t nold = 0;
    for (size_t i = 0; i < n; i++) {
        if (items[i].prev != FT_TOP_NONE)
            old[nold++] = (uint32_t)i;
    }
    if (nold == 0)
        return;
    sort_by_previous(old, ms->indices_spare, nold, items);

    struct ft_top_item *w = ms->spare;
    size_t at = 0;
    for (size_t i = 0; i < n && items[i].prev == FT_TOP_NONE; i++)
        w[at++] = items[i];
    for (size_t k = 0; k < nold; k++) {
        size_t i = old[k];
        w[at++] = items[i];
        for (i++; i < n && items[i].prev == FT_TOP_NONE; i++)
            w[at++] = items[i];
    }

    size_t moves = 0;
    size_t budget = 8 * n + 64;
    for (size_t i = 1; i < n; i++) {
        struct ft_top_item x = w[i];
        size_t j = i;
        while (j > 0 && may_pass(&x, &w[j - 1], o)) {
            w[j] = w[j - 1];
            j--;
            if (++moves > budget) {
                /* Too much has changed to hold rows back: take the sorted order. */
                for (size_t r = 0; r < n; r++)
                    items[r].held = false;
                return;
            }
        }
        w[j] = x;
    }
    memcpy(items, w, n * sizeof(*items));
}

static enum key_type key_type(enum ft_top_sort sort)
{
    switch (sort) {
    case FT_TOP_SORT_USER:
    case FT_TOP_SORT_PROCESS:
    case FT_TOP_SORT_SCRIPT:
    case FT_TOP_SORT_FILE:
    case FT_TOP_SORT_METHOD:
    case FT_TOP_SORT_CONFIDENCE:
    case FT_TOP_SORT_KIND:
    case FT_TOP_SORT_HOSTNAME:
        return BY_TEXT;
    case FT_TOP_SORT_DESTINATION:
        return BY_ADDRESS;
    default:
        return BY_VALUE;
    }
}

/* Keys that drift a little each refresh; exact ones and text never flicker. */
static bool drifts(enum ft_top_sort sort)
{
    return sort == FT_TOP_SORT_RATE || sort == FT_TOP_SORT_BYTES || sort == FT_TOP_SORT_PROGRESS ||
           sort == FT_TOP_SORT_TOTAL;
}

static struct order mode_order(const struct ft_top_mode_state *ms)
{
    return (struct order){
        .type = key_type(ms->sort),
        .descending = ms->descending,
        .hysteresis = !ms->reorder && drifts(ms->sort),
    };
}

static struct order rate_order(const struct ft_top_mode_state *ms)
{
    return (struct order){.type = BY_VALUE, .descending = true, .hysteresis = !ms->reorder};
}

static void transfer_item(struct ft_top_item *it, const struct ft_top_transfer_entry *e,
                          enum ft_top_sort sort)
{
    const struct ft_top_transfer *t = &e->pub;
    *it = (struct ft_top_item){
        .entity = t,
        .key = e->key,
        .rate = e->smoothed,
        .kind = FT_TOP_ROW_TRANSFER,
    };
    switch (sort) {
    case FT_TOP_SORT_BYTES:
        it->value = (double)t->bytes;
        break;
    case FT_TOP_SORT_PROGRESS:
        it->value = t->progress;
        break;
    case FT_TOP_SORT_AGE:
        it->value = (double)t->age_ns;
        break;
    case FT_TOP_SORT_PID:
        it->value = t->pid;
        break;
    case FT_TOP_SORT_SIZE:
        it->value = (double)t->size;
        break;
    case FT_TOP_SORT_USER:
        it->text = t->process->user;
        break;
    case FT_TOP_SORT_PROCESS:
        it->text = t->process->title;
        break;
    case FT_TOP_SORT_SCRIPT:
        it->text = t->script;
        break;
    case FT_TOP_SORT_FILE:
        it->text = t->path;
        break;
    case FT_TOP_SORT_METHOD:
        it->text = ft_method_name((enum ft_method)t->method);
        break;
    case FT_TOP_SORT_CONFIDENCE:
        it->text = ft_confidence_name((enum ft_confidence)t->confidence);
        break;
    case FT_TOP_SORT_DESTINATION:
        it->addr = &t->remote;
        break;
    default:
        it->value = e->smoothed;
        break;
    }
}

/* The fields a process row and a fold row are sorted by. */
struct tally {
    uint64_t rate;
    uint64_t total;
    uint32_t files;
    uint32_t destinations;
    uint32_t pid;
    uint8_t method;
    const char *user;
    const char *title;
};

static void tally_item(struct ft_top_item *it, const struct tally *t, enum ft_top_sort sort)
{
    it->rate = (double)t->rate;
    switch (sort) {
    case FT_TOP_SORT_TOTAL:
        it->value = (double)t->total;
        break;
    case FT_TOP_SORT_FILES:
        it->value = t->files;
        break;
    case FT_TOP_SORT_DESTINATIONS:
        it->value = t->destinations;
        break;
    case FT_TOP_SORT_PID:
        it->value = t->pid;
        break;
    case FT_TOP_SORT_USER:
        it->text = t->user;
        break;
    case FT_TOP_SORT_METHOD:
        it->text = ft_method_name((enum ft_method)t->method);
        break;
    case FT_TOP_SORT_PROCESS:
        it->text = t->title;
        break;
    default:
        it->value = (double)t->rate;
        break;
    }
}

static void process_item(struct ft_top_item *it, const struct ft_top_process *p,
                         enum ft_top_sort sort)
{
    *it = (struct ft_top_item){
        .entity = p,
        .key = {p->pid, 0, FT_TOP_KEY_PROCESS},
        .kind = FT_TOP_ROW_PROCESS,
    };
    tally_item(it,
               &(struct tally){p->rate, p->total, p->files, p->destinations, p->pid, p->method,
                               p->user, p->title},
               sort);
}

static void destination_item(struct ft_top_item *it, const struct ft_top_destination_entry *e,
                             enum ft_top_sort sort)
{
    const struct ft_top_destination *d = &e->pub;
    *it = (struct ft_top_item){
        .entity = d,
        .key = e->key,
        .rate = (double)d->rate,
        .kind = FT_TOP_ROW_DESTINATION,
    };
    switch (sort) {
    case FT_TOP_SORT_TOTAL:
        it->value = (double)d->total;
        break;
    case FT_TOP_SORT_FILES:
        it->value = d->files;
        break;
    case FT_TOP_SORT_PROCESSES:
        it->value = d->processes;
        break;
    case FT_TOP_SORT_DESTINATION:
        it->addr = &d->address;
        break;
    case FT_TOP_SORT_KIND:
        it->text = d->is_public ? "public" : "private";
        break;
    case FT_TOP_SORT_HOSTNAME:
        it->text = d->host ? d->host : "";
        break;
    case FT_TOP_SORT_PROCESS:
        it->text = d->top_process ? d->top_process->title : "";
        break;
    case FT_TOP_SORT_FILE:
        it->text = d->top ? d->top->path : "";
        break;
    default:
        it->value = (double)d->rate;
        break;
    }
}

static void file_item(struct ft_top_item *it, const struct ft_top_file_entry *e,
                      enum ft_top_sort sort)
{
    const struct ft_top_file *f = &e->pub;
    *it = (struct ft_top_item){
        .entity = f,
        .key = e->key,
        .rate = (double)f->rate,
        .kind = FT_TOP_ROW_FILE,
    };
    switch (sort) {
    case FT_TOP_SORT_SIZE:
        it->value = (double)f->size;
        break;
    case FT_TOP_SORT_TRANSFERS:
        it->value = f->active;
        break;
    case FT_TOP_SORT_DESTINATIONS:
        it->value = f->destinations;
        break;
    case FT_TOP_SORT_FILE:
        it->text = f->path;
        break;
    case FT_TOP_SORT_PROCESS:
        it->text = f->senders;
        break;
    case FT_TOP_SORT_METHOD:
        it->text = ft_method_name((enum ft_method)f->method);
        break;
    default:
        it->value = (double)f->rate;
        break;
    }
}

static struct ft_top_map *next_memory(struct ft_top_mode_state *ms)
{
    return &ms->memory[ms->memory_now ^ 1];
}

static bool remember(struct ft_top_mode_state *ms, struct ft_top_key key, size_t row, uint8_t due)
{
    return ft_top_map_put(next_memory(ms), key, (uint32_t)row | (uint32_t)due << 24);
}

/* How many builds in a row the item has been held back, this one included. */
static uint8_t next_due(const struct ft_top_item *it)
{
    return it->held ? (uint8_t)(it->due < 255 ? it->due + 1 : 255) : 0;
}

static bool emit(struct ft_top_mode_state *ms, const struct ft_top_item *it, uint8_t depth,
                 uint32_t rails, enum ft_top_node node, bool last)
{
    if (ms->nrows >= POSITION_MASK)
        return false;
    if (ms->nrows == ms->rows_cap) {
        size_t rows_cap = ms->rows_cap;
        size_t keys_cap = ms->rows_cap;
        if (!ft_top_reserve(&ms->rows, &rows_cap, ms->nrows + 1, sizeof(*ms->rows)) ||
            !ft_top_reserve(&ms->row_keys, &keys_cap, ms->nrows + 1, sizeof(*ms->row_keys)))
            return false;
        ms->rows_cap = rows_cap < keys_cap ? rows_cap : keys_cap;
    }
    if (!remember(ms, it->key, ms->nrows, next_due(it)))
        return false;
    ms->rows[ms->nrows] = (struct ft_top_row){
        .entity = it->entity,
        .rails = rails,
        .kind = (enum ft_top_row_kind)it->kind,
        .node = node,
        .depth = depth,
        .flags = last ? FT_TOP_ROW_LAST : 0,
    };
    ms->row_keys[ms->nrows] = it->key;
    ms->nrows++;
    return true;
}

static bool reserve_lists(struct ft_top_mode_state *ms, size_t n)
{
    return ft_top_reserve(&ms->lists, &ms->lists_cap, n, sizeof(*ms->lists));
}

static int by_rate(const void *a, const void *b)
{
    const struct ft_top_transfer *x = *(const struct ft_top_transfer *const *)a;
    const struct ft_top_transfer *y = *(const struct ft_top_transfer *const *)b;
    if (x->rate != y->rate)
        return x->rate > y->rate ? -1 : 1;
    return (x->id > y->id) - (x->id < y->id);
}

static void sort_by_rate(const struct ft_top_transfer **list, size_t n)
{
    if (n > 1)
        qsort(list, n, sizeof(*list), by_rate);
}

struct summary {
    uint64_t rate;
    uint32_t processes;
    uint32_t files;
    uint32_t destinations;
    uint8_t method;
    uint8_t confidence;
};

/* Distinct processes, files and destinations of the transfers not done; method by rate. */
static void summarize(const struct ft_top_transfer *const *list, size_t n, uint32_t mark,
                      struct summary *s)
{
    uint64_t by_method[FT_TOP_METHODS] = {0};
    uint8_t lowest[FT_TOP_METHODS] = {0};
    bool seen[FT_TOP_METHODS] = {0};

    *s = (struct summary){0};
    for (size_t i = 0; i < n; i++) {
        const struct ft_top_transfer *t = list[i];
        if (t->done)
            continue;
        struct ft_top_process_entry *p = process_entry(t->process);
        struct ft_top_file_entry *f = (struct ft_top_file_entry *)(void *)t->file;
        struct ft_top_destination_entry *d =
            (struct ft_top_destination_entry *)(void *)t->destination;
        s->rate += t->rate;
        if (p->mark != mark) {
            p->mark = mark;
            s->processes++;
        }
        if (f->mark != mark) {
            f->mark = mark;
            s->files++;
        }
        if (d->mark != mark) {
            d->mark = mark;
            s->destinations++;
        }
        size_t method = t->method < FT_TOP_METHODS ? t->method : FT_METHOD_NONE;
        by_method[method] += t->rate;
        if (!seen[method] || t->confidence < lowest[method])
            lowest[method] = t->confidence;
        seen[method] = true;
    }
    size_t best = FT_TOP_METHODS;
    for (size_t i = 0; i < FT_TOP_METHODS; i++) {
        if (seen[i] && (best == FT_TOP_METHODS || by_method[i] > by_method[best]))
            best = i;
    }
    if (best < FT_TOP_METHODS) {
        s->method = (uint8_t)best;
        s->confidence = lowest[best];
    }
}

static bool pass_filter(struct ft_top_model *m, struct ft_top_mode_state *ms)
{
    if (!ft_top_reserve(&ms->passed, &ms->passed_cap, m->ntransfers, sizeof(*ms->passed)))
        return false;
    ms->npassed = 0;
    for (size_t i = 0; i < m->ntransfers; i++) {
        struct ft_top_transfer_entry *e = &m->transfers[i];
        struct ft_top_subject s;
        if (ms->filter) {
            ft_top_subject_of(&e->pub, &s);
            if (!ft_top_filter_match(ms->filter, &s))
                continue;
        }
        ms->passed[ms->npassed++] = e;
    }
    return true;
}

static void count_view(struct ft_top_model *m, struct ft_top_mode_state *ms)
{
    struct ft_top_view *v = &ms->view;
    uint32_t mark = ft_top_next_mark(m);

    *v = (struct ft_top_view){0};
    ft_top_map_clear(&ms->scratch);
    for (size_t i = 0; i < ms->npassed; i++) {
        const struct ft_top_transfer *t = &ms->passed[i]->pub;
        if (t->done)
            continue;
        struct ft_top_process_entry *p = process_entry(t->process);
        struct ft_top_file_entry *f = (struct ft_top_file_entry *)(void *)t->file;
        struct ft_top_destination_entry *d =
            (struct ft_top_destination_entry *)(void *)t->destination;
        v->transfers++;
        v->named += t->names != nullptr;
        v->rate += t->rate;
        if (p->mark != mark) {
            p->mark = mark;
            v->processes++;
        }
        if (f->mark != mark) {
            f->mark = mark;
            v->files++;
        }
        if (d->mark != mark) {
            d->mark = mark;
            v->destinations++;
            v->destinations_public += d->pub.is_public;
        }
        if (t->script[0]) {
            size_t len = strlen(t->script);
            struct ft_top_key key = {ft_top_hash(t->script, len, 1), ft_top_hash(t->script, len, 2),
                                     FT_TOP_KEY_TEXT};
            if (!ft_top_map_find(&ms->scratch, key) && ft_top_map_put(&ms->scratch, key, 1))
                v->scripts++;
        }
    }
}

static const struct ft_top_transfer *representative(const struct ft_top_item *it)
{
    switch (it->kind) {
    case FT_TOP_ROW_PROCESS: {
        const struct ft_top_process *p = it->entity;
        return p->ntransfers ? p->transfers[0] : nullptr;
    }
    case FT_TOP_ROW_DESTINATION:
        return ((const struct ft_top_destination *)it->entity)->top;
    case FT_TOP_ROW_FILE:
        return ((const struct ft_top_file *)it->entity)->top;
    default:
        return it->entity;
    }
}

/* The transfers behind an item; one holds a transfer item's own. */
static size_t item_transfers(const struct ft_top_item *it, const struct ft_top_transfer **one,
                             const struct ft_top_transfer *const **list)
{
    switch (it->kind) {
    case FT_TOP_ROW_PROCESS: {
        const struct ft_top_process *p = it->entity;
        *list = p->transfers;
        return p->ntransfers;
    }
    case FT_TOP_ROW_DESTINATION: {
        const struct ft_top_destination *d = it->entity;
        *list = d->transfers;
        return d->ntransfers;
    }
    case FT_TOP_ROW_FILE: {
        const struct ft_top_file *f = it->entity;
        *list = f->transfers;
        return f->ntransfers;
    }
    default:
        *one = it->entity;
        *list = one;
        return 1;
    }
}

/* The text a transfer is grouped under; buf holds it when it is not one of t's strings. */
static const char *group_text(const struct ft_top_transfer *t, enum ft_top_group group, char *buf,
                              size_t size, size_t *len)
{
    const char *text = "";
    *len = 0;
    if (!t)
        return text;
    switch (group) {
    case FT_TOP_GROUP_PROCESS:
        text = t->process->title;
        break;
    case FT_TOP_GROUP_SCRIPT:
        text = t->script;
        break;
    case FT_TOP_GROUP_DESTINATION:
        text = t->destination->text;
        break;
    case FT_TOP_GROUP_DIRECTORY:
        text = t->path;
        *len = t->path_known ? t->name_offset : 0;
        return text;
    case FT_TOP_GROUP_SUBNET: {
        struct ft_endpoint net = t->destination->address;
        unsigned bits = net.family == 6 ? 64 : 24;
        char address[48];
        memset(net.addr + bits / 8, 0, sizeof(net.addr) - bits / 8);
        ft_addr_format(&net, address, sizeof(address));
        if (net.family)
            snprintf(buf, size, "%s/%u", address, bits);
        else
            buf[0] = '\0';
        text = buf;
        break;
    }
    case FT_TOP_GROUP_NAME:
        if (t->names) {
            ft_remote_name_format(t->names, buf, size);
            text = buf;
        }
        break;
    default:
        break;
    }
    *len = strlen(text);
    return text;
}

static enum ft_top_node section_node(const struct ft_top_mode_state *ms, struct ft_top_key key)
{
    uint32_t *state = ft_top_map_find(&ms->expansion, key);
    if (state)
        return *state == EXPLICIT_COLLAPSED ? FT_TOP_NODE_COLLAPSED : FT_TOP_NODE_EXPANDED;
    return FT_TOP_NODE_EXPANDED;
}

/* Puts each item under the section of its group, sections ordered by rate, then emits them. */
static bool emit_sections(struct ft_top_model *m, struct ft_top_mode_state *ms, size_t n)
{
    struct ft_top_item *items = ms->items;
    size_t nsections = 0;
    char buf[FT_NAMES_TEXT_MAX];

    ft_top_map_clear(&ms->scratch);
    if (!ft_top_reserve(&ms->sections, &ms->sections_cap, n, sizeof(*ms->sections)) ||
        !reserve_items(ms, 2 * n + 1))
        return false;
    items = ms->items;

    for (size_t i = 0; i < n; i++) {
        size_t len;
        const char *text = group_text(representative(&items[i]), ms->group, buf, sizeof(buf), &len);
        struct ft_top_key key = {ft_top_hash(text, len, ms->group),
                                 ft_top_hash(text, len, ms->group + 100), FT_TOP_KEY_SECTION};
        uint32_t *found = ft_top_map_find(&ms->scratch, key);
        uint32_t s;
        if (found) {
            s = *found;
        } else {
            s = (uint32_t)nsections++;
            ms->sections[s] = (struct ft_top_section){
                .by = ms->group,
                .title = ft_top_pool_text(&ms->pool, text, len),
            };
            if (!ft_top_map_put(&ms->scratch, key, s))
                return false;
            items[n + s] = (struct ft_top_item){
                .entity = &ms->sections[s],
                .key = key,
                .kind = FT_TOP_ROW_SECTION,
            };
        }
        items[i].index = s;
        ms->sections[s].rows++;
        ms->sections[s].rate += items[i].rate < 0x1p64 ? (uint64_t)items[i].rate : UINT64_MAX;
    }

    /* Items by section, keeping their order; then each section's distinct counts. */
    struct ft_top_item *grouped = ms->spare;
    uint32_t *first = ms->indices;
    for (size_t s = 0; s <= nsections; s++)
        first[s] = 0;
    for (size_t i = 0; i < n; i++)
        first[items[i].index + 1]++;
    for (size_t s = 0; s < nsections; s++)
        first[s + 1] += first[s];
    for (size_t i = 0; i < n; i++)
        grouped[first[items[i].index]++] = items[i];
    for (size_t s = nsections; s > 0; s--)
        first[s] = first[s - 1];
    first[0] = 0;
    memcpy(items, grouped, n * sizeof(*items));

    for (size_t s = 0; s < nsections; s++) {
        struct ft_top_section *sec = &ms->sections[s];
        uint32_t mark = ft_top_next_mark(m);
        for (size_t i = first[s]; i < first[s] + sec->rows; i++) {
            const struct ft_top_transfer *one;
            const struct ft_top_transfer *const *list;
            struct summary sum;
            size_t count = item_transfers(&items[i], &one, &list);
            summarize(list, count, mark, &sum);
            sec->processes += sum.processes;
            sec->files += sum.files;
            sec->destinations += sum.destinations;
        }
        items[n + s].rate = (double)sec->rate;
        items[n + s].value = (double)sec->rate;
        items[n + s].index = first[s];
    }

    struct ft_top_item *heads = items + n;
    struct order by_rate_order = rate_order(ms);
    order_items(ms, heads, nsections, &by_rate_order);
    struct order o = mode_order(ms);
    for (size_t h = 0; h < nsections; h++) {
        const struct ft_top_section *sec = heads[h].entity;
        size_t at = heads[h].index;
        enum ft_top_node node = section_node(ms, heads[h].key);
        size_t row = ms->nrows;
        if (!emit(ms, &heads[h], 0, 0, node, false))
            return false;
        order_items(ms, items + at, sec->rows, &o);
        for (size_t i = at; i < at + sec->rows; i++) {
            bool ok = node == FT_TOP_NODE_COLLAPSED
                          ? remember(ms, items[i].key, row, next_due(&items[i]))
                          : emit(ms, &items[i], 0, 0, FT_TOP_NODE_LEAF, false);
            if (!ok)
                return false;
        }
    }
    return true;
}

static bool emit_flat(struct ft_top_model *m, struct ft_top_mode_state *ms, size_t n)
{
    if (ms->group != FT_TOP_GROUP_NONE)
        return emit_sections(m, ms, n);
    struct order o = mode_order(ms);
    order_items(ms, ms->items, n, &o);
    for (size_t i = 0; i < n; i++) {
        if (!emit(ms, &ms->items[i], 0, 0, FT_TOP_NODE_LEAF, false))
            return false;
    }
    return true;
}

static bool build_transfers(struct ft_top_model *m, struct ft_top_mode_state *ms)
{
    if (!reserve_items(ms, ms->npassed + 1))
        return false;
    for (size_t i = 0; i < ms->npassed; i++)
        transfer_item(&ms->items[i], ms->passed[i], ms->sort);
    ms->view.shown = ms->view.transfers;
    ms->view.total = m->totals.transfers;
    return emit_flat(m, ms, ms->npassed);
}

/* Slices of the passed transfers per entity, by rate, at lists[0]; returns how many there are. */
static size_t slice_by(struct ft_top_mode_state *ms, uint32_t *count, uint32_t *first, size_t n,
                       uint32_t (*owner)(const struct ft_top_transfer_entry *), bool with_done)
{
    size_t total = 0;
    for (size_t i = 0; i < n; i++)
        count[i] = 0;
    for (size_t i = 0; i < ms->npassed; i++) {
        if (with_done || !ms->passed[i]->pub.done)
            count[owner(ms->passed[i])]++;
    }
    for (size_t i = 0; i < n; i++) {
        first[i] = (uint32_t)total;
        total += count[i];
        count[i] = 0;
    }
    for (size_t i = 0; i < ms->npassed; i++) {
        const struct ft_top_transfer_entry *e = ms->passed[i];
        if (!with_done && e->pub.done)
            continue;
        uint32_t o = owner(e);
        ms->lists[first[o] + count[o]++] = &e->pub;
    }
    for (size_t i = 0; i < n; i++)
        sort_by_rate(ms->lists + first[i], count[i]);
    return total;
}

static uint32_t process_of(const struct ft_top_transfer_entry *e)
{
    return e->process;
}

static uint32_t destination_of(const struct ft_top_transfer_entry *e)
{
    return e->destination;
}

static uint32_t file_of(const struct ft_top_transfer_entry *e)
{
    return e->file;
}

struct slicing {
    uint32_t *count;
    uint32_t *first;
};

static bool slicing_reserve(struct ft_top_mode_state *ms, struct slicing *s, size_t n)
{
    if (!reserve_items(ms, n + 1))
        return false;
    s->count = ms->indices;
    s->first = ms->indices_spare;
    return true;
}

static void process_values(struct ft_top_model *m, struct ft_top_process_entry *p,
                           const struct ft_top_transfer **list, size_t n)
{
    struct summary sum;
    summarize(list, n, ft_top_next_mark(m), &sum);
    p->pub.rate = sum.rate;
    p->pub.files = sum.files;
    p->pub.destinations = sum.destinations;
    p->pub.method = sum.method;
    p->pub.confidence = sum.confidence;
    p->pub.transfers = list;
    p->pub.ntransfers = n;
    uint64_t bytes = 0;
    for (size_t i = 0; i < n; i++)
        bytes += list[i]->bytes;
    p->pub.total = p->pub.known ? p->file_bytes : bytes;
}

static bool build_processes(struct ft_top_model *m, struct ft_top_mode_state *ms)
{
    size_t n = m->nprocesses[m->now];
    struct ft_top_process_entry *procs = m->processes[m->now];
    struct slicing s;

    if (!reserve_lists(ms, ms->npassed + 1) || !slicing_reserve(ms, &s, n))
        return false;
    slice_by(ms, s.count, s.first, n, process_of, false);

    size_t shown = 0;
    for (size_t i = 0; i < n; i++) {
        procs[i].count = s.count[i];
        procs[i].first = s.first[i];
    }
    for (size_t i = 0; i < n; i++) {
        struct ft_top_process_entry *p = &procs[i];
        if (p->count == 0)
            continue;
        process_values(m, p, ms->lists + p->first, p->count);
        process_item(&ms->items[shown++], &p->pub, ms->sort);
    }
    ms->view.shown = shown;
    ms->view.total = m->totals.processes.value;
    return emit_flat(m, ms, shown);
}

static void destination_label(struct ft_top_destination *d, uint16_t port)
{
    const char *open = d->address.family == 6 ? "[" : "";
    const char *close = d->address.family == 6 ? "]" : "";
    if (d->address.family == 0)
        snprintf(d->label, sizeof(d->label), "*");
    else if (d->ports == 1)
        snprintf(d->label, sizeof(d->label), "%s%s%s:%u", open, d->text, close, port);
    else
        snprintf(d->label, sizeof(d->label), "%s%s%s:*", open, d->text, close);
}

struct named {
    const char *text;
    uint64_t bytes; /* of the transfers that used it */
    uint32_t first; /* the order in which the names were met */
};

static void meet_name(struct ft_top_mode_state *ms, uint64_t destination, struct named *met,
                      size_t *n, const char *text, uint64_t bytes)
{
    size_t len = strlen(text);
    struct ft_top_key key = {ft_top_hash(text, len, destination),
                             ft_top_hash(text, len, destination + 1), FT_TOP_KEY_TEXT};
    uint32_t *at = ft_top_map_find(&ms->scratch, key);

    if (at && strcmp(met[*at].text, text) == 0) {
        met[*at].bytes += bytes;
        return;
    }
    met[*n] = (struct named){.text = text, .bytes = bytes, .first = (uint32_t)*n};
    ft_top_map_put(&ms->scratch, key, (uint32_t)*n);
    (*n)++;
}

static int by_bytes(const void *a, const void *b)
{
    const struct named *x = a;
    const struct named *y = b;
    if (x->bytes != y->bytes)
        return x->bytes > y->bytes ? -1 : 1;
    return (x->first > y->first) - (x->first < y->first);
}

static bool has_name(const struct ft_remote_names *n, const char *name)
{
    if (strcmp(n->tls, name) == 0)
        return true;
    for (uint32_t i = 0; i < n->listed; i++) {
        if (strcmp(n->resolved[i], name) == 0)
            return true;
    }
    return false;
}

static bool has_all(const struct ft_remote_names *n, const char *const *names, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!has_name(n, names[i]))
            return false;
    }
    return true;
}

static const char *destination_name(struct ft_top_pool *pool, const struct ft_top_transfer *lead,
                                    const char *const *names, size_t count)
{
    char text[FT_NAMES_TEXT_MAX];

    if (has_all(lead->names, names, count))
        ft_remote_name_format(lead->names, text, sizeof(text));
    else
        snprintf(text, sizeof(text), "%s (+%zu)", names[0], count - 1);
    return ft_top_pool_text(pool, text, strlen(text));
}

/* The names behind a destination, most bytes first, and what its NAME column shows of them. */
static void name_destination(struct ft_top_mode_state *ms, struct ft_top_destination *d,
                             uint64_t index)
{
    size_t most = 0;

    d->name = "";
    d->names = nullptr;
    d->nnames = 0;
    for (size_t k = 0; k < d->ntransfers; k++)
        most += d->transfers[k]->names ? 1 + FT_RESOLVED_NAMES : 0;
    if (most == 0)
        return;
    struct named *met = ft_top_pool_alloc(&ms->pool, most * sizeof(*met));
    const char **names = ft_top_pool_alloc(&ms->pool, most * sizeof(*names));
    if (!met || !names)
        return;

    size_t n = 0;
    for (size_t k = 0; k < d->ntransfers; k++) {
        const struct ft_remote_names *rn = d->transfers[k]->names;
        if (!rn)
            continue;
        const char *used = ft_remote_name(rn);
        uint64_t bytes = d->transfers[k]->bytes;
        if (rn->tls[0])
            meet_name(ms, index, met, &n, rn->tls, rn->tls == used ? bytes : 0);
        for (uint32_t i = 0; i < rn->listed; i++)
            meet_name(ms, index, met, &n, rn->resolved[i], rn->resolved[i] == used ? bytes : 0);
    }
    qsort(met, n, sizeof(*met), by_bytes);
    for (size_t i = 0; i < n; i++)
        names[i] = met[i].text;

    const struct ft_top_transfer *lead = nullptr;
    for (size_t k = 0; k < d->ntransfers && !lead; k++) {
        const struct ft_remote_names *rn = d->transfers[k]->names;
        if (rn && strcmp(ft_remote_name(rn), names[0]) == 0)
            lead = d->transfers[k];
    }
    d->names = names;
    d->nnames = n;
    d->name = destination_name(&ms->pool, lead, names, n);
}

static bool build_destinations(struct ft_top_model *m, struct ft_top_mode_state *ms)
{
    size_t n = m->ndestinations;
    struct slicing s;

    if (!reserve_lists(ms, ms->npassed + 1) || !slicing_reserve(ms, &s, n))
        return false;
    slice_by(ms, s.count, s.first, n, destination_of, false);
    ft_top_map_clear(&ms->scratch);

    size_t shown = 0;
    for (size_t i = 0; i < n; i++) {
        struct ft_top_destination_entry *e = &m->destinations[i];
        e->count = s.count[i];
        e->first = s.first[i];
    }
    for (size_t i = 0; i < n; i++) {
        struct ft_top_destination_entry *e = &m->destinations[i];
        struct ft_top_destination *d = &e->pub;
        const struct ft_top_transfer **list = ms->lists + e->first;
        struct summary sum;
        if (e->count == 0)
            continue;

        summarize(list, e->count, ft_top_next_mark(m), &sum);
        d->rate = sum.rate;
        d->files = sum.files;
        d->processes = sum.processes;
        d->method = sum.method;
        d->confidence = sum.confidence;
        d->transfers = list;
        d->ntransfers = e->count;
        d->top = list[0];
        name_destination(ms, d, i);

        uint64_t bytes = 0;
        uint32_t mark = ft_top_next_mark(m);
        const struct ft_top_process_entry *top = nullptr;
        d->ports = 0;
        for (size_t k = 0; k < e->count; k++) {
            const struct ft_top_transfer *t = list[k];
            struct ft_top_process_entry *p = process_entry(t->process);
            struct ft_top_key port = {i, t->remote.port, FT_TOP_KEY_PORT};
            bytes += t->bytes;
            if (!ft_top_map_find(&ms->scratch, port) && ft_top_map_put(&ms->scratch, port, 1))
                d->ports++;
            if (p->sum_mark != mark) {
                p->sum_mark = mark;
                p->sum_rate = 0;
            }
            p->sum_rate += t->rate;
            if (!top || p->sum_rate > top->sum_rate)
                top = p;
        }
        d->top_process = &top->pub;
        d->total = e->lifetime_known ? e->lifetime_bytes : bytes;
        destination_label(d, d->top->remote.port);
        destination_item(&ms->items[shown++], e, ms->sort);
    }
    ms->view.shown = shown;
    ms->view.total = m->totals.destinations;
    return emit_flat(m, ms, shown);
}

static int by_sender_rate(const void *a, const void *b)
{
    const struct ft_top_sender *x = a;
    const struct ft_top_sender *y = b;
    if (x->rate != y->rate)
        return x->rate > y->rate ? -1 : 1;
    return (x->process->pid > y->process->pid) - (x->process->pid < y->process->pid);
}

/* "nginx ×4", "nginx, php-fpm", "nginx ×3, php-fpm, java, +2". */
static const char *senders_text(struct ft_top_pool *pool, const struct ft_top_sender *senders,
                                size_t n)
{
    constexpr size_t SHOWN = 3;
    const char *names[SHOWN];
    size_t counts[SHOWN];
    size_t distinct = 0;
    size_t more = 0;
    char text[160];
    size_t len = 0;

    for (size_t i = 0; i < n; i++) {
        const char *name = senders[i].process->name;
        size_t k = 0;
        while (k < distinct && strcmp(names[k], name) != 0)
            k++;
        if (k < distinct) {
            counts[k]++;
        } else if (distinct < SHOWN) {
            names[distinct] = name;
            counts[distinct++] = 1;
        } else {
            bool listed = false;
            for (size_t j = 0; j < i && !listed; j++)
                listed = strcmp(senders[j].process->name, name) == 0;
            more += !listed;
        }
    }
    text[0] = '\0';
    for (size_t k = 0; k < distinct && len < sizeof(text); k++) {
        int w = counts[k] > 1
                    ? snprintf(text + len, sizeof(text) - len, "%s%s ×%zu", k ? ", " : "", names[k],
                               counts[k])
                    : snprintf(text + len, sizeof(text) - len, "%s%s", k ? ", " : "", names[k]);
        len += w > 0 ? (size_t)w : 0;
    }
    if (more && len < sizeof(text))
        snprintf(text + len, sizeof(text) - len, ", +%zu", more);
    return ft_top_pool_text(pool, text, strnlen(text, sizeof(text)));
}

static bool build_files(struct ft_top_model *m, struct ft_top_mode_state *ms)
{
    size_t n = m->nfiles;
    struct slicing s;

    if (!reserve_lists(ms, ms->npassed + 1) || !slicing_reserve(ms, &s, n) ||
        !ft_top_reserve(&ms->senders, &ms->senders_cap, ms->npassed + 1, sizeof(*ms->senders)))
        return false;
    slice_by(ms, s.count, s.first, n, file_of, false);

    size_t shown = 0;
    size_t nsenders = 0;
    for (size_t i = 0; i < n; i++) {
        m->files[i].count = s.count[i];
        m->files[i].first = s.first[i];
    }
    for (size_t i = 0; i < n; i++) {
        struct ft_top_file_entry *e = &m->files[i];
        struct ft_top_file *f = &e->pub;
        const struct ft_top_transfer **list = ms->lists + e->first;
        struct summary sum;
        if (e->count == 0)
            continue;

        summarize(list, e->count, ft_top_next_mark(m), &sum);
        f->rate = sum.rate;
        f->destinations = sum.destinations;
        f->processes = sum.processes;
        f->method = sum.method;
        f->confidence = sum.confidence;
        f->active = e->count;
        f->transfers = list;
        f->ntransfers = e->count;
        f->top = list[0];
        f->rate_public = 0;

        struct ft_top_sender *senders = ms->senders + nsenders;
        size_t count = 0;
        uint32_t mark = ft_top_next_mark(m);
        for (size_t k = 0; k < e->count; k++) {
            const struct ft_top_transfer *t = list[k];
            struct ft_top_process_entry *p = process_entry(t->process);
            if (t->is_public)
                f->rate_public += t->rate;
            if (p->sum_mark != mark) {
                p->sum_mark = mark;
                p->sum_transfers = (uint32_t)count;
                senders[count++] = (struct ft_top_sender){.process = &p->pub};
            }
            senders[p->sum_transfers].transfers++;
            senders[p->sum_transfers].rate += t->rate;
        }
        qsort(senders, count, sizeof(*senders), by_sender_rate);
        nsenders += count;
        f->by_sender = senders;
        f->nsenders = count;
        f->public_share = f->rate ? (double)f->rate_public / (double)f->rate : 0.0;
        f->senders = senders_text(&ms->pool, senders, count);
        file_item(&ms->items[shown++], e, ms->sort);
    }
    ms->view.shown = shown;
    ms->view.total = m->totals.files.value;
    return emit_flat(m, ms, shown);
}

struct tree {
    struct ft_top_model *m;
    struct ft_top_mode_state *ms;
    struct ft_top_tree_node *nodes;
    size_t nnodes;
    uint32_t roots;                     /* first root; roots are linked by next_sibling */
    const struct ft_top_transfer **own; /* own transfers per node, at nodes[i].own_first */
    const struct ft_top_transfer **sub; /* transfers in depth-first order */
    size_t top;                         /* items in use below this level */
    size_t nfolds;
};

static uint32_t add_node(struct tree *t, struct ft_top_process_entry *p)
{
    uint32_t i = (uint32_t)t->nnodes++;
    t->nodes[i] = (struct ft_top_tree_node){
        .proc = p,
        .parent = FT_TOP_NONE,
        .first_child = FT_TOP_NONE,
        .next_sibling = FT_TOP_NONE,
    };
    p->node = i;
    return i;
}

static struct ft_top_process_entry *placeholder(struct tree *t, uint32_t pid, size_t *nplaceholders)
{
    struct ft_top_mode_state *ms = t->ms;
    struct ft_top_key key = {pid, 0, FT_TOP_KEY_PROCESS};
    uint32_t *found = ft_top_map_find(&ms->scratch, key);
    if (found)
        return &ms->placeholders[*found];

    struct ft_top_process_entry *p = &ms->placeholders[*nplaceholders];
    *p = (struct ft_top_process_entry){.node = FT_TOP_NONE};
    snprintf(p->pid_text, sizeof(p->pid_text), "%u", pid);
    p->pub = (struct ft_top_process){
        .pid = pid,
        .user = "",
        .comm = "",
        .exe = "",
        .command_line = "",
        .cwd = "",
        .script = "",
        .script_name = "",
        .title = "",
        .name = "",
        .head = "",
        .rest = "",
    };
    ft_top_map_put(&ms->scratch, key, (uint32_t)(*nplaceholders)++);
    return p;
}

/* Every process with a passed transfer, and the ancestors that lead to it. */
static void grow_tree(struct tree *t)
{
    struct ft_top_model *m = t->m;
    struct ft_top_process_entry *procs = m->processes[m->now];
    size_t nprocs = m->nprocesses[m->now];
    size_t nplaceholders = 0;

    ft_top_map_clear(&t->ms->scratch);
    for (size_t i = 0; i < nprocs; i++)
        procs[i].node = FT_TOP_NONE;
    for (size_t i = 0; i < nprocs; i++) {
        if (procs[i].count)
            add_node(t, &procs[i]);
    }
    for (size_t i = 0; i < t->nnodes; i++) {
        struct ft_top_process_entry *p = t->nodes[i].proc;
        uint32_t ppid = p->pub.ppid;
        if (!p->pub.known && p->pub.ppid == 0)
            continue;
        if (ppid <= 1 || ppid == p->pub.pid)
            continue;
        uint32_t *found =
            ft_top_map_find(&m->process_index, (struct ft_top_key){ppid, 0, FT_TOP_KEY_PROCESS});
        struct ft_top_process_entry *parent =
            found ? &procs[*found] : placeholder(t, ppid, &nplaceholders);
        if (parent->node == FT_TOP_NONE)
            add_node(t, parent);
        t->nodes[i].parent = parent->node;
    }

    /* A loop of parents would hide its members, a chain too long would nest too deep: cut both. */
    for (size_t i = 0; i < t->nnodes; i++) {
        uint32_t at = t->nodes[i].parent;
        for (size_t depth = 1; at != FT_TOP_NONE; depth++) {
            if (depth == TREE_LEVELS || at == i) {
                t->nodes[i].parent = FT_TOP_NONE;
                break;
            }
            at = t->nodes[at].parent;
        }
    }

    t->roots = FT_TOP_NONE;
    for (size_t i = t->nnodes; i-- > 0;) {
        struct ft_top_tree_node *node = &t->nodes[i];
        if (node->parent == FT_TOP_NONE) {
            node->next_sibling = t->roots;
            t->roots = (uint32_t)i;
        } else {
            struct ft_top_tree_node *parent = &t->nodes[node->parent];
            node->next_sibling = parent->first_child;
            parent->first_child = (uint32_t)i;
            parent->children++;
        }
    }
}

/* Lays out each node's transfers and its descendants' as one range, and sums over it. */
static void sum_tree(struct tree *t)
{
    struct ft_top_model *m = t->m;
    uint32_t *preorder = t->ms->indices;
    size_t npre = 0;
    size_t pos = 0;

    for (uint32_t root = t->roots; root != FT_TOP_NONE; root = t->nodes[root].next_sibling) {
        uint32_t v = root;
        bool finished = false;
        while (!finished) {
            struct ft_top_tree_node *node = &t->nodes[v];
            preorder[npre++] = v;
            node->sub_first = (uint32_t)pos;
            for (size_t k = 0; k < node->own_count; k++)
                t->sub[pos++] = t->own[node->own_first + k];
            if (node->first_child != FT_TOP_NONE) {
                v = node->first_child;
                continue;
            }
            for (;;) {
                t->nodes[v].sub_end = (uint32_t)pos;
                if (v == root) {
                    finished = true;
                    break;
                }
                if (t->nodes[v].next_sibling != FT_TOP_NONE) {
                    v = t->nodes[v].next_sibling;
                    break;
                }
                v = t->nodes[v].parent;
            }
        }
    }

    for (size_t i = 0; i < t->nnodes; i++) {
        struct ft_top_tree_node *node = &t->nodes[i];
        const struct ft_top_process_entry *p = node->proc;
        node->total = p->pub.known ? p->file_bytes : 0;
        for (size_t k = 0; !p->pub.known && k < node->own_count; k++)
            node->total += t->own[node->own_first + k]->bytes;
    }
    for (size_t k = npre; k-- > 0;) {
        const struct ft_top_tree_node *node = &t->nodes[preorder[k]];
        if (node->parent != FT_TOP_NONE)
            t->nodes[node->parent].total += node->total;
    }
    for (size_t i = 0; i < t->nnodes; i++) {
        struct ft_top_tree_node *node = &t->nodes[i];
        struct ft_top_process *p = &node->proc->pub;
        struct summary sum;
        summarize(t->sub + node->sub_first, node->sub_end - node->sub_first, ft_top_next_mark(m),
                  &sum);
        p->rate = sum.rate;
        p->files = sum.files;
        p->destinations = sum.destinations;
        p->method = sum.method;
        p->confidence = sum.confidence;
        p->total = node->total;
        p->transfers = t->own + node->own_first;
        p->ntransfers = node->own_count;
    }
}

static enum shows node_shows(const struct ft_top_mode_state *ms, struct ft_top_key key,
                             bool has_children)
{
    uint32_t *state = ft_top_map_find(&ms->expansion, key);
    if (state)
        return *state == EXPLICIT_COLLAPSED ? SHOWS_NOTHING : SHOWS_ALL;
    if (ms->expanded_all)
        return SHOWS_ALL;
    return has_children ? SHOWS_CHILDREN : SHOWS_NOTHING;
}

static bool fold_open(const struct ft_top_mode_state *ms, struct ft_top_key key)
{
    uint32_t *state = ft_top_map_find(&ms->expansion, key);
    return state ? *state == EXPLICIT_EXPANDED : ms->expanded_all;
}

static uint32_t child_rails(uint32_t rails, uint8_t depth, bool last)
{
    return depth >= 1 && depth < 32 && !last ? rails | 1u << depth : rails;
}

static bool emit_node(struct tree *t, uint32_t v, uint8_t depth, uint32_t rails, bool last,
                      const struct ft_top_item *it);

/* A fold row for siblings beyond the first of their title. */
static void fold_values(struct tree *t, struct ft_top_fold *fold, struct ft_top_item *it)
{
    uint32_t mark = ft_top_next_mark(t->m);
    struct summary sum = {0};
    struct summary part;
    uint64_t by_method[FT_TOP_METHODS] = {0};

    for (size_t k = 0; k < fold->count; k++) {
        const struct ft_top_tree_node *node = &t->nodes[process_entry(fold->members[k])->node];
        summarize(t->sub + node->sub_first, node->sub_end - node->sub_first, mark, &part);
        sum.rate += part.rate;
        sum.files += part.files;
        sum.destinations += part.destinations;
        by_method[part.method] += part.rate;
        fold->total += node->total;
    }
    for (size_t i = 0; i < FT_TOP_METHODS; i++) {
        if (by_method[i] > by_method[sum.method])
            sum.method = (uint8_t)i;
    }
    if (sum.rate == 0 && fold->count)
        sum.method = fold->members[0]->method;
    fold->rate = sum.rate;
    fold->files = sum.files;
    fold->destinations = sum.destinations;
    fold->method = sum.method;
    tally_item(it,
               &(struct tally){fold->rate, fold->total, fold->files, fold->destinations,
                               fold->members[0]->pid, fold->method, fold->members[0]->user,
                               fold->title},
               t->ms->sort);
}

/*
 * Emits what hangs below a node at depth: its own transfers when it shows them, then its
 * children, siblings sharing a title beyond the first of them folded into one row.
 */
static bool emit_below(struct tree *t, uint32_t parent, uint32_t first_child, size_t ntransfers,
                       const struct ft_top_transfer *const *transfers, uint8_t depth,
                       uint32_t rails)
{
    struct ft_top_mode_state *ms = t->ms;
    size_t base = t->top;
    size_t nchildren = 0;

    for (uint32_t c = first_child; c != FT_TOP_NONE; c = t->nodes[c].next_sibling) {
        struct ft_top_item *it = &ms->items[base + nchildren++];
        process_item(it, &t->nodes[c].proc->pub, ms->sort);
        it->index = c;
    }
    struct order o = mode_order(ms);
    order_items(ms, ms->items + base, nchildren, &o);

    /* Count titles, then send the second and later of a crowded title into its fold. */
    uint32_t parent_pid = parent == FT_TOP_NONE ? 0 : t->nodes[parent].proc->pub.pid;
    ft_top_map_clear(&ms->scratch);
    for (size_t k = 0; k < nchildren; k++) {
        const struct ft_top_process *p = ms->items[base + k].entity;
        size_t len = strlen(p->title);
        struct ft_top_key key = {ft_top_hash(p->title, len, 7), parent_pid, FT_TOP_KEY_FOLD};
        uint32_t *n = ft_top_map_find(&ms->scratch, key);
        ft_top_map_put(&ms->scratch, key, n ? *n + 1 : 1);
    }

    size_t listed = base + nchildren;
    size_t nlisted = 0;
    struct ft_top_item *list = &ms->items[listed];
    for (size_t k = 0; k < nchildren; k++) {
        struct ft_top_item *it = &ms->items[base + k];
        const struct ft_top_process *p = it->entity;
        size_t len = strlen(p->title);
        struct ft_top_key key = {ft_top_hash(p->title, len, 7), parent_pid, FT_TOP_KEY_FOLD};
        uint32_t *n = ft_top_map_find(&ms->scratch, key);
        process_entry(p)->fold = FT_TOP_NONE;
        if (!n || *n < FOLD_AT || p->title[0] == '\0') {
            list[nlisted++] = *it;
            continue;
        }
        /* The first of the title keeps its row, and its fold row follows it. */
        struct ft_top_key first = {key.a, key.b, FT_TOP_KEY_SECTION};
        uint32_t *at = ft_top_map_find(&ms->scratch, first);
        if (!at) {
            list[nlisted++] = *it;
            struct ft_top_fold *fold = &ms->folds[t->nfolds];
            const struct ft_top_process **members =
                ft_top_pool_alloc(&ms->pool, (*n - 1) * sizeof(*members));
            if (!members)
                return false;
            *fold = (struct ft_top_fold){.title = p->title, .name = p->name, .members = members};
            list[nlisted] = (struct ft_top_item){
                .entity = fold,
                .key = key,
                .kind = FT_TOP_ROW_FOLD,
                .index = (uint32_t)t->nfolds++,
            };
            ft_top_map_put(&ms->scratch, first, (uint32_t)nlisted++);
            continue;
        }
        struct ft_top_fold *fold = (struct ft_top_fold *)(void *)list[*at].entity;
        ((const struct ft_top_process **)fold->members)[fold->count++] = p;
        process_entry(p)->fold = list[*at].index;
    }
    for (size_t k = 0; k < nlisted; k++) {
        if (list[k].kind == FT_TOP_ROW_FOLD)
            fold_values(t, (struct ft_top_fold *)(void *)list[k].entity, &list[k]);
    }
    t->top = listed + nlisted;

    /* Own transfers first, by rate. */
    size_t tbase = t->top;
    for (size_t k = 0; k < ntransfers; k++)
        transfer_item(&ms->items[tbase + k], transfer_entry(transfers[k]), FT_TOP_SORT_RATE);
    struct order by_rate_order = rate_order(ms);
    order_items(ms, ms->items + tbase, ntransfers, &by_rate_order);
    t->top = tbase + ntransfers;

    uint8_t below = depth < UINT8_MAX ? (uint8_t)(depth + 1) : depth;
    if (parent == FT_TOP_NONE)
        below = 0;
    for (size_t k = 0; k < ntransfers; k++) {
        bool last = k + 1 == ntransfers && nlisted == 0;
        if (!emit(ms, &ms->items[tbase + k], below, rails, FT_TOP_NODE_LEAF, last))
            return false;
    }
    for (size_t k = 0; k < nlisted; k++) {
        const struct ft_top_item *it = &list[k];
        bool last = k + 1 == nlisted;
        bool ok;
        if (it->kind == FT_TOP_ROW_FOLD) {
            const struct ft_top_fold *fold = it->entity;
            bool open = fold_open(ms, it->key);
            size_t row = ms->nrows;
            ok = emit(ms, it, below, rails, open ? FT_TOP_NODE_EXPANDED : FT_TOP_NODE_COLLAPSED,
                      last);
            uint32_t inner = child_rails(rails, below, last);
            uint8_t deeper = below < UINT8_MAX ? (uint8_t)(below + 1) : below;
            size_t j = 0;
            for (size_t c = 0; ok && c < nchildren; c++) {
                const struct ft_top_item *member = &ms->items[base + c];
                if (process_entry(member->entity)->fold != it->index)
                    continue;
                j++;
                ok = open ? emit_node(t, member->index, deeper, inner, j == fold->count, member)
                          : remember(ms, member->key, row, next_due(member));
            }
        } else {
            ok = emit_node(t, it->index, below, rails, last, it);
        }
        if (!ok)
            return false;
    }
    t->top = base;
    return true;
}

static bool emit_node(struct tree *t, uint32_t v, uint8_t depth, uint32_t rails, bool last,
                      const struct ft_top_item *it)
{
    struct ft_top_mode_state *ms = t->ms;
    const struct ft_top_tree_node *node = &t->nodes[v];
    bool has_children = node->first_child != FT_TOP_NONE;
    enum shows shows = node_shows(ms, it->key, has_children);
    enum ft_top_node state = !has_children && node->own_count == 0 ? FT_TOP_NODE_LEAF
                             : shows == SHOWS_NOTHING              ? FT_TOP_NODE_COLLAPSED
                                                                   : FT_TOP_NODE_EXPANDED;
    size_t row = ms->nrows;

    if (!emit(ms, it, depth, rails, state, last))
        return false;
    if (shows == SHOWS_NOTHING) {
        for (size_t k = 0; k < node->own_count; k++) {
            if (!remember(ms, transfer_entry(t->own[node->own_first + k])->key, row, 0))
                return false;
        }
        for (uint32_t c = node->first_child; c != FT_TOP_NONE; c = t->nodes[c].next_sibling) {
            if (!remember(ms, (struct ft_top_key){t->nodes[c].proc->pub.pid, 0, FT_TOP_KEY_PROCESS},
                          row, 0))
                return false;
        }
        return true;
    }
    size_t ntransfers = shows == SHOWS_ALL ? node->own_count : 0;
    return emit_below(t, v, node->first_child, ntransfers, t->own + node->own_first, depth,
                      child_rails(rails, depth, last));
}

static bool build_tree(struct ft_top_model *m, struct ft_top_mode_state *ms)
{
    size_t nprocs = m->nprocesses[m->now];
    struct ft_top_process_entry *procs = m->processes[m->now];
    size_t most = 2 * nprocs + 1;
    struct slicing s;
    struct tree t = {.m = m, .ms = ms};

    if (!reserve_lists(ms, 2 * ms->npassed + 1) || !slicing_reserve(ms, &s, nprocs) ||
        !ft_top_reserve(&ms->nodes, &ms->nodes_cap, most, sizeof(*ms->nodes)) ||
        !ft_top_reserve(&ms->placeholders, &ms->placeholders_cap, nprocs + 1,
                        sizeof(*ms->placeholders)) ||
        !ft_top_reserve(&ms->folds, &ms->folds_cap, nprocs + 1, sizeof(*ms->folds)) ||
        !ft_top_map_reserve(&ms->scratch, most))
        return false;
    size_t shown = 0;
    slice_by(ms, s.count, s.first, nprocs, process_of, true);
    for (size_t i = 0; i < nprocs; i++) {
        procs[i].count = s.count[i];
        procs[i].first = s.first[i];
        shown += s.count[i] != 0;
    }

    t.nodes = ms->nodes;
    t.own = ms->lists;
    t.sub = ms->lists + ms->npassed;
    grow_tree(&t);
    for (size_t i = 0; i < t.nnodes; i++) {
        struct ft_top_tree_node *node = &t.nodes[i];
        node->own_first = node->proc->count ? node->proc->first : 0;
        node->own_count = node->proc->count;
    }
    if (!reserve_items(ms, 3 * t.nnodes + ms->npassed + 16))
        return false;
    sum_tree(&t);

    ms->view.shown = shown;
    ms->view.total = m->totals.processes.value;
    return emit_below(&t, FT_TOP_NONE, t.roots, 0, nullptr, 0, 0);
}

static struct ft_top_key leader_key(const struct ft_row_leader *row)
{
    size_t len = strlen(row->text);
    uint64_t address =
        ft_top_hash((const char *)row->remote.addr, sizeof(row->remote.addr), row->remote.family);
    return (struct ft_top_key){ft_top_hash(row->text, len, 11), address, FT_TOP_KEY_LEADER};
}

static bool build_leaders(struct ft_top_model *m, struct ft_top_mode_state *ms)
{
    const struct ft_top_cached_answer *a = ft_top_current_answer(m);
    struct ft_top_leaders *view = &m->leaders;
    enum ft_top_sort by = ms->sort;

    *view = (struct ft_top_leaders){
        .window = m->leaders_window,
        .key = m->leaders_key,
        .by = by,
        .answered = a != nullptr,
    };
    ms->view = (struct ft_top_view){0};
    if (!a)
        return true;

    size_t nside = a->ndirectories + a->ndestinations;
    if (!ft_top_reserve(&m->side, &m->side_cap, nside + 1, sizeof(*m->side)) ||
        !ft_top_reserve(&ms->leaders, &ms->leaders_cap, a->nrows + 1, sizeof(*ms->leaders)) ||
        !reserve_items(ms, a->nrows + 1))
        return false;

    double span = (double)a->summary.bytes;
    bool compared = a->summary.previous_from_wall_ns != 0;
    view->summary = a->summary;
    view->exact_share = span > 0 ? (double)a->summary.bytes_exact / span : 0.0;
    view->concentration = span > 0 ? (double)a->summary.top_bytes / span : 0.0;
    for (size_t i = 0; i < a->ndirectories; i++)
        ft_top_leader_fill(m, &a->directories[i], (double)a->directories[0].bytes, span,
                           FT_TOP_SORT_BYTES, compared, &m->side[i]);
    for (size_t i = 0; i < a->ndestinations; i++)
        ft_top_leader_fill(m, &a->destinations[i], (double)a->destinations[0].bytes, span,
                           FT_TOP_SORT_BYTES, compared, &m->side[a->ndirectories + i]);
    view->directories = m->side;
    view->ndirectories = a->ndirectories;
    view->destinations = m->side + a->ndirectories;
    view->ndestinations = a->ndestinations;

    double top = 0;
    if (a->nrows) {
        const struct ft_row_leader *first = &a->rows[0];
        top = (double)(by == FT_TOP_SORT_TRANSFERS      ? first->transfers
                       : by == FT_TOP_SORT_DESTINATIONS ? first->destinations
                                                        : first->bytes);
    }
    size_t shown = 0;
    for (size_t i = 0; i < a->nrows; i++) {
        struct ft_top_leader *l = &ms->leaders[i];
        ft_top_leader_fill(m, &a->rows[i], top, span, by, compared, l);
        const char *senders[FT_LEADER_SENDERS];
        size_t nsenders = 0;
        for (size_t k = 0; k < FT_LEADER_SENDERS && a->rows[i].senders[k].name[0]; k++)
            senders[nsenders++] = a->rows[i].senders[k].name;
        struct ft_top_leader_subject subject = {
            .text = a->rows[i].text,
            .senders = senders,
            .nsenders = nsenders,
            .remote = &a->rows[i].remote,
            .remote_text = l->remote_text,
            .host = l->host,
            .method = a->rows[i].method,
            .confidence = a->rows[i].confidence,
        };
        if (ms->filter && !ft_top_filter_match_leader(ms->filter, &subject))
            continue;
        struct ft_top_item it = {
            .entity = l, .key = leader_key(&a->rows[i]), .kind = FT_TOP_ROW_LEADER};
        if (!emit(ms, &it, 0, 0, FT_TOP_NODE_LEAF, false))
            return false;
        shown++;
    }
    ms->view.shown = shown;
    ms->view.total = a->nrows;
    return true;
}

static bool names_match(const struct ft_remote_names *names, const char *needle, size_t n)
{
    size_t a;
    size_t b;

    if (!names)
        return false;
    if (ft_top_find(names->tls, needle, n, &a, &b))
        return true;
    for (uint32_t i = 0; i < names->listed; i++) {
        if (ft_top_find(names->resolved[i], needle, n, &a, &b))
            return true;
    }
    return false;
}

static bool row_matches(const struct ft_top_row *r, const char *needle, size_t n)
{
    size_t a;
    size_t b;
#define FIND(text) ft_top_find((text), needle, n, &a, &b)
    switch (r->kind) {
    case FT_TOP_ROW_TRANSFER: {
        const struct ft_top_transfer *t = r->transfer;
        const struct ft_top_process_entry *p = process_entry(t->process);
        return FIND(p->pid_text) || FIND(p->pub.user) || FIND(p->pub.title) || FIND(t->script) ||
               FIND(t->path) || FIND(t->remote_text) || names_match(t->names, needle, n) ||
               FIND(t->destination->host) || FIND(ft_method_name((enum ft_method)t->method)) ||
               FIND(ft_confidence_name((enum ft_confidence)t->confidence));
    }
    case FT_TOP_ROW_PROCESS: {
        const struct ft_top_process *p = r->process;
        return FIND(process_entry(p)->pid_text) || FIND(p->user) || FIND(p->title) ||
               FIND(p->rest) || FIND(p->script);
    }
    case FT_TOP_ROW_DESTINATION: {
        const struct ft_top_destination *d = r->destination;
        bool named = false;
        for (size_t k = 0; k < d->nnames && !named; k++)
            named = FIND(d->names[k]);
        return FIND(d->label) || named || FIND(d->host) ||
               (d->top_process && FIND(d->top_process->title)) || (d->top && FIND(d->top->path));
    }
    case FT_TOP_ROW_FILE:
        return FIND(r->file->path) || FIND(r->file->senders);
    case FT_TOP_ROW_SECTION:
        return FIND(r->section->title);
    case FT_TOP_ROW_FOLD:
        return FIND(r->fold->title);
    case FT_TOP_ROW_LEADER: {
        const struct ft_top_leader *l = r->leader;
        bool sender = false;
        for (size_t k = 0; k < FT_LEADER_SENDERS && !sender; k++)
            sender = FIND(l->row->senders[k].name);
        return sender || FIND(l->row->text) || FIND(l->remote_text) || FIND(l->host);
    }
    default:
        return false;
    }
#undef FIND
}

void ft_top_refresh_flags(struct ft_top_model *m, enum ft_top_mode mode)
{
    struct ft_top_mode_state *ms = &m->modes[mode];
    size_t matches = 0;

    for (size_t i = 0; i < ms->nrows; i++) {
        struct ft_top_row *r = &ms->rows[i];
        uint8_t flags = r->flags & FT_TOP_ROW_LAST;
        if (r->kind == FT_TOP_ROW_TRANSFER && r->transfer->done)
            flags |= FT_TOP_ROW_DONE;
        if (ms->tags.count && ft_top_map_find(&ms->tags, ms->row_keys[i]))
            flags |= FT_TOP_ROW_TAGGED;
        if (ms->search_len && row_matches(r, ms->search, ms->search_len)) {
            flags |= FT_TOP_ROW_MATCH;
            matches++;
        }
        if (i == ms->selected_index)
            flags |= FT_TOP_ROW_SELECTED;
        r->flags = flags;
    }
    ms->view.matches = matches;
}

/* Keeps the selection on its entity, or else on the row that took its place. */
static void place_selection(struct ft_top_mode_state *ms)
{
    if (ms->nrows == 0) {
        ms->selected_index = SIZE_MAX;
        return;
    }
    if (ms->has_selected) {
        uint32_t *found = ft_top_map_find(&ms->memory[ms->memory_now], ms->selected);
        if (found) {
            ms->selected_index = *found & POSITION_MASK;
            return;
        }
    }
    size_t i = ms->selected_index;
    if (!ms->has_selected || i == SIZE_MAX)
        i = 0;
    else if (i >= ms->nrows)
        i = ms->nrows - 1;
    ms->selected_index = i;
    ms->selected = ms->row_keys[i];
    ms->has_selected = true;
}

bool ft_top_build(struct ft_top_model *m, enum ft_top_mode mode)
{
    struct ft_top_mode_state *ms = &m->modes[mode];
    bool ok;

    ft_top_pool_reset(&ms->pool);
    ft_top_map_clear(next_memory(ms));
    ms->nrows = 0;
    if (mode == FT_TOP_LEADERS) {
        ok = build_leaders(m, ms);
    } else {
        ok = pass_filter(m, ms);
        if (ok) {
            count_view(m, ms);
            if (mode == FT_TOP_TRANSFERS) {
                ok = build_transfers(m, ms);
            } else if (mode == FT_TOP_PROCESSES) {
                ok = m->tree ? build_tree(m, ms) : build_processes(m, ms);
            } else if (mode == FT_TOP_DESTINATIONS) {
                ok = build_destinations(m, ms);
            } else {
                ok = build_files(m, ms);
            }
        }
    }
    ok = ok && !ms->pool.failed;
    if (!ok)
        ms->nrows = 0;

    ms->memory_now ^= 1;
    place_selection(ms);
    ft_top_refresh_flags(m, mode);
    ms->stale = !ok;
    if (ok)
        ms->reorder = false;
    return ok;
}
