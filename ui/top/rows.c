#include "ui/top/model_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

constexpr double HOLD_SHARE = 0.05; /* rows closer than this keep their order */
constexpr uint32_t POSITION_MASK = 0xffffffu;
constexpr uint32_t EXPLICIT_COLLAPSED = 1;

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

static struct ft_top_process_entry *process_entry(const struct ft_top_process *p)
{
    return (struct ft_top_process_entry *)(void *)p;
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

static void process_item(struct ft_top_item *it, const struct ft_top_process *p,
                         enum ft_top_sort sort)
{
    *it = (struct ft_top_item){
        .entity = p,
        .key = {p->pid, 0, FT_TOP_KEY_PROCESS},
        .kind = FT_TOP_ROW_PROCESS,
    };
    it->rate = (double)p->rate;
    switch (sort) {
    case FT_TOP_SORT_TOTAL:
        it->value = (double)p->total;
        break;
    case FT_TOP_SORT_FILES:
        it->value = p->files;
        break;
    case FT_TOP_SORT_DESTINATIONS:
        it->value = p->destinations;
        break;
    case FT_TOP_SORT_PID:
        it->value = p->pid;
        break;
    case FT_TOP_SORT_USER:
        it->text = p->user;
        break;
    case FT_TOP_SORT_METHOD:
        it->text = ft_method_name((enum ft_method)p->method);
        break;
    case FT_TOP_SORT_PROCESS:
        it->text = p->title;
        break;
    default:
        it->value = (double)p->rate;
        break;
    }
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
    char buf[64];

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
        ms->sections[s].rate += (uint64_t)items[i].rate;
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
               FIND(t->path) || FIND(t->remote_text) || FIND(t->destination->host) ||
               FIND(ft_method_name((enum ft_method)t->method)) ||
               FIND(ft_confidence_name((enum ft_confidence)t->confidence));
    }
    case FT_TOP_ROW_PROCESS: {
        const struct ft_top_process *p = r->process;
        return FIND(process_entry(p)->pid_text) || FIND(p->user) || FIND(p->title) ||
               FIND(p->rest) || FIND(p->script);
    }
    case FT_TOP_ROW_DESTINATION: {
        const struct ft_top_destination *d = r->destination;
        return FIND(d->label) || FIND(d->host) || (d->top_process && FIND(d->top_process->title)) ||
               (d->top && FIND(d->top->path));
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
        ms->view = (struct ft_top_view){0};
        ok = true;
    } else {
        ok = pass_filter(m, ms);
        if (ok) {
            count_view(m, ms);
            if (mode == FT_TOP_TRANSFERS) {
                ok = build_transfers(m, ms);
            } else if (mode == FT_TOP_PROCESSES) {
                ok = build_processes(m, ms);
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
