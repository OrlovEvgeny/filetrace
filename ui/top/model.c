#include "ui/top/model_internal.h"

#include "filetrace/format.h"

#include <errno.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

constexpr uint64_t HALF_LIFE_NS = 3 * FT_NS_PER_SEC;
constexpr uint64_t RECENT_NS =
    5 * 60 * FT_NS_PER_SEC; /* NEW, and how long an idle address is kept */
constexpr uint64_t SHRINK_NS = 60 * FT_NS_PER_SEC;
constexpr size_t LOOKUPS_PER_SAMPLE = 256;
constexpr size_t CHUNK_SIZE = 64 * 1024;

enum scale_index : uint8_t {
    SCALE_RATE,
    SCALE_STARTED,
    SCALE_PROCESSES,
    SCALE_FILES,
    SCALE_FANOUT,
    SCALE_NEW,
};

struct ft_top_chunk {
    struct ft_top_chunk *next;
    size_t size;
    size_t used;
    max_align_t data[];
};

static uint64_t mix(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static size_t home_slot(size_t capacity, uint64_t a, uint64_t b, uint32_t kind)
{
    return (size_t)mix(a ^ mix(b + ((uint64_t)kind << 40))) & (capacity - 1);
}

static bool slot_is(const struct ft_top_map_slot *s, struct ft_top_key key)
{
    return s->kind == key.kind && s->a == key.a && s->b == key.b;
}

/* The slot that holds key, or the map's capacity when none does. */
static size_t slot_of(const struct ft_top_map *map, struct ft_top_key key)
{
    if (map->count == 0)
        return map->capacity;
    for (size_t i = home_slot(map->capacity, key.a, key.b, key.kind);;
         i = (i + 1) & (map->capacity - 1)) {
        const struct ft_top_map_slot *s = &map->slots[i];
        if (s->kind == FT_TOP_KEY_EMPTY)
            return map->capacity;
        if (slot_is(s, key))
            return i;
    }
}

uint32_t *ft_top_map_find(const struct ft_top_map *map, struct ft_top_key key)
{
    size_t i = slot_of(map, key);
    return i < map->capacity ? &map->slots[i].value : nullptr;
}

static void map_place(struct ft_top_map *map, const struct ft_top_map_slot *entry)
{
    size_t i = home_slot(map->capacity, entry->a, entry->b, entry->kind);
    while (map->slots[i].kind != FT_TOP_KEY_EMPTY)
        i = (i + 1) & (map->capacity - 1);
    map->slots[i] = *entry;
    map->count++;
}

/* Makes room for count entries in all, so that putting them cannot fail. */
bool ft_top_map_reserve(struct ft_top_map *map, size_t count)
{
    size_t capacity = map->capacity ? map->capacity : 64;
    while (count * 4 > capacity * 3)
        capacity *= 2;
    if (capacity == map->capacity)
        return true;

    struct ft_top_map_slot *slots = calloc(capacity, sizeof(*slots));
    if (!slots)
        return false;
    struct ft_top_map old = *map;
    map->slots = slots;
    map->capacity = capacity;
    map->count = 0;
    for (size_t i = 0; i < old.capacity; i++) {
        if (old.slots[i].kind != FT_TOP_KEY_EMPTY)
            map_place(map, &old.slots[i]);
    }
    free(old.slots);
    return true;
}

bool ft_top_map_put(struct ft_top_map *map, struct ft_top_key key, uint32_t value)
{
    uint32_t *found = ft_top_map_find(map, key);
    if (found) {
        *found = value;
        return true;
    }
    if (!ft_top_map_reserve(map, map->count + 1))
        return false;
    map_place(map, &(struct ft_top_map_slot){key.a, key.b, key.kind, value});
    return true;
}

void ft_top_map_remove(struct ft_top_map *map, struct ft_top_key key)
{
    size_t hole = slot_of(map, key);
    if (hole >= map->capacity)
        return;

    size_t mask = map->capacity - 1;
    for (size_t j = (hole + 1) & mask; map->slots[j].kind != FT_TOP_KEY_EMPTY; j = (j + 1) & mask) {
        const struct ft_top_map_slot *s = &map->slots[j];
        size_t home = home_slot(map->capacity, s->a, s->b, s->kind);
        bool stays = hole <= j ? (hole < home && home <= j) : (hole < home || home <= j);
        if (!stays) {
            map->slots[hole] = *s;
            hole = j;
        }
    }
    map->slots[hole].kind = FT_TOP_KEY_EMPTY;
    map->count--;
}

void ft_top_map_clear(struct ft_top_map *map)
{
    if (map->count)
        memset(map->slots, 0, map->capacity * sizeof(*map->slots));
    map->count = 0;
}

void ft_top_map_free(struct ft_top_map *map)
{
    free(map->slots);
    *map = (struct ft_top_map){0};
}

uint64_t ft_top_hash(const char *text, size_t len, uint64_t seed)
{
    uint64_t h = 0xcbf29ce484222325ULL ^ mix(seed);
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)text[i];
        h *= 0x100000001b3ULL;
    }
    return mix(h ^ len);
}

void *ft_top_pool_alloc(struct ft_top_pool *p, size_t size)
{
    size_t need = (size + 15) & ~(size_t)15;
    struct ft_top_chunk *c = p->current;

    while (c && c->used + need > c->size)
        c = c->next;
    if (!c) {
        size_t capacity = need > CHUNK_SIZE ? need : CHUNK_SIZE;
        c = malloc(sizeof(*c) + capacity);
        if (!c) {
            p->failed = true;
            return nullptr;
        }
        c->size = capacity;
        c->used = 0;
        if (p->current) {
            c->next = p->current->next;
            p->current->next = c;
        } else {
            c->next = p->chunks;
            p->chunks = c;
        }
    }
    p->current = c;
    void *out = (unsigned char *)c->data + c->used;
    c->used += need;
    return out;
}

const char *ft_top_pool_text(struct ft_top_pool *p, const char *s, size_t len)
{
    char *out = ft_top_pool_alloc(p, len + 1);
    if (!out)
        return "";
    memcpy(out, s, len);
    out[len] = '\0';
    return out;
}

void ft_top_pool_reset(struct ft_top_pool *p)
{
    for (struct ft_top_chunk *c = p->chunks; c; c = c->next)
        c->used = 0;
    p->current = p->chunks;
    p->failed = false;
}

void ft_top_pool_free(struct ft_top_pool *p)
{
    while (p->chunks) {
        struct ft_top_chunk *next = p->chunks->next;
        free(p->chunks);
        p->chunks = next;
    }
    p->current = nullptr;
}

bool ft_top_reserve(void *items, size_t *capacity, size_t needed, size_t size)
{
    void *old;
    if (needed <= *capacity)
        return true;
    size_t grown_capacity = *capacity + *capacity / 2;
    if (grown_capacity < needed)
        grown_capacity = needed;
    memcpy(&old, items, sizeof(old));
    void *grown = realloc(old, grown_capacity * size);
    if (!grown)
        return false;
    memcpy(items, &grown, sizeof(grown));
    *capacity = grown_capacity;
    return true;
}

uint32_t ft_top_next_mark(struct ft_top_model *m)
{
    if (++m->mark == 0) {
        for (size_t i = 0; i < m->nprocesses[m->now]; i++)
            m->processes[m->now][i].mark = m->processes[m->now][i].sum_mark = 0;
        for (size_t i = 0; i < m->nfiles; i++)
            m->files[i].mark = 0;
        for (size_t i = 0; i < m->ndestinations; i++)
            m->destinations[i].mark = 0;
        for (size_t mode = 0; mode < FT_TOP_MODE_COUNT; mode++) {
            struct ft_top_mode_state *ms = &m->modes[mode];
            for (size_t i = 0; i < ms->placeholders_cap; i++)
                ms->placeholders[i].mark = ms->placeholders[i].sum_mark = 0;
        }
        m->mark = 1;
    }
    return m->mark;
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static uint32_t name_offset(const char *path)
{
    size_t len = strlen(path);
    size_t i = len;
    /* A directory's own name is its last component, whether or not a '/' ends it. */
    if (i > 1 && path[i - 1] == '/')
        i--;
    while (i > 0 && path[i - 1] != '/')
        i--;
    return (uint32_t)i;
}

static void set_title(struct ft_top_pool *pool, struct ft_top_process *p)
{
    const char *line = p->command_line;
    while (*line == ' ')
        line++;
    if (!*line) {
        p->title = p->name = p->head = p->comm;
        p->rest = "";
        return;
    }

    size_t first = strcspn(line, " ");
    const char *after = line + first + strspn(line + first, " ");
    bool daemon = first >= 2 && line[first - 1] == ':' && !memchr(line, '/', first) && *after;
    if (daemon) {
        size_t second = strcspn(after, " ");
        const char *rest = after + second + strspn(after + second, " ");
        p->title = line;
        p->name = ft_top_pool_text(pool, line, first - 1);
        p->head = ft_top_pool_text(pool, line, (size_t)(after + second - line));
        p->rest = rest;
        return;
    }

    const char *base = line;
    for (const char *c = line; c < line + first; c++) {
        if (*c == '/' && c + 1 < line + first)
            base = c + 1;
    }
    p->title = p->name = p->head = ft_top_pool_text(pool, base, (size_t)(line + first - base));
    p->rest = after;
}

static const struct ft_top_user *user_of(struct ft_top_model *m, uint32_t uid)
{
    static struct ft_top_user fallback;
    struct ft_top_key key = {uid, 0, FT_TOP_KEY_USER};
    uint32_t *found = ft_top_map_find(&m->user_index, key);
    if (found)
        return m->users[*found];

    struct ft_top_user *u = calloc(1, sizeof(*u));
    if (!u || !ft_top_reserve(&m->users, &m->users_cap, m->nusers + 1, sizeof(*m->users)) ||
        !ft_top_map_put(&m->user_index, key, (uint32_t)m->nusers)) {
        free(u);
        u = &fallback;
    } else {
        m->users[m->nusers++] = u;
    }

    struct passwd pw;
    struct passwd *result = nullptr;
    char buf[4096];
    u->uid = uid;
    if (getpwuid_r((uid_t)uid, &pw, buf, sizeof(buf), &result) == 0 && result)
        ft_strlcpy(u->name, result->pw_name, sizeof(u->name));
    else
        snprintf(u->name, sizeof(u->name), "%" PRIu32, uid);
    return u;
}

/* The strings ft_process_strings_pack wrote; each one "" unless terminated inside the buffer. */
static void unpack_strings(const char *buf, size_t size, const char *out[3], size_t len[3])
{
    size_t used = 0;
    for (size_t i = 0; i < 3; i++) {
        size_t n = used < size ? strnlen(buf + used, size - used) : 0;
        if (used >= size || used + n == size) {
            out[i] = "";
            len[i] = 0;
            continue;
        }
        out[i] = buf + used;
        len[i] = n;
        used += n + 1;
    }
}

/* 2^-x without libm, which the build does not link. */
static double half_power(double x)
{
    if (x <= 0.0)
        return 1.0;
    if (x > 64.0)
        return 0.0;
    unsigned whole = (unsigned)x;
    double z = -(x - whole) * 0.6931471805599453;
    double term = 1.0;
    double sum = 1.0;
    for (int i = 1; i < 20; i++) {
        term *= z / i;
        sum += term;
    }
    for (unsigned i = 0; i < whole; i++)
        sum *= 0.5;
    return sum;
}

static struct ft_top_process_entry *new_process(struct ft_top_model *m, uint32_t pid)
{
    struct ft_top_process_entry *p = &m->processes[m->now][m->nprocesses[m->now]];
    *p = (struct ft_top_process_entry){0};
    p->pub.pid = pid;
    p->node = FT_TOP_NONE;
    snprintf(p->pid_text, sizeof(p->pid_text), "%" PRIu32, pid);
    ft_top_map_put(&m->process_index, (struct ft_top_key){pid, 0, FT_TOP_KEY_PROCESS},
                   (uint32_t)m->nprocesses[m->now]);
    m->nprocesses[m->now]++;
    return p;
}

static void set_process_text(struct ft_top_pool *pool, struct ft_top_process *p, const char *comm,
                             const char *exe, const char *const text[3], const size_t len[3])
{
    p->comm = ft_top_pool_text(pool, comm, strnlen(comm, FT_COMM_MAX));
    p->exe = ft_top_pool_text(pool, exe, strnlen(exe, FT_EXE_MAX));
    p->command_line = ft_top_pool_text(pool, text[0], len[0]);
    p->cwd = ft_top_pool_text(pool, text[1], len[1]);
    p->script = ft_top_pool_text(pool, text[2], len[2]);
    p->script_name = base_name(p->script);
    set_title(pool, p);
}

static void add_processes(struct ft_top_model *m, const struct ft_rows *rows,
                          struct ft_top_pool *pool)
{
    constexpr size_t FIXED = offsetof(struct ft_row_process, text);
    struct ft_row_process *row = (struct ft_row_process *)(void *)m->row_buf;

    for (size_t i = 0; rows && i < rows->count; i++) {
        ft_rows_get(rows, i, row, FIXED);
        if (ft_top_map_find(&m->process_index,
                            (struct ft_top_key){row->pid, 0, FT_TOP_KEY_PROCESS}))
            continue;

        const char *text[3];
        size_t len[3];
        size_t size = rows->sizes[i];
        const char *tail = (const char *)rows->data + rows->offsets[i] + FIXED;
        unpack_strings(tail, size > FIXED ? size - FIXED : 0, text, len);

        struct ft_top_process_entry *p = new_process(m, row->pid);
        const struct ft_top_user *u = user_of(m, row->uid);
        p->pub.ppid = row->ppid;
        p->pub.uid = row->uid;
        p->pub.uid_known = true;
        p->pub.known = true;
        p->pub.user = u->name;
        p->pub.start_wall_ns = row->start_wall_ns;
        p->pub.total = row->file_bytes;
        p->file_bytes = row->file_bytes;
        set_process_text(pool, &p->pub, row->comm, row->exe, text, len);
    }
}

/* A process the agent no longer reports, kept for a finished transfer still on screen. */
static uint32_t adopt_process(struct ft_top_model *m, const struct ft_top_process_entry *entry,
                              struct ft_top_pool *pool)
{
    const struct ft_top_process *old = &entry->pub;
    uint32_t *found =
        ft_top_map_find(&m->process_index, (struct ft_top_key){old->pid, 0, FT_TOP_KEY_PROCESS});
    if (found)
        return *found;

    struct ft_top_process_entry *p = new_process(m, old->pid);
    const char *text[3] = {old->command_line, old->cwd, old->script};
    size_t len[3] = {strlen(old->command_line), strlen(old->cwd), strlen(old->script)};
    p->pub.ppid = old->ppid;
    p->pub.uid = old->uid;
    p->pub.uid_known = old->uid_known;
    p->pub.known = old->known;
    p->pub.user = ft_top_pool_text(pool, old->user, strlen(old->user));
    p->pub.start_wall_ns = old->start_wall_ns;
    p->file_bytes = entry->file_bytes;
    set_process_text(pool, &p->pub, old->comm, old->exe, text, len);
    return (uint32_t)(m->nprocesses[m->now] - 1);
}

static bool is_selected(const struct ft_top_model *m, struct ft_top_key key)
{
    const struct ft_top_mode_state *t = &m->modes[FT_TOP_TRANSFERS];
    const struct ft_top_mode_state *p = &m->modes[FT_TOP_PROCESSES];
    bool in_transfers = t->has_selected && t->selected.kind == key.kind && t->selected.a == key.a &&
                        t->selected.b == key.b;
    bool in_tree = m->tree && p->has_selected && p->selected.kind == key.kind &&
                   p->selected.a == key.a && p->selected.b == key.b;
    return in_transfers || in_tree;
}

static void remove_transfer(struct ft_top_model *m, size_t i)
{
    size_t last = m->ntransfers - 1;
    ft_top_map_remove(&m->transfer_index, m->transfers[i].key);
    if (i != last) {
        m->transfers[i] = m->transfers[last];
        ft_top_map_put(&m->transfer_index, m->transfers[i].key, (uint32_t)i);
    }
    m->ntransfers--;
}

static void set_path(struct ft_top_transfer *t, struct ft_top_pool *pool, uint32_t flags,
                     uint64_t dev, uint64_t ino, const char *path, size_t len)
{
    char fallback[64];

    t->path_known = (flags & FT_XFER_PATH_KNOWN) != 0;
    t->deleted = (flags & FT_XFER_FILE_DELETED) != 0;
    if (t->path_known) {
        t->path = ft_top_pool_text(pool, path, len);
        t->name_offset = name_offset(t->path);
        return;
    }
    if (flags & FT_XFER_FILE_KNOWN)
        snprintf(fallback, sizeof(fallback), "(device %" PRIu64 " inode %" PRIu64 ")", dev, ino);
    else
        ft_strlcpy(fallback, "unknown", sizeof(fallback));
    t->path = ft_top_pool_text(pool, fallback, strlen(fallback));
    t->name_offset = 0;
}

static void set_script(struct ft_top_transfer *t, struct ft_top_pool *pool,
                       const struct ft_top_process *p, const char *script, size_t len)
{
    if (len == strlen(p->script) && memcmp(script, p->script, len) == 0)
        t->script = p->script;
    else
        t->script = ft_top_pool_text(pool, script, len);
    t->script_name = base_name(t->script);
}

/* Returns how many of the rows are transfers the model had not seen before. */
static size_t take_transfers(struct ft_top_model *m, const struct ft_rows *rows,
                             struct ft_top_pool *pool, double decay)
{
    constexpr size_t FIXED = offsetof(struct ft_row_transfer, path);
    struct ft_row_transfer *row = (struct ft_row_transfer *)(void *)m->row_buf;
    size_t started = 0;

    for (size_t i = 0; rows && i < rows->count; i++) {
        ft_rows_get(rows, i, row, FIXED);
        bool file_known = (row->flags & FT_XFER_FILE_KNOWN) != 0;
        struct ft_top_key key = {row->id, file_known ? 1u : 0u, FT_TOP_KEY_TRANSFER};
        uint32_t *found = ft_top_map_find(&m->transfer_index, key);
        struct ft_top_transfer_entry *e;

        if (found && m->transfers[*found].seen == m->samples)
            continue;
        if (found) {
            e = &m->transfers[*found];
            double raw = (double)row->rate;
            e->smoothed = e->pub.done ? raw : raw + (e->smoothed - raw) * decay;
        } else {
            e = &m->transfers[m->ntransfers];
            *e = (struct ft_top_transfer_entry){.key = key, .smoothed = (double)row->rate};
            ft_top_map_put(&m->transfer_index, key, (uint32_t)m->ntransfers);
            m->ntransfers++;
            started++;
        }

        size_t size = rows->sizes[i];
        size_t tail_len = size > FIXED ? size - FIXED : 0;
        const char *tail = (const char *)rows->data + rows->offsets[i] + FIXED;
        size_t path_len = strnlen(tail, tail_len < FT_PATH_MAX - 1 ? tail_len : FT_PATH_MAX - 1);
        const char *text[3] = {"", "", ""};
        size_t len[3] = {0, 0, 0};
        if ((row->flags & FT_XFER_PROCESS_TEXT) && path_len + 1 < tail_len)
            unpack_strings(tail + path_len + 1, tail_len - path_len - 1, text, len);

        uint32_t *proc = ft_top_map_find(&m->process_index,
                                         (struct ft_top_key){row->pid, 0, FT_TOP_KEY_PROCESS});
        if (proc) {
            e->process = *proc;
        } else {
            struct ft_top_process_entry *p = new_process(m, row->pid);
            p->pub.ppid = row->ppid;
            p->pub.user = "";
            set_process_text(pool, &p->pub, row->comm, row->exe, text, len);
            e->process = (uint32_t)(m->nprocesses[m->now] - 1);
        }
        const struct ft_top_process *p = &m->processes[m->now][e->process].pub;

        struct ft_top_transfer *t = &e->pub;
        e->raw_rate = row->rate;
        e->seen = m->samples;
        e->done_mono_ns = 0;
        e->dev = row->dev;
        e->ino = row->ino;
        e->file_known = file_known;
        t->id = row->id;
        t->pid = row->pid;
        t->done = false;
        set_path(t, pool, row->flags, row->dev, row->ino, tail, path_len);
        set_script(t, pool, p, text[2], len[2]);
        t->remote = row->remote;
        ft_endpoint_format(&row->remote, t->remote_text, sizeof(t->remote_text));
        t->is_public = row->remote.family != 0 && !ft_addr_is_private(&row->remote);
        t->rate = (uint64_t)(e->smoothed + 0.5);
        t->bytes = row->bytes;
        t->size = row->file_size;
        t->progress = row->file_size ? (double)row->bytes / (double)row->file_size : -1.0;
        if (t->progress > 1.0)
            t->progress = 1.0;
        t->first_wall_ns = row->first_wall_ns;
        t->age_ns = m->wall_ns > row->first_wall_ns ? m->wall_ns - row->first_wall_ns : 0;
        t->method = row->method;
        t->confidence = row->confidence;
        t->incomplete = (row->flags & FT_XFER_INCOMPLETE) != 0;
    }
    return started;
}

/* Lets go of the transfers the agent no longer reports, but for a selected one, kept as done. */
static void finish_transfers(struct ft_top_model *m, uint64_t mono_ns, struct ft_top_pool *pool)
{
    const struct ft_top_process_entry *old = m->processes[m->now ^ 1];

    for (size_t i = m->ntransfers; i-- > 0;) {
        struct ft_top_transfer_entry *e = &m->transfers[i];
        if (e->seen == m->samples)
            continue;
        bool keep =
            is_selected(m, e->key) && (!e->pub.done || mono_ns - e->done_mono_ns < FT_TOP_DONE_NS);
        if (!keep) {
            remove_transfer(m, i);
            continue;
        }
        if (!e->pub.done) {
            e->pub.done = true;
            e->done_mono_ns = mono_ns;
        }
        e->raw_rate = 0;
        e->pub.rate = 0;
        e->process = adopt_process(m, &old[e->process], pool);

        struct ft_top_transfer *t = &e->pub;
        const char *script = t->script;
        t->path = ft_top_pool_text(pool, t->path, strlen(t->path));
        set_script(t, pool, &m->processes[m->now][e->process].pub, script, strlen(script));
    }
}

static void build_files(struct ft_top_model *m)
{
    m->nfiles = 0;
    ft_top_map_clear(&m->file_index);
    for (size_t i = 0; i < m->ntransfers; i++) {
        struct ft_top_transfer_entry *e = &m->transfers[i];
        struct ft_top_key key = {e->file_known ? e->dev : 0, e->file_known ? e->ino : 0,
                                 FT_TOP_KEY_FILE};
        uint32_t *found = ft_top_map_find(&m->file_index, key);
        struct ft_top_file_entry *f;
        if (found) {
            f = &m->files[*found];
        } else {
            f = &m->files[m->nfiles];
            *f = (struct ft_top_file_entry){.key = key};
            f->pub.dev = key.a;
            f->pub.ino = key.b;
            f->pub.path = e->pub.path;
            f->pub.name_offset = e->pub.name_offset;
            f->pub.path_known = e->pub.path_known;
            f->pub.deleted = e->pub.deleted;
            ft_top_map_put(&m->file_index, key, (uint32_t)m->nfiles);
            e->file = (uint32_t)m->nfiles++;
        }
        if (found)
            e->file = *found;
        if (e->pub.size > f->pub.size)
            f->pub.size = e->pub.size;
        if (!e->pub.done)
            f->active++;
    }
}

static struct ft_top_key address_key(const struct ft_endpoint *ep, uint32_t kind)
{
    uint64_t a;
    uint64_t b;
    memcpy(&a, ep->addr, sizeof(a));
    memcpy(&b, ep->addr + 8, sizeof(b));
    return (struct ft_top_key){a, b ^ ((uint64_t)ep->family << 56), kind};
}

static struct ft_top_key subnet_key(const struct ft_endpoint *ep)
{
    struct ft_endpoint net = {.family = ep->family};
    memcpy(net.addr, ep->addr, ep->family == 6 ? 8 : 3);
    return address_key(&net, FT_TOP_KEY_SUBNET);
}

static void take_lifetime(struct ft_top_model *m, const struct ft_rows *rows)
{
    struct ft_row_leader *row = (struct ft_row_leader *)(void *)m->row_buf;

    m->nlifetime = 0;
    ft_top_map_clear(&m->lifetime_index);
    for (size_t i = 0; i < rows->count; i++) {
        ft_rows_get(rows, i, row, offsetof(struct ft_row_leader, text));
        struct ft_endpoint address = row->remote;
        address.port = 0;
        struct ft_top_key key = address_key(&address, FT_TOP_KEY_DESTINATION);
        if (ft_top_map_find(&m->lifetime_index, key))
            continue;
        m->lifetime[m->nlifetime] =
            (struct ft_top_lifetime){address, row->bytes, row->first_wall_ns};
        ft_top_map_put(&m->lifetime_index, key, (uint32_t)m->nlifetime++);
    }
}

static void resolve_host(struct ft_top_model *m, struct ft_top_destination *d, size_t *budget)
{
    if (!m->resolve) {
        d->host_state = FT_TOP_HOST_OFF;
        d->host = nullptr;
        return;
    }
    if (d->host_state == FT_TOP_HOST_NAMED || d->host_state == FT_TOP_HOST_NAMELESS)
        return;
    if (d->address.family == 0) {
        d->host_state = FT_TOP_HOST_NAMELESS;
        return;
    }
    d->host_state = FT_TOP_HOST_PENDING;
    if (*budget == 0)
        return;
    (*budget)--;
    d->host = ft_resolver_name(&d->address);
    if (d->host)
        d->host_state = FT_TOP_HOST_NAMED;
    else if (ft_resolver_nameless(&d->address))
        d->host_state = FT_TOP_HOST_NAMELESS;
}

static void set_trend(struct ft_top_destination_entry *d, uint64_t slot, uint64_t into_slot_ns)
{
    for (size_t i = 0; i < FT_TOP_TREND; i++) {
        uint64_t back = FT_TOP_TREND - 1 - i;
        uint64_t s = slot >= back ? slot - back : UINT64_MAX;
        uint64_t bytes = 0;
        if (slot >= back && s <= d->last_slot && d->last_slot - s < FT_TOP_TREND)
            bytes = d->slot_bytes[s % FT_TOP_TREND];
        uint64_t span_ns = back == 0 ? into_slot_ns : FT_TOP_TREND_SLOT_NS;
        if (span_ns < FT_NS_PER_SEC)
            span_ns = FT_NS_PER_SEC;
        d->pub.trend[i] = (uint64_t)((double)bytes * (double)FT_NS_PER_SEC / (double)span_ns);
    }
}

static void update_destinations(struct ft_top_model *m, uint64_t dt_ns)
{
    uint64_t since_start = m->mono_ns - m->start_mono_ns;
    uint64_t slot = since_start / FT_TOP_TREND_SLOT_NS;

    for (size_t i = 0; i < m->ndestinations; i++)
        m->destinations[i].active = false;

    for (size_t i = 0; i < m->ntransfers; i++) {
        struct ft_top_transfer_entry *e = &m->transfers[i];
        struct ft_endpoint address = e->pub.remote;
        address.port = 0;
        struct ft_top_key key = address_key(&address, FT_TOP_KEY_DESTINATION);
        uint32_t *found = ft_top_map_find(&m->destination_index, key);
        struct ft_top_destination_entry *d;
        if (found) {
            d = &m->destinations[*found];
        } else {
            d = &m->destinations[m->ndestinations];
            *d = (struct ft_top_destination_entry){.key = key, .last_slot = slot};
            d->pub.address = address;
            ft_addr_format(&address, d->pub.text, sizeof(d->pub.text));
            d->pub.is_public = address.family != 0 && !ft_addr_is_private(&address);
            d->pub.first_seen_wall_ns = m->samples > 1 ? m->wall_ns : 0;
            ft_top_map_put(&m->destination_index, key, (uint32_t)m->ndestinations++);
        }
        d->active = true;
        if (e->pub.done)
            continue;
        d->last_active_mono_ns = m->mono_ns;
        if (slot > d->last_slot) {
            for (uint64_t s = d->last_slot + 1; s <= slot && s - d->last_slot <= FT_TOP_TREND; s++)
                d->slot_bytes[s % FT_TOP_TREND] = 0;
            d->last_slot = slot;
        }
        d->slot_bytes[slot % FT_TOP_TREND] +=
            (uint64_t)((double)e->raw_rate * (double)dt_ns / (double)FT_NS_PER_SEC);
    }

    for (size_t i = m->ndestinations; i-- > 0;) {
        struct ft_top_destination_entry *d = &m->destinations[i];
        if (d->active || m->mono_ns - d->last_active_mono_ns < RECENT_NS)
            continue;
        size_t last = m->ndestinations - 1;
        ft_top_map_remove(&m->destination_index, d->key);
        if (i != last) {
            *d = m->destinations[last];
            ft_top_map_put(&m->destination_index, d->key, (uint32_t)i);
        }
        m->ndestinations--;
    }

    size_t budget = LOOKUPS_PER_SAMPLE;
    uint64_t into_slot = since_start - slot * FT_TOP_TREND_SLOT_NS;
    ft_top_map_clear(&m->subnet_counts);
    for (size_t i = 0; i < m->ndestinations; i++) {
        struct ft_top_destination_entry *d = &m->destinations[i];
        uint32_t *lifetime = ft_top_map_find(&m->lifetime_index, d->key);
        d->lifetime_known = lifetime != nullptr;
        if (lifetime) {
            d->lifetime_bytes = m->lifetime[*lifetime].bytes;
            if (m->lifetime[*lifetime].first_wall_ns)
                d->pub.first_seen_wall_ns = m->lifetime[*lifetime].first_wall_ns;
        }
        uint64_t first = d->pub.first_seen_wall_ns;
        d->pub.is_new = first && first <= m->wall_ns && m->wall_ns - first < RECENT_NS;
        set_trend(d, slot, into_slot);
        if (d->active) {
            resolve_host(m, &d->pub, &budget);
            struct ft_top_key subnet = subnet_key(&d->pub.address);
            uint32_t *n = ft_top_map_find(&m->subnet_counts, subnet);
            ft_top_map_put(&m->subnet_counts, subnet, n ? *n + 1 : 1);
        }
    }
    for (size_t i = 0; i < m->ndestinations; i++) {
        struct ft_top_destination_entry *d = &m->destinations[i];
        uint32_t *n = ft_top_map_find(&m->subnet_counts, subnet_key(&d->pub.address));
        d->pub.subnet_destinations = d->active && n ? *n : 0;
    }
}

static void link_transfers(struct ft_top_model *m)
{
    for (size_t i = 0; i < m->ntransfers; i++) {
        struct ft_top_transfer_entry *e = &m->transfers[i];
        struct ft_endpoint address = e->pub.remote;
        address.port = 0;
        uint32_t *d =
            ft_top_map_find(&m->destination_index, address_key(&address, FT_TOP_KEY_DESTINATION));
        e->destination = d ? *d : 0;
        e->pub.process = &m->processes[m->now][e->process].pub;
        e->pub.file = &m->files[e->file].pub;
        e->pub.destination = &m->destinations[e->destination].pub;
    }
}

static uint64_t nice_ceiling(uint64_t value)
{
    uint64_t step = 1;
    for (;;) {
        if (value <= step)
            return step;
        if (value <= 2 * step)
            return 2 * step;
        if (value <= 5 * step)
            return 5 * step;
        if (step > UINT64_MAX / 10)
            return UINT64_MAX;
        step *= 10;
    }
}

static uint64_t scale_update(struct ft_top_scale *s, uint64_t value, uint64_t mono_ns)
{
    if (value > s->scale || s->scale == 0) {
        s->scale = nice_ceiling(value);
        s->low_since_ns = 0;
    } else if (value < s->scale / 5) {
        if (s->low_since_ns == 0) {
            s->low_since_ns = mono_ns ? mono_ns : 1;
            s->low_peak = value;
        } else if (value > s->low_peak) {
            s->low_peak = value;
        }
        if (mono_ns - s->low_since_ns >= SHRINK_NS) {
            s->scale = nice_ceiling(s->low_peak);
            s->low_since_ns = 0;
        }
    } else {
        s->low_since_ns = 0;
    }
    return s->scale;
}

static double share(uint64_t part, uint64_t whole)
{
    return whole ? (double)part / (double)whole : 0.0;
}

static void count_totals(struct ft_top_model *m)
{
    struct ft_top_totals *t = &m->totals;
    uint32_t mark = ft_top_next_mark(m);
    uint64_t processes = 0;
    uint64_t files = 0;
    uint64_t fanout = 0;
    uint64_t fresh = 0;

    *t = (struct ft_top_totals){.now_wall_ns = m->wall_ns, .started = t->started};
    for (size_t i = 0; i < m->ntransfers; i++) {
        const struct ft_top_transfer_entry *e = &m->transfers[i];
        if (e->pub.done)
            continue;
        const struct ft_top_transfer *x = &e->pub;
        size_t method = x->method < FT_TOP_METHODS ? x->method : FT_METHOD_NONE;
        t->rate.value += x->rate;
        t->rate_by_method[method] += x->rate;
        t->transfers_by_method[method]++;
        if (x->confidence < FT_TOP_CONFIDENCES)
            t->transfers_by_confidence[x->confidence]++;
        if (x->confidence == FT_CONF_EXACT)
            t->rate_exact += x->rate;
        if (x->is_public)
            t->rate_public += x->rate;
        else
            t->rate_private += x->rate;
        t->transfers++;

        struct ft_top_process_entry *p = &m->processes[m->now][e->process];
        if (p->mark != mark) {
            p->mark = mark;
            processes++;
        }
    }
    for (size_t i = 0; i < m->nfiles; i++) {
        if (m->files[i].active) {
            files++;
            if (m->files[i].active > fanout)
                fanout = m->files[i].active;
        }
    }
    for (size_t i = 0; i < m->ndestinations; i++) {
        const struct ft_top_destination_entry *d = &m->destinations[i];
        fresh += d->pub.is_new;
        if (!d->active || d->last_active_mono_ns != m->mono_ns)
            continue;
        t->destinations++;
        if (d->pub.is_public)
            t->destinations_public++;
        else
            t->destinations_private++;
    }

    t->exact_share = share(t->rate_exact, t->rate.value);
    t->public_share = share(t->rate_public, t->rate.value);
    t->sendfile_share = share(t->rate_by_method[FT_METHOD_SENDFILE], t->rate.value);
    t->processes.value = processes;
    t->files.value = files;
    t->fanout.value = fanout;
    t->new_destinations.value = fresh;
    t->started.value = (uint64_t)(m->started + 0.5);

    t->rate.scale = scale_update(&m->scales[SCALE_RATE], t->rate.value, m->mono_ns);
    t->started.scale = scale_update(&m->scales[SCALE_STARTED], t->started.value, m->mono_ns);
    t->processes.scale = scale_update(&m->scales[SCALE_PROCESSES], processes, m->mono_ns);
    t->files.scale = scale_update(&m->scales[SCALE_FILES], files, m->mono_ns);
    t->fanout.scale = scale_update(&m->scales[SCALE_FANOUT], fanout, m->mono_ns);
    t->new_destinations.scale = scale_update(&m->scales[SCALE_NEW], fresh, m->mono_ns);

    t->agent = m->have_stats;
    if (m->have_stats) {
        const struct ft_row_stats *st = &m->stats;
        t->stats = st;
        t->backend = st->backend;
        t->degraded = st->health != FT_HEALTH_OK;
        t->events_dropped = st->events_dropped;
        uint64_t percent = st->queue_bytes ? st->queue_peak_bytes * 100 / st->queue_bytes : 0;
        t->queue_percent = (uint32_t)(percent > 100 ? 100 : percent);
    } else {
        t->backend = "";
    }
}

static void mark_stale(struct ft_top_model *m)
{
    for (size_t i = 0; i < FT_TOP_MODE_COUNT; i++)
        m->modes[i].stale = true;
}

/* Copies a field of a row as received, or zeros when the row is too short to hold it. */
static void peek(const struct ft_rows *rows, size_t i, size_t offset, void *out, size_t size)
{
    if (rows->sizes[i] >= offset + size)
        memcpy(out, rows->data + rows->offsets[i] + offset, size);
    else
        memset(out, 0, size);
}

struct bounds {
    size_t new_transfers;
    size_t new_processes; /* reported only through their transfers */
    size_t new_destinations;
};

/* How much each table may grow with a sample, read off its rows before anything changes. */
static bool measure(struct ft_top_model *m, const struct ft_top_sample *s, struct bounds *b)
{
    const struct ft_rows *t = s->transfers;
    const struct ft_rows *p = s->processes;
    size_t nt = t ? t->count : 0;
    size_t np = p ? p->count : 0;

    *b = (struct bounds){0};
    ft_top_map_clear(&m->scan);
    if (!ft_top_map_reserve(&m->scan, np + nt))
        return false;
    for (size_t i = 0; i < np; i++) {
        uint32_t pid;
        peek(p, i, offsetof(struct ft_row_process, pid), &pid, sizeof(pid));
        ft_top_map_put(&m->scan, (struct ft_top_key){pid, 0, FT_TOP_KEY_PROCESS}, 0);
    }
    for (size_t i = 0; i < nt; i++) {
        uint64_t id;
        uint32_t flags;
        uint32_t pid;
        peek(t, i, offsetof(struct ft_row_transfer, id), &id, sizeof(id));
        peek(t, i, offsetof(struct ft_row_transfer, flags), &flags, sizeof(flags));
        peek(t, i, offsetof(struct ft_row_transfer, pid), &pid, sizeof(pid));
        struct ft_top_key key = {id, (flags & FT_XFER_FILE_KNOWN) ? 1u : 0u, FT_TOP_KEY_TRANSFER};
        b->new_transfers += !ft_top_map_find(&m->transfer_index, key);
        struct ft_top_key process = {pid, 0, FT_TOP_KEY_PROCESS};
        if (!ft_top_map_find(&m->scan, process)) {
            ft_top_map_put(&m->scan, process, 0);
            b->new_processes++;
        }
    }
    ft_top_map_clear(&m->scan);
    for (size_t i = 0; i < nt; i++) {
        struct ft_endpoint remote;
        peek(t, i, offsetof(struct ft_row_transfer, remote), &remote, sizeof(remote));
        remote.port = 0;
        struct ft_top_key key = address_key(&remote, FT_TOP_KEY_DESTINATION);
        if (!ft_top_map_find(&m->destination_index, key) && !ft_top_map_find(&m->scan, key)) {
            ft_top_map_put(&m->scan, key, 0);
            b->new_destinations++;
        }
    }
    return true;
}

bool ft_top_model_sample(struct ft_top_model *m, const struct ft_top_sample *s)
{
    /* Only a selected transfer outlives the sample that stops reporting it: one per mode. */
    constexpr size_t LINGERING = 2;
    size_t nt = s->transfers ? s->transfers->count : 0;
    size_t np = s->processes ? s->processes->count : 0;
    size_t nl = s->destinations ? s->destinations->count : 0;
    uint8_t next = m->now ^ 1;
    struct bounds b;

    if (!measure(m, s, &b))
        return false;
    size_t transfers = m->ntransfers + b.new_transfers;
    size_t processes = np + b.new_processes + LINGERING;
    size_t files = nt + LINGERING;
    size_t destinations = m->ndestinations + b.new_destinations;
    if (!ft_top_reserve(&m->transfers, &m->transfers_cap, transfers, sizeof(*m->transfers)) ||
        !ft_top_reserve(&m->processes[next], &m->processes_cap[next], processes,
                        sizeof(*m->processes[next])) ||
        !ft_top_reserve(&m->files, &m->files_cap, files, sizeof(*m->files)) ||
        !ft_top_reserve(&m->destinations, &m->destinations_cap, destinations,
                        sizeof(*m->destinations)) ||
        !ft_top_reserve(&m->lifetime, &m->lifetime_cap, nl, sizeof(*m->lifetime)) ||
        !ft_top_map_reserve(&m->transfer_index, transfers) ||
        !ft_top_map_reserve(&m->process_index, processes) ||
        !ft_top_map_reserve(&m->file_index, files) ||
        !ft_top_map_reserve(&m->destination_index, destinations) ||
        !ft_top_map_reserve(&m->subnet_counts, destinations) ||
        !ft_top_map_reserve(&m->lifetime_index, nl))
        return false;

    uint64_t dt = m->samples && s->mono_ns > m->mono_ns ? s->mono_ns - m->mono_ns : 0;
    if (m->samples == 0)
        m->start_mono_ns = s->mono_ns;
    m->samples++;
    m->wall_ns = s->stats && s->stats->now_wall_ns ? s->stats->now_wall_ns : m->wall_ns + dt;
    m->mono_ns = s->mono_ns;
    m->have_stats = s->stats != nullptr;
    if (s->stats)
        m->stats = *s->stats;

    m->now = next;
    struct ft_top_pool *pool = &m->pools[next];
    ft_top_pool_reset(pool);
    m->nprocesses[next] = 0;
    ft_top_map_clear(&m->process_index);

    add_processes(m, s->processes, pool);
    size_t started =
        take_transfers(m, s->transfers, pool, half_power((double)dt / (double)HALF_LIFE_NS));
    finish_transfers(m, s->mono_ns, pool);
    build_files(m);
    if (s->destinations)
        take_lifetime(m, s->destinations);
    update_destinations(m, dt);
    link_transfers(m);

    if (m->samples > 2 && dt) {
        double per_second = (double)started * (double)FT_NS_PER_SEC / (double)dt;
        m->started =
            per_second + (m->started - per_second) * half_power((double)dt / (double)HALF_LIFE_NS);
    } else if (m->samples == 2 && dt) {
        m->started = (double)started * (double)FT_NS_PER_SEC / (double)dt;
    }
    count_totals(m);

    mark_stale(m);
    bool built = ft_top_build(m, m->mode);
    return built && !pool->failed;
}

bool ft_top_model_tick(struct ft_top_model *m, uint64_t mono_ns)
{
    bool changed = false;
    for (size_t i = m->ntransfers; i-- > 0;) {
        const struct ft_top_transfer_entry *e = &m->transfers[i];
        if (!e->pub.done)
            continue;
        if (mono_ns - e->done_mono_ns >= FT_TOP_DONE_NS || !is_selected(m, e->key)) {
            remove_transfer(m, i);
            changed = true;
        }
    }
    if (changed)
        mark_stale(m);
    return changed;
}

static bool copy_rows(const struct ft_rows *rows, struct ft_row_leader **out, size_t *count)
{
    *out = nullptr;
    *count = 0;
    if (!rows || rows->count == 0)
        return true;
    *out = calloc(rows->count, sizeof(**out));
    if (!*out)
        return false;
    for (size_t i = 0; i < rows->count; i++) {
        ft_rows_get(rows, i, &(*out)[i], sizeof(**out));
        (*out)[i].text[sizeof((*out)[i].text) - 1] = '\0';
    }
    *count = rows->count;
    return true;
}

static void answer_free(struct ft_top_cached_answer *a)
{
    free(a->rows);
    free(a->directories);
    free(a->destinations);
    *a = (struct ft_top_cached_answer){0};
}

bool ft_top_model_leaders(struct ft_top_model *m, const struct ft_top_leaders_sample *s)
{
    struct ft_top_cached_answer *slot = nullptr;
    for (size_t i = 0; i < FT_TOP_ANSWERS && !slot; i++) {
        struct ft_top_cached_answer *a = &m->answers[i];
        if (a->used && a->window == s->window && a->key == s->key && a->by == s->by)
            slot = a;
    }
    for (size_t i = 0; i < FT_TOP_ANSWERS && !slot; i++) {
        if (!m->answers[i].used)
            slot = &m->answers[i];
    }
    if (!slot) {
        slot = &m->answers[0];
        for (size_t i = 1; i < FT_TOP_ANSWERS; i++) {
            if (m->answers[i].used_at < slot->used_at)
                slot = &m->answers[i];
        }
    }

    struct ft_top_cached_answer next = {
        .used = true,
        .used_at = ++m->answers_used,
        .window = s->window,
        .key = s->key,
        .by = s->by,
    };
    if (s->summary)
        next.summary = *s->summary;
    if (!copy_rows(s->ranking, &next.rows, &next.nrows) ||
        !copy_rows(s->directories, &next.directories, &next.ndirectories) ||
        !copy_rows(s->destinations, &next.destinations, &next.ndestinations)) {
        answer_free(&next);
        return false;
    }
    answer_free(slot);
    *slot = next;
    m->modes[FT_TOP_LEADERS].stale = true;
    return true;
}

const struct ft_top_cached_answer *ft_top_current_answer(const struct ft_top_model *m)
{
    enum ft_top_sort by = m->modes[FT_TOP_LEADERS].sort;
    for (size_t i = 0; i < FT_TOP_ANSWERS; i++) {
        const struct ft_top_cached_answer *a = &m->answers[i];
        if (a->used && a->window == m->leaders_window && a->key == m->leaders_key && a->by == by)
            return a;
    }
    return nullptr;
}

static uint64_t ranked_value(const struct ft_row_leader *row, enum ft_top_sort by)
{
    switch (by) {
    case FT_TOP_SORT_TRANSFERS:
        return row->transfers;
    case FT_TOP_SORT_DESTINATIONS:
        return row->destinations;
    default:
        return row->bytes;
    }
}

void ft_top_leader_fill(const struct ft_top_model *m, const struct ft_row_leader *row,
                        double top_value, double span_bytes, enum ft_top_sort by, bool compared,
                        struct ft_top_leader *out)
{
    *out = (struct ft_top_leader){.row = row, .name_offset = name_offset(row->text)};
    if (row->remote.family) {
        ft_addr_format(&row->remote, out->remote_text, sizeof(out->remote_text));
        if (m->resolve) {
            out->host = ft_resolver_name(&row->remote);
            out->host_state = out->host                            ? FT_TOP_HOST_NAMED
                              : ft_resolver_nameless(&row->remote) ? FT_TOP_HOST_NAMELESS
                                                                   : FT_TOP_HOST_PENDING;
        }
    }
    out->is_new = compared && row->previous_rank == 0;
    out->rank_change = row->previous_rank ? (int32_t)row->previous_rank - (int32_t)row->rank : 0;
    out->bar = top_value > 0 ? (double)ranked_value(row, by) / top_value : 0.0;
    out->share = span_bytes > 0 ? (double)row->bytes / span_bytes : 0.0;
}

static const struct ft_top_sort_option transfer_sorts[] = {
    {FT_TOP_SORT_RATE, "RATE", true},
    {FT_TOP_SORT_BYTES, "BYTES SENT", true},
    {FT_TOP_SORT_PROGRESS, "PROGRESS", true},
    {FT_TOP_SORT_AGE, "AGE", true},
    {FT_TOP_SORT_PID, "PID", true},
    {FT_TOP_SORT_USER, "USER", false},
    {FT_TOP_SORT_PROCESS, "PROCESS", false},
    {FT_TOP_SORT_SCRIPT, "SCRIPT", false},
    {FT_TOP_SORT_FILE, "FILE", false},
    {FT_TOP_SORT_SIZE, "FILE SIZE", true},
    {FT_TOP_SORT_DESTINATION, "DESTINATION", false},
    {FT_TOP_SORT_METHOD, "METHOD", false},
    {FT_TOP_SORT_CONFIDENCE, "CONFIDENCE", false},
};

static const struct ft_top_sort_option process_sorts[] = {
    {FT_TOP_SORT_RATE, "RATE", true},      {FT_TOP_SORT_TOTAL, "TOTAL", true},
    {FT_TOP_SORT_FILES, "FILES", true},    {FT_TOP_SORT_DESTINATIONS, "DESTS", true},
    {FT_TOP_SORT_PID, "PID", true},        {FT_TOP_SORT_USER, "USER", false},
    {FT_TOP_SORT_METHOD, "METHOD", false}, {FT_TOP_SORT_PROCESS, "COMMAND", false},
};

static const struct ft_top_sort_option destination_sorts[] = {
    {FT_TOP_SORT_RATE, "RATE", true},
    {FT_TOP_SORT_TOTAL, "TOTAL", true},
    {FT_TOP_SORT_FILES, "FILES", true},
    {FT_TOP_SORT_PROCESSES, "PROCS", true},
    {FT_TOP_SORT_DESTINATION, "DESTINATION", false},
    {FT_TOP_SORT_KIND, "KIND", false},
    {FT_TOP_SORT_HOSTNAME, "rDNS", false},
    {FT_TOP_SORT_PROCESS, "TOP PROCESS", false},
    {FT_TOP_SORT_FILE, "TOP FILE", false},
};

static const struct ft_top_sort_option file_sorts[] = {
    {FT_TOP_SORT_RATE, "RATE", true},        {FT_TOP_SORT_SIZE, "SIZE", true},
    {FT_TOP_SORT_TRANSFERS, "ACTIVE", true}, {FT_TOP_SORT_DESTINATIONS, "DESTS", true},
    {FT_TOP_SORT_FILE, "FILE", false},       {FT_TOP_SORT_PROCESS, "SENDERS", false},
    {FT_TOP_SORT_METHOD, "METHOD", false},
};

static const struct ft_top_sort_option leader_sorts[] = {
    {FT_TOP_SORT_BYTES, "BYTES", true},
    {FT_TOP_SORT_TRANSFERS, "TRANSFERS", true},
    {FT_TOP_SORT_DESTINATIONS, "DESTINATIONS", true},
};

const struct ft_top_sort_option *ft_top_mode_sorts(enum ft_top_mode mode, size_t *count)
{
    switch (mode) {
    case FT_TOP_PROCESSES:
        *count = FT_ARRAY_LEN(process_sorts);
        return process_sorts;
    case FT_TOP_DESTINATIONS:
        *count = FT_ARRAY_LEN(destination_sorts);
        return destination_sorts;
    case FT_TOP_FILES:
        *count = FT_ARRAY_LEN(file_sorts);
        return file_sorts;
    case FT_TOP_LEADERS:
        *count = FT_ARRAY_LEN(leader_sorts);
        return leader_sorts;
    default:
        *count = FT_ARRAY_LEN(transfer_sorts);
        return transfer_sorts;
    }
}

struct ft_top_model *ft_top_model_create(void)
{
    struct ft_top_model *m = calloc(1, sizeof(*m));
    size_t row_size = sizeof(struct ft_row_transfer);

    if (sizeof(struct ft_row_process) > row_size)
        row_size = sizeof(struct ft_row_process);
    if (sizeof(struct ft_row_leader) > row_size)
        row_size = sizeof(struct ft_row_leader);
    if (!m || !(m->row_buf = malloc(row_size))) {
        free(m);
        return nullptr;
    }
    for (size_t i = 0; i < FT_TOP_MODE_COUNT; i++) {
        struct ft_top_mode_state *ms = &m->modes[i];
        size_t n;
        const struct ft_top_sort_option *sorts = ft_top_mode_sorts((enum ft_top_mode)i, &n);
        ms->sort = sorts[0].key;
        ms->descending = sorts[0].descending;
        ms->stale = true;
        ms->reorder = true;
        ms->selected_index = SIZE_MAX;
    }
    m->leaders_window = FT_WINDOW_1H;
    m->leaders_key = FT_LEADER_FILE;
    m->totals.backend = "";
    return m;
}

static void mode_free(struct ft_top_mode_state *ms)
{
    ft_top_filter_free(ms->filter);
    free(ms->search);
    free(ms->rows);
    free(ms->row_keys);
    for (size_t i = 0; i < 2; i++)
        ft_top_map_free(&ms->memory[i]);
    ft_top_map_free(&ms->tags);
    ft_top_map_free(&ms->expansion);
    ft_top_map_free(&ms->scratch);
    ft_top_pool_free(&ms->pool);
    free(ms->passed);
    free(ms->lists);
    free(ms->items);
    free(ms->spare);
    free(ms->indices);
    free(ms->indices_spare);
    free(ms->sections);
    free(ms->senders);
    free(ms->nodes);
    free(ms->placeholders);
    free(ms->folds);
    free(ms->leaders);
}

void ft_top_model_destroy(struct ft_top_model *m)
{
    if (!m)
        return;
    for (size_t i = 0; i < FT_TOP_MODE_COUNT; i++)
        mode_free(&m->modes[i]);
    for (size_t i = 0; i < FT_TOP_ANSWERS; i++)
        answer_free(&m->answers[i]);
    for (size_t i = 0; i < m->nusers; i++)
        free(m->users[i]);
    for (size_t i = 0; i < 2; i++) {
        free(m->processes[i]);
        ft_top_pool_free(&m->pools[i]);
    }
    free(m->users);
    free(m->transfers);
    free(m->files);
    free(m->destinations);
    free(m->lifetime);
    free(m->side);
    free(m->row_buf);
    ft_top_map_free(&m->transfer_index);
    ft_top_map_free(&m->process_index);
    ft_top_map_free(&m->file_index);
    ft_top_map_free(&m->destination_index);
    ft_top_map_free(&m->subnet_counts);
    ft_top_map_free(&m->scan);
    ft_top_map_free(&m->lifetime_index);
    ft_top_map_free(&m->user_index);
    free(m);
}

void ft_top_subject_of(const struct ft_top_transfer *t, struct ft_top_subject *s)
{
    const struct ft_top_process_entry *p = (const struct ft_top_process_entry *)t->process;
    const struct ft_top_destination *d = t->destination;
    *s = (struct ft_top_subject){
        .pid = t->pid,
        .pid_text = p->pid_text,
        .uid = p->pub.uid,
        .uid_known = p->pub.uid_known,
        .user = p->pub.user,
        .title = p->pub.title,
        .comm = p->pub.comm,
        .script = t->script,
        .path = t->path,
        .remote = &t->remote,
        .remote_text = t->remote_text,
        .host = d->host_state == FT_TOP_HOST_NAMED ? d->host : nullptr,
        .is_public = t->is_public,
        .method = t->method,
        .confidence = t->confidence,
        .rate = t->rate,
    };
}

/* Reading a mode builds it first if it is out of date; the model itself is never const. */
static struct ft_top_mode_state *fresh(const struct ft_top_model *cm, enum ft_top_mode mode)
{
    struct ft_top_model *m = (struct ft_top_model *)cm;
    if (m->modes[mode].stale)
        ft_top_build(m, mode);
    return &m->modes[mode];
}

static void rebuild(struct ft_top_model *m, enum ft_top_mode mode, bool reorder)
{
    m->modes[mode].stale = true;
    if (reorder)
        m->modes[mode].reorder = true;
}

void ft_top_set_mode(struct ft_top_model *m, enum ft_top_mode mode)
{
    if (mode < FT_TOP_MODE_COUNT)
        m->mode = mode;
}

size_t ft_top_row_count(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return fresh(m, mode)->nrows;
}

const struct ft_top_row *ft_top_row_at(const struct ft_top_model *m, enum ft_top_mode mode,
                                       size_t i)
{
    const struct ft_top_mode_state *ms = fresh(m, mode);
    return i < ms->nrows ? &ms->rows[i] : nullptr;
}

const struct ft_top_view *ft_top_view_of(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return &fresh(m, mode)->view;
}

const struct ft_top_totals *ft_top_totals(const struct ft_top_model *m)
{
    return &m->totals;
}

const struct ft_top_leaders *ft_top_leaders(const struct ft_top_model *m)
{
    fresh(m, FT_TOP_LEADERS);
    return &m->leaders;
}

bool ft_top_set_sort(struct ft_top_model *m, enum ft_top_mode mode, enum ft_top_sort key,
                     bool descending)
{
    size_t n;
    const struct ft_top_sort_option *sorts = ft_top_mode_sorts(mode, &n);
    struct ft_top_mode_state *ms = &m->modes[mode];

    if (key == FT_TOP_SORT_DEFAULT)
        key = sorts[0].key;
    for (size_t i = 0; i < n; i++) {
        if (sorts[i].key != key)
            continue;
        ms->sort = key;
        ms->descending = mode == FT_TOP_LEADERS ? true : descending;
        rebuild(m, mode, true);
        return true;
    }
    return false;
}

void ft_top_sort_of(const struct ft_top_model *m, enum ft_top_mode mode, enum ft_top_sort *key,
                    bool *descending)
{
    *key = m->modes[mode].sort;
    *descending = m->modes[mode].descending;
}

bool ft_top_set_filter(struct ft_top_model *m, enum ft_top_mode mode, const char *expression,
                       struct ft_error *err)
{
    constexpr uint32_t LEADER_FIELDS =
        FT_TOP_FIELD_BIT(FT_TOP_FIELD_FILE) | FT_TOP_FIELD_BIT(FT_TOP_FIELD_PROC) |
        FT_TOP_FIELD_BIT(FT_TOP_FIELD_DEST) | FT_TOP_FIELD_BIT(FT_TOP_FIELD_METHOD) |
        FT_TOP_FIELD_BIT(FT_TOP_FIELD_CONF) | FT_TOP_FIELD_BIT(FT_TOP_FIELD_ANY);
    struct ft_top_mode_state *ms = &m->modes[mode];
    struct ft_top_filter *f = ft_top_filter_compile(expression, err);

    if (!f)
        return false;
    if (mode == FT_TOP_LEADERS && !ft_top_filter_restrict(f, LEADER_FIELDS, "Leaders", err)) {
        ft_top_filter_free(f);
        return false;
    }
    if (ft_top_filter_empty(f)) {
        ft_top_filter_free(f);
        f = nullptr;
    }
    ft_top_filter_free(ms->filter);
    ms->filter = f;
    rebuild(m, mode, true);
    return true;
}

const char *ft_top_filter_of(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return ft_top_filter_text(m->modes[mode].filter);
}

const struct ft_top_filter *ft_top_filter_get(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return m->modes[mode].filter;
}

void ft_top_set_search(struct ft_top_model *m, enum ft_top_mode mode, const char *text)
{
    struct ft_top_mode_state *ms = &m->modes[mode];
    size_t len = text ? strlen(text) : 0;
    char *copy = len ? malloc(len + 1) : nullptr;

    if (len && !copy)
        return;
    if (copy)
        memcpy(copy, text, len + 1);
    free(ms->search);
    ms->search = copy;
    ms->search_len = len;

    ms = fresh(m, mode);
    ft_top_refresh_flags(m, mode);
    if (ms->selected_index < ms->nrows && !(ms->rows[ms->selected_index].flags & FT_TOP_ROW_MATCH))
        ft_top_search_step(m, mode, 1);
}

const char *ft_top_search_of(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return m->modes[mode].search ? m->modes[mode].search : "";
}

static void select_index(struct ft_top_mode_state *ms, size_t i)
{
    if (ms->selected_index < ms->nrows)
        ms->rows[ms->selected_index].flags &= (uint8_t)~FT_TOP_ROW_SELECTED;
    ms->selected_index = i;
    ms->selected = ms->row_keys[i];
    ms->has_selected = true;
    ms->rows[i].flags |= FT_TOP_ROW_SELECTED;
}

bool ft_top_search_step(struct ft_top_model *m, enum ft_top_mode mode, int direction)
{
    struct ft_top_mode_state *ms = fresh(m, mode);
    size_t n = ms->nrows;

    if (n == 0 || ms->view.matches == 0)
        return false;
    size_t start = ms->selected_index < n ? ms->selected_index : n - 1;
    for (size_t k = 1; k <= n; k++) {
        size_t i = direction >= 0 ? (start + k) % n : (start + n - k % n) % n;
        if (ms->rows[i].flags & FT_TOP_ROW_MATCH) {
            select_index(ms, i);
            return true;
        }
    }
    return false;
}

void ft_top_set_group(struct ft_top_model *m, enum ft_top_mode mode, enum ft_top_group group)
{
    if (group >= FT_TOP_GROUP_COUNT || m->modes[mode].group == group)
        return;
    m->modes[mode].group = group;
    rebuild(m, mode, true);
}

enum ft_top_group ft_top_group_of(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return m->modes[mode].group;
}

void ft_top_set_tree(struct ft_top_model *m, bool on)
{
    if (m->tree == on)
        return;
    m->tree = on;
    rebuild(m, FT_TOP_PROCESSES, true);
}

bool ft_top_tree_of(const struct ft_top_model *m)
{
    return m->tree;
}

void ft_top_set_resolve(struct ft_top_model *m, bool on)
{
    size_t budget = LOOKUPS_PER_SAMPLE;

    if (m->resolve == on)
        return;
    m->resolve = on;
    for (size_t i = 0; i < m->ndestinations; i++) {
        struct ft_top_destination *d = &m->destinations[i].pub;
        if (!on)
            d->host_state = FT_TOP_HOST_OFF;
        resolve_host(m, d, &budget);
    }
    for (size_t i = 0; i < FT_TOP_MODE_COUNT; i++)
        rebuild(m, (enum ft_top_mode)i, false);
}

bool ft_top_resolve_of(const struct ft_top_model *m)
{
    return m->resolve;
}

void ft_top_set_leaders_request(struct ft_top_model *m, enum ft_leader_window window,
                                enum ft_leader_key key)
{
    if (m->leaders_window == window && m->leaders_key == key)
        return;
    m->leaders_window = window;
    m->leaders_key = key;
    rebuild(m, FT_TOP_LEADERS, true);
}

size_t ft_top_selected(const struct ft_top_model *m, enum ft_top_mode mode)
{
    const struct ft_top_mode_state *ms = fresh(m, mode);
    return ms->selected_index < ms->nrows ? ms->selected_index : SIZE_MAX;
}

void ft_top_select_by(struct ft_top_model *m, enum ft_top_mode mode, long delta)
{
    struct ft_top_mode_state *ms = fresh(m, mode);
    if (ms->nrows == 0)
        return;
    size_t at = ms->selected_index < ms->nrows ? ms->selected_index : 0;
    size_t step = delta < 0 ? (size_t)(-(delta + 1)) + 1 : (size_t)delta;
    if (delta < 0)
        at = step > at ? 0 : at - step;
    else
        at = step > ms->nrows - 1 - at ? ms->nrows - 1 : at + step;
    select_index(ms, at);
}

void ft_top_select_at(struct ft_top_model *m, enum ft_top_mode mode, size_t index)
{
    struct ft_top_mode_state *ms = fresh(m, mode);
    if (ms->nrows)
        select_index(ms, index < ms->nrows ? index : ms->nrows - 1);
}

void ft_top_tag_toggle(struct ft_top_model *m, enum ft_top_mode mode)
{
    struct ft_top_mode_state *ms = fresh(m, mode);
    size_t i = ms->selected_index;
    if (i >= ms->nrows)
        return;
    struct ft_top_key key = ms->row_keys[i];
    if (ft_top_map_find(&ms->tags, key)) {
        ft_top_map_remove(&ms->tags, key);
        ms->rows[i].flags &= (uint8_t)~FT_TOP_ROW_TAGGED;
    } else if (ft_top_map_put(&ms->tags, key, 1)) {
        ms->rows[i].flags |= FT_TOP_ROW_TAGGED;
    }
}

void ft_top_tags_clear(struct ft_top_model *m, enum ft_top_mode mode)
{
    struct ft_top_mode_state *ms = &m->modes[mode];
    ft_top_map_clear(&ms->tags);
    for (size_t i = 0; i < ms->nrows; i++)
        ms->rows[i].flags &= (uint8_t)~FT_TOP_ROW_TAGGED;
}

size_t ft_top_tag_count(const struct ft_top_model *m, enum ft_top_mode mode)
{
    return m->modes[mode].tags.count;
}

void ft_top_set_expanded(struct ft_top_model *m, enum ft_top_mode mode, size_t index, bool expanded)
{
    struct ft_top_mode_state *ms = fresh(m, mode);
    if (index >= ms->nrows || ms->rows[index].node == FT_TOP_NODE_LEAF)
        return;
    if (ft_top_map_put(&ms->expansion, ms->row_keys[index], expanded ? 2 : 1))
        rebuild(m, mode, false);
}

void ft_top_toggle_expanded(struct ft_top_model *m, enum ft_top_mode mode, size_t index)
{
    struct ft_top_mode_state *ms = fresh(m, mode);
    if (index < ms->nrows)
        ft_top_set_expanded(m, mode, index, ms->rows[index].node != FT_TOP_NODE_EXPANDED);
}

void ft_top_expand_all(struct ft_top_model *m, enum ft_top_mode mode)
{
    struct ft_top_mode_state *ms = &m->modes[mode];
    ft_top_map_clear(&ms->expansion);
    ms->expanded_all = true;
    rebuild(m, mode, false);
}
