#include "filetrace/state.h"

#include <string.h>

struct lookup_key {
    uint64_t image;
    uint8_t addr[16];
    uint8_t family;
    uint8_t pad[7];
};

struct lookup_name {
    uint64_t ts_ns;
    struct ft_name_ref name;
    uint32_t tid;
};

/* What one process image looked up to one address. */
struct lookup {
    struct lookup_name names[FT_RESOLVED_NAMES]; /* the latest; a reference may no longer resolve */
    uint64_t seen; /* a bit per name ever looked up, by its hash: counts those no longer kept */
};

bool ft_state_names_create(struct ft_state *st)
{
    if (!st->cfg.names || !st->cfg.max_names || !st->cfg.max_name_lookups)
        return true;
    st->names = ft_names_create(st->cfg.max_names);
    st->lookups =
        ft_table_create(st->cfg.max_name_lookups, sizeof(struct lookup_key), sizeof(struct lookup));
    return st->names && st->lookups;
}

void ft_state_names_destroy(struct ft_state *st)
{
    ft_table_destroy(st->lookups);
    ft_names_destroy(st->names);
    st->lookups = nullptr;
    st->names = nullptr;
}

/* An address as lookups are kept by it: without a port, and IPv4-mapped IPv6 as IPv4. */
static bool lookup_key(struct lookup_key *key, uint64_t image, const struct ft_endpoint *ep)
{
    struct ft_endpoint addr;

    if (ep->family != 4 && ep->family != 6)
        return false;
    ft_endpoint_set(&addr, ep->family == 6, ep->addr, 0);
    if (!ft_addr_is_set(&addr))
        return false;
    memset(key, 0, sizeof(*key));
    key->image = image;
    memcpy(key->addr, addr.addr, sizeof(key->addr));
    key->family = addr.family;
    return true;
}

static void lookup_add(struct ft_state *st, struct lookup *l, struct ft_name_ref name, uint32_t tid,
                       uint64_t ts_ns)
{
    struct lookup_name *slot = nullptr;
    bool slot_free = false;

    /* The name's own place, else one whose name was forgotten, else the oldest lookup's. */
    for (size_t i = 0; i < FT_RESOLVED_NAMES; i++) {
        struct lookup_name *n = &l->names[i];
        uint32_t id = ft_names_resolve(st->names, n->name);
        if (id == name.id) {
            slot = n;
            break;
        }
        bool free = id == 0;
        if (!slot || (free && !slot_free) || (free == slot_free && n->ts_ns < slot->ts_ns)) {
            slot = n;
            slot_free = free;
        }
    }
    *slot = (struct lookup_name){.ts_ns = ts_ns, .name = name, .tid = tid};
    l->seen |= UINT64_C(1) << (ft_names_hash(st->names, name.id) >> 58);
}

void ft_lookup_record(struct ft_state *st, const struct ft_process *p, const struct ft_ev_lookup *e,
                      uint64_t ts_ns)
{
    struct ft_name_ref name = {0};
    uint32_t count = e->addr_count < FT_LOOKUP_ADDRS ? e->addr_count : FT_LOOKUP_ADDRS;

    if (!st->names || !e->name)
        return;
    for (uint32_t i = 0; i < count; i++) {
        struct lookup_key key;
        if (!lookup_key(&key, p->image, &e->addrs[i]))
            continue;
        if (!name.id)
            name = ft_names_intern(st->names, e->name);
        if (!name.id)
            return;
        lookup_add(st, ft_table_insert(st->lookups, &key, nullptr), name, e->tid, ts_ns);
    }
}

struct found {
    uint32_t id;
    uint64_t ts_ns;
    bool own_thread;
};

struct search {
    struct ft_state *st;
    const struct ft_endpoint *remote;
    uint32_t tid;
    uint64_t now_ns;
    struct found names[(FT_NAME_GENERATIONS + 1) * FT_RESOLVED_NAMES];
    size_t count;
    uint32_t beyond; /* names looked up that the records no longer keep */
};

static bool comes_first(const struct found *a, const struct found *b)
{
    if (a->own_thread != b->own_thread)
        return a->own_thread;
    return a->ts_ns > b->ts_ns;
}

/* Takes what one image looked up to the address before before_ns. */
static void search_image(struct search *s, uint64_t image, uint64_t before_ns)
{
    struct ft_state *st = s->st;
    uint64_t max_age = st->cfg.name_max_age_ns;
    struct lookup_key key;
    uint32_t kept = 0;
    bool used = false;

    if (!lookup_key(&key, image, s->remote))
        return;
    const struct lookup *l = ft_table_find(st->lookups, &key);
    if (!l)
        return;

    for (size_t i = 0; i < FT_RESOLVED_NAMES; i++) {
        const struct lookup_name *n = &l->names[i];
        struct found f = {
            .id = ft_names_resolve(st->names, n->name),
            .ts_ns = n->ts_ns,
            .own_thread = s->tid && n->tid == s->tid,
        };
        if (!f.id)
            continue;
        kept++;
        if (n->ts_ns >= before_ns)
            continue;
        if (max_age && s->now_ns > n->ts_ns && s->now_ns - n->ts_ns > max_age)
            continue;
        used = true;

        size_t at = 0;
        while (at < s->count && s->names[at].id != f.id)
            at++;
        if (at == s->count)
            s->names[s->count++] = f;
        else if (comes_first(&f, &s->names[at]))
            s->names[at] = f;
    }
    if (!used)
        return;
    uint32_t seen = (uint32_t)__builtin_popcountll(l->seen);
    if (seen > kept)
        s->beyond += seen - kept;
    /* A record that still names connections is in use, however long ago it was made. */
    ft_table_touch(st->lookups, &key);
}

void ft_binding_make(struct ft_state *st, struct ft_name_binding *b, const struct ft_process *p,
                     const struct ft_endpoint *remote, uint32_t tid, uint64_t now_ns)
{
    struct search s = {.st = st, .remote = remote, .tid = tid, .now_ns = now_ns};

    if (!st->names)
        return;
    search_image(&s, p->image, UINT64_MAX);
    for (size_t g = 0; g < FT_NAME_GENERATIONS && p->ancestors[g].image; g++)
        search_image(&s, p->ancestors[g].image, p->ancestors[g].before_ns);
    /* A parent whose lookups its children use keeps its place, for the children still to come. */
    if (p->ancestors[0].image)
        ft_table_touch(st->processes, &p->ppid);

    for (size_t i = 1; i < s.count; i++) {
        struct found f = s.names[i];
        size_t at = i;
        for (; at > 0 && comes_first(&f, &s.names[at - 1]); at--)
            s.names[at] = s.names[at - 1];
        s.names[at] = f;
    }

    size_t count = s.count + s.beyond;
    b->count = (uint16_t)(count > UINT16_MAX ? UINT16_MAX : count);
    b->listed = (uint8_t)(s.count < FT_RESOLVED_NAMES ? s.count : FT_RESOLVED_NAMES);
    for (size_t i = 0; i < b->listed; i++) {
        b->resolved[i] = s.names[i].id;
        ft_names_hold(st->names, s.names[i].id);
    }
}

void ft_binding_set_tls(struct ft_state *st, struct ft_name_binding *b, const char *name)
{
    if (!st->names)
        return;

    uint32_t id = name ? ft_names_intern(st->names, name).id : 0;
    if (id)
        ft_names_hold(st->names, id);
    if (b->tls)
        ft_names_release(st->names, b->tls);
    b->tls = id;
}

void ft_binding_clear(struct ft_state *st, struct ft_name_binding *b)
{
    if (st->names) {
        if (b->tls)
            ft_names_release(st->names, b->tls);
        for (size_t i = 0; i < b->listed; i++)
            ft_names_release(st->names, b->resolved[i]);
    }
    *b = (struct ft_name_binding){0};
}

static bool bound(const struct ft_name_binding *b)
{
    return b->tls || b->listed;
}

const struct ft_name_binding *ft_state_socket_names(const struct ft_state *st,
                                                    const struct ft_socket *s)
{
    struct ft_flow_key key;

    if (bound(&s->names) || s->proto == FT_PROTO_TCP || s->many_remotes ||
        !ft_addr_is_set(&s->remote))
        return &s->names;
    memset(&key, 0, sizeof(key));
    key.sock_id = s->id;
    key.pid = s->pid;
    key.remote = s->remote;
    const struct ft_flow *f = ft_table_find(st->flows, &key);
    return f ? &f->names : &s->names;
}

void ft_binding_names(const struct ft_state *st, const struct ft_name_binding *b,
                      struct ft_remote_names *out)
{
    *out = (struct ft_remote_names){.tls = ""};
    if (!st->names || !b)
        return;
    if (b->tls)
        out->tls = ft_names_text(st->names, b->tls);
    for (size_t i = 0; i < b->listed; i++)
        out->resolved[out->listed++] = ft_names_text(st->names, b->resolved[i]);
    out->count = b->count;
}
