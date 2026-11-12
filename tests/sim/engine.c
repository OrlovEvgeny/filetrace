#include "sim/engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

constexpr size_t CLIENT_POOL = 320;
constexpr uint64_t JITTER_MAX_NS = 30 * FT_NS_PER_MS;
constexpr uint64_t MIN_SEGMENT_NS = 1000;
constexpr size_t NO_PATH = SIZE_MAX;
constexpr uint32_t PIDNS = 4026531836u;
constexpr uint32_t MNTNS = 4026531841u;
constexpr uint32_t NETNS = 4026531840u;

/* The host's own addresses, indexed by 2 * ipv6 + public. */
static const char *const host_addrs[4] = {"10.0.0.10", "203.0.113.10", "fd00:10::10",
                                          "2001:db8:10::10"};

/* The first two bytes of the residential and business ranges the clients come from. */
static const uint8_t client_prefixes[][2] = {
    {81, 2},    {62, 45}, {84, 241}, {145, 53}, {188, 207}, {77, 162}, {85, 144},  {92, 68},
    {213, 127}, {86, 83}, {89, 99},  {31, 21},  {176, 10},  {94, 208}, {82, 73},   {95, 96},
    {2, 56},    {37, 17}, {80, 57},  {178, 84}, {217, 103}, {87, 213}, {145, 132}, {194, 171},
};

/* Documentation ranges; 203.0.113.10 is the host's own address. */
static const uint8_t documentation_prefixes[][3] = {{192, 0, 2}, {198, 51, 100}, {203, 0, 113}};

struct rng {
    uint64_t state;
};

static uint64_t splitmix(uint64_t x)
{
    x += 0x9e3779b97f4a7c15ULL;
    x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
    x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
    return x ^ (x >> 31);
}

static void rng_seed(struct rng *r, uint64_t seed)
{
    r->state = splitmix(seed);
    if (r->state == 0)
        r->state = 0x2545f4914f6cdd1dULL;
}

static uint64_t rng_next(struct rng *r)
{
    uint64_t x = r->state;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    r->state = x;
    return x * 0x2545f4914f6cdd1dULL;
}

/* Uniform in [0, n); n must not be 0. */
static uint64_t rng_below(struct rng *r, uint64_t n)
{
    return rng_next(r) % n;
}

static uint64_t rng_range(struct rng *r, uint64_t lo, uint64_t hi)
{
    return lo + rng_below(r, hi - lo + 1);
}

static double rng_unit(struct rng *r)
{
    return (double)(rng_next(r) >> 11) * (1.0 / 9007199254740992.0);
}

static uint64_t hash_bytes(const char *s, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;

    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)s[i];
        h *= 0x100000001b3ULL;
    }
    return h;
}

static uint64_t hash_text(const char *s)
{
    return hash_bytes(s, strlen(s));
}

struct proc_rt {
    const struct ft_sim_process *def;
    uint32_t pid;
    uint32_t ppid;
    uint64_t start_ns;
    uint64_t cgroup_id;
    char *args;
    size_t args_len;
    uint32_t busy; /* transfers in progress */
    bool alive;
};

struct slot {
    uint32_t gen;
    uint32_t index; /* within its generator */
    bool running;
    bool has_socket;
    bool fresh; /* the socket has carried nothing yet */
    uint32_t proc;
    uint64_t idle_until_ns;
    uint64_t sock_id;
    struct ft_endpoint local;
    struct ft_endpoint remote;

    const struct ft_sim_flavor *flavor;
    struct ft_file_id file;
    uint64_t size;
    uint64_t sent;
    uint64_t read_total;
    uint64_t rate; /* bytes per second, before the wobble */
    uint64_t cycles;
    double level;
    double dip_factor;
    uint32_t dip_steps;

    /* What the socket and the transfer carried since the last delivery: one record each. */
    uint64_t xfer_first_ns;
    uint64_t xfer_last_ns;
    uint64_t xfer_bytes;
    uint64_t xfer_read;
    uint32_t xfer_ops;
    uint32_t xfer_alternations;
    uint64_t flow_first_ns;
    uint64_t flow_last_ns;
    uint64_t flow_tx;
    uint64_t flow_rx;
    uint32_t flow_tx_ops;
    uint32_t flow_rx_ops;
};

struct gen_rt {
    const struct ft_sim_generator *def;
    size_t first_counter;
    size_t flavors;
    size_t npids;
    unsigned total_weight;
};

struct sort_key {
    uint64_t ts;
    uint64_t seq;
};

struct ring_event {
    struct sort_key key;
    size_t path_off; /* into the step's paths, for a file */
    struct ft_event ev;
};

struct pending_flow {
    struct sort_key key;
    struct ft_ev_flow flow;
};

struct pending_transfer {
    struct sort_key key;
    struct ft_ev_transfer transfer;
};

struct order {
    struct sort_key key;
    uint32_t index;
};

struct ft_sim_engine {
    const struct ft_sim_scenario *sc;
    struct ft_sink sink;
    struct rng rng;
    uint64_t seed;
    uint64_t origin_ns;
    uint64_t now_ns;
    uint64_t events;
    uint64_t queued;
    uint64_t seq;
    uint64_t sockets;
    bool failed;

    struct proc_rt *procs;
    size_t nprocs;
    size_t procs_capacity;
    uint32_t next_pid;
    uint64_t next_recycle_ns;

    struct gen_rt *gens;
    size_t ngens;
    struct slot *slots;
    size_t nslots;
    uint64_t *counters;

    struct ft_endpoint hosts[4];
    struct ft_endpoint clients[CLIENT_POOL];

    uint64_t *seen; /* files already announced, by identity */
    size_t seen_capacity;
    size_t seen_count;

    uint64_t next_loss_ns;
    bool loss_due;
    struct ft_ev_loss loss;

    struct {
        struct ring_event *items;
        size_t count;
        size_t capacity;
    } ring;
    struct {
        struct pending_flow *items;
        size_t count;
        size_t capacity;
    } flows;
    struct {
        struct pending_transfer *items;
        size_t count;
        size_t capacity;
    } transfers;
    struct {
        char *data;
        size_t length;
        size_t capacity;
    } paths;
    struct order *order;
    size_t order_capacity;
};

static void *grow(void *items, size_t *capacity, size_t need, size_t item_size)
{
    if (need <= *capacity)
        return items;

    size_t cap = *capacity ? *capacity : 256;
    while (cap < need)
        cap *= 2;
    void *grown = realloc(items, cap * item_size);
    if (grown)
        *capacity = cap;
    return grown;
}

#define DEFINE_NEXT(name, type, member)                                                            \
    static type *name(struct ft_sim_engine *e)                                                     \
    {                                                                                              \
        void *items = grow(e->member.items, &e->member.capacity, e->member.count + 1,              \
                           sizeof(*e->member.items));                                              \
        if (!items) {                                                                              \
            e->failed = true;                                                                      \
            return nullptr;                                                                        \
        }                                                                                          \
        e->member.items = items;                                                                   \
        return &e->member.items[e->member.count++];                                                \
    }

DEFINE_NEXT(next_ring, struct ring_event, ring)
DEFINE_NEXT(next_flow, struct pending_flow, flows)
DEFINE_NEXT(next_transfer, struct pending_transfer, transfers)

static struct sort_key make_key(struct ft_sim_engine *e, uint64_t ts)
{
    return (struct sort_key){.ts = ts, .seq = ++e->seq};
}

static size_t store_path(struct ft_sim_engine *e, const char *path)
{
    size_t need = strlen(path) + 1;
    void *data = grow(e->paths.data, &e->paths.capacity, e->paths.length + need, 1);

    if (!data) {
        e->failed = true;
        return NO_PATH;
    }
    e->paths.data = data;
    size_t off = e->paths.length;
    memcpy(e->paths.data + off, path, need);
    e->paths.length += need;
    return off;
}

/* ------------------------------------------------------------------------------------------ */
/* Events that a kernel queues one by one                                                     */
/* ------------------------------------------------------------------------------------------ */

static void ring_process(struct ft_sim_engine *e, enum ft_event_type type, const struct proc_rt *p,
                         uint64_t ts)
{
    struct ring_event *r = next_ring(e);
    if (!r)
        return;

    const struct ft_sim_process *d = p->def;
    r->key = make_key(e, ts);
    r->path_off = NO_PATH;
    r->ev = (struct ft_event){
        .type = type,
        .ts_ns = ts,
        .process =
            {
                .pid = p->pid,
                .ppid = p->ppid,
                .uid = d->uid,
                .gid = d->uid,
                .start_ns = p->start_ns,
                .cgroup_id = p->cgroup_id,
                .pidns = PIDNS,
                .mntns = MNTNS,
                .netns = NETNS,
            },
    };
    ft_strlcpy(r->ev.process.comm, d->comm, sizeof(r->ev.process.comm));
    if (type == FT_EVENT_PROCESS_EXEC) {
        ft_strlcpy(r->ev.process.exe, d->exe, sizeof(r->ev.process.exe));
        r->ev.process.args = p->args;
        r->ev.process.args_len = p->args_len;
        r->ev.process.cwd = d->cwd;
    }
}

static void ring_socket(struct ft_sim_engine *e, uint64_t ts, uint64_t sock_id, uint32_t pid,
                        enum ft_sock_state state, const struct ft_endpoint *local,
                        const struct ft_endpoint *remote)
{
    struct ring_event *r = next_ring(e);
    if (!r)
        return;

    r->key = make_key(e, ts);
    r->path_off = NO_PATH;
    r->ev = (struct ft_event){
        .type = FT_EVENT_SOCKET_STATE,
        .ts_ns = ts,
        .socket =
            {
                .sock_id = sock_id,
                .pid = pid,
                .proto = FT_PROTO_TCP,
                .state = state,
                .local = *local,
                .remote = *remote,
            },
    };
}

static void ring_file(struct ft_sim_engine *e, uint64_t ts, const struct ft_file_id *id,
                      uint64_t size, uint32_t uid, const char *fs_type, const char *path)
{
    struct ring_event *r = next_ring(e);
    if (!r)
        return;

    r->key = make_key(e, ts);
    r->path_off = store_path(e, path);
    r->ev = (struct ft_event){
        .type = FT_EVENT_FILE_SEEN,
        .ts_ns = ts,
        .file =
            {
                .id = *id,
                .generation = 1,
                .mnt_id = 29 + (uint32_t)(id->dev & 0xff),
                .mntns = MNTNS,
                .uid = uid,
                .size = size,
            },
    };
    ft_strlcpy(r->ev.file.fs_type, fs_type ? fs_type : "ext4", sizeof(r->ev.file.fs_type));
}

/* ------------------------------------------------------------------------------------------ */
/* Hosts, clients and files                                                                   */
/* ------------------------------------------------------------------------------------------ */

static void endpoint_v4(struct ft_endpoint *ep, uint8_t a, uint8_t b, uint8_t c, uint8_t d,
                        uint16_t port)
{
    uint8_t raw[16] = {a, b, c, d};
    ft_endpoint_set(ep, false, raw, port);
}

static void endpoint_v6(struct ft_endpoint *ep, const uint8_t raw[static 16], uint16_t port)
{
    ft_endpoint_set(ep, true, raw, port);
}

static void random_v6(struct ft_sim_engine *e, struct ft_endpoint *ep)
{
    uint8_t raw[16];

    for (size_t i = 0; i < sizeof(raw); i++)
        raw[i] = (uint8_t)rng_below(&e->rng, 256);
    /* Half from the documentation prefix, half from a provider's range. */
    if (rng_below(&e->rng, 2) == 0) {
        raw[0] = 0x20;
        raw[1] = 0x01;
        raw[2] = 0x0d;
        raw[3] = 0xb8;
    } else {
        raw[0] = 0x2a;
        raw[1] = 0x02;
    }
    endpoint_v6(ep, raw, 0);
}

/* Any address a client on the internet could have, v6 now and then. */
static void random_public(struct ft_sim_engine *e, struct ft_endpoint *ep)
{
    static const uint8_t reserved[] = {0, 10, 100, 127, 169, 172, 192, 198, 203};

    if (rng_below(&e->rng, 100) < 3) {
        random_v6(e, ep);
        return;
    }
    for (;;) {
        uint8_t first = (uint8_t)rng_range(&e->rng, 1, 223);
        bool skip = false;

        for (size_t i = 0; i < sizeof(reserved); i++)
            skip = skip || first == reserved[i];
        if (skip)
            continue;
        endpoint_v4(ep, first, (uint8_t)rng_below(&e->rng, 256),
                    (uint8_t)rng_range(&e->rng, 1, 254), (uint8_t)rng_range(&e->rng, 1, 254), 0);
        return;
    }
}

static void make_client_pool(struct ft_sim_engine *e)
{
    for (size_t i = 0; i < CLIENT_POOL; i++) {
        struct ft_endpoint *ep = &e->clients[i];
        uint64_t kind = rng_below(&e->rng, 100);

        if (kind < 4) {
            random_v6(e, ep);
        } else if (kind < 10) {
            const uint8_t *d = documentation_prefixes[rng_below(&e->rng, 3)];
            endpoint_v4(ep, d[0], d[1], d[2], (uint8_t)rng_range(&e->rng, 11, 254), 0);
        } else {
            const uint8_t *p = client_prefixes[rng_below(&e->rng, FT_ARRAY_LEN(client_prefixes))];
            endpoint_v4(ep, p[0], p[1], (uint8_t)rng_range(&e->rng, 1, 254),
                        (uint8_t)rng_range(&e->rng, 1, 254), 0);
        }
    }
}

static uint16_t ephemeral_port(struct ft_sim_engine *e)
{
    return (uint16_t)rng_range(&e->rng, 32768, 60999);
}

static bool parse_dest(const struct ft_sim_dest *d, struct ft_endpoint *ep)
{
    if (!ft_addr_parse(d->addr, ep))
        return false;
    ep->port = d->port;
    return true;
}

static uint64_t next_socket_id(struct ft_sim_engine *e)
{
    uint64_t id = splitmix(e->seed ^ ++e->sockets);
    return id ? id : 1;
}

/* Returns true the first time a file is seen. */
static bool announce(struct ft_sim_engine *e, const struct ft_file_id *id)
{
    uint64_t key = splitmix(id->ino ^ (id->dev << 40) ^ ((uint64_t)id->instance << 56)) | 1;

    if ((e->seen_count + 1) * 2 > e->seen_capacity) {
        size_t cap = e->seen_capacity ? e->seen_capacity * 2 : 1024;
        uint64_t *table = calloc(cap, sizeof(*table));
        if (!table) {
            e->failed = true;
            return false;
        }
        for (size_t i = 0; i < e->seen_capacity; i++) {
            if (e->seen[i]) {
                size_t at = e->seen[i] % cap;
                while (table[at])
                    at = (at + 1) % cap;
                table[at] = e->seen[i];
            }
        }
        free(e->seen);
        e->seen = table;
        e->seen_capacity = cap;
    }
    size_t at = key % e->seen_capacity;
    while (e->seen[at]) {
        if (e->seen[at] == key)
            return false;
        at = (at + 1) % e->seen_capacity;
    }
    e->seen[at] = key;
    e->seen_count++;
    return true;
}

static struct ft_file_id file_identity(const char *path, uint64_t instance)
{
    /* The first two directories pick the device, which keeps a service's files together. */
    size_t slashes = 0;
    size_t len = 0;

    while (path[len] && !(path[len] == '/' && ++slashes == 3))
        len++;
    uint64_t minor = 1 + 16 * (hash_bytes(path, len) % 4);

    return (struct ft_file_id){
        .dev = (8u << 8) | minor,
        .ino = (hash_text(path) & 0x0000ffffffffffffULL) | 0x100000,
        .instance = (uint32_t)instance,
    };
}

/* ------------------------------------------------------------------------------------------ */
/* Processes                                                                                  */
/* ------------------------------------------------------------------------------------------ */

static char *build_args(const struct ft_sim_process *d, size_t *len)
{
    size_t n = strlen(d->cmdline);
    char *args = malloc(n + 1);

    if (!args)
        return nullptr;
    memcpy(args, d->cmdline, n + 1);
    if (!d->title) {
        for (size_t i = 0; i < n; i++) {
            if (args[i] == ' ')
                args[i] = '\0';
        }
    }
    *len = n + 1;
    return args;
}

static struct proc_rt *find_proc(const struct ft_sim_engine *e, uint32_t pid)
{
    for (size_t i = e->nprocs; i-- > 0;) {
        if (e->procs[i].pid == pid && e->procs[i].alive)
            return &e->procs[i];
    }
    return nullptr;
}

static uint64_t service_cgroup(const struct ft_sim_engine *e, const struct ft_sim_process *d,
                               uint32_t ppid)
{
    if (d->service)
        return hash_text(d->service) & 0x0000ffffffffffffULL;
    const struct proc_rt *parent = find_proc(e, ppid);
    return parent ? parent->cgroup_id : 1;
}

static bool add_proc(struct ft_sim_engine *e, const struct ft_sim_process *d, uint32_t pid,
                     uint32_t ppid, uint64_t start_ns)
{
    void *items = grow(e->procs, &e->procs_capacity, e->nprocs + 1, sizeof(*e->procs));
    if (!items)
        return false;
    e->procs = items;

    struct proc_rt *p = &e->procs[e->nprocs];
    *p = (struct proc_rt){
        .def = d,
        .pid = pid,
        .ppid = ppid,
        .start_ns = start_ns,
        .cgroup_id = service_cgroup(e, d, ppid),
        .alive = true,
    };
    p->args = build_args(d, &p->args_len);
    if (!p->args)
        return false;
    e->nprocs++;
    return true;
}

static void start_processes(struct ft_sim_engine *e, uint64_t at)
{
    for (const struct ft_sim_process *d = e->sc->processes; d->pid; d++) {
        for (uint32_t k = 0; k < (d->count ? d->count : 1); k++) {
            uint64_t age = (uint64_t)d->age_s * FT_NS_PER_SEC;

            if (!add_proc(e, d, d->pid + k, d->ppid, at > age ? at - age : 1)) {
                e->failed = true;
                return;
            }
            const struct proc_rt *p = &e->procs[e->nprocs - 1];
            ring_process(e, d->forked ? FT_EVENT_PROCESS_FORK : FT_EVENT_PROCESS_EXEC, p, at);
            if (d->listen_port) {
                struct ft_endpoint any = {.port = d->listen_port, .family = 4};
                struct ft_endpoint none = {0};
                ring_socket(e, at, next_socket_id(e), p->pid, FT_SOCK_LISTENING, &any, &none);
            }
        }
    }
}

static int pick_process(struct ft_sim_engine *e, const struct gen_rt *g, const struct slot *s)
{
    if (g->def->parent) {
        size_t candidates = 0;

        for (size_t i = 0; i < e->nprocs; i++)
            candidates += e->procs[i].alive && e->procs[i].ppid == g->def->parent;
        if (candidates == 0)
            return -1;
        size_t nth = rng_below(&e->rng, candidates);
        for (size_t i = 0; i < e->nprocs; i++) {
            if (e->procs[i].alive && e->procs[i].ppid == g->def->parent && nth-- == 0)
                return (int)i;
        }
        return -1;
    }
    uint32_t pid = g->def->pids[s->index % g->npids];
    for (size_t i = 0; i < e->nprocs; i++) {
        if (e->procs[i].alive && e->procs[i].pid == pid)
            return (int)i;
    }
    return -1;
}

/* Exits one idle child of the scenario's recycled parent and forks another in its place. */
static void recycle_due(struct ft_sim_engine *e, uint64_t t0, uint64_t t1)
{
    const struct ft_sim_recycle *r = &e->sc->recycle;

    if (!r->parent || e->next_recycle_ns >= t1)
        return;

    uint64_t at = e->next_recycle_ns > t0 ? e->next_recycle_ns : t0;
    size_t candidates = 0;
    for (size_t i = 0; i < e->nprocs; i++)
        candidates += e->procs[i].alive && e->procs[i].ppid == r->parent && e->procs[i].busy == 0;
    if (candidates == 0) {
        e->next_recycle_ns = t1;
        return;
    }
    size_t nth = rng_below(&e->rng, candidates);
    size_t victim = 0;
    for (size_t i = 0; i < e->nprocs; i++) {
        if (e->procs[i].alive && e->procs[i].ppid == r->parent && e->procs[i].busy == 0 &&
            nth-- == 0) {
            victim = i;
            break;
        }
    }

    const struct ft_sim_process *def = e->procs[victim].def;
    ring_process(e, FT_EVENT_PROCESS_EXIT, &e->procs[victim], at);
    e->procs[victim].alive = false;
    if (add_proc(e, def, e->next_pid++, r->parent, at + FT_NS_PER_MS))
        ring_process(e, FT_EVENT_PROCESS_FORK, &e->procs[e->nprocs - 1], at + FT_NS_PER_MS);
    else
        e->failed = true;
    e->next_recycle_ns = at + rng_range(&e->rng, r->min_s, r->max_s) * FT_NS_PER_SEC;
}

/* ------------------------------------------------------------------------------------------ */
/* Transfers                                                                                  */
/* ------------------------------------------------------------------------------------------ */

static void pick_destination(struct ft_sim_engine *e, const struct ft_sim_generator *g,
                             const struct slot *s, struct ft_endpoint *remote)
{
    switch (g->dest_kind) {
    case FT_SIM_DEST_LIST: {
        size_t n = 0;
        while (g->dests[n].addr)
            n++;
        const struct ft_sim_dest *d = &g->dests[s->index % n];
        if (!parse_dest(d, remote))
            memset(remote, 0, sizeof(*remote));
        if (remote->port == 0)
            remote->port = ephemeral_port(e);
        return;
    }
    case FT_SIM_DEST_PUBLIC: {
        double u = rng_unit(&e->rng);
        size_t index = (size_t)((double)CLIENT_POOL * u * u);
        *remote = e->clients[index < CLIENT_POOL ? index : CLIENT_POOL - 1];
        break;
    }
    case FT_SIM_DEST_PUBLIC_RANDOM:
        random_public(e, remote);
        break;
    case FT_SIM_DEST_PRIVATE:
        endpoint_v4(remote, 10, 0, (uint8_t)rng_range(&e->rng, 1, 250),
                    (uint8_t)rng_range(&e->rng, 1, 250), 0);
        break;
    }
    remote->port = ephemeral_port(e);
}

static void open_socket(struct ft_sim_engine *e, struct slot *s, const struct gen_rt *g,
                        const struct proc_rt *p, uint64_t at)
{
    struct ft_endpoint remote;

    pick_destination(e, g->def, s, &remote);
    bool v6 = remote.family == 6;
    bool pub = !ft_addr_is_private(&remote);
    s->remote = remote;
    s->local = e->hosts[(v6 ? 2 : 0) + (pub ? 1 : 0)];
    s->local.port = g->def->outbound ? ephemeral_port(e) : g->def->local_port;
    s->sock_id = next_socket_id(e);
    s->has_socket = true;
    s->fresh = true;

    if (g->def->outbound)
        ring_socket(e, at, s->sock_id, p->pid, FT_SOCK_CONNECTING, &s->local, &s->remote);
    ring_socket(e, at + 100 * 1000, s->sock_id, p->pid, FT_SOCK_ESTABLISHED, &s->local, &s->remote);
}

static uint64_t flavor_number(struct ft_sim_engine *e, const struct ft_sim_flavor *f,
                              uint64_t *counter, uint64_t at)
{
    switch (f->numbering) {
    case FT_SIM_NUMBER_RANDOM:
        return f->first + rng_below(&e->rng, f->last - f->first + 1);
    case FT_SIM_NUMBER_SEQUENCE:
        return f->first + (*counter)++ * f->step;
    case FT_SIM_NUMBER_EPOCH:
        return f->first + (at - e->origin_ns) / (f->period_ms * FT_NS_PER_MS);
    default:
        return 0;
    }
}

static bool transfer_start(struct ft_sim_engine *e, struct slot *s, struct gen_rt *g, uint64_t at)
{
    const struct ft_sim_generator *def = g->def;
    int pi = pick_process(e, g, s);

    if (pi < 0)
        return false;
    struct proc_rt *p = &e->procs[pi];

    size_t fi = 0;
    if (def->flavor_by_slot) {
        fi = s->index % g->flavors;
    } else {
        uint64_t pick = rng_below(&e->rng, g->total_weight);
        while (pick >= def->flavors[fi].weight) {
            pick -= def->flavors[fi].weight;
            fi++;
        }
    }
    const struct ft_sim_flavor *f = &def->flavors[fi];

    char path[FT_PATH_MAX];
    uint64_t number = flavor_number(e, f, &e->counters[g->first_counter + fi], at);
    snprintf(path, sizeof(path), f->path, (unsigned long long)number);

    if (def->rotates)
        s->cycles++;
    s->file = file_identity(path, def->rotates ? s->cycles : 0);
    s->flavor = f;
    s->size = f->size_min;
    if (f->size_max > f->size_min)
        s->size += splitmix(hash_text(path)) % (f->size_max - f->size_min + 1);
    s->rate = rng_range(&e->rng, f->rate_min, f->rate_max) * 1024;
    s->sent = 0;
    s->read_total = 0;
    s->level = 0.97 + 0.06 * rng_unit(&e->rng);
    s->dip_steps = 0;

    if (!(def->keep_socket && s->has_socket))
        open_socket(e, s, g, p, at);
    if (announce(e, &s->file))
        ring_file(e, at + 200 * 1000, &s->file, s->size, p->def->uid, f->fs_type, path);

    s->proc = (uint32_t)pi;
    s->running = true;
    p->busy++;
    return true;
}

static void flow_flush(struct ft_sim_engine *e, struct slot *s)
{
    if (s->flow_tx == 0 && s->flow_rx == 0)
        return;

    struct pending_flow *f = next_flow(e);
    if (f) {
        f->key = make_key(e, s->flow_last_ns);
        f->flow = (struct ft_ev_flow){
            .sock_id = s->sock_id,
            .pid = e->procs[s->proc].pid,
            .proto = FT_PROTO_TCP,
            .local = s->local,
            .remote = s->remote,
            .first_ns = s->flow_first_ns,
            .tx_bytes = s->flow_tx,
            .rx_bytes = s->flow_rx,
            .tx_ops = s->flow_tx_ops,
            .rx_ops = s->flow_rx_ops,
        };
    }
    s->flow_tx = 0;
    s->flow_rx = 0;
    s->flow_tx_ops = 0;
    s->flow_rx_ops = 0;
}

static void transfer_flush(struct ft_sim_engine *e, struct slot *s)
{
    if (s->xfer_bytes == 0)
        return;

    struct pending_transfer *t = next_transfer(e);
    if (t) {
        t->key = make_key(e, s->xfer_last_ns);
        t->transfer = (struct ft_ev_transfer){
            .sock_id = s->sock_id,
            .pid = e->procs[s->proc].pid,
            .method = e->gens[s->gen].def->method,
            .file = s->file,
            .first_ns = s->xfer_first_ns,
            .bytes = s->xfer_bytes,
            .read_bytes = s->xfer_read,
            .ops = s->xfer_ops,
            .alternations = s->xfer_alternations,
            .script = s->flavor->script,
        };
    }
    s->xfer_bytes = 0;
    s->xfer_read = 0;
    s->xfer_ops = 0;
    s->xfer_alternations = 0;
}

/* Sends bytes of the slot's file between from_ns and end_ns; ts is when the last one went. */
static void send_segment(struct ft_sim_engine *e, struct slot *s, const struct gen_rt *g,
                         uint64_t from_ns, uint64_t end_ns, uint64_t bytes, bool last)
{
    const struct ft_sim_generator *def = g->def;
    uint64_t span = end_ns - from_ns;
    uint64_t ts = end_ns;

    if (bytes == 0)
        return;
    if (!last) {
        uint64_t reach = span / 4 < JITTER_MAX_NS ? span / 4 : JITTER_MAX_NS;
        ts -= rng_below(&e->rng, reach + 1);
    }

    s->sent += bytes;
    uint64_t ops = (bytes + def->chunk - 1) / def->chunk;
    if (s->xfer_bytes == 0)
        s->xfer_first_ns = from_ns;
    s->xfer_last_ns = ts;
    s->xfer_bytes += bytes;
    s->xfer_ops += (uint32_t)ops;
    if (def->method != FT_METHOD_SENDFILE) {
        uint64_t read_total = s->sent + def->chunk;
        if (read_total > s->size)
            read_total = s->size;
        s->xfer_read += read_total - s->read_total;
        s->read_total = read_total;
        s->xfer_alternations += (uint32_t)ops;
    }

    if (s->flow_tx == 0 && s->flow_rx == 0)
        s->flow_first_ns = from_ns;
    s->flow_last_ns = ts;
    s->flow_tx += bytes;
    s->flow_tx_ops += (uint32_t)ops;
    /* Requests and acknowledgements the application reads, a little. */
    uint64_t rx = bytes / 4096;
    if (s->fresh) {
        rx += rng_range(&e->rng, 350, 950);
        s->fresh = false;
    }
    if (rx) {
        s->flow_rx += rx;
        s->flow_rx_ops++;
    }
}

static void transfer_finish(struct ft_sim_engine *e, struct slot *s, const struct gen_rt *g,
                            uint64_t end_ns, uint64_t step_end_ns)
{
    struct proc_rt *p = &e->procs[s->proc];

    transfer_flush(e, s);
    if (!g->def->keep_socket) {
        flow_flush(e, s);
        uint64_t ts = end_ns + FT_NS_PER_MS;
        ring_socket(e, ts < step_end_ns ? ts : step_end_ns, s->sock_id, p->pid, FT_SOCK_CLOSED,
                    &s->local, &s->remote);
        s->has_socket = false;
    }
    p->busy--;
    s->running = false;
    s->idle_until_ns =
        end_ns + rng_range(&e->rng, g->def->pause_min_ms, g->def->pause_max_ms) * FT_NS_PER_MS;
}

/* A rate that wanders a few percent around its mean and now and then dips. */
static double wobble(struct ft_sim_engine *e, struct slot *s)
{
    double noise = (rng_unit(&e->rng) - 0.5) * 0.04;

    s->level += 0.06 * (1.0 - s->level) + noise;
    if (s->level < 0.85)
        s->level = 0.85;
    if (s->level > 1.15)
        s->level = 1.15;
    if (s->dip_steps) {
        s->dip_steps--;
    } else if (rng_unit(&e->rng) < 0.0016) {
        s->dip_steps = (uint32_t)rng_range(&e->rng, 10, 35);
        s->dip_factor = 0.3 + 0.4 * rng_unit(&e->rng);
    }
    return s->level * (s->dip_steps ? s->dip_factor : 1.0);
}

static void slot_run(struct ft_sim_engine *e, struct slot *s, uint64_t t0, uint64_t t1)
{
    struct gen_rt *g = &e->gens[s->gen];
    uint64_t cursor = t0;

    while (cursor < t1) {
        if (!s->running) {
            if (s->idle_until_ns >= t1)
                break;
            if (s->idle_until_ns > cursor)
                cursor = s->idle_until_ns;
            if (!transfer_start(e, s, g, cursor)) {
                s->idle_until_ns = t1;
                break;
            }
        }

        double rate = (double)s->rate * wobble(e, s);
        if (rate < 1.0)
            rate = 1.0;
        uint64_t capacity = (uint64_t)(rate * ((double)(t1 - cursor) / (double)FT_NS_PER_SEC));
        uint64_t remaining = s->size - s->sent;
        bool done = remaining <= capacity;
        uint64_t end_ns = t1;

        if (done) {
            end_ns = cursor + (uint64_t)((double)remaining / rate * (double)FT_NS_PER_SEC);
            if (end_ns < cursor + MIN_SEGMENT_NS)
                end_ns = cursor + MIN_SEGMENT_NS;
            if (end_ns > t1)
                end_ns = t1;
        }
        send_segment(e, s, g, cursor, end_ns, done ? remaining : capacity, done);
        if (!done)
            break;
        transfer_finish(e, s, g, end_ns, t1);
        cursor = end_ns;
    }
}

/* ------------------------------------------------------------------------------------------ */
/* Delivery                                                                                   */
/* ------------------------------------------------------------------------------------------ */

static int compare_order(const void *a, const void *b)
{
    const struct order *x = a;
    const struct order *y = b;

    if (x->key.ts != y->key.ts)
        return x->key.ts < y->key.ts ? -1 : 1;
    if (x->key.seq != y->key.seq)
        return x->key.seq < y->key.seq ? -1 : 1;
    return 0;
}

/* Every item starts with its sort key. */
static const struct order *sorted(struct ft_sim_engine *e, const void *items, size_t stride,
                                  size_t count)
{
    void *order = grow(e->order, &e->order_capacity, count, sizeof(*e->order));

    if (!order) {
        e->failed = true;
        return nullptr;
    }
    e->order = order;
    for (size_t i = 0; i < count; i++) {
        memcpy(&e->order[i].key, (const char *)items + i * stride, sizeof(struct sort_key));
        e->order[i].index = (uint32_t)i;
    }
    qsort(e->order, count, sizeof(*e->order), compare_order);
    return e->order;
}

static void deliver(struct ft_sim_engine *e, const struct ft_event *ev, bool queued)
{
    e->events++;
    if (queued)
        e->queued++;
    e->sink.emit(e->sink.ctx, ev);
}

/* The kernel's queue is read first, then the counters it kept in between. */
static void deliver_step(struct ft_sim_engine *e)
{
    const struct order *o = sorted(e, e->ring.items, sizeof(*e->ring.items), e->ring.count);
    for (size_t i = 0; o && i < e->ring.count; i++) {
        struct ring_event *r = &e->ring.items[o[i].index];

        if (r->path_off != NO_PATH)
            r->ev.file.path = e->paths.data + r->path_off;
        deliver(e, &r->ev, true);
    }

    o = sorted(e, e->flows.items, sizeof(*e->flows.items), e->flows.count);
    for (size_t i = 0; o && i < e->flows.count; i++) {
        const struct pending_flow *f = &e->flows.items[o[i].index];
        struct ft_event ev = {.type = FT_EVENT_FLOW, .ts_ns = f->key.ts, .flow = f->flow};

        deliver(e, &ev, false);
    }

    o = sorted(e, e->transfers.items, sizeof(*e->transfers.items), e->transfers.count);
    for (size_t i = 0; o && i < e->transfers.count; i++) {
        const struct pending_transfer *t = &e->transfers.items[o[i].index];
        struct ft_event ev = {
            .type = FT_EVENT_TRANSFER, .ts_ns = t->key.ts, .transfer = t->transfer};

        deliver(e, &ev, false);
    }

    if (e->loss_due) {
        struct ft_event ev = {.type = FT_EVENT_LOSS, .ts_ns = e->now_ns, .loss = e->loss};

        deliver(e, &ev, false);
        e->loss_due = false;
    }
    e->ring.count = 0;
    e->flows.count = 0;
    e->transfers.count = 0;
    e->paths.length = 0;
}

static void loss_due(struct ft_sim_engine *e, uint64_t t0, uint64_t t1)
{
    if (e->next_loss_ns >= t1)
        return;

    uint64_t pick = rng_below(&e->rng, 100);
    e->loss = (struct ft_ev_loss){
        .kind = pick < 60 ? FT_LOSS_SOCKET_IDENT
                          : (pick < 85 ? FT_LOSS_AGGREGATION : FT_LOSS_EVENT_QUEUE),
        .count = rng_range(&e->rng, 1, 3),
        .since_ns = t0,
    };
    e->loss_due = true;
    e->next_loss_ns = t1 + rng_range(&e->rng, 60, 120) * FT_NS_PER_SEC;
}

static void step(struct ft_sim_engine *e, uint64_t step_ns)
{
    uint64_t t0 = e->now_ns;
    uint64_t t1 = t0 + step_ns;

    recycle_due(e, t0, t1);
    for (size_t i = 0; i < e->nslots; i++)
        slot_run(e, &e->slots[i], t0, t1);
    loss_due(e, t0, t1);
    e->now_ns = t1;
}

void ft_sim_engine_run(struct ft_sim_engine *e, uint64_t until_ns, uint64_t step_ns)
{
    while (e->now_ns + step_ns <= until_ns)
        step(e, step_ns);

    for (size_t i = 0; i < e->nslots; i++) {
        struct slot *s = &e->slots[i];

        if (s->running)
            transfer_flush(e, s);
        if (s->has_socket)
            flow_flush(e, s);
    }
    deliver_step(e);
}

void ft_sim_engine_skip_to(struct ft_sim_engine *e, uint64_t ns)
{
    if (ns > e->now_ns)
        e->now_ns = ns;
}

uint64_t ft_sim_engine_now(const struct ft_sim_engine *e)
{
    return e->now_ns;
}

uint64_t ft_sim_engine_events(const struct ft_sim_engine *e)
{
    return e->events;
}

uint64_t ft_sim_engine_queued_events(const struct ft_sim_engine *e)
{
    return e->queued;
}

bool ft_sim_engine_process(const struct ft_sim_engine *e, uint32_t pid, struct ft_ev_process *out)
{
    const struct proc_rt *p = find_proc(e, pid);

    if (!p)
        return false;
    *out = (struct ft_ev_process){
        .pid = p->pid,
        .ppid = p->ppid,
        .uid = p->def->uid,
        .gid = p->def->uid,
        .start_ns = p->start_ns,
        .cgroup_id = p->cgroup_id,
        .pidns = PIDNS,
        .mntns = MNTNS,
        .netns = NETNS,
    };
    ft_strlcpy(out->comm, p->def->comm, sizeof(out->comm));
    ft_strlcpy(out->exe, p->def->exe, sizeof(out->exe));
    return true;
}

bool ft_sim_engine_process_text(const struct ft_sim_engine *e, uint32_t pid,
                                struct ft_process_text *out)
{
    const struct proc_rt *p = find_proc(e, pid);

    if (!p)
        return false;
    out->args_len = p->args_len < sizeof(out->args) ? p->args_len : sizeof(out->args) - 1;
    memcpy(out->args, p->args, out->args_len);
    ft_strlcpy(out->cwd, p->def->cwd, sizeof(out->cwd));
    return true;
}

/* ------------------------------------------------------------------------------------------ */
/* Creation                                                                                   */
/* ------------------------------------------------------------------------------------------ */

static bool start_generators(struct ft_sim_engine *e, uint64_t at)
{
    size_t ngens = 0;
    size_t nslots = 0;
    size_t nflavors = 0;

    for (const struct ft_sim_generator *g = e->sc->generators; g->name; g++) {
        ngens++;
        nslots += g->slots;
        for (const struct ft_sim_flavor *f = g->flavors; f->weight; f++)
            nflavors++;
    }
    e->gens = calloc(ngens + 1, sizeof(*e->gens));
    e->slots = calloc(nslots + 1, sizeof(*e->slots));
    e->counters = calloc(nflavors + 1, sizeof(*e->counters));
    if (!e->gens || !e->slots || !e->counters)
        return false;

    size_t counter = 0;
    for (const struct ft_sim_generator *g = e->sc->generators; g->name; g++) {
        struct gen_rt *rt = &e->gens[e->ngens];

        rt->def = g;
        rt->first_counter = counter;
        for (const struct ft_sim_flavor *f = g->flavors; f->weight; f++) {
            rt->flavors++;
            rt->total_weight += f->weight;
        }
        for (const uint32_t *pid = g->pids; pid && *pid; pid++)
            rt->npids++;
        counter += rt->flavors;
        if (rt->flavors == 0 || (!g->parent && rt->npids == 0))
            return false;

        uint64_t spread = g->spread_ms ? g->spread_ms : g->pause_max_ms;
        if (spread < 1000)
            spread = 1000;
        for (uint32_t i = 0; i < g->slots; i++) {
            struct slot *s = &e->slots[e->nslots++];

            s->gen = (uint32_t)e->ngens;
            s->index = i;
            s->level = 1.0;
            s->idle_until_ns = at + (spread ? rng_below(&e->rng, spread) : 0) * FT_NS_PER_MS;
        }
        e->ngens++;
    }
    return true;
}

struct ft_sim_engine *ft_sim_engine_create(const struct ft_sim_scenario *sc, uint64_t seed,
                                           uint64_t start_ns, const struct ft_sink *sink)
{
    struct ft_sim_engine *e = calloc(1, sizeof(*e));

    if (!e)
        return nullptr;
    e->sc = sc;
    e->sink = *sink;
    e->seed = seed;
    rng_seed(&e->rng, seed);
    e->origin_ns = start_ns;
    e->now_ns = start_ns;
    e->next_pid = sc->recycle.first_pid;

    bool ok = true;
    for (size_t i = 0; i < FT_ARRAY_LEN(e->hosts); i++)
        ok = ok && ft_addr_parse(host_addrs[i], &e->hosts[i]);
    make_client_pool(e);
    start_processes(e, start_ns);
    ok = ok && !e->failed && start_generators(e, start_ns);
    if (!ok) {
        ft_sim_engine_destroy(e);
        return nullptr;
    }

    if (sc->recycle.parent)
        e->next_recycle_ns =
            start_ns + rng_range(&e->rng, sc->recycle.min_s, sc->recycle.max_s) * FT_NS_PER_SEC;
    e->next_loss_ns = start_ns + rng_range(&e->rng, 25, 50) * FT_NS_PER_SEC;
    deliver_step(e);
    return e;
}

void ft_sim_engine_destroy(struct ft_sim_engine *e)
{
    if (!e)
        return;
    for (size_t i = 0; i < e->nprocs; i++)
        free(e->procs[i].args);
    free(e->procs);
    free(e->gens);
    free(e->slots);
    free(e->counters);
    free(e->seen);
    free(e->ring.items);
    free(e->flows.items);
    free(e->transfers.items);
    free(e->paths.data);
    free(e->order);
    free(e);
}
