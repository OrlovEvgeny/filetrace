#include "agent/telemetry.h"

#include "filetrace/client.h"
#include "filetrace/clock.h"
#include "filetrace/net.h"
#include "filetrace/sysinfo.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

constexpr size_t MAX_CLIENTS = 32;
constexpr size_t MAX_REPLY_BYTES = 64u * 1024u * 1024u;
constexpr uint64_t RATE_WINDOW_NS = FT_NS_PER_SEC;
/* A follower that has this much unread is sent no more until it catches up. */
constexpr size_t FOLLOW_BACKLOG_BYTES = 1024 * 1024;

struct client {
    int fd;
    bool session;
    bool overflow;
    size_t in_len;
    size_t out_len;
    size_t out_off;
    size_t out_cap;
    unsigned char *out;
    struct ft_query *follow; /* the events query whose matches it is being sent, or nullptr */
    uint64_t follow_from_ns;
    uint64_t follow_to_ns;
    uint64_t follow_missed;
    unsigned char in[sizeof(struct ft_frame_hdr) + sizeof(struct ft_query)];
};

struct agent {
    const struct ft_agent_config *cfg;
    struct ft_state *state;
    struct ft_backend *backend;
    int listen_fd;
    struct client clients[MAX_CLIENTS];
    size_t nclients;
    struct ft_row_event *live; /* a record on its way to followers */
    struct ft_poller poller;
    struct ft_scrape *scrape;
    struct ft_otlp *otlp;
    struct ft_api *api;

    uint64_t start_wall_ns;
    uint64_t rate_mono_ns;
    uint64_t rate_events;
    uint64_t rate_cpu_ns;
    uint64_t events_per_sec_milli;
    uint32_t cpu_milli_percent;
};

static volatile sig_atomic_t stop_requested;

void ft_agent_stop(void)
{
    stop_requested = 1;
}

void ft_agent_config_defaults(struct ft_agent_config *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->backend = ft_backend_native();
    ft_backend_config_defaults(&cfg->backend_cfg);
    ft_state_config_defaults(&cfg->state_cfg);
    cfg->socket_path = ft_default_socket_path();
    cfg->session_fd = -1;
    cfg->flush_interval_ms = 250;

    ft_strlcpy(cfg->prometheus.listen, "127.0.0.1:9464", sizeof(cfg->prometheus.listen));
    ft_strlcpy(cfg->otlp.endpoint, "127.0.0.1:4317", sizeof(cfg->otlp.endpoint));
    cfg->otlp.logs = true;
    cfg->otlp.metrics = true;
    cfg->otlp.file_paths = true;
    cfg->otlp.names = true;
    cfg->otlp.event_types = 1u << FT_REC_FILE_TRANSFER | 1u << FT_REC_EVENT_LOSS;
    cfg->otlp.batch_size = 1024;
    cfg->otlp.flush_interval_ns = 5 * FT_NS_PER_SEC;
    cfg->otlp.metrics_interval_ns = 30 * FT_NS_PER_SEC;
    cfg->otlp.timeout_ns = 10 * FT_NS_PER_SEC;

    /* Beside the socket the command-line interface uses. */
    char dir[sizeof(cfg->api.listen)];
    ft_strlcpy(dir, cfg->socket_path, sizeof(dir));
    snprintf(cfg->api.listen, sizeof(cfg->api.listen), "unix:%s/api.sock", dirname(dir));
}

static void on_event(void *ctx, const struct ft_event *ev)
{
    struct agent *d = ctx;
    ft_state_ingest(d->state, ev);
}

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
}

static int open_listener(const char *path, struct ft_error *err)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};

    if (strlen(path) >= sizeof(addr.sun_path)) {
        ft_error_set(err, FT_EXIT_CONFIG, "Socket path is too long: %s", path);
        return -1;
    }
    ft_strlcpy(addr.sun_path, path, sizeof(addr.sun_path));

    char dir[sizeof(addr.sun_path)];
    ft_strlcpy(dir, path, sizeof(dir));
    if (mkdir(dirname(dir), 0755) != 0 && errno != EEXIST) {
        ft_error_set(err, errno == EACCES ? FT_EXIT_PERMISSION : FT_EXIT_ERROR,
                     "Cannot create the socket directory for %s: %s", path, strerror(errno));
        return -1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot create a socket: %s", strerror(errno));
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        close(fd);
        ft_error_set(err, FT_EXIT_ERROR, "An agent is already serving %s.", path);
        return -1;
    }
    unlink(path);

    mode_t old_mask = umask(0177);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    int saved = errno;
    umask(old_mask);
    if (rc != 0 || listen(fd, 16) != 0) {
        if (rc == 0)
            saved = errno;
        close(fd);
        ft_error_set(err, saved == EACCES ? FT_EXIT_PERMISSION : FT_EXIT_ERROR,
                     "Cannot listen on %s: %s", path, strerror(saved));
        return -1;
    }
    set_nonblocking(fd);
    return fd;
}

static void reply(struct client *c, uint16_t type, const void *payload, size_t size)
{
    if (c->overflow)
        return;
    /* Written bytes are dropped once they outweigh the unwritten ones. */
    if (c->out_off && c->out_off >= c->out_len - c->out_off) {
        memmove(c->out, c->out + c->out_off, c->out_len - c->out_off);
        c->out_len -= c->out_off;
        c->out_off = 0;
    }

    size_t need = c->out_len + sizeof(struct ft_frame_hdr) + size;
    if (need > c->out_cap) {
        size_t cap = c->out_cap ? c->out_cap : 16384;
        while (cap < need)
            cap *= 2;
        unsigned char *grown = cap <= MAX_REPLY_BYTES ? realloc(c->out, cap) : nullptr;
        if (!grown) {
            c->overflow = true;
            return;
        }
        c->out = grown;
        c->out_cap = cap;
    }

    struct ft_frame_hdr hdr = {
        .magic = FT_WIRE_MAGIC,
        .version = FT_WIRE_VERSION,
        .type = type,
        .length = (uint32_t)size,
    };
    memcpy(c->out + c->out_len, &hdr, sizeof(hdr));
    if (size)
        memcpy(c->out + c->out_len + sizeof(hdr), payload, size);
    c->out_len = need;
}

static void reply_row(void *ctx, uint16_t type, const void *row, size_t size)
{
    reply(ctx, type, row, size);
}

[[gnu::format(printf, 3, 4)]]
static void reply_error(struct client *c, int code, const char *fmt, ...)
{
    struct ft_msg_error e = {.code = (uint32_t)code};
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(e.msg, sizeof(e.msg), fmt, ap);
    va_end(ap);
    c->overflow = false;
    reply(c, FT_MSG_ERROR, &e, sizeof(e));
}

static void on_record(void *ctx, const struct ft_row_event *row)
{
    struct agent *d = ctx;
    struct ft_row_event *live = d->live;

    ft_otlp_record(d->otlp, row);
    ft_api_record(d->api, row);
    for (size_t i = 0; i < d->nclients; i++) {
        struct client *c = &d->clients[i];

        if (!c->follow ||
            !ft_state_record_matches(c->follow, c->follow_from_ns, c->follow_to_ns, row))
            continue;
        if (c->out_len - c->out_off > FOLLOW_BACKLOG_BYTES) {
            c->follow_missed++;
            continue;
        }
        if (c->follow_missed) {
            memset(live, 0, offsetof(struct ft_row_event, text) + 1);
            live->type = FT_REC_EVENT_LOSS;
            live->time_ns = ft_clock_wall_ns();
            live->bytes = c->follow_missed;
            live->loss_kind = FT_EVENT_LOSS_READER;
            live->confidence = FT_CONF_ANY;
            reply(c, FT_MSG_ROW_EVENT, live, ft_row_event_size(live));
            c->follow_missed = 0;
        }
        size_t size = ft_row_event_size(row);
        memcpy(live, row, size);
        live->time_ns = ft_clock_mono_to_wall(row->time_ns);
        reply(c, FT_MSG_ROW_EVENT, live, size);
    }
}

static void follow_end(struct client *c)
{
    free(c->follow);
    c->follow = nullptr;
    c->follow_missed = 0;
}

static void sample_rates(struct agent *d, uint64_t now_ns)
{
    struct ft_self_usage usage;
    ft_sysinfo_self(&usage);

    uint64_t elapsed = now_ns - d->rate_mono_ns;
    if (elapsed) {
        uint64_t events = d->state->events - d->rate_events;
        uint64_t cpu = usage.cpu_ns - d->rate_cpu_ns;
        d->events_per_sec_milli = events * 1000 * FT_NS_PER_SEC / elapsed;
        d->cpu_milli_percent = (uint32_t)(cpu * 100'000 / elapsed);
    }
    d->rate_mono_ns = now_ns;
    d->rate_events = d->state->events;
    d->rate_cpu_ns = usage.cpu_ns;
}

static void fill_stats(void *agent, uint64_t now_ns, struct ft_row_stats *row)
{
    struct agent *d = agent;
    struct ft_backend_stats bs = {0};
    struct ft_self_usage usage;

    if (d->events_per_sec_milli == 0 && d->cpu_milli_percent == 0)
        sample_rates(d, now_ns);

    d->cfg->backend->stats(d->backend, &bs);
    ft_sysinfo_self(&usage);
    ft_state_fill_stats(d->state, now_ns, row);

    row->start_wall_ns = d->start_wall_ns;
    row->now_wall_ns = ft_clock_wall_ns();
    row->events_received = bs.events + row->events_dropped;
    row->events_per_sec_milli = d->events_per_sec_milli;
    row->cpu_milli_percent = d->cpu_milli_percent;
    row->rss_bytes = usage.rss_bytes;
    row->open_fds = usage.open_fds;
    row->queue_bytes = bs.queue_bytes;
    row->queue_peak_bytes = bs.queue_peak_bytes;
    row->listed_files = (struct ft_table_usage){
        .count = bs.listed_files, .capacity = bs.listed_capacity, .evictions = bs.listed_refused};
    row->name_libraries = (struct ft_table_usage){.count = bs.name_libraries,
                                                  .capacity = bs.name_library_capacity,
                                                  .evictions = bs.name_libraries_forgotten};
    row->name_libraries_configured = bs.name_libraries_configured;
    row->tls_libraries = bs.tls_libraries;
    row->tls_library_capacity = bs.tls_library_capacity;
    row->probe_skips = bs.probe_skips;
    row->probe_skips_sent = bs.probe_skips_sent;
    row->probe_skips_received = bs.probe_skips_received;
    row->probe_skips_read = bs.probe_skips_read;
    row->pid = (uint32_t)getpid();
    if (d->cfg->backend->describe)
        d->cfg->backend->describe(d->backend, row->backend, sizeof(row->backend));
    else
        ft_strlcpy(row->backend, d->cfg->backend->name, sizeof(row->backend));
    ft_strlcpy(row->mode, ft_mode_name(d->cfg->backend_cfg.mode), sizeof(row->mode));
    ft_strlcpy(row->version, FT_VERSION, sizeof(row->version));
}

static void reply_stats(struct agent *d, struct client *c, uint64_t now_ns)
{
    struct ft_row_stats row = {0};
    struct ft_msg_end end = {.rows = 1};

    fill_stats(d, now_ns, &row);
    end.health = row.health;
    end.observed_since_wall_ns = d->start_wall_ns;
    reply(c, FT_MSG_ROW_STATS, &row, sizeof(row));
    reply(c, FT_MSG_END, &end, sizeof(end));
}

static void reply_capabilities(struct agent *d, struct client *c)
{
    struct ft_capabilities caps = {0};
    struct ft_msg_end end = {.rows = FT_FEAT_COUNT, .observed_since_wall_ns = d->start_wall_ns};

    d->cfg->backend->capabilities(d->backend, &caps);
    for (size_t f = 0; f < FT_FEAT_COUNT; f++) {
        struct ft_row_capability row = {.feature = (uint8_t)f, .status = caps.items[f].status};
        ft_strlcpy(row.reason, caps.items[f].reason, sizeof(row.reason));
        reply(c, FT_MSG_ROW_CAPABILITY, &row, sizeof(row));
    }
    reply(c, FT_MSG_END, &end, sizeof(end));
}

static void handle_query(struct agent *d, struct client *c, const void *payload, size_t size)
{
    struct ft_query *q = calloc(1, sizeof(*q));

    follow_end(c);
    if (!q) {
        reply_error(c, FT_EXIT_ERROR, "Out of memory");
        return;
    }
    memcpy(q, payload, size < sizeof(*q) ? size : sizeof(*q));
    q->process[sizeof(q->process) - 1] = '\0';
    q->script[sizeof(q->script) - 1] = '\0';
    q->path[sizeof(q->path) - 1] = '\0';

    uint64_t now_ns = ft_clock_mono_ns();
    switch (q->kind) {
    case FT_Q_STATS:
        reply_stats(d, c, now_ns);
        break;
    case FT_Q_CAPABILITIES:
        reply_capabilities(d, c);
        break;
    case FT_Q_PROCESSES:
    case FT_Q_CONNECTIONS:
    case FT_Q_FLOWS:
    case FT_Q_TRANSFERS:
    case FT_Q_EVENTS:
    case FT_Q_LEADERS: {
        struct ft_msg_end end;
        struct ft_error err = {0};
        size_t mark = c->out_len;
        if (!ft_state_query(d->state, q, now_ns, reply_row, c, &end, &err)) {
            c->out_len = mark;
            reply_error(c, err.code, "%s", err.msg);
        } else if (c->overflow) {
            reply_error(c, FT_EXIT_ERROR,
                        "The result is too large. Narrow it with filters or --limit.");
        } else if (q->kind == FT_Q_EVENTS && (q->flags & FT_QF_FOLLOW)) {
            /* No end follows: the records made from here on do, until the client leaves. */
            c->follow = q;
            c->follow_from_ns = q->since_wall_ns ? ft_clock_wall_to_mono(q->since_wall_ns) : 0;
            c->follow_to_ns =
                q->until_wall_ns ? ft_clock_wall_to_mono(q->until_wall_ns) : UINT64_MAX;
            return;
        } else {
            reply(c, FT_MSG_END, &end, sizeof(end));
        }
        break;
    }
    default:
        reply_error(c, FT_EXIT_USAGE, "Unknown query kind %u", q->kind);
        break;
    }
    free(q);
}

static void client_add(struct agent *d, int fd, bool session)
{
    if (d->nclients == MAX_CLIENTS) {
        close(fd);
        return;
    }
    struct client *c = &d->clients[d->nclients++];
    memset(c, 0, sizeof(*c));
    c->fd = fd;
    c->session = session;
    set_nonblocking(fd);
#if defined(SO_NOSIGPIPE)
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
}

static void client_drop(struct agent *d, size_t index)
{
    struct client *c = &d->clients[index];
    if (c->session)
        stop_requested = 1;
    close(c->fd);
    free(c->out);
    free(c->follow);
    d->clients[index] = d->clients[--d->nclients];
}

/* Returns false when the client is gone. */
static bool client_write(struct client *c)
{
    while (c->out_off < c->out_len) {
#if defined(MSG_NOSIGNAL)
        ssize_t n = send(c->fd, c->out + c->out_off, c->out_len - c->out_off, MSG_NOSIGNAL);
#else
        ssize_t n = write(c->fd, c->out + c->out_off, c->out_len - c->out_off);
#endif
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
        c->out_off += (size_t)n;
    }
    c->out_off = 0;
    c->out_len = 0;
    if (c->out_cap > 1024 * 1024) {
        free(c->out);
        c->out = nullptr;
        c->out_cap = 0;
    }
    return true;
}

/* Returns false when the client is gone or sent something invalid. */
static bool client_read(struct agent *d, struct client *c)
{
    for (;;) {
        ssize_t n = read(c->fd, c->in + c->in_len, sizeof(c->in) - c->in_len);
        if (n == 0)
            return false;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return errno == EAGAIN || errno == EWOULDBLOCK;
        }
        c->in_len += (size_t)n;

        while (c->in_len >= sizeof(struct ft_frame_hdr)) {
            struct ft_frame_hdr hdr;
            memcpy(&hdr, c->in, sizeof(hdr));
            if (hdr.magic != FT_WIRE_MAGIC || hdr.length > sizeof(struct ft_query))
                return false;
            size_t frame = sizeof(hdr) + hdr.length;
            if (c->in_len < frame)
                break;

            if (hdr.version != FT_WIRE_VERSION) {
                reply_error(c, FT_EXIT_ERROR,
                            "The agent speaks protocol version %u, the client %u. "
                            "Upgrade filetrace and filetrace-agent together.",
                            FT_WIRE_VERSION, hdr.version);
            } else if (hdr.type == FT_MSG_QUERY) {
                handle_query(d, c, c->in + sizeof(hdr), hdr.length);
            } else if (hdr.type == FT_MSG_SHUTDOWN) {
                struct ft_msg_end end = {0};
                reply(c, FT_MSG_END, &end, sizeof(end));
                stop_requested = 1;
            } else {
                reply_error(c, FT_EXIT_USAGE, "Unknown request type %u", hdr.type);
            }
            memmove(c->in, c->in + frame, c->in_len - frame);
            c->in_len -= frame;
        }
        if (!client_write(c))
            return false;
    }
}

static void accept_clients(struct agent *d)
{
    for (;;) {
        int fd = accept(d->listen_fd, nullptr, nullptr);
        if (fd < 0)
            return;
        if (!ft_net_peer_trusted(fd)) {
            ft_log(FT_LOG_WARN, "rejected a client that is neither root nor the agent's user");
            close(fd);
            continue;
        }
        client_add(d, fd, false);
    }
}

static int fail_session(const struct ft_agent_config *cfg, const struct ft_error *err)
{
    if (cfg->session_fd >= 0) {
        struct ft_msg_error e = {.code = (uint32_t)err->code};
        ft_strlcpy(e.msg, err->msg, sizeof(e.msg));
        ft_wire_send(cfg->session_fd, FT_MSG_ERROR, &e, sizeof(e));
        close(cfg->session_fd);
    }
    return err->code;
}

static void agent_close(struct agent *d)
{
    while (d->nclients)
        client_drop(d, d->nclients - 1);
    ft_scrape_close(d->scrape);
    ft_otlp_close(d->otlp);
    ft_api_close(d->api);
    if (d->listen_fd >= 0) {
        close(d->listen_fd);
        unlink(d->cfg->socket_path);
    }
    if (d->backend)
        d->cfg->backend->close(d->backend);
    ft_state_destroy(d->state);
    free(d->live);
    free(d);
}

static bool agent_open(struct agent *d, struct ft_error *err)
{
    const struct ft_agent_config *cfg = d->cfg;

    struct ft_state_config state_cfg = cfg->state_cfg;
    if (!state_cfg.lookup_process)
        state_cfg.lookup_process = cfg->backend->lookup_process;
    if (!state_cfg.read_process_text)
        state_cfg.read_process_text = cfg->backend->read_process_text;
    /* Names come from probes that only standard mode attaches; with none asked for, none come. */
    state_cfg.names = state_cfg.names && cfg->backend_cfg.mode == FT_MODE_STANDARD &&
                      (cfg->backend_cfg.lookup_names || cfg->backend_cfg.tls_names);
    d->state = ft_state_create(&state_cfg);
    d->live = malloc(sizeof(*d->live));
    if (!d->state || !d->live) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return false;
    }
    d->state->on_record = on_record;
    d->state->on_record_ctx = d;

    struct ft_sink sink = {.ctx = d, .emit = on_event};
    d->backend = cfg->backend->open(&cfg->backend_cfg, &sink, err);
    if (!d->backend)
        return false;

    if (cfg->socket_path) {
        d->listen_fd = open_listener(cfg->socket_path, err);
        if (d->listen_fd < 0)
            return false;
    }

    struct ft_telemetry_source src = {.state = d->state, .agent = d, .stats = fill_stats};
    struct ft_host_info host;
    ft_sysinfo_host(&host);
    ft_strlcpy(src.host, host.hostname, sizeof(src.host));

    if (cfg->prometheus.enabled) {
        d->scrape = ft_scrape_open(&cfg->prometheus, &src, err);
        if (!d->scrape)
            return false;
    }
    if (cfg->otlp.enabled && (cfg->otlp.logs || cfg->otlp.metrics)) {
        d->otlp = ft_otlp_open(&cfg->otlp, &src, err);
        if (!d->otlp)
            return false;
    }
    if (cfg->api.enabled) {
        d->api = ft_api_open(&cfg->api, &src, err);
        if (!d->api)
            return false;
    }
    return true;
}

int ft_agent_run(const struct ft_agent_config *cfg, struct ft_error *err)
{
    ft_sysinfo_small_pages();

    struct agent *d = calloc(1, sizeof(*d));
    if (!d)
        return ft_error_set(err, FT_EXIT_ERROR, "Out of memory");

    d->cfg = cfg;
    d->listen_fd = -1;
    stop_requested = 0;
    signal(SIGPIPE, SIG_IGN);

    if (!agent_open(d, err)) {
        agent_close(d);
        return fail_session(cfg, err);
    }
    if (cfg->session_fd >= 0)
        client_add(d, cfg->session_fd, true);

    uint64_t interval_ns =
        (uint64_t)(cfg->flush_interval_ms ? cfg->flush_interval_ms : 250) * FT_NS_PER_MS;
    uint64_t now_ns = ft_clock_mono_ns();
    uint64_t next_flush_ns = now_ns + interval_ns;
    int backend_fd = cfg->backend->poll_fd ? cfg->backend->poll_fd(d->backend) : -1;

    d->start_wall_ns = ft_clock_wall_ns();
    d->state->start_ns = now_ns;
    d->rate_mono_ns = now_ns;
    ft_log(FT_LOG_INFO, "collecting with the %s backend in %s mode", cfg->backend->name,
           ft_mode_name(cfg->backend_cfg.mode));

    while (!stop_requested) {
        struct ft_poller *p = &d->poller;

        ft_poller_begin(p, next_flush_ns);
        size_t listen_slot =
            d->listen_fd >= 0 ? ft_poller_add(p, d->listen_fd, POLLIN) : FT_POLLER_NONE;
        size_t backend_slot =
            backend_fd >= 0 ? ft_poller_add(p, backend_fd, POLLIN) : FT_POLLER_NONE;
        size_t first_client = p->count;
        for (size_t i = 0; i < d->nclients; i++)
            ft_poller_add(p, d->clients[i].fd, d->clients[i].out_len ? POLLIN | POLLOUT : POLLIN);
        ft_scrape_poll(d->scrape, p);
        ft_otlp_poll(d->otlp, p);
        ft_api_poll(d->api, p);

        int ready = ft_poller_wait(p, ft_clock_mono_ns());
        if (ready < 0 && errno != EINTR) {
            ft_log(FT_LOG_ERROR, "poll failed: %s", strerror(errno));
            break;
        }

        now_ns = ft_clock_mono_ns();
        bool backend_ready = ready > 0 && (ft_poller_revents(p, backend_slot) & POLLIN);
        if (now_ns >= next_flush_ns || backend_ready) {
            cfg->backend->flush(d->backend);
            if (now_ns - d->rate_mono_ns >= RATE_WINDOW_NS) {
                sample_rates(d, now_ns);
                ft_state_sweep(d->state, now_ns);
            }
            if (now_ns >= next_flush_ns)
                next_flush_ns = now_ns + interval_ns;
        }
        if (ready < 0)
            continue;

        /* Dropping a client moves the last one into its place, so walk backwards. */
        for (size_t i = d->nclients; i-- > 0;) {
            short revents = ft_poller_revents(p, first_client + i);
            struct client *c = &d->clients[i];
            bool alive = true;

            if (revents & POLLOUT)
                alive = client_write(c);
            if (alive && (revents & (POLLIN | POLLHUP | POLLERR)))
                alive = client_read(d, c);
            if (!alive)
                client_drop(d, i);
        }
        if (ft_poller_revents(p, listen_slot) & POLLIN)
            accept_clients(d);
        ft_scrape_dispatch(d->scrape, p, now_ns);
        ft_otlp_dispatch(d->otlp, p, now_ns);
        ft_api_dispatch(d->api, p);
    }

    ft_log(FT_LOG_INFO, "stopping");
    agent_close(d);
    return FT_EXIT_OK;
}
