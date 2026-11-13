#include "ui/top/source.h"

#include "filetrace/clock.h"
#include "unit/test.h"

#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* What the fake agent answers with; a row echoes a field of the query it answers. */
constexpr uint64_t FAKE_TRANSFER_BASE = 10;
constexpr uint32_t FAKE_TRANSFERS = 2;
constexpr uint32_t FAKE_PROCESSES = 3;
constexpr uint64_t FAKE_ACTIVE = 42;
constexpr uint64_t FAKE_LOST = 7;
constexpr uint32_t FAKE_EVENTS = 3;
constexpr size_t SEEN_MAX = 64;

struct seen {
    uint16_t kind;
    uint16_t sort;
    uint32_t flags;
    uint32_t limit;
    uint32_t pid;
    uint8_t window;
    uint8_t leader_key;
    uint8_t method;
    uint64_t min_bytes;
    struct ft_endpoint remote;
    char script[32];
    char path[32];
    char remote_name[32];
};

struct fake {
    int listener;
    char dir[64];
    char path[96];
    pthread_t thread;
    atomic_bool quit;
    atomic_bool unknown_leaders; /* leaders queries get "Unknown query kind" */
    atomic_bool silent;          /* queries are read and never answered */
    atomic_bool drop;            /* the next query closes the connection */
    atomic_bool wrong_version;   /* the next answer is framed for another protocol version */
    pthread_mutex_t lock;
    struct seen log[SEEN_MAX];
    size_t logged;
};

static bool read_exact(struct fake *fake, int fd, void *buf, size_t size)
{
    unsigned char *p = buf;

    while (size > 0) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (atomic_load(&fake->quit))
            return false;
        if (poll(&pfd, 1, 20) <= 0)
            continue;
        ssize_t n = read(fd, p, size);
        if (n <= 0)
            return false;
        p += n;
        size -= (size_t)n;
    }
    return true;
}

static void send_end(int fd, uint32_t rows, uint64_t lost)
{
    struct ft_msg_end end = {.rows = rows, .lost_events = lost};
    ft_wire_send(fd, FT_MSG_END, &end, sizeof(end));
}

/* How many rows each key gets; the lifetime ranking of destinations gets FAKE_TOTALS. */
static const uint32_t leader_rows[FT_LEADER_KEY_COUNT] = {5, 2, 4, 3};
constexpr uint32_t FAKE_TOTALS = 6;

static void send_leaders(int fd, const struct ft_query *q)
{
    struct ft_row_leader_summary summary = {
        .window_ns = q->window,
        .transfers = q->limit,
        .bytes = q->sort,
    };
    struct ft_row_leader *row = calloc(1, sizeof(*row));
    uint32_t rows = leader_rows[q->leader_key % FT_LEADER_KEY_COUNT];

    if (!row)
        return;
    if (q->window == FT_WINDOW_LIFETIME && q->leader_key == FT_LEADER_DESTINATION)
        rows = FAKE_TOTALS;
    ft_wire_send(fd, FT_MSG_ROW_LEADER_SUMMARY, &summary, sizeof(summary));
    /* A row tells which query it answers: its bytes are the key times a hundred plus its place. */
    for (uint32_t i = 0; i < rows; i++) {
        row->bytes = (uint64_t)q->leader_key * 100 + i;
        row->rank = i + 1;
        ft_wire_send(fd, FT_MSG_ROW_LEADER, row, sizeof(*row));
    }
    send_end(fd, rows, 0);
    free(row);
}

static void answer(struct fake *fake, int fd, const struct ft_query *q)
{
    if (atomic_exchange(&fake->wrong_version, false)) {
        struct ft_frame_hdr hdr = {
            .magic = FT_WIRE_MAGIC, .version = FT_WIRE_VERSION + 1, .type = FT_MSG_END};
        ssize_t n = write(fd, &hdr, sizeof(hdr));
        (void)n;
        return;
    }
    switch (q->kind) {
    case FT_Q_STATS: {
        struct ft_row_stats stats = {.active_transfers = FAKE_ACTIVE, .tx_rate = q->pid};
        ft_wire_send(fd, FT_MSG_ROW_STATS, &stats, sizeof(stats));
        send_end(fd, 1, 0);
        break;
    }
    case FT_Q_TRANSFERS: {
        struct ft_row_transfer *row = calloc(1, sizeof(*row));
        if (!row)
            return;
        for (uint32_t i = 0; i < FAKE_TRANSFERS; i++) {
            row->id = FAKE_TRANSFER_BASE + i;
            row->pid = q->pid;
            ft_wire_send(fd, FT_MSG_ROW_TRANSFER, row, sizeof(*row));
        }
        send_end(fd, FAKE_TRANSFERS, FAKE_LOST);
        free(row);
        break;
    }
    case FT_Q_PROCESSES: {
        struct ft_row_process *row = calloc(1, sizeof(*row));
        if (!row)
            return;
        for (uint32_t i = 0; i < FAKE_PROCESSES; i++) {
            row->pid = 100 * (i + 1);
            row->ppid = q->pid;
            ft_wire_send(fd, FT_MSG_ROW_PROCESS, row, sizeof(*row));
        }
        send_end(fd, FAKE_PROCESSES, 0);
        free(row);
        break;
    }
    case FT_Q_EVENTS: {
        struct ft_row_event *row = calloc(1, sizeof(*row));
        if (!row)
            return;
        for (uint32_t i = 0; i < FAKE_EVENTS; i++) {
            row->seq = i + 1;
            row->pid = q->pid;
            row->type = FT_REC_FILE_TRANSFER;
            ft_wire_send(fd, FT_MSG_ROW_EVENT, row, ft_row_event_size(row));
        }
        send_end(fd, FAKE_EVENTS, 0);
        free(row);
        break;
    }
    case FT_Q_LEADERS:
        if (atomic_load(&fake->unknown_leaders)) {
            struct ft_msg_error e = {.code = FT_EXIT_USAGE};
            snprintf(e.msg, sizeof(e.msg), "Unknown query kind %u", q->kind);
            ft_wire_send(fd, FT_MSG_ERROR, &e, sizeof(e));
        } else {
            send_leaders(fd, q);
        }
        break;
    default:
        break;
    }
}

static void note(struct fake *fake, const struct ft_query *q)
{
    pthread_mutex_lock(&fake->lock);
    if (fake->logged < SEEN_MAX) {
        struct seen *s = &fake->log[fake->logged];
        *s = (struct seen){.kind = q->kind,
                           .sort = q->sort,
                           .flags = q->flags,
                           .limit = q->limit,
                           .pid = q->pid,
                           .window = q->window,
                           .leader_key = q->leader_key,
                           .method = q->method,
                           .min_bytes = q->min_bytes,
                           .remote = q->remote};
        memcpy(s->script, q->script, sizeof(s->script) - 1);
        memcpy(s->path, q->path, sizeof(s->path) - 1);
        memcpy(s->remote_name, q->remote_name, sizeof(s->remote_name) - 1);
    }
    fake->logged++;
    pthread_mutex_unlock(&fake->lock);
}

static void serve(struct fake *fake, int fd)
{
    struct ft_query *q = calloc(1, sizeof(*q));
    unsigned char *payload = malloc(FT_WIRE_MAX_PAYLOAD);

    while (q && payload) {
        struct ft_frame_hdr hdr;
        if (!read_exact(fake, fd, &hdr, sizeof(hdr)) || hdr.length > FT_WIRE_MAX_PAYLOAD ||
            !read_exact(fake, fd, payload, hdr.length))
            break;
        if (hdr.type != FT_MSG_QUERY)
            continue;
        memset(q, 0, sizeof(*q));
        memcpy(q, payload, hdr.length < sizeof(*q) ? hdr.length : sizeof(*q));
        note(fake, q);
        if (atomic_exchange(&fake->drop, false))
            break;
        if (!atomic_load(&fake->silent))
            answer(fake, fd, q);
    }
    free(q);
    free(payload);
}

static void *fake_main(void *arg)
{
    struct fake *fake = arg;

    while (!atomic_load(&fake->quit)) {
        struct pollfd pfd = {.fd = fake->listener, .events = POLLIN};
        if (poll(&pfd, 1, 20) <= 0)
            continue;
        int fd = accept(fake->listener, nullptr, nullptr);
        if (fd < 0)
            continue;
#if defined(SO_NOSIGPIPE)
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));
#endif
        serve(fake, fd);
        close(fd);
    }
    return nullptr;
}

static bool fake_start(struct fake *fake)
{
    struct sockaddr_un addr = {.sun_family = AF_UNIX};

    memset(fake, 0, sizeof(*fake));
    pthread_mutex_init(&fake->lock, nullptr);
    snprintf(fake->dir, sizeof(fake->dir), "/tmp/ft_top_source.XXXXXX");
    if (!mkdtemp(fake->dir))
        return false;
    snprintf(fake->path, sizeof(fake->path), "%s/agent.sock", fake->dir);
    ft_strlcpy(addr.sun_path, fake->path, sizeof(addr.sun_path));
    fake->listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fake->listener < 0 || bind(fake->listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(fake->listener, 4) != 0)
        return false;
    return pthread_create(&fake->thread, nullptr, fake_main, fake) == 0;
}

static void fake_stop(struct fake *fake)
{
    atomic_store(&fake->quit, true);
    pthread_join(fake->thread, nullptr);
    close(fake->listener);
    unlink(fake->path);
    rmdir(fake->dir);
    pthread_mutex_destroy(&fake->lock);
}

static size_t fake_logged(struct fake *fake)
{
    pthread_mutex_lock(&fake->lock);
    size_t n = fake->logged;
    pthread_mutex_unlock(&fake->lock);
    return n;
}

static struct seen fake_seen(struct fake *fake, size_t i)
{
    pthread_mutex_lock(&fake->lock);
    struct seen s = fake->log[i];
    pthread_mutex_unlock(&fake->lock);
    return s;
}

/* Whether the fake has read at least n queries by the time the timeout ends. */
static bool fake_reached(struct fake *fake, size_t n, int timeout_ms)
{
    for (int waited = 0; waited <= timeout_ms; waited += 5) {
        if (fake_logged(fake) >= n)
            return true;
        usleep(5000);
    }
    return false;
}

struct rig {
    struct fake fake;
    struct ft_cli cli;
    struct ft_session session;
    struct ft_top_source *source;
    struct ft_top_frame frame;
};

/* With a delay of five seconds the refreshes are the first and one per request. */
static void rig_request(struct ft_top_request *req)
{
    ft_top_request_init(req);
    req->delay_ns = 5 * FT_NS_PER_SEC;
    req->live = true;
}

/* The fake agent is listening and the session is connected to it; the source is not running. */
static bool rig_open(struct rig *rig)
{
    struct ft_error err = {0};

    memset(rig, 0, sizeof(*rig));
    ft_top_frame_init(&rig->frame);
    if (!fake_start(&rig->fake))
        return false;
    rig->cli.socket_path = rig->fake.path;
    rig->session.client = ft_client_connect(rig->fake.path, &err);
    return rig->session.client != nullptr;
}

static bool rig_run(struct rig *rig, const struct ft_top_request *first)
{
    struct ft_error err = {0};

    rig->source = ft_top_source_start(&rig->session, &rig->cli, first, &err);
    return rig->source != nullptr;
}

static bool rig_start(struct rig *rig, const struct ft_top_request *first)
{
    return rig_open(rig) && rig_run(rig, first);
}

static uint64_t rig_stop(struct rig *rig)
{
    uint64_t began = ft_clock_mono_ns();

    ft_top_source_stop(rig->source);
    uint64_t took = ft_clock_mono_ns() - began;
    ft_session_close(&rig->session);
    fake_stop(&rig->fake);
    ft_top_frame_free(&rig->frame);
    return took;
}

static bool readable(int fd, int timeout_ms)
{
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    return poll(&pfd, 1, timeout_ms) == 1 && (pfd.revents & POLLIN) != 0;
}

static bool rig_take(struct rig *rig, int timeout_ms)
{
    return readable(ft_top_source_fd(rig->source), timeout_ms) &&
           ft_top_source_take(rig->source, &rig->frame);
}

static uint64_t transfer_id(const struct ft_top_frame *frame, size_t i)
{
    struct ft_row_transfer *row = malloc(sizeof(*row));
    uint64_t id = 0;

    if (row) {
        ft_rows_get(&frame->transfers, i, row, sizeof(*row));
        id = row->id;
    }
    free(row);
    return id;
}

static uint32_t transfer_pid(const struct ft_top_frame *frame, size_t i)
{
    struct ft_row_transfer *row = malloc(sizeof(*row));
    uint32_t pid = 0;

    if (row) {
        ft_rows_get(&frame->transfers, i, row, sizeof(*row));
        pid = row->pid;
    }
    free(row);
    return pid;
}

static uint64_t leader_bytes(const struct ft_rows *rows, size_t i)
{
    struct ft_row_leader *row = malloc(sizeof(*row));
    uint64_t bytes = 0;

    if (row) {
        ft_rows_get(rows, i, row, sizeof(*row));
        bytes = row->bytes;
    }
    free(row);
    return bytes;
}

static void check_rows_and_order(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    req.totals = true;
    req.leaders = true;
    req.window = FT_WINDOW_24H;
    req.key = FT_LEADER_EXTENSION;
    req.by = FT_SORT_TRANSFERS;
    req.limit = 9;
    ft_strlcpy(req.leader_path, "/srv/*", sizeof(req.leader_path));
    req.scope.pid = 77;
    req.scope.method = FT_METHOD_SENDFILE;
    ft_strlcpy(req.scope.script, "pool:*", sizeof(req.scope.script));
    ft_strlcpy(req.scope.remote_name, "*.example.com", sizeof(req.scope.remote_name));

    CHECK(rig_start(&rig, &req));
    CHECK(rig_take(&rig, 2000));
    struct ft_top_frame *f = &rig.frame;

    CHECK_U64(f->serial, 1);
    CHECK_U64(f->request_serial, 1);
    CHECK_U64(f->code, FT_EXIT_OK);
    CHECK(f->wall_ns > 0 && f->mono_ns > 0 && f->took_ns > 0);
    CHECK_U64(f->stats.active_transfers, FAKE_ACTIVE);
    CHECK_U64(f->transfers.count, FAKE_TRANSFERS);
    CHECK_U64(transfer_id(f, 0), FAKE_TRANSFER_BASE);
    CHECK_U64(transfer_id(f, 1), FAKE_TRANSFER_BASE + 1);
    CHECK_U64(transfer_pid(f, 0), 77);
    CHECK_U64(f->end.lost_events, FAKE_LOST);
    CHECK_U64(f->processes.count, FAKE_PROCESSES);

    CHECK(f->has_totals);
    CHECK_U64(f->destination_totals.count, FAKE_TOTALS);
    CHECK_U64(leader_bytes(&f->destination_totals, 0), FT_LEADER_DESTINATION * 100);

    CHECK(f->has_leaders);
    CHECK_U64(f->leader_summary.window_ns, FT_WINDOW_24H);
    CHECK_U64(f->leader_summary.transfers, 9);
    CHECK_U64(f->leader_summary.bytes, FT_SORT_TRANSFERS);
    CHECK_U64(f->leaders.count, leader_rows[FT_LEADER_EXTENSION]);
    CHECK_U64(leader_bytes(&f->leaders, 3), FT_LEADER_EXTENSION * 100 + 3);
    CHECK_U64(f->leader_directories.count, leader_rows[FT_LEADER_DIRECTORY]);
    CHECK_U64(leader_bytes(&f->leader_directories, 1), FT_LEADER_DIRECTORY * 100 + 1);
    CHECK_U64(f->leader_destinations.count, leader_rows[FT_LEADER_DESTINATION]);

    /* The fd is readable exactly while a frame waits. */
    CHECK(!readable(ft_top_source_fd(rig.source), 0));
    CHECK(!ft_top_source_take(rig.source, f));

    CHECK(fake_reached(&rig.fake, 7, 1000));
    enum ft_query_kind order[] = {FT_Q_STATS,   FT_Q_TRANSFERS, FT_Q_PROCESSES, FT_Q_LEADERS,
                                  FT_Q_LEADERS, FT_Q_LEADERS,   FT_Q_LEADERS};
    for (size_t i = 0; i < FT_ARRAY_LEN(order); i++)
        CHECK_U64(fake_seen(&rig.fake, i).kind, order[i]);

    struct seen transfers = fake_seen(&rig.fake, 1);
    CHECK(transfers.flags & FT_QF_ACTIVE);
    CHECK_U64(transfers.limit, 0);
    CHECK_U64(transfers.pid, 77);
    CHECK_U64(transfers.method, FT_METHOD_SENDFILE);
    CHECK_STR(transfers.script, "pool:*");
    CHECK_STR(transfers.remote_name, "*.example.com");

    struct seen processes = fake_seen(&rig.fake, 2);
    CHECK_U64(processes.limit, 0);
    CHECK_U64(processes.min_bytes, 0);
    CHECK(!(processes.flags & FT_QF_INCLUDE_CHILDREN));
    CHECK(processes.flags & FT_QF_INCLUDE_IDLE);
    CHECK_U64(processes.pid, 77);
    CHECK_U64(processes.method, FT_METHOD_ANY);

    struct seen totals = fake_seen(&rig.fake, 3);
    CHECK_U64(totals.window, FT_WINDOW_LIFETIME);
    CHECK_U64(totals.leader_key, FT_LEADER_DESTINATION);
    CHECK_U64(totals.limit, 1000);

    struct seen ranking = fake_seen(&rig.fake, 4);
    CHECK_U64(ranking.window, FT_WINDOW_24H);
    CHECK_U64(ranking.leader_key, FT_LEADER_EXTENSION);
    CHECK_U64(ranking.sort, FT_SORT_TRANSFERS);
    CHECK_U64(ranking.limit, 9);
    CHECK_STR(ranking.path, "/srv/*");

    struct seen directories = fake_seen(&rig.fake, 5);
    CHECK_U64(directories.leader_key, FT_LEADER_DIRECTORY);
    CHECK_U64(directories.limit, 7);
    CHECK_U64(directories.window, FT_WINDOW_24H);
    struct seen destinations = fake_seen(&rig.fake, 6);
    CHECK_U64(destinations.leader_key, FT_LEADER_DESTINATION);
    CHECK_U64(destinations.limit, 7);
    CHECK_U64(destinations.window, FT_WINDOW_24H);

    rig_stop(&rig);
}

static void check_newest_frame_wins(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    req.scope.pid = 111;
    CHECK(rig_start(&rig, &req));
    CHECK(readable(ft_top_source_fd(rig.source), 2000));

    /* The first frame is still waiting when two more refreshes are asked for. */
    req.scope.pid = 222;
    CHECK_U64(ft_top_source_request(rig.source, &req), 2);
    req.scope.pid = 333;
    CHECK_U64(ft_top_source_request(rig.source, &req), 3);
    for (int i = 0; i < 400; i++) {
        struct seen last = fake_seen(&rig.fake, fake_logged(&rig.fake) - 1);
        if (last.kind == FT_Q_PROCESSES && last.pid == 333)
            break;
        usleep(5000);
    }
    usleep(100 * 1000);

    CHECK(ft_top_source_take(rig.source, &rig.frame));
    CHECK_U64(rig.frame.request_serial, 3);
    CHECK(rig.frame.serial >= 2);
    CHECK_U64(transfer_pid(&rig.frame, 0), 333);
    CHECK(!ft_top_source_take(rig.source, &rig.frame));
    rig_stop(&rig);
}

static void check_totals_survive_a_dropped_frame(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    req.totals = true;
    CHECK(rig_start(&rig, &req));
    CHECK(readable(ft_top_source_fd(rig.source), 2000));

    /* The second refresh does not ask for the totals again; it replaces the first frame unread. */
    ft_top_source_request(rig.source, &req);
    CHECK(fake_reached(&rig.fake, 4 + 3, 2000));
    usleep(100 * 1000);

    CHECK(ft_top_source_take(rig.source, &rig.frame));
    CHECK_U64(rig.frame.serial, 2);
    CHECK(rig.frame.has_totals);
    CHECK_U64(rig.frame.destination_totals.count, FAKE_TOTALS);
    CHECK_U64(fake_logged(&rig.fake), 4 + 3);
    rig_stop(&rig);
}

static void check_request_refreshes_at_once(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    CHECK(rig_start(&rig, &req));
    CHECK(rig_take(&rig, 2000));

    req.leaders = true;
    req.window = FT_WINDOW_5M;
    uint64_t serial = ft_top_source_request(rig.source, &req);
    CHECK_U64(serial, 2);

    /* The delay is five seconds; the answer comes long before it. */
    CHECK(rig_take(&rig, 1000));
    CHECK_U64(rig.frame.request_serial, serial);
    CHECK_U64(rig.frame.serial, 2);
    CHECK(rig.frame.has_leaders);
    CHECK_U64(rig.frame.leader_summary.window_ns, FT_WINDOW_5M);
    CHECK(!rig.frame.has_totals);
    rig_stop(&rig);
}

static void check_agent_without_leaders(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    req.totals = true;
    req.leaders = true;
    CHECK(rig_open(&rig));
    atomic_store(&rig.fake.unknown_leaders, true);
    CHECK(rig_run(&rig, &req));
    CHECK(rig_take(&rig, 2000));

    CHECK_U64(rig.frame.code, FT_EXIT_OK);
    CHECK_STR(rig.frame.error, "");
    CHECK(!rig.frame.has_leaders);
    CHECK(!rig.frame.has_totals);
    CHECK_U64(rig.frame.leaders.count, 0);
    CHECK_U64(rig.frame.leader_directories.count, 0);
    CHECK_U64(rig.frame.transfers.count, FAKE_TRANSFERS);
    CHECK_U64(rig.frame.processes.count, FAKE_PROCESSES);

    /* The agent has said once that it lacks them; it is not asked again. */
    size_t before = fake_logged(&rig.fake);
    ft_top_source_request(rig.source, &req);
    CHECK(rig_take(&rig, 1000));
    CHECK_U64(fake_logged(&rig.fake) - before, 3);
    rig_stop(&rig);
}

static uint64_t event_seq(const struct ft_top_frame *frame, size_t i)
{
    struct ft_row_event *row = malloc(sizeof(*row));
    uint64_t seq = 0;

    if (row) {
        ft_rows_get(&frame->events, i, row, sizeof(*row));
        seq = row->seq;
    }
    free(row);
    return seq;
}

static void check_events_once_per_request(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    req.delay_ns = 100 * FT_NS_PER_MS;
    CHECK(rig_start(&rig, &req));
    CHECK(rig_take(&rig, 2000));
    CHECK(!rig.frame.has_events);

    req.events = true;
    req.events_pid = 4242;
    CHECK(ft_addr_parse("192.0.2.9", &req.events_remote));
    req.events_remote.port = 443;
    ft_strlcpy(req.events_path, "/srv/*.pdf", sizeof(req.events_path));
    uint64_t serial = ft_top_source_request(rig.source, &req);
    bool answered = false;
    for (int i = 0; i < 10 && !answered; i++)
        answered = rig_take(&rig, 2000) && rig.frame.request_serial == serial;
    CHECK(answered);
    CHECK(rig.frame.has_events);
    CHECK_U64(rig.frame.events.count, FAKE_EVENTS);
    CHECK_U64(event_seq(&rig.frame, 0), 1);
    CHECK_U64(event_seq(&rig.frame, FAKE_EVENTS - 1), FAKE_EVENTS);

    size_t asked = 0;
    for (size_t i = 0; i < fake_logged(&rig.fake) && i < SEEN_MAX; i++) {
        struct seen s = fake_seen(&rig.fake, i);
        if (s.kind != FT_Q_EVENTS)
            continue;
        asked++;
        CHECK_U64(s.limit, FT_TOP_EVENTS_LIMIT);
        CHECK_U64(s.pid, 4242);
        CHECK_U64(s.remote.family, 4);
        CHECK_U64(s.remote.port, 0);
        CHECK_STR(s.path, "/srv/*.pdf");
    }
    CHECK_U64(asked, 1);

    /* The refreshes that follow under the same request do not ask again. */
    CHECK(rig_take(&rig, 2000));
    CHECK_U64(rig.frame.request_serial, serial);
    CHECK(!rig.frame.has_events);
    CHECK_U64(rig.frame.events.count, 0);
    rig_stop(&rig);
}

static void check_events_stay_out_of_a_failed_frame(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    req.events = true;
    req.events_pid = 111;
    CHECK(rig_start(&rig, &req));
    CHECK(readable(ft_top_source_fd(rig.source), 2000));

    /* The refresh for another process fails and replaces the unread frame with its events. */
    atomic_store(&rig.fake.drop, true);
    req.events_pid = 222;
    uint64_t serial = ft_top_source_request(rig.source, &req);
    CHECK(fake_reached(&rig.fake, 4 + 1, 2000));
    usleep(100 * 1000);

    CHECK(ft_top_source_take(rig.source, &rig.frame));
    CHECK_U64(rig.frame.request_serial, serial);
    CHECK(rig.frame.code != FT_EXIT_OK);
    CHECK(!rig.frame.has_events);
    CHECK_U64(rig.frame.events.count, 0);
    rig_stop(&rig);
}

static void check_lost_agent(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    CHECK(rig_start(&rig, &req));
    CHECK(rig_take(&rig, 2000));
    CHECK_U64(rig.frame.code, FT_EXIT_OK);

    atomic_store(&rig.fake.drop, true);
    ft_top_source_request(rig.source, &req);
    CHECK(rig_take(&rig, 2000));
    CHECK(rig.frame.code != FT_EXIT_OK);
    CHECK(rig.frame.error[0] != '\0');
    CHECK_U64(rig.frame.transfers.count, 0);
    CHECK_U64(rig.frame.processes.count, 0);
    CHECK_U64(rig.frame.stats.active_transfers, 0);

    /* The agent listens again; the source connects to it before the next refresh. */
    ft_top_source_request(rig.source, &req);
    CHECK(rig_take(&rig, 2000));
    CHECK_U64(rig.frame.code, FT_EXIT_OK);
    CHECK_U64(rig.frame.transfers.count, FAKE_TRANSFERS);

    CHECK(rig_stop(&rig) < 200 * FT_NS_PER_MS);
}

static void check_protocol_mismatch(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    CHECK(rig_start(&rig, &req));
    CHECK(rig_take(&rig, 2000));

    atomic_store(&rig.fake.wrong_version, true);
    ft_top_source_request(rig.source, &req);
    CHECK(rig_take(&rig, 2000));
    CHECK(rig.frame.code != FT_EXIT_OK);
    CHECK(strstr(rig.frame.error, "Upgrade") != nullptr);

    ft_top_source_request(rig.source, &req);
    CHECK(rig_take(&rig, 2000));
    CHECK_U64(rig.frame.code, FT_EXIT_OK);
    rig_stop(&rig);
}

static void check_stop_during_a_wait(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    CHECK(rig_start(&rig, &req));
    CHECK(rig_take(&rig, 2000));
    CHECK(rig_stop(&rig) < 200 * FT_NS_PER_MS);
}

static void check_stop_while_the_agent_is_silent(void)
{
    struct rig rig;
    struct ft_top_request req;

    rig_request(&req);
    CHECK(rig_start(&rig, &req));
    CHECK(rig_take(&rig, 2000));

    atomic_store(&rig.fake.silent, true);
    size_t before = fake_logged(&rig.fake);
    ft_top_source_request(rig.source, &req);
    CHECK(fake_reached(&rig.fake, before + 1, 2000));
    CHECK(rig_stop(&rig) < 1000 * FT_NS_PER_MS);
}

void test_top_source(void)
{
    check_rows_and_order();
    check_newest_frame_wins();
    check_totals_survive_a_dropped_frame();
    check_request_refreshes_at_once();
    check_agent_without_leaders();
    check_events_once_per_request();
    check_events_stay_out_of_a_failed_frame();
    check_lost_agent();
    check_protocol_mismatch();
    check_stop_during_a_wait();
    check_stop_while_the_agent_is_silent();
}
