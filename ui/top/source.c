#include "ui/top/source.h"

#include "filetrace/clock.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

constexpr uint32_t TOTALS_EVERY = 5;
constexpr uint32_t TOTALS_LIMIT = 1000;
constexpr uint32_t SIDE_LIMIT = 7;
constexpr uint64_t MIN_DELAY_NS = FT_NS_PER_MS; /* a request without a delay must not spin */

struct ft_top_source {
    struct ft_session *session;
    const struct ft_cli *cli;
    pthread_t thread;
    int frame_pipe[2]; /* a byte while a frame waits; read by the caller */
    int wake_pipe[2];  /* a byte when the thread has to look at the request or the flag */
    volatile sig_atomic_t stop;

    pthread_mutex_t lock;
    struct ft_top_request request;
    uint64_t request_serial;
    struct ft_top_frame ready;
    bool ready_valid;
    bool notified; /* frame_pipe holds its byte */

    /* Used by the thread alone. */
    struct ft_top_frame work;
    struct ft_top_request current;
    struct ft_query *query;
    uint64_t frames;
    uint32_t since_totals;
    bool totals_known;
    bool agent_lost;        /* the connection is closed; the next refresh connects again */
    bool no_leaders;        /* the agent does not know the leaders queries */
    uint64_t serving;       /* the serial of the request being answered */
    uint64_t events_served; /* the serial of the request whose events were fetched */
};

void ft_top_request_init(struct ft_top_request *req)
{
    memset(req, 0, sizeof(*req));
    ft_query_init(&req->scope, FT_Q_TRANSFERS);
    req->delay_ns = FT_NS_PER_SEC;
    req->window = FT_WINDOW_1H;
    req->key = FT_LEADER_FILE;
    req->by = FT_SORT_BYTES;
    req->limit = 50;
}

void ft_top_frame_init(struct ft_top_frame *frame)
{
    memset(frame, 0, sizeof(*frame));
    ft_rows_init(&frame->transfers, FT_MSG_ROW_TRANSFER);
    ft_rows_init(&frame->processes, FT_MSG_ROW_PROCESS);
    ft_rows_init(&frame->destination_totals, FT_MSG_ROW_LEADER);
    ft_rows_init(&frame->leaders, FT_MSG_ROW_LEADER);
    ft_rows_init(&frame->leader_directories, FT_MSG_ROW_LEADER);
    ft_rows_init(&frame->leader_destinations, FT_MSG_ROW_LEADER);
    ft_rows_init(&frame->events, FT_MSG_ROW_EVENT);
}

void ft_top_frame_free(struct ft_top_frame *frame)
{
    ft_rows_free(&frame->transfers);
    ft_rows_free(&frame->processes);
    ft_rows_free(&frame->destination_totals);
    ft_rows_free(&frame->leaders);
    ft_rows_free(&frame->leader_directories);
    ft_rows_free(&frame->leader_destinations);
    ft_rows_free(&frame->events);
}

/* Empties a frame but keeps its buffers. */
static void frame_clear(struct ft_top_frame *f)
{
    ft_rows_clear(&f->transfers);
    ft_rows_clear(&f->processes);
    ft_rows_clear(&f->destination_totals);
    ft_rows_clear(&f->leaders);
    ft_rows_clear(&f->leader_directories);
    ft_rows_clear(&f->leader_destinations);
    ft_rows_clear(&f->events);
    f->code = FT_EXIT_OK;
    f->error[0] = '\0';
    f->has_totals = false;
    f->has_leaders = false;
    f->has_events = false;
    memset(&f->stats, 0, sizeof(f->stats));
    memset(&f->end, 0, sizeof(f->end));
    memset(&f->leader_summary, 0, sizeof(f->leader_summary));
}

static void frame_swap(struct ft_top_frame *a, struct ft_top_frame *b)
{
    struct ft_top_frame t = *a;
    *a = *b;
    *b = t;
}

static void wake(struct ft_top_source *src)
{
    /* A full pipe already holds a wake-up. */
    ssize_t n = write(src->wake_pipe[1], "x", 1);
    (void)n;
}

static void drain(int fd)
{
    char buf[16];
    while (read(fd, buf, sizeof(buf)) > 0)
        continue;
}

static bool make_pipe(int fds[2])
{
    if (pipe(fds) != 0)
        return false;
    for (int i = 0; i < 2; i++) {
        if (fcntl(fds[i], F_SETFL, fcntl(fds[i], F_GETFL) | O_NONBLOCK) != 0 ||
            fcntl(fds[i], F_SETFD, FD_CLOEXEC) != 0) {
            close(fds[0]);
            close(fds[1]);
            fds[0] = fds[1] = -1;
            return false;
        }
    }
    return true;
}

/* Where the rows of one answer go; the statistics and the summary are single rows. */
struct sink {
    struct ft_rows *rows;
    struct ft_row_stats *stats;
    struct ft_row_leader_summary *summary;
    bool full;
};

static void keep_row(void *dst, size_t dst_size, const void *payload, size_t size)
{
    memset(dst, 0, dst_size);
    memcpy(dst, payload, size < dst_size ? size : dst_size);
}

static void keep_stats(struct ft_row_stats *st, const void *payload, size_t size)
{
    keep_row(st, sizeof(*st), payload, size);
    st->backend[sizeof(st->backend) - 1] = '\0';
    st->mode[sizeof(st->mode) - 1] = '\0';
    st->version[sizeof(st->version) - 1] = '\0';
}

static void on_row(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct sink *sink = ctx;

    if (sink->rows && type == sink->rows->type) {
        if (!ft_rows_append(sink->rows, payload, size))
            sink->full = true;
    } else if (sink->stats && type == FT_MSG_ROW_STATS) {
        keep_stats(sink->stats, payload, size);
    } else if (sink->summary && type == FT_MSG_ROW_LEADER_SUMMARY) {
        keep_row(sink->summary, sizeof(*sink->summary), payload, size);
    }
}

static int ask(struct ft_top_source *src, const struct sink *wanted, struct ft_msg_end *end,
               struct ft_error *err)
{
    struct sink sink = *wanted;
    int code = ft_client_query(src->session->client, src->query, on_row, &sink, end, err);

    if (code == FT_EXIT_OK && sink.full)
        code = ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
    return code;
}

/* dst is zeroed, so the copy ends with a terminator even when src has none. */
static void copy_text(char *dst, size_t dst_size, const char *src, size_t src_size)
{
    memcpy(dst, src, strnlen(src, src_size < dst_size ? src_size : dst_size - 1));
}

/* A scope that was never initialised, with kind 0, selects everything. */
static void scope_process(struct ft_query *q, const struct ft_query *scope)
{
    if (scope->kind == 0)
        return;
    q->pid = scope->pid;
    q->uid = scope->uid;
    q->flags |= scope->flags & FT_QF_HAS_UID;
    q->cgroup_id = scope->cgroup_id;
    q->ns_inum = scope->ns_inum;
    copy_text(q->process, sizeof(q->process), scope->process, sizeof(scope->process));
    copy_text(q->script, sizeof(q->script), scope->script, sizeof(scope->script));
}

static void scope_transfer(struct ft_query *q, const struct ft_query *scope)
{
    if (scope->kind == 0)
        return;
    scope_process(q, scope);
    q->remote = scope->remote;
    q->remote_host_bits = scope->remote_host_bits;
    q->method = scope->method;
    q->confidence = scope->confidence;
}

static int fetch_live(struct ft_top_source *src, struct ft_error *err)
{
    struct ft_top_frame *f = &src->work;
    struct ft_query *q = src->query;
    const struct ft_query *scope = &src->current.scope;
    int code;

    ft_query_init(q, FT_Q_STATS);
    code = ask(src, &(struct sink){.stats = &f->stats}, nullptr, err);
    if (code != FT_EXIT_OK || src->stop)
        return code;

    ft_query_init(q, FT_Q_TRANSFERS);
    q->flags |= FT_QF_ACTIVE;
    scope_transfer(q, scope);
    code = ask(src, &(struct sink){.rows = &f->transfers}, &f->end, err);
    if (code != FT_EXIT_OK || src->stop)
        return code;

    /* No limit, no minimum and no FT_QF_INCLUDE_CHILDREN: a row holds one process's own figures. */
    ft_query_init(q, FT_Q_PROCESSES);
    q->flags |= FT_QF_INCLUDE_IDLE;
    scope_process(q, scope);
    return ask(src, &(struct sink){.rows = &f->processes}, nullptr, err);
}

static bool unknown_query(const struct ft_error *err)
{
    static const char text[] = "Unknown query kind";
    return err->code == FT_EXIT_USAGE && strncmp(err->msg, text, sizeof(text) - 1) == 0;
}

/* An agent without the leaders queries has no data to give, which is not a failure. */
static int leaders_answer(struct ft_top_source *src, int code, const struct ft_error *err)
{
    if (code == FT_EXIT_OK || !unknown_query(err))
        return code;
    src->no_leaders = true;
    return FT_EXIT_OK;
}

static void leaders_query(struct ft_query *q, enum ft_leader_window window, enum ft_leader_key key,
                          uint32_t limit)
{
    ft_query_init(q, FT_Q_LEADERS);
    q->window = window;
    q->leader_key = key;
    q->limit = limit;
}

static int fetch_totals(struct ft_top_source *src, struct ft_error *err)
{
    struct ft_top_frame *f = &src->work;

    leaders_query(src->query, FT_WINDOW_LIFETIME, FT_LEADER_DESTINATION, TOTALS_LIMIT);
    int code = ask(src, &(struct sink){.rows = &f->destination_totals}, nullptr, err);
    code = leaders_answer(src, code, err);
    if (code == FT_EXIT_OK && !src->no_leaders) {
        f->has_totals = true;
        src->totals_known = true;
        src->since_totals = 1;
    }
    return code;
}

static int fetch_leaders(struct ft_top_source *src, struct ft_error *err)
{
    struct ft_top_frame *f = &src->work;
    struct ft_query *q = src->query;
    const struct ft_top_request *req = &src->current;
    int code;

    leaders_query(q, req->window, req->key, req->limit);
    q->sort = (uint16_t)req->by;
    copy_text(q->path, sizeof(q->path), req->leader_path, sizeof(req->leader_path));
    code =
        ask(src, &(struct sink){.rows = &f->leaders, .summary = &f->leader_summary}, nullptr, err);
    code = leaders_answer(src, code, err);
    if (code != FT_EXIT_OK || src->no_leaders || src->stop)
        return code;
    f->has_leaders = true;

    leaders_query(q, req->window, FT_LEADER_DIRECTORY, SIDE_LIMIT);
    code = ask(src, &(struct sink){.rows = &f->leader_directories}, nullptr, err);
    if (code != FT_EXIT_OK || src->stop)
        return code;

    leaders_query(q, req->window, FT_LEADER_DESTINATION, SIDE_LIMIT);
    return ask(src, &(struct sink){.rows = &f->leader_destinations}, nullptr, err);
}

static int fetch_events(struct ft_top_source *src, struct ft_error *err)
{
    struct ft_top_frame *f = &src->work;
    struct ft_query *q = src->query;
    const struct ft_top_request *req = &src->current;

    ft_query_init(q, FT_Q_EVENTS);
    q->limit = FT_TOP_EVENTS_LIMIT;
    q->pid = req->events_pid;
    q->remote = req->events_remote;
    q->remote.port = 0;
    copy_text(q->path, sizeof(q->path), req->events_path, sizeof(req->events_path));
    int code = ask(src, &(struct sink){.rows = &f->events}, nullptr, err);
    if (code == FT_EXIT_OK) {
        f->has_events = true;
        src->events_served = src->serving;
    }
    return code;
}

static int fetch(struct ft_top_source *src, struct ft_error *err)
{
    const struct ft_top_request *req = &src->current;
    int code = FT_EXIT_OK;

    if (req->live)
        code = fetch_live(src, err);

    if (!req->totals || src->no_leaders) {
        src->totals_known = false;
    } else if (code == FT_EXIT_OK && !src->stop) {
        if (!src->totals_known || src->since_totals >= TOTALS_EVERY)
            code = fetch_totals(src, err);
        else
            src->since_totals++;
    }

    if (req->leaders && !src->no_leaders && code == FT_EXIT_OK && !src->stop)
        code = fetch_leaders(src, err);
    if (req->events && src->events_served != src->serving && code == FT_EXIT_OK && !src->stop)
        code = fetch_events(src, err);
    return code;
}

static int connect_again(struct ft_top_source *src, struct ft_error *err)
{
    struct ft_client *c = ft_client_connect(src->cli->socket_path, err);

    if (!c)
        return err->code;
    ft_client_stop_on(c, &src->stop);
    src->session->client = c;
    src->agent_lost = false;
    src->no_leaders = false;
    return FT_EXIT_OK;
}

/* A failed query may leave the stream out of step, so the connection is replaced. */
static void fail(struct ft_top_source *src, const struct ft_error *err)
{
    struct ft_top_frame *f = &src->work;
    size_t len = strcspn(err->msg, "\n");

    frame_clear(f);
    f->code = err->code != FT_EXIT_OK ? err->code : FT_EXIT_ERROR;
    if (len >= sizeof(f->error))
        len = sizeof(f->error) - 1;
    memcpy(f->error, err->msg, len);
    f->error[len] = '\0';

    src->totals_known = false;
    if (src->session->collector == 0 && !src->agent_lost) {
        ft_client_close(src->session->client);
        src->session->client = nullptr;
        src->agent_lost = true;
    }
}

static void publish(struct ft_top_source *src)
{
    struct ft_top_frame *work = &src->work;
    struct ft_top_frame *ready = &src->ready;

    pthread_mutex_lock(&src->lock);
    /* The totals come rarely, so a frame that replaces an unread one keeps its totals. */
    if (src->ready_valid && ready->has_totals && !work->has_totals && work->code == FT_EXIT_OK) {
        struct ft_rows totals = work->destination_totals;
        work->destination_totals = ready->destination_totals;
        ready->destination_totals = totals;
        work->has_totals = true;
    }
    /* The events are fetched once per request, so they too outlive the frame that brought them. */
    if (src->ready_valid && ready->has_events && !work->has_events && work->code == FT_EXIT_OK) {
        struct ft_rows events = work->events;
        work->events = ready->events;
        ready->events = events;
        work->has_events = true;
    }
    frame_swap(work, ready);
    src->ready_valid = true;
    if (!src->notified) {
        ssize_t n = write(src->frame_pipe[1], "x", 1);
        src->notified = n == 1;
    }
    pthread_mutex_unlock(&src->lock);
}

/* Returns the serial of the request it answered. */
static uint64_t refresh(struct ft_top_source *src)
{
    struct ft_top_frame *f = &src->work;
    struct ft_error err = {0};
    uint64_t served;
    int code;

    pthread_mutex_lock(&src->lock);
    src->current = src->request;
    served = src->request_serial;
    pthread_mutex_unlock(&src->lock);
    src->serving = served;

    frame_clear(f);
    f->serial = ++src->frames;
    f->request_serial = served;
    f->wall_ns = ft_clock_wall_ns();
    f->mono_ns = ft_clock_mono_ns();

    code = src->agent_lost ? connect_again(src, &err) : FT_EXIT_OK;
    if (code == FT_EXIT_OK)
        code = fetch(src, &err);
    if (src->stop)
        return served;

    if (code != FT_EXIT_OK)
        fail(src, &err);
    f->took_ns = ft_clock_mono_ns() - f->mono_ns;
    publish(src);
    return served;
}

/* Returns at the deadline, once a request newer than the one served is waiting, or on stop. */
static void wait_for(struct ft_top_source *src, uint64_t deadline_ns, uint64_t served)
{
    for (;;) {
        pthread_mutex_lock(&src->lock);
        bool pending = src->request_serial != served;
        pthread_mutex_unlock(&src->lock);

        uint64_t now = ft_clock_mono_ns();
        if (src->stop || pending || now >= deadline_ns)
            return;

        uint64_t ms = (deadline_ns - now + FT_NS_PER_MS - 1) / FT_NS_PER_MS;
        struct pollfd pfd = {.fd = src->wake_pipe[0], .events = POLLIN};
        if (poll(&pfd, 1, ms > INT_MAX ? INT_MAX : (int)ms) > 0)
            drain(src->wake_pipe[0]);
    }
}

static void *run(void *arg)
{
    struct ft_top_source *src = arg;
    uint64_t next_ns = 0;
    uint64_t served = 0;

    while (!src->stop) {
        wait_for(src, next_ns, served);
        if (src->stop)
            break;

        uint64_t start_ns = ft_clock_mono_ns();
        served = refresh(src);
        uint64_t delay_ns = src->current.delay_ns;
        next_ns = start_ns + (delay_ns < MIN_DELAY_NS ? MIN_DELAY_NS : delay_ns);
    }
    return nullptr;
}

static void destroy(struct ft_top_source *src)
{
    for (int i = 0; i < 2; i++) {
        if (src->frame_pipe[i] >= 0)
            close(src->frame_pipe[i]);
        if (src->wake_pipe[i] >= 0)
            close(src->wake_pipe[i]);
    }
    pthread_mutex_destroy(&src->lock);
    ft_top_frame_free(&src->ready);
    ft_top_frame_free(&src->work);
    free(src->query);
    free(src);
}

struct ft_top_source *ft_top_source_start(struct ft_session *s, const struct ft_cli *cli,
                                          const struct ft_top_request *first, struct ft_error *err)
{
    struct ft_top_source *src = calloc(1, sizeof(*src));
    sigset_t blocked, previous;
    int rc;

    if (!src) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return nullptr;
    }
    src->session = s;
    src->cli = cli;
    src->frame_pipe[0] = src->frame_pipe[1] = -1;
    src->wake_pipe[0] = src->wake_pipe[1] = -1;
    pthread_mutex_init(&src->lock, nullptr);
    ft_top_frame_init(&src->ready);
    ft_top_frame_init(&src->work);
    src->query = malloc(sizeof(*src->query));
    src->request = *first;
    src->request_serial = 1;

    if (!src->query || !make_pipe(src->frame_pipe) || !make_pipe(src->wake_pipe)) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot set up the data source: %s",
                     src->query ? strerror(errno) : "out of memory");
        destroy(src);
        return nullptr;
    }
    if (s->client)
        ft_client_stop_on(s->client, &src->stop);

    /* The signals the process handles are for its main thread. */
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    sigaddset(&blocked, SIGWINCH);
    sigaddset(&blocked, SIGHUP);
    sigaddset(&blocked, SIGTSTP);
    sigaddset(&blocked, SIGCONT);
    pthread_sigmask(SIG_BLOCK, &blocked, &previous);
    rc = pthread_create(&src->thread, nullptr, run, src);
    pthread_sigmask(SIG_SETMASK, &previous, nullptr);

    if (rc != 0) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot start the data source: %s", strerror(rc));
        if (s->client)
            ft_client_stop_on(s->client, nullptr);
        destroy(src);
        return nullptr;
    }
    return src;
}

void ft_top_source_stop(struct ft_top_source *src)
{
    if (!src)
        return;
    src->stop = 1;
    wake(src);
    pthread_join(src->thread, nullptr);
    if (src->session->client)
        ft_client_stop_on(src->session->client, nullptr);
    destroy(src);
}

int ft_top_source_fd(const struct ft_top_source *src)
{
    return src->frame_pipe[0];
}

bool ft_top_source_take(struct ft_top_source *src, struct ft_top_frame *frame)
{
    bool taken;

    pthread_mutex_lock(&src->lock);
    taken = src->ready_valid;
    if (taken) {
        frame_swap(frame, &src->ready);
        src->ready_valid = false;
    }
    if (src->notified) {
        drain(src->frame_pipe[0]);
        src->notified = false;
    }
    pthread_mutex_unlock(&src->lock);
    return taken;
}

uint64_t ft_top_source_request(struct ft_top_source *src, const struct ft_top_request *req)
{
    uint64_t serial;

    pthread_mutex_lock(&src->lock);
    src->request = *req;
    serial = ++src->request_serial;
    pthread_mutex_unlock(&src->lock);
    wake(src);
    return serial;
}
