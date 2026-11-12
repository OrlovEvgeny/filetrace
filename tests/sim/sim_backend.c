#include "sim/sim.h"

#include "sim/engine.h"

#include "filetrace/clock.h"

#include <stdlib.h>

constexpr uint64_t STEP_NS = 50 * FT_NS_PER_MS;
constexpr uint64_t FLUSH_NS = 250 * FT_NS_PER_MS;
constexpr uint64_t MAX_LAG_NS = 5 * FT_NS_PER_SEC;
constexpr uint64_t HISTORY_STEPS = 300;
constexpr uint64_t HISTORY_STEP_MAX_NS = 60 * FT_NS_PER_SEC;
/* Left between the start of the monotonic clock and the first simulated event. */
constexpr uint64_t HISTORY_HEADROOM_NS = 10 * FT_NS_PER_SEC;
constexpr uint64_t QUEUED_EVENT_BYTES = 112;

static struct ft_sim_options options = {.scenario = "edge", .seed = 1, .transfers = 10000};

struct ft_backend {
    struct ft_backend_config cfg;
    struct ft_sim_scenario *scenario;
    struct ft_sim_engine *engine;
    uint64_t flushes;
    uint64_t queued_seen;
    uint64_t queue_peak_bytes;
    bool lag_reported;
};

/* The callbacks that name no backend reach the one that is open. */
static struct ft_backend *active;

void ft_sim_configure(const struct ft_sim_options *opt)
{
    options = *opt;
}

static void fill_capabilities(struct ft_capabilities *caps)
{
    ft_capability_set(caps, FT_FEAT_PROCESS, FT_CAP_FULL, "%s", "");
    ft_capability_set(caps, FT_FEAT_FILE_OPEN, FT_CAP_UNAVAILABLE, "%s",
                      "a file is identified when it is read or sent");
    ft_capability_set(caps, FT_FEAT_FILE_READ, FT_CAP_PARTIAL, "%s",
                      "reads of regular files that a send follows");
    ft_capability_set(caps, FT_FEAT_FILE_WRITE, FT_CAP_UNAVAILABLE, "%s", "writes are not traced");
    ft_capability_set(caps, FT_FEAT_TCP, FT_CAP_FULL, "%s", "");
    ft_capability_set(caps, FT_FEAT_UDP, FT_CAP_UNAVAILABLE, "%s",
                      "the simulation makes no datagrams");
    ft_capability_set(caps, FT_FEAT_IPV6, FT_CAP_FULL, "%s", "");
    ft_capability_set(caps, FT_FEAT_SENDFILE, FT_CAP_FULL, "%s", "");
    ft_capability_set(caps, FT_FEAT_READ_SEND, FT_CAP_PARTIAL, "%s",
                      "a thread that reads a file and then sends is reported as INFERRED");
    ft_capability_set(caps, FT_FEAT_SPLICE, FT_CAP_UNAVAILABLE, "%s", "not simulated");
    ft_capability_set(caps, FT_FEAT_IO_URING, FT_CAP_UNAVAILABLE, "%s", "not simulated");
    ft_capability_set(caps, FT_FEAT_MMAP, FT_CAP_UNAVAILABLE, "%s", "not simulated");
    ft_capability_set(caps, FT_FEAT_PACKET_EGRESS, FT_CAP_UNAVAILABLE, "%s", "not simulated");
    ft_capability_set(caps, FT_FEAT_NAMESPACES, FT_CAP_PARTIAL, "%s",
                      "control group and namespace identifiers are made up per process");
}

static void backend_diagnose(const struct ft_backend_config *cfg, struct ft_diagnosis *out)
{
    (void)cfg;
    ft_strlcpy(out->backend, "sim", sizeof(out->backend));
    ft_diagnosis_add(out, FT_CHECK_OK, false, "Collection backend", "%s",
                     "events are made up, nothing is collected");
    fill_capabilities(&out->caps);
    out->exit_code = FT_EXIT_OK;
    ft_strlcpy(out->result, "Simulated monitoring", sizeof(out->result));
}

/* Runs the simulation up to until_ns, delivering what the kernel would have after each interval. */
static void run_to(struct ft_backend *b, uint64_t until_ns)
{
    while (ft_sim_engine_now(b->engine) + STEP_NS <= until_ns) {
        uint64_t to = ft_sim_engine_now(b->engine) + FLUSH_NS;

        ft_sim_engine_run(b->engine, to < until_ns ? to : until_ns, STEP_NS);
    }
}

/* Runs the simulation up to the present, which moves on while it does. */
static void catch_up(struct ft_backend *b)
{
    for (int pass = 0; pass < 8; pass++) {
        uint64_t now = ft_clock_mono_ns();

        if (ft_sim_engine_now(b->engine) + STEP_NS > now)
            return;
        run_to(b, now);
    }
}

static struct ft_backend *backend_open(const struct ft_backend_config *cfg,
                                       const struct ft_sink *sink, struct ft_error *err)
{
    struct ft_backend *b = calloc(1, sizeof(*b));

    if (!b) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return nullptr;
    }
    b->cfg = *cfg;
    b->scenario = ft_sim_scenario_create(options.scenario, options.transfers);
    if (!b->scenario) {
        ft_error_set(err, FT_EXIT_USAGE, "Unknown scenario '%s'", options.scenario);
        free(b);
        return nullptr;
    }
    /* The state asks about processes while the history is made. */
    active = b;

    uint64_t now = ft_clock_mono_ns();
    uint64_t history = options.history_ns;
    if (history + HISTORY_HEADROOM_NS > now) {
        history = now > HISTORY_HEADROOM_NS ? now - HISTORY_HEADROOM_NS : 0;
        ft_log(FT_LOG_WARN, "the monotonic clock has run for %llu s only: history is cut to %llu s",
               (unsigned long long)(now / FT_NS_PER_SEC),
               (unsigned long long)(history / FT_NS_PER_SEC));
    }
    b->engine = ft_sim_engine_create(b->scenario, options.seed, now - history, sink);
    if (!b->engine) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot set up the simulation: out of memory");
        active = nullptr;
        ft_sim_scenario_free(b->scenario);
        free(b);
        return nullptr;
    }

    if (history) {
        uint64_t step = history / HISTORY_STEPS;
        if (step < STEP_NS)
            step = STEP_NS;
        if (step > HISTORY_STEP_MAX_NS)
            step = HISTORY_STEP_MAX_NS;
        while (ft_sim_engine_now(b->engine) + step <= now)
            ft_sim_engine_run(b->engine, ft_sim_engine_now(b->engine) + step, step);
    }
    catch_up(b);
    b->queued_seen = ft_sim_engine_queued_events(b->engine);
    return b;
}

static int backend_poll_fd(struct ft_backend *b)
{
    (void)b;
    return -1;
}

/* A few percent of the queue is in use, and what it holds now and then is larger. */
static void update_queue(struct ft_backend *b)
{
    uint64_t queued = ft_sim_engine_queued_events(b->engine);
    uint64_t wobble_permille = 15 + (b->flushes++ * 0x9e3779b97f4a7c15ULL >> 40) % 30;
    uint64_t used = b->cfg.queue_bytes / 1000 * wobble_permille +
                    (queued - b->queued_seen) * QUEUED_EVENT_BYTES;

    b->queued_seen = queued;
    if (used > b->cfg.queue_bytes)
        used = b->cfg.queue_bytes;
    b->queue_peak_bytes =
        used > b->queue_peak_bytes ? used : b->queue_peak_bytes - b->queue_peak_bytes / 256;
}

static void backend_flush(struct ft_backend *b)
{
    uint64_t now = ft_clock_mono_ns();
    uint64_t at = ft_sim_engine_now(b->engine);

    if (now > at + MAX_LAG_NS) {
        if (!b->lag_reported) {
            ft_log(FT_LOG_WARN,
                   "the simulation is %llu s behind and skips ahead; "
                   "ask for fewer transfers",
                   (unsigned long long)((now - at) / FT_NS_PER_SEC));
            b->lag_reported = true;
        }
        ft_sim_engine_skip_to(b->engine, now - STEP_NS);
    }
    run_to(b, now);
    update_queue(b);
}

static void backend_stats(struct ft_backend *b, struct ft_backend_stats *out)
{
    out->events = ft_sim_engine_events(b->engine);
    out->queue_bytes = b->cfg.queue_bytes;
    out->queue_peak_bytes = b->queue_peak_bytes;
}

static void backend_capabilities(struct ft_backend *b, struct ft_capabilities *out)
{
    (void)b;
    fill_capabilities(out);
}

static bool backend_lookup_process(uint32_t pid, struct ft_ev_process *out)
{
    return active && active->engine && ft_sim_engine_process(active->engine, pid, out);
}

static bool backend_read_process_text(uint32_t pid, struct ft_process_text *out)
{
    return active && active->engine && ft_sim_engine_process_text(active->engine, pid, out);
}

static void backend_close(struct ft_backend *b)
{
    if (!b)
        return;
    if (active == b)
        active = nullptr;
    ft_sim_engine_destroy(b->engine);
    ft_sim_scenario_free(b->scenario);
    free(b);
}

static const struct ft_backend_ops ops = {
    .name = "sim",
    .diagnose = backend_diagnose,
    .open = backend_open,
    .poll_fd = backend_poll_fd,
    .flush = backend_flush,
    .stats = backend_stats,
    .capabilities = backend_capabilities,
    .lookup_process = backend_lookup_process,
    .read_process_text = backend_read_process_text,
    .close = backend_close,
};

const struct ft_backend_ops *ft_sim_backend(void)
{
    return &ops;
}
