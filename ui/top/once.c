#include "ui/top/once.h"

#include "filetrace/clock.h"
#include "ui/top/document.h"
#include "ui/top/plain.h"
#include "ui/top/presets.h"
#include "ui/top/source.h"
#include "ui/ui.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static bool ends_with_csv(const char *path)
{
    size_t len = strlen(path);

    return len >= 4 && strcasecmp(path + len - 4, ".csv") == 0;
}

/* Opens a new file beside path, to be renamed over it once it is complete. */
static int create_beside(const char *path, char *temp, size_t size)
{
    static unsigned serial;

    for (int attempt = 0; attempt < 16; attempt++) {
        int len = snprintf(temp, size, "%s.tmp-%ld-%u", path, (long)getpid(), serial++);

        if (len < 0 || (size_t)len >= size) {
            errno = ENAMETOOLONG;
            return -1;
        }
        int fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
        if (fd >= 0 || errno != EEXIST)
            return fd;
    }
    return -1;
}

static bool write_failed(struct ft_error *err, const char *path, int error)
{
    ft_error_set(err, FT_EXIT_ERROR, "Cannot write %s: %s", path, strerror(error));
    return false;
}

bool ft_top_export(const struct ft_top_model *m, enum ft_top_mode mode, const char *path,
                   size_t *rows, struct ft_error *err)
{
    char temp[PATH_MAX + 32];
    int fd;
    FILE *out;
    int error = 0;

    *rows = 0;
    if (!path || !path[0])
        return write_failed(err, "", ENOENT);
    fd = create_beside(path, temp, sizeof(temp));
    if (fd < 0)
        return write_failed(err, path, errno);
    out = fdopen(fd, "w");
    if (!out) {
        error = errno;
        close(fd);
        unlink(temp);
        return write_failed(err, path, error);
    }

    size_t written = ends_with_csv(path) ? ft_top_write_csv(m, mode, out)
                                         : ft_top_write_document(m, mode, true, out);
    if (fflush(out) != 0 || ferror(out))
        error = errno ? errno : EIO;
    if (fclose(out) != 0 && error == 0)
        error = errno ? errno : EIO;
    if (error == 0 && rename(temp, path) != 0)
        error = errno;
    if (error != 0) {
        unlink(temp);
        return write_failed(err, path, error);
    }
    *rows = written;
    return true;
}

constexpr int DEFAULT_COLUMNS = 174;
constexpr uint64_t FIRST_FRAME_NS = 10 * FT_NS_PER_SEC;
constexpr uint64_t POLL_NS = 100 * FT_NS_PER_MS;
constexpr uint64_t NAMES_NS = 3 * FT_NS_PER_SEC;
constexpr size_t PRESET_SIZE = 1024;

static volatile sig_atomic_t interrupted;

static void on_signal(int signo)
{
    (void)signo;
    interrupted = 1;
}

struct signals {
    struct sigaction interrupt;
    struct sigaction terminate;
    struct sigaction pipe;
};

/* Interrupts end the wait, and a closed pipe fails the write instead of killing the process. */
static void signals_catch(struct signals *saved)
{
    struct sigaction catch = {.sa_handler = on_signal};
    struct sigaction ignore = {.sa_handler = SIG_IGN};

    sigemptyset(&catch.sa_mask);
    sigemptyset(&ignore.sa_mask);
    interrupted = 0;
    sigaction(SIGINT, &catch, &saved->interrupt);
    sigaction(SIGTERM, &catch, &saved->terminate);
    sigaction(SIGPIPE, &ignore, &saved->pipe);
}

static void signals_restore(const struct signals *saved)
{
    sigaction(SIGINT, &saved->interrupt, nullptr);
    sigaction(SIGTERM, &saved->terminate, nullptr);
    sigaction(SIGPIPE, &saved->pipe, nullptr);
}

/* The filter with a leading @name replaced by what the preset holds; nullptr when it has none. */
static int expand_preset(const char *filter, char **expanded)
{
    struct ft_error err = {0};
    char expression[PRESET_SIZE];
    char name[128];

    *expanded = nullptr;
    if (!filter || filter[0] != '@')
        return FT_EXIT_OK;
    size_t len = strcspn(filter + 1, " \t");
    if (len == 0 || len >= sizeof(name))
        return ft_usage_error("top", "filter: a preset name must follow '@'");
    memcpy(name, filter + 1, len);
    name[len] = '\0';
    if (!ft_top_presets_find(name, expression, sizeof(expression), &err))
        return ft_usage_error("top", "filter: %s", err.msg);

    const char *rest = filter + 1 + len + strspn(filter + 1 + len, " \t");
    size_t size = strlen(expression) + strlen(rest) + 2;
    *expanded = malloc(size);
    if (!*expanded) {
        fprintf(stderr, "filetrace: out of memory\n");
        return FT_EXIT_ERROR;
    }
    snprintf(*expanded, size, "%s%s%s", expression, rest[0] ? " " : "", rest);
    return FT_EXIT_OK;
}

static enum ft_top_sort ranking_sort(enum ft_sort by)
{
    switch (by) {
    case FT_SORT_TRANSFERS:
        return FT_TOP_SORT_TRANSFERS;
    case FT_SORT_DESTINATIONS:
        return FT_TOP_SORT_DESTINATIONS;
    default:
        return FT_TOP_SORT_BYTES;
    }
}

static int set_sort(struct ft_top_model *m, const struct ft_top_options *opt)
{
    enum ft_top_mode mode = opt->mode;
    size_t count;
    const struct ft_top_sort_option *keys = ft_top_mode_sorts(mode, &count);

    if (mode == FT_TOP_LEADERS) {
        ft_top_set_sort(m, mode, ranking_sort(opt->by), true);
        return FT_EXIT_OK;
    }
    enum ft_top_sort key = opt->sort == FT_TOP_SORT_DEFAULT ? keys[0].key : opt->sort;
    char names[160] = "";
    size_t len = 0;

    for (size_t i = 0; i < count; i++) {
        if (keys[i].key == key)
            return ft_top_set_sort(m, mode, key, keys[i].descending != opt->reverse)
                       ? FT_EXIT_OK
                       : FT_EXIT_ERROR;
        int n =
            snprintf(names + len, sizeof(names) - len, "%s%s",
                     i == 0 ? "" : (i == count - 1 ? " or " : ", "), ft_top_sort_name(keys[i].key));
        if (n > 0 && (size_t)n < sizeof(names) - len)
            len += (size_t)n;
    }
    return ft_usage_error("top", "--sort %s does not apply to the %s mode (use %s)",
                          ft_top_sort_name(key), ft_top_mode_name(mode), names);
}

/* Gives the model what the options ask for; reports and returns the exit code when one is wrong. */
static int configure(struct ft_top_model *m, const struct ft_top_options *opt)
{
    struct ft_error err = {0};
    char *expanded;
    int code = expand_preset(opt->filter, &expanded);

    if (code != FT_EXIT_OK)
        return code;
    ft_top_set_mode(m, opt->mode);
    bool accepted = ft_top_set_filter(m, opt->mode,
                                      expanded ? expanded : (opt->filter ? opt->filter : ""), &err);
    free(expanded);
    if (!accepted) {
        if (err.code == FT_EXIT_USAGE)
            return ft_usage_error("top", "filter: %s", err.msg);
        fprintf(stderr, "filetrace: %s\n", err.msg);
        return err.code;
    }
    code = set_sort(m, opt);
    if (code != FT_EXIT_OK)
        return code;
    ft_top_set_group(m, opt->mode, opt->group);
    ft_top_set_tree(m, opt->tree);
    ft_top_set_resolve(m, opt->resolve);
    ft_top_set_leaders_request(m, opt->window, FT_LEADER_FILE);
    return FT_EXIT_OK;
}

static void make_request(struct ft_top_request *req, const struct ft_top_options *opt,
                         const struct ft_top_model *m)
{
    ft_top_request_init(req);
    req->delay_ns = opt->delay_ns;
    if (opt->mode == FT_TOP_LEADERS) {
        req->leaders = true;
        req->window = opt->window;
        req->key = FT_LEADER_FILE;
        req->by = opt->by;
        req->limit = opt->limit;
        return;
    }
    req->live = true;
    req->totals = opt->mode == FT_TOP_DESTINATIONS;
    ft_top_filter_pushdown(ft_top_filter_get(m, opt->mode), &req->scope);
}

/* Returns 1 with a frame taken, 0 when none came within the time, -1 when interrupted. */
static int wait_frame(struct ft_top_source *src, struct ft_top_frame *frame, uint64_t timeout_ns)
{
    struct pollfd pfd = {.fd = ft_top_source_fd(src), .events = POLLIN};
    uint64_t start_ns = ft_clock_mono_ns();

    while (!interrupted) {
        if (ft_top_source_take(src, frame))
            return 1;
        if (ft_clock_mono_ns() - start_ns >= timeout_ns)
            return 0;
        poll(&pfd, 1, (int)(POLL_NS / FT_NS_PER_MS));
    }
    return -1;
}

static bool feed(struct ft_top_model *m, const struct ft_top_options *opt,
                 const struct ft_top_frame *frame)
{
    if (opt->mode == FT_TOP_LEADERS) {
        struct ft_top_leaders_sample sample = {
            .window = opt->window,
            .key = FT_LEADER_FILE,
            .by = ranking_sort(opt->by),
            .summary = &frame->leader_summary,
            .ranking = &frame->leaders,
            .directories = &frame->leader_directories,
            .destinations = &frame->leader_destinations,
        };
        return ft_top_model_leaders(m, &sample);
    }
    struct ft_top_sample sample = {
        .mono_ns = frame->mono_ns,
        .stats = &frame->stats,
        .transfers = &frame->transfers,
        .processes = &frame->processes,
        .destinations = frame->has_totals ? &frame->destination_totals : nullptr,
    };
    return ft_top_model_sample(m, &sample);
}

static bool shows_script(const struct ft_top_model *m, const struct ft_top_options *opt)
{
    uint32_t fields = ft_top_filter_fields(ft_top_filter_get(m, opt->mode));

    return (fields & FT_TOP_FIELD_BIT(FT_TOP_FIELD_SCRIPT)) != 0 ||
           opt->sort == FT_TOP_SORT_SCRIPT || opt->group == FT_TOP_GROUP_SCRIPT;
}

static int output_width(void)
{
    int rows;
    int cols;

    if (!isatty(STDOUT_FILENO))
        return DEFAULT_COLUMNS;
    ft_term_size(&rows, &cols);
    return cols;
}

/* Writes what the model holds as the options ask: the table, or the document. */
static bool compose(const struct ft_top_model *m, const struct ft_top_options *opt, bool indent,
                    FILE *out)
{
    if (opt->json) {
        ft_top_write_document(m, opt->mode, indent, out);
        return true;
    }
    struct ft_top_ui ui = {
        .mode = opt->mode,
        .previous_mode = FT_TOP_TRANSFERS,
        .full_paths = true,
        .no_selection = true,
        .script_column = shows_script(m, opt),
        .delay_ns = opt->delay_ns,
        .window = opt->window,
        .key = FT_LEADER_FILE,
        .by = ranking_sort(opt->by),
    };
    enum ft_color_depth depth =
        opt->color == FT_TOP_COLOR_ALWAYS ? FT_DEPTH_TRUECOLOR : FT_DEPTH_NONE;

    return ft_top_print_table(m, &ui, output_width(), depth, out);
}

/* Returns 0, or the error that stopped the write: EPIPE when the reader has gone. */
static int send_all(const char *data, size_t size)
{
    while (size > 0) {
        ssize_t n = write(STDOUT_FILENO, data, size);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return errno;
        }
        data += n;
        size -= (size_t)n;
    }
    return 0;
}

enum delivery : uint8_t {
    DELIVERED,
    READER_GONE,
    DELIVERY_FAILED,
};

/* Writes the output in one piece, so that a reader that goes away never sees half of it. */
static enum delivery deliver(const struct ft_top_model *m, const struct ft_top_options *opt,
                             bool indent)
{
    char *text = nullptr;
    size_t size = 0;
    FILE *out = open_memstream(&text, &size);
    bool composed = out && compose(m, opt, indent, out) && !ferror(out);

    if (out && fclose(out) != 0)
        composed = false;
    if (!composed) {
        free(text);
        fprintf(stderr, "filetrace: out of memory\n");
        return DELIVERY_FAILED;
    }
    int error = send_all(text, size);

    free(text);
    if (error == EPIPE)
        return READER_GONE;
    if (error != 0) {
        fprintf(stderr, "filetrace: cannot write the output: %s\n", strerror(error));
        return DELIVERY_FAILED;
    }
    return DELIVERED;
}

static struct ft_output output_of(const struct ft_top_options *opt)
{
    struct ft_output out;

    ft_output_init(&out);
    out.format = opt->json ? FT_FMT_JSON : FT_FMT_TABLE;
    return out;
}

/* A frame without data: the agent's own words, or ours. */
static int report_frame(const struct ft_top_frame *frame, const struct ft_top_options *opt)
{
    struct ft_error err = {.code = frame->code};
    struct ft_output out = output_of(opt);

    ft_strlcpy(err.msg, frame->error[0] ? frame->error : "The agent gave no data.",
               sizeof(err.msg));
    return ft_finish_query(frame->code, &err, &frame->end, &out);
}

/* Takes the first frame into the model, waiting for the names when they were asked for. */
static int first_sample(struct ft_top_source *src, struct ft_top_model *m,
                        const struct ft_top_options *opt, struct ft_top_frame *frame)
{
    int got = wait_frame(src, frame, FIRST_FRAME_NS);

    if (got < 0)
        return FT_EXIT_ERROR;
    if (got == 0) {
        fprintf(stderr, "The agent did not answer within %d seconds.\n",
                (int)(FIRST_FRAME_NS / FT_NS_PER_SEC));
        return FT_EXIT_NO_AGENT;
    }
    if (frame->code != FT_EXIT_OK)
        return report_frame(frame, opt);
    if (opt->mode == FT_TOP_LEADERS && !frame->has_leaders) {
        fprintf(stderr, "filetrace: this agent does not keep rankings over time; "
                        "restart filetrace-agent\n");
        return FT_EXIT_UNSUPPORTED;
    }
    if (!feed(m, opt, frame)) {
        fprintf(stderr, "filetrace: out of memory\n");
        return FT_EXIT_ERROR;
    }
    if (opt->resolve) {
        /* Switching the names on again has the model ask the resolver, whose lookups are done. */
        ft_resolver_wait(NAMES_NS);
        ft_top_set_resolve(m, false);
        ft_top_set_resolve(m, true);
    }
    return FT_EXIT_OK;
}

/* One snapshot, which ends like any other query: with the loss of events as its exit code. */
static int snapshot(const struct ft_top_model *m, const struct ft_top_options *opt,
                    const struct ft_top_frame *frame)
{
    struct ft_output out = output_of(opt);
    struct ft_error none = {0};

    if (deliver(m, opt, true) == DELIVERY_FAILED)
        return FT_EXIT_ERROR;
    return ft_finish_query(FT_EXIT_OK, &none, &frame->end, &out);
}

/* One document per frame, each on a line, until interrupted or until the reader has gone. */
static int stream(struct ft_top_source *src, struct ft_top_model *m,
                  const struct ft_top_options *opt, struct ft_top_frame *frame)
{
    char reported[sizeof(frame->error)] = "";

    for (;;) {
        enum delivery result = deliver(m, opt, false);

        if (result == READER_GONE)
            return FT_EXIT_OK;
        if (result == DELIVERY_FAILED)
            return FT_EXIT_ERROR;
        for (;;) {
            if (wait_frame(src, frame, UINT64_MAX) < 0)
                return FT_EXIT_OK;
            if (frame->code == FT_EXIT_OK)
                break;
            /* The source retries by itself; each message is reported once. */
            if (strcmp(reported, frame->error) != 0) {
                fprintf(stderr, "%s\n", frame->error);
                ft_strlcpy(reported, frame->error, sizeof(reported));
            }
        }
        reported[0] = '\0';
        if (!feed(m, opt, frame)) {
            fprintf(stderr, "filetrace: out of memory\n");
            return FT_EXIT_ERROR;
        }
    }
}

static int serve(struct ft_session *s, const struct ft_cli *cli, const struct ft_top_options *opt,
                 struct ft_top_model *m, struct ft_top_frame *frame)
{
    struct ft_top_request req;
    struct ft_error err = {0};
    struct ft_top_source *src;

    make_request(&req, opt, m);
    src = ft_top_source_start(s, cli, &req, &err);
    if (!src) {
        fprintf(stderr, "%s\n", err.msg);
        return err.code != FT_EXIT_OK ? err.code : FT_EXIT_ERROR;
    }
    int code = first_sample(src, m, opt, frame);

    if (code == FT_EXIT_OK)
        code = opt->once ? snapshot(m, opt, frame) : stream(src, m, opt, frame);
    ft_top_source_stop(src);
    return code;
}

int ft_top_once(struct ft_session *s, const struct ft_cli *cli, const struct ft_top_options *opt)
{
    struct ft_top_model *m = ft_top_model_create();
    struct ft_top_frame frame;
    struct signals saved;
    int code;

    if (!m) {
        fprintf(stderr, "filetrace: out of memory\n");
        return FT_EXIT_ERROR;
    }
    ft_top_frame_init(&frame);
    signals_catch(&saved);
    code = configure(m, opt);
    if (code == FT_EXIT_OK)
        code = serve(s, cli, opt, m, &frame);
    signals_restore(&saved);
    ft_top_frame_free(&frame);
    ft_top_model_destroy(m);
    return code;
}
