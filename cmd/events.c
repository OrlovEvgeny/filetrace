#include "cmd/cli.h"

#include "exporters/exporters.h"
#include "filetrace/clock.h"
#include "filetrace/event.h"
#include "filetrace/format.h"
#include "ui/ui.h"

#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

static volatile sig_atomic_t stop_requested;

static void on_stop(int signo)
{
    (void)signo;
    stop_requested = 1;
}

struct printer {
    const struct ft_output *out;
    struct ft_row_event *row;
    uint64_t count;
    bool raw;
    bool follow;
};

static bool has_process(const struct ft_row_event *e)
{
    return e->pid != 0;
}

static bool has_socket(const struct ft_row_event *e)
{
    return e->sock_id != 0;
}

static bool has_file(const struct ft_row_event *e)
{
    return e->type == FT_REC_FILE_SEEN || e->type == FT_REC_FILE_TRANSFER;
}

static bool has_executable(const struct ft_row_event *e)
{
    return e->type >= FT_REC_PROCESS_EXEC && e->type <= FT_REC_PROCESS_EXIT && e->text[0];
}

static const char *loss_cause(const struct ft_row_event *e)
{
    if (e->loss_kind == FT_EVENT_LOSS_READER)
        return "this reader fell behind";
    return ft_loss_kind_name((enum ft_loss_kind)e->loss_kind);
}

static void endpoint_text(const struct ft_endpoint *ep, char *buf, size_t size)
{
    if (ep->family == 0 && ep->port == 0)
        ft_strlcpy(buf, "*", size);
    else
        ft_endpoint_format(ep, buf, size);
}

static void print_text(FILE *o, const struct ft_row_event *e)
{
    char clock[16];
    char name[32];
    char buf[96];
    size_t i = 0;

    for (const char *type = ft_record_type_name((enum ft_record_type)e->type);
         type[i] && i + 1 < sizeof(name); i++)
        name[i] = (char)toupper((unsigned char)type[i]);
    name[i] = '\0';
    ft_format_clock_local(e->time_ns, clock, sizeof(clock));
    fprintf(o, "%s.%03u %s\n", clock, (unsigned)(e->time_ns % FT_NS_PER_SEC / FT_NS_PER_MS), name);

    if (has_process(e)) {
        fprintf(o, "  pid=%" PRIu32 "\n", e->pid);
        if (e->comm[0])
            fprintf(o, "  process=%s\n", e->comm);
    }
    if (has_executable(e)) {
        if (e->ppid)
            fprintf(o, "  ppid=%" PRIu32 "\n", e->ppid);
        fprintf(o, "  executable=%s\n", e->text);
    }
    if (e->type == FT_REC_PROCESS_EXIT) {
        if (WIFSIGNALED(e->exit_status))
            fprintf(o, "  signal=%d\n", WTERMSIG(e->exit_status));
        else
            fprintf(o, "  exit_status=%d\n", WEXITSTATUS(e->exit_status));
    }
    if (has_file(e)) {
        if (e->text[0])
            fprintf(o, "  file=%s\n", e->text);
        fprintf(o, "  inode=%" PRIu64 "\n", e->ino);
        if (e->type == FT_REC_FILE_SEEN) {
            fprintf(o, "  device=%" PRIu64 "\n", e->dev);
            fprintf(o, "  size=%" PRIu64 "\n", e->file_size);
        }
        if (e->flags & FT_EVENT_FILE_DELETED)
            fputs("  deleted=yes\n", o);
    }
    if (has_socket(e)) {
        fprintf(o, "  socket=%" PRIu64 "\n", e->sock_id);
        if (e->type != FT_REC_FILE_TRANSFER) {
            char proto[8];
            fprintf(o, "  protocol=%s\n", ft_proto_name(e->proto, proto));
            endpoint_text(&e->local, buf, sizeof(buf));
            fprintf(o, "  local=%s\n", buf);
        }
        endpoint_text(&e->remote, buf, sizeof(buf));
        fprintf(o, "  remote=%s\n", buf);
    }
    switch (e->type) {
    case FT_REC_NETWORK_SEND:
    case FT_REC_NETWORK_RECEIVE:
        fprintf(o, "  bytes=%" PRIu64 "\n", e->bytes);
        break;
    case FT_REC_FILE_TRANSFER:
        fprintf(o, "  bytes=%" PRIu64 "\n", e->bytes);
        if (e->method == FT_METHOD_READ_SEND)
            fprintf(o, "  bytes_read=%" PRIu64 "\n", e->read_bytes);
        fprintf(o, "  method=%s\n", ft_method_name((enum ft_method)e->method));
        /* Below the reporting thresholds an association has no level yet. */
        fprintf(o, "  confidence=%s\n",
                (e->flags & FT_EVENT_HAS_CONFIDENCE)
                    ? ft_confidence_name((enum ft_confidence)e->confidence)
                    : "pending");
        break;
    case FT_REC_EVENT_LOSS:
        fprintf(o, "  events=%" PRIu64 "\n", e->bytes);
        fprintf(o, "  cause=%s\n", loss_cause(e));
        break;
    default:
        break;
    }
    fputc('\n', o);
}

/* Every field, unformatted and in a fixed order; the text comes last because it may hold spaces. */
static void print_raw(FILE *o, const struct ft_row_event *e)
{
    char local[64];
    char remote[64];

    ft_addr_format(&e->local, local, sizeof(local));
    ft_addr_format(&e->remote, remote, sizeof(remote));
    fprintf(o,
            "seq=%" PRIu64 " time_ns=%" PRIu64 " type=%s pid=%" PRIu32 " ppid=%" PRIu32
            " uid=%" PRIu32 " comm=%s exit_status=%d socket=%" PRIu64 " protocol=%u"
            " local_ip=%s local_port=%u remote_ip=%s remote_port=%u bytes=%" PRIu64
            " bytes_read=%" PRIu64 " device=%" PRIu64 " inode=%" PRIu64 " file_size=%" PRIu64
            " method=%u confidence=%u loss_kind=%u flags=%u text=%s\n",
            e->seq, e->time_ns, ft_record_type_name((enum ft_record_type)e->type), e->pid, e->ppid,
            e->uid, e->comm[0] ? e->comm : "-", e->exit_status, e->sock_id, e->proto, local,
            e->local.port, remote, e->remote.port, e->bytes, e->read_bytes, e->dev, e->ino,
            e->file_size, e->method, e->confidence, e->loss_kind, e->flags, e->text);
}

static void json_endpoint(FILE *o, const char *side, const struct ft_endpoint *ep)
{
    char buf[64];

    if (ep->family) {
        ft_addr_format(ep, buf, sizeof(buf));
        fprintf(o, ",\"%s_ip\":\"%s\"", side, buf);
    }
    if (ep->port)
        fprintf(o, ",\"%s_port\":%u", side, ep->port);
}

/* The groups and keys are those of the transfer records that 'files' prints. */
static void print_json(FILE *o, const struct ft_row_event *e)
{
    char stamp[40];
    char proto[8];

    ft_format_time_rfc3339(e->time_ns, stamp, sizeof(stamp));
    fprintf(o, "{\"event\":\"%s\",\"timestamp\":\"%s\",\"sequence\":%" PRIu64,
            ft_record_type_name((enum ft_record_type)e->type), stamp, e->seq);

    if (has_process(e)) {
        fprintf(o, ",\"process\":{\"pid\":%" PRIu32, e->pid);
        if (e->ppid)
            fprintf(o, ",\"ppid\":%" PRIu32, e->ppid);
        if (e->comm[0]) {
            fputs(",\"name\":", o);
            ft_json_string(o, e->comm);
        }
        if (has_executable(e)) {
            fputs(",\"executable\":", o);
            ft_json_string(o, e->text);
        }
        if (e->type == FT_REC_PROCESS_EXIT) {
            if (WIFSIGNALED(e->exit_status))
                fprintf(o, ",\"signal\":%d", WTERMSIG(e->exit_status));
            else
                fprintf(o, ",\"exit_status\":%d", WEXITSTATUS(e->exit_status));
        }
        fputc('}', o);
    }
    if (has_file(e)) {
        fputs(",\"file\":{", o);
        if (e->text[0]) {
            fputs("\"path\":", o);
            ft_json_string(o, e->text);
            fputc(',', o);
        }
        fprintf(
            o, "\"inode\":%" PRIu64 ",\"device\":%" PRIu64 ",\"size\":%" PRIu64 ",\"deleted\":%s}",
            e->ino, e->dev, e->file_size, (e->flags & FT_EVENT_FILE_DELETED) ? "true" : "false");
    }
    if (has_socket(e)) {
        fprintf(o, ",\"network\":{\"protocol\":\"%s\",\"socket_id\":%" PRIu64,
                ft_proto_name(e->proto, proto), e->sock_id);
        json_endpoint(o, "local", &e->local);
        json_endpoint(o, "remote", &e->remote);
        if (e->type == FT_REC_NETWORK_SEND)
            fprintf(o, ",\"bytes_sent\":%" PRIu64, e->bytes);
        if (e->type == FT_REC_NETWORK_RECEIVE)
            fprintf(o, ",\"bytes_received\":%" PRIu64, e->bytes);
        fputc('}', o);
    }
    if (e->type == FT_REC_FILE_TRANSFER) {
        fprintf(o, ",\"transfer\":{\"method\":\"%s\",\"bytes_sent\":%" PRIu64,
                ft_method_name((enum ft_method)e->method), e->bytes);
        if (e->method == FT_METHOD_READ_SEND)
            fprintf(o, ",\"bytes_read\":%" PRIu64, e->read_bytes);
        if (e->flags & FT_EVENT_HAS_CONFIDENCE)
            fprintf(o, ",\"confidence\":\"%s\"",
                    ft_confidence_name((enum ft_confidence)e->confidence));
        fputc('}', o);
    }
    if (e->type == FT_REC_EVENT_LOSS) {
        fprintf(o, ",\"loss\":{\"events\":%" PRIu64 ",\"cause\":", e->bytes);
        ft_json_string(o, loss_cause(e));
        fputc('}', o);
    }
    fputc('}', o);
}

static void on_event(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct printer *p = ctx;
    struct ft_row_event *e = p->row;
    FILE *o = p->out->stream;

    if (type != FT_MSG_ROW_EVENT || size < offsetof(struct ft_row_event, text))
        return;
    memset(e, 0, offsetof(struct ft_row_event, text) + 1);
    memcpy(e, payload, size < sizeof(*e) ? size : sizeof(*e));
    e->comm[sizeof(e->comm) - 1] = '\0';
    e->text[size < sizeof(*e) ? size - offsetof(struct ft_row_event, text) : FT_PATH_MAX - 1] =
        '\0';

    if (p->raw) {
        print_raw(o, e);
    } else if (p->out->format == FT_FMT_JSON) {
        fputs(p->count ? ",\n " : "[\n ", o);
        print_json(o, e);
    } else if (p->out->format == FT_FMT_JSONL) {
        print_json(o, e);
        fputc('\n', o);
    } else {
        print_text(o, e);
    }
    p->count++;
    if (p->follow)
        fflush(o);
}

static int parse_types(const char *list, uint32_t *mask)
{
    char name[32];

    for (const char *p = list; *p;) {
        size_t len = strcspn(p, ",");
        enum ft_record_type type;

        if (len == 0 || len >= sizeof(name))
            return ft_usage_error("events", "invalid value '%s' for --type", list);
        memcpy(name, p, len);
        name[len] = '\0';
        if (!ft_record_type_parse(name, &type)) {
            fprintf(stderr, "filetrace: unknown event type '%s'. The collector records:\n", name);
            for (int t = 1; t < FT_REC_TYPE_COUNT; t++)
                fprintf(stderr, "  %s\n", ft_record_type_name((enum ft_record_type)t));
            fputs("\nSee 'filetrace help events' for what each one means.\n", stderr);
            return FT_EXIT_USAGE;
        }
        *mask |= 1u << type;
        p += len;
        if (*p == ',')
            p++;
    }
    return FT_EXIT_OK;
}

int ft_cmd_events(const struct ft_cli *cli, struct ft_args *a)
{
    struct ft_query_args qa;
    struct printer printer = {.out = &qa.out};
    bool follow = false;
    const char *v;

    ft_query_args_init(&qa, "events", FT_Q_EVENTS, FT_OPTS_EVENTS, 0);
    qa.formats = FT_FORMATS_EVENTS;

    while (!ft_args_done(a)) {
        int r = ft_query_args_parse(&qa, a);
        if (r < 0)
            return FT_EXIT_USAGE;
        if (r > 0)
            continue;
        if (ft_args_flag(a, "--follow") || ft_args_flag(a, "-f")) {
            follow = true;
        } else if (ft_args_flag(a, "--raw")) {
            printer.raw = true;
        } else if ((r = ft_args_value(a, "--type", &v)) != 0) {
            if (r < 0)
                return FT_EXIT_USAGE;
            int code = parse_types(v, &qa.query.event_types);
            if (code != FT_EXIT_OK)
                return code;
        } else {
            return ft_usage_error("events", "unknown argument '%s' for 'events'", ft_args_peek(a));
        }
    }
    if (printer.raw && qa.out.format_given)
        return ft_usage_error("events", "--raw is a format of its own; drop --format or --raw");

    if (follow) {
        qa.query.flags |= FT_QF_FOLLOW;
        /* Following starts at the present unless the past was asked for. */
        if (!qa.query.since_wall_ns && !qa.query.limit)
            qa.query.since_wall_ns = ft_clock_wall_ns();
    }

    struct ft_session session;
    struct ft_msg_end end = {0};
    struct ft_error err = {0};
    int code = ft_output_open(&qa.out, qa.output_path);
    if (code != FT_EXIT_OK)
        return code;
    code = ft_session_open(cli, follow, &session);
    if (code != FT_EXIT_OK) {
        ft_output_close(&qa.out);
        return code;
    }

    printer.follow = follow;
    printer.row = malloc(sizeof(*printer.row));
    if (!printer.row) {
        ft_session_close(&session);
        ft_output_close(&qa.out);
        return FT_EXIT_ERROR;
    }

    if (follow) {
        struct sigaction sa = {.sa_handler = on_stop};
        sigemptyset(&sa.sa_mask);
        stop_requested = 0;
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
        ft_client_stop_on(session.client, &stop_requested);
    }

    code = ft_client_query(session.client, &qa.query, on_event, &printer, &end, &err);

    FILE *o = qa.out.stream;
    bool table = !printer.raw && qa.out.format == FT_FMT_TABLE;
    if (!printer.raw && qa.out.format == FT_FMT_JSON)
        fputs(printer.count ? "\n]\n" : "[]\n", o);
    if (code == FT_EXIT_OK && table && !follow) {
        char since[32];
        bool styled = ft_term_styled(o);

        ft_format_time_local(end.observed_since_wall_ns, since, sizeof(since));
        fprintf(o,
                "%s%" PRIu64 " %s. The event log reaches back to %s; it is kept in memory\n"
                "and holds only the most recent events.%s\n",
                styled ? FT_STYLE_DIM : "", printer.count, printer.count == 1 ? "event" : "events",
                since, styled ? FT_STYLE_RESET : "");
    }
    fflush(o);
    code = follow && code == FT_EXIT_OK ? FT_EXIT_OK : ft_finish_query(code, &err, &end, &qa.out);

    free(printer.row);
    ft_session_close(&session);
    ft_output_close(&qa.out);
    return code;
}
