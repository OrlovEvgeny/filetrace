#include "agent/telemetry.h"

#include "filetrace/arena.h"
#include "filetrace/clock.h"
#include "filetrace/format.h"
#include "filetrace/sysinfo.h"
#include "rpc/grpc.h"

#include "filetrace/v1/filetrace.pb-c.h"

#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <unistd.h>

typedef Filetrace__V1__Process Process;
typedef Filetrace__V1__File File;
typedef Filetrace__V1__Endpoint Endpoint;
typedef Filetrace__V1__Connection Connection;
typedef Filetrace__V1__Transfer Transfer;
typedef Filetrace__V1__TransferFilter Filter;
typedef Filetrace__V1__TransferEvent TransferEvent;
typedef Filetrace__V1__GetStatusResponse StatusResponse;
typedef Filetrace__V1__ListTransfersRequest ListRequest;
typedef Filetrace__V1__ListTransfersResponse ListResponse;
typedef Filetrace__V1__WatchTransfersRequest WatchRequest;
typedef Filetrace__V1__WatchTransfersResponse WatchResponse;

constexpr size_t MAX_WATCHERS = 16;
constexpr uint32_t MAX_LISTED = 1000;
constexpr size_t MAX_EVIDENCE = 8;

struct watcher {
    struct ft_grpc_call *call;
    struct ft_query *query; /* an events query that selects the transfers asked for */
    uint64_t missed;        /* events it was not sent because it read too slowly */
};

struct ft_api {
    struct ft_telemetry_source src;
    struct ft_grpc_server *server;
    char socket_path[108]; /* removed on close; empty when listening on TCP */
    struct watcher watchers[MAX_WATCHERS];
    size_t watcher_count;
};

/* The nested messages of one transfer, with room for their short strings. */
struct parts {
    Process process;
    File file;
    Connection connection;
    Endpoint local;
    Endpoint remote;
    char *resolved[FT_RESOLVED_NAMES];
    char name[FT_COMM_MAX];
    char local_address[64];
    char remote_address[64];
};

static Filetrace__V1__Transport transport_of(uint16_t proto)
{
    return proto == FT_PROTO_TCP   ? FILETRACE__V1__TRANSPORT__TRANSPORT_TCP
           : proto == FT_PROTO_UDP ? FILETRACE__V1__TRANSPORT__TRANSPORT_UDP
                                   : FILETRACE__V1__TRANSPORT__TRANSPORT_UNSPECIFIED;
}

static Filetrace__V1__Method method_of(uint8_t method)
{
    return method == FT_METHOD_SENDFILE    ? FILETRACE__V1__METHOD__METHOD_SENDFILE
           : method == FT_METHOD_READ_SEND ? FILETRACE__V1__METHOD__METHOD_READ_WRITE
                                           : FILETRACE__V1__METHOD__METHOD_UNSPECIFIED;
}

static Filetrace__V1__NameSource name_source_of(enum ft_name_source source)
{
    switch (source) {
    case FT_NAME_SOURCE_LOOKUP:
        return FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_LOOKUP;
    case FT_NAME_SOURCE_TLS:
        return FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_TLS;
    case FT_NAME_SOURCE_LOOKUP_TLS:
        return FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_LOOKUP_AND_TLS;
    default:
        return FILETRACE__V1__NAME_SOURCE__NAME_SOURCE_UNSPECIFIED;
    }
}

/* The API numbers the levels one above the agent's, leaving zero for "not given". */
static Filetrace__V1__Confidence confidence_of(uint8_t confidence)
{
    return (Filetrace__V1__Confidence)(confidence + 1);
}

static void fill_process(struct parts *p, uint32_t pid, uint32_t ppid, const char *comm, char *exe)
{
    filetrace__v1__process__init(&p->process);
    ft_utf8_copy(p->name, comm, sizeof(p->name));
    p->process.pid = pid;
    p->process.parent_pid = ppid;
    p->process.name = p->name;
    p->process.executable = exe;
}

static Endpoint *fill_endpoint(Endpoint *out, char *address, size_t size,
                               const struct ft_endpoint *ep)
{
    if (ep->family == 0 && ep->port == 0)
        return nullptr;
    filetrace__v1__endpoint__init(out);
    address[0] = '\0';
    if (ep->family)
        ft_addr_format(ep, address, size);
    out->address = address;
    out->port = ep->port;
    return out;
}

static void fill_connection(struct parts *p, uint64_t sock_id, uint16_t proto,
                            const struct ft_endpoint *local, const struct ft_endpoint *remote)
{
    filetrace__v1__connection__init(&p->connection);
    p->connection.socket_id = sock_id;
    p->connection.transport = transport_of(proto);
    p->connection.local =
        fill_endpoint(&p->local, p->local_address, sizeof(p->local_address), local);
    p->connection.remote =
        fill_endpoint(&p->remote, p->remote_address, sizeof(p->remote_address), remote);
}

/* The strings must outlive the message; a connection without a name keeps its fields empty. */
static void fill_names(struct parts *p, const char *name, enum ft_name_source source,
                       const struct ft_remote_names *names)
{
    Connection *c = &p->connection;

    if (name[0]) {
        c->remote_name = (char *)(uintptr_t)name;
        c->remote_name_source = name_source_of(source);
    }
    for (uint32_t i = 0; i < names->listed && i < FT_RESOLVED_NAMES; i++)
        p->resolved[c->n_resolved_names++] = (char *)(uintptr_t)names->resolved[i];
    c->resolved_names = p->resolved;
    c->resolved_name_count = names->count;
}

static void reply(struct ft_grpc_call *call, const ProtobufCMessage *message)
{
    size_t size = protobuf_c_message_get_packed_size(message);
    uint8_t *bytes = malloc(size ? size : 1);

    if (!bytes) {
        ft_grpc_finish(call, FT_GRPC_INTERNAL, "Out of memory");
        return;
    }
    protobuf_c_message_pack(message, bytes);
    if (ft_grpc_send(call, bytes, size))
        ft_grpc_finish(call, FT_GRPC_OK, nullptr);
    else
        ft_grpc_finish(call, FT_GRPC_RESOURCE_EXHAUSTED,
                       "The result is too large. Narrow it with a filter or a limit.");
    free(bytes);
}

static void get_status(struct ft_api *a, struct ft_grpc_call *call)
{
    struct ft_row_stats stats = {0};
    StatusResponse response;

    a->src.stats(a->src.agent, ft_clock_mono_ns(), &stats);
    filetrace__v1__get_status_response__init(&response);
    response.version = stats.version;
    response.host = a->src.host;
    response.platform = (char *)(uintptr_t)ft_platform_name();
    response.backend = stats.backend;
    response.mode = stats.mode;
    response.start_time_unix_nano = stats.start_wall_ns;
    response.degraded = stats.health != FT_HEALTH_OK;
    response.events_processed = stats.events_processed;
    response.events_dropped = stats.events_dropped;
    response.bytes_sent = stats.tx_bytes;
    response.bytes_received = stats.rx_bytes;
    response.active_transfers = stats.active_transfers;
    response.active_processes = stats.active_processes;
    response.open_connections = stats.open_sockets;
    reply(call, &response.base);
}

/* A query that selects what the filter asks for, or nullptr with the reason in why. */
static struct ft_query *query_for(const Filter *f, enum ft_query_kind kind, const char **why)
{
    struct ft_query *q = calloc(1, sizeof(*q));
    uint8_t bits;

    *why = "Out of memory";
    if (!q)
        return nullptr;
    ft_query_init(q, kind);
    if (!f)
        return q;

    *why = nullptr;
    if (strlen(f->process) >= sizeof(q->process) || strlen(f->path) >= sizeof(q->path) ||
        strlen(f->script) >= sizeof(q->script))
        *why = "The process, script or path pattern is too long.";
    else if (f->port > UINT16_MAX)
        *why = "port is not a port number.";
    else if (f->remote[0] && !ft_prefix_parse(f->remote, &q->remote, &bits))
        *why = "remote is neither an IP address nor a CIDR network.";
    else if (f->method > FILETRACE__V1__METHOD__METHOD_READ_WRITE)
        *why = "method is not a known transfer method.";
    else if (f->confidence > FILETRACE__V1__CONFIDENCE__CONFIDENCE_EXACT)
        *why = "confidence is not a known level.";
    else if (f->transport > FILETRACE__V1__TRANSPORT__TRANSPORT_UDP)
        *why = "transport is not a known transport.";
    if (*why) {
        free(q);
        return nullptr;
    }

    q->pid = f->pid;
    ft_strlcpy(q->process, f->process, sizeof(q->process));
    ft_strlcpy(q->script, f->script, sizeof(q->script));
    ft_strlcpy(q->path, f->path, sizeof(q->path));
    if (f->remote[0])
        q->remote_host_bits = (uint8_t)((q->remote.family == 6 ? 128 : 32) - bits);
    q->port = (uint16_t)f->port;
    q->proto = f->transport == FILETRACE__V1__TRANSPORT__TRANSPORT_TCP   ? FT_PROTO_TCP
               : f->transport == FILETRACE__V1__TRANSPORT__TRANSPORT_UDP ? FT_PROTO_UDP
                                                                         : 0;
    if (f->method == FILETRACE__V1__METHOD__METHOD_SENDFILE)
        q->method = FT_METHOD_SENDFILE;
    else if (f->method == FILETRACE__V1__METHOD__METHOD_READ_WRITE)
        q->method = FT_METHOD_READ_SEND;
    if (f->confidence != FILETRACE__V1__CONFIDENCE__CONFIDENCE_UNSPECIFIED)
        q->confidence = (uint8_t)(f->confidence - 1);
    return q;
}

struct listing {
    struct ft_arena arena;
    Transfer **transfers;
    size_t count;
};

static void list_row(void *ctx, uint16_t type, const void *payload, size_t size)
{
    struct listing *l = ctx;
    const struct ft_row_transfer *row = payload;
    const char *names[MAX_EVIDENCE];

    (void)size;
    if (type != FT_MSG_ROW_TRANSFER || l->count == MAX_LISTED)
        return;
    Transfer *t = ft_arena_alloc(&l->arena, sizeof(*t));
    struct parts *p = ft_arena_alloc(&l->arena, sizeof(*p));
    size_t evidence = ft_evidence_names(row->evidence, names, MAX_EVIDENCE);
    char **evidence_names = ft_arena_alloc(&l->arena, MAX_EVIDENCE * sizeof(char *));
    if (!t || !p || !evidence_names)
        return;

    filetrace__v1__transfer__init(t);
    fill_process(p, row->pid, row->ppid, row->comm, ft_arena_text(&l->arena, row->exe));
    struct ft_process_strings strings;
    ft_row_transfer_strings(row, &strings);
    p->process.command_line = ft_arena_text(&l->arena, strings.command_line);
    p->process.working_directory = ft_arena_text(&l->arena, strings.cwd);
    p->process.script = ft_arena_text(&l->arena, strings.script);
    fill_connection(p, row->sock_id, row->proto, &row->local, &row->remote);
    struct ft_remote_names remote_names;
    ft_row_transfer_names(row, &remote_names);
    remote_names.tls = ft_arena_text(&l->arena, remote_names.tls);
    for (uint32_t i = 0; i < remote_names.listed; i++)
        remote_names.resolved[i] = ft_arena_text(&l->arena, remote_names.resolved[i]);
    fill_names(p, ft_remote_name(&remote_names), ft_remote_name_source(&remote_names),
               &remote_names);
    t->id = row->id;
    t->process = &p->process;
    t->connection = &p->connection;
    if (row->flags & FT_XFER_FILE_KNOWN) {
        filetrace__v1__file__init(&p->file);
        p->file.path = ft_arena_text(&l->arena, row->path);
        p->file.inode = row->ino;
        p->file.device = row->dev;
        p->file.size = row->file_size;
        p->file.owner_uid = row->file_uid;
        p->file.filesystem = ft_arena_text(&l->arena, row->fs_type);
        p->file.deleted = (row->flags & FT_XFER_FILE_DELETED) != 0;
        p->file.path_truncated = (row->flags & FT_XFER_PATH_TRUNCATED) != 0;
        t->file = &p->file;
    }
    t->method = method_of(row->method);
    t->confidence = confidence_of(row->confidence);
    for (size_t i = 0; i < evidence; i++)
        evidence_names[i] = (char *)(uintptr_t)names[i];
    t->evidence = evidence_names;
    t->n_evidence = evidence;
    t->bytes_sent = row->bytes;
    t->bytes_read = row->read_bytes;
    t->bytes_per_second = row->rate;
    t->operations = row->ops;
    t->start_time_unix_nano = row->first_wall_ns;
    t->last_time_unix_nano = row->last_wall_ns;
    t->active = (row->flags & FT_XFER_ACTIVE) != 0;
    t->incomplete = (row->flags & FT_XFER_INCOMPLETE) != 0;
    l->transfers[l->count++] = t;
}

static void list_transfers(struct ft_api *a, struct ft_grpc_call *call, const ListRequest *request)
{
    const char *why;
    struct ft_query *q = query_for(request->filter, FT_Q_TRANSFERS, &why);
    struct listing l = {0};
    struct ft_msg_end end = {0};
    struct ft_error err = {0};
    ListResponse response;

    if (!q) {
        ft_grpc_finish(call, FT_GRPC_INVALID_ARGUMENT, why);
        return;
    }
    if (request->active_only)
        q->flags |= FT_QF_ACTIVE;
    if (request->include_unattributed)
        q->flags |= FT_QF_INCLUDE_UNKNOWN;
    q->min_bytes = request->min_bytes;
    q->limit = request->limit && request->limit < MAX_LISTED ? request->limit : MAX_LISTED;

    l.transfers = ft_arena_alloc(&l.arena, MAX_LISTED * sizeof(Transfer *));
    if (!l.transfers) {
        ft_grpc_finish(call, FT_GRPC_INTERNAL, "Out of memory");
    } else if (!ft_state_query(a->src.state, q, ft_clock_mono_ns(), list_row, &l, &end, &err)) {
        ft_grpc_finish(call, FT_GRPC_INVALID_ARGUMENT, err.msg);
    } else if (l.arena.failed) {
        ft_grpc_finish(call, FT_GRPC_INTERNAL, "Out of memory");
    } else {
        filetrace__v1__list_transfers_response__init(&response);
        response.transfers = l.transfers;
        response.n_transfers = l.count;
        response.observed_since_unix_nano = end.observed_since_wall_ns;
        response.lost_events = end.lost_events;
        reply(call, &response.base);
    }
    ft_arena_release(&l.arena);
    free(q);
}

static void watch_transfers(struct ft_api *a, struct ft_grpc_call *call,
                            const WatchRequest *request)
{
    const char *why;

    if (a->watcher_count == MAX_WATCHERS) {
        ft_grpc_finish(call, FT_GRPC_RESOURCE_EXHAUSTED, "Too many watchers.");
        return;
    }
    struct ft_query *q = query_for(request->filter, FT_Q_EVENTS, &why);
    if (!q) {
        ft_grpc_finish(call, FT_GRPC_INVALID_ARGUMENT, why);
        return;
    }
    q->event_types = 1u << FT_REC_FILE_TRANSFER;
    a->watchers[a->watcher_count++] = (struct watcher){.call = call, .query = q};
    ft_grpc_start(call);
}

static bool wanted(const struct watcher *w, const struct ft_row_event *row)
{
    const struct ft_query *q = w->query;

    if (!ft_state_record_matches(q, 0, UINT64_MAX, row))
        return false;
    if (q->method != FT_METHOD_ANY && q->method != row->method)
        return false;
    if (q->confidence != FT_CONF_ANY &&
        !((row->flags & FT_EVENT_HAS_CONFIDENCE) && q->confidence == row->confidence))
        return false;
    return true;
}

void ft_api_record(struct ft_api *a, const struct ft_row_event *row)
{
    static char path[FT_PATH_MAX];
    static char command_line[FT_CMDLINE_MAX];
    static char cwd[FT_PATH_MAX];
    static char script[FT_PATH_MAX];
    static char none[1];
    static uint8_t bytes[FT_PATH_MAX + FT_PROCESS_TEXT_MAX + FT_NAMES_TEXT_MAX + 512];
    struct parts parts;
    struct ft_remote_names names;
    TransferEvent event;
    WatchResponse response;
    bool described = false;

    if (!a || row->type != FT_REC_FILE_TRANSFER || a->watcher_count == 0)
        return;
    ft_telemetry_transfer_names(&a->src, row, &names);
    for (size_t i = 0; i < a->watcher_count; i++) {
        struct watcher *w = &a->watchers[i];

        if (!wanted(w, row))
            continue;
        if (!described) {
            described = true;
            ft_utf8_copy(path, row->text, sizeof(path));
            struct ft_process_strings strings;
            ft_row_event_strings(row, &strings);
            ft_utf8_copy(command_line, strings.command_line, sizeof(command_line));
            ft_utf8_copy(cwd, strings.cwd, sizeof(cwd));
            ft_utf8_copy(script, strings.script, sizeof(script));
            fill_process(&parts, row->pid, row->ppid, row->comm, none);
            parts.process.command_line = command_line;
            parts.process.working_directory = cwd;
            parts.process.script = script;
            fill_connection(&parts, row->sock_id, row->proto, &row->local, &row->remote);
            fill_names(&parts, ft_row_event_name(row), (enum ft_name_source)row->name_source,
                       &names);
            filetrace__v1__file__init(&parts.file);
            parts.file.path = path;
            parts.file.inode = row->ino;
            parts.file.device = row->dev;
            parts.file.size = row->file_size;
            parts.file.deleted = (row->flags & FT_EVENT_FILE_DELETED) != 0;

            filetrace__v1__transfer_event__init(&event);
            event.sequence = row->seq;
            event.time_unix_nano = ft_clock_mono_to_wall(row->time_ns);
            event.process = &parts.process;
            event.file = &parts.file;
            event.connection = &parts.connection;
            event.method = method_of(row->method);
            if (row->flags & FT_EVENT_HAS_CONFIDENCE)
                event.confidence = confidence_of(row->confidence);
            event.bytes_sent = row->bytes;
            event.bytes_read = row->read_bytes;
        }
        filetrace__v1__watch_transfers_response__init(&response);
        response.event = &event;
        response.missed = w->missed;
        size_t size = filetrace__v1__watch_transfers_response__get_packed_size(&response);
        if (size <= sizeof(bytes))
            filetrace__v1__watch_transfers_response__pack(&response, bytes);
        if (size <= sizeof(bytes) && ft_grpc_send(w->call, bytes, size))
            w->missed = 0;
        else
            w->missed++;
    }
}

static void on_call(void *ctx, struct ft_grpc_call *call, const char *path, const uint8_t *request,
                    size_t size)
{
    static const char service[] = "/filetrace.v1.FiletraceService/";
    struct ft_api *a = ctx;
    const ProtobufCMethodDescriptor *method =
        strncmp(path, service, sizeof(service) - 1) == 0
            ? protobuf_c_service_descriptor_get_method_by_name(
                  &filetrace__v1__filetrace_service__descriptor, path + sizeof(service) - 1)
            : nullptr;

    if (!method) {
        ft_grpc_finish(call, FT_GRPC_UNIMPLEMENTED, "No such method.");
        return;
    }
    ProtobufCMessage *message = protobuf_c_message_unpack(method->input, nullptr, size, request);
    if (!message) {
        ft_grpc_finish(call, FT_GRPC_INVALID_ARGUMENT, "The request is not what the method takes.");
        return;
    }
    if (strcmp(method->name, "GetStatus") == 0)
        get_status(a, call);
    else if (strcmp(method->name, "ListTransfers") == 0)
        list_transfers(a, call, (const ListRequest *)message);
    else if (strcmp(method->name, "WatchTransfers") == 0)
        watch_transfers(a, call, (const WatchRequest *)message);
    else
        ft_grpc_finish(call, FT_GRPC_UNIMPLEMENTED, "No such method.");
    protobuf_c_message_free_unpacked(message, nullptr);
}

static void on_end(void *ctx, struct ft_grpc_call *call)
{
    struct ft_api *a = ctx;

    for (size_t i = 0; i < a->watcher_count; i++) {
        if (a->watchers[i].call != call)
            continue;
        free(a->watchers[i].query);
        a->watchers[i] = a->watchers[--a->watcher_count];
        return;
    }
}

struct ft_api *ft_api_open(const struct ft_api_config *cfg, const struct ft_telemetry_source *src,
                           struct ft_error *err)
{
    struct ft_net_addr addr;
    struct ft_error why = {0};

    if (!ft_net_addr_parse(cfg->listen, &addr)) {
        ft_error_set(err, FT_EXIT_CONFIG,
                     "[grpc] listen = \"%s\" is neither \"unix:\" and a socket path nor a "
                     "numeric address and port, such as \"127.0.0.1:9500\".",
                     cfg->listen);
        return nullptr;
    }
    struct ft_api *a = calloc(1, sizeof(*a));
    if (!a) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return nullptr;
    }
    a->src = *src;

    bool is_unix = ft_net_addr_is_unix(&addr);
    int fd = ft_net_listen(&addr, &why);
    struct ft_grpc_service service = {.ctx = a, .on_call = on_call, .on_end = on_end};
    if (fd >= 0)
        a->server = ft_grpc_server_new(fd, is_unix, &service);
    if (!a->server) {
        ft_error_set(err, fd < 0 ? why.code : FT_EXIT_ERROR, "Cannot serve the gRPC API on %s: %s",
                     cfg->listen, fd < 0 ? why.msg : "out of memory");
        if (fd >= 0)
            close(fd);
        free(a);
        return nullptr;
    }
    if (is_unix)
        ft_strlcpy(a->socket_path, ((const struct sockaddr_un *)&addr.ss)->sun_path,
                   sizeof(a->socket_path));
    else
        ft_log(FT_LOG_WARN,
               "the gRPC API on %s is open to whoever can connect; a \"unix:\" socket admits "
               "only root and the agent's user",
               cfg->listen);
    ft_log(FT_LOG_INFO, "serving the gRPC API on %s", cfg->listen);
    return a;
}

void ft_api_close(struct ft_api *a)
{
    if (!a)
        return;
    ft_grpc_server_free(a->server);
    for (size_t i = 0; i < a->watcher_count; i++)
        free(a->watchers[i].query);
    if (a->socket_path[0])
        unlink(a->socket_path);
    free(a);
}

void ft_api_poll(struct ft_api *a, struct ft_poller *p)
{
    if (a)
        ft_grpc_server_poll(a->server, p);
}

void ft_api_dispatch(struct ft_api *a, const struct ft_poller *p)
{
    if (a)
        ft_grpc_server_dispatch(a->server, p);
}
