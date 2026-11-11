#include "cmd/cli.h"

#include "exporters/exporters.h"
#include "filetrace/format.h"
#include "filetrace/sysinfo.h"
#include "ui/ui.h"

#include <ctype.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>

enum vtype : uint8_t {
    V_STR,
    V_UINT,
    V_BYTES,
    V_RATE,
    V_TIME,
    V_BOOL,
    V_LIST,
};

struct value {
    enum vtype type;
    bool absent;
    bool b;
    uint64_t u;
    const char *s;
    const char *list[8];
    size_t nlist;
    char buf[FT_PATH_MAX + 64];
};

constexpr unsigned F_VIRTUAL = 0x1; /* table-only combination of other fields */
constexpr unsigned F_UPPER = 0x2;   /* upper case in tables */

struct field {
    const char *key;
    unsigned flags;
    void (*get)(const void *row, struct value *v);
};

struct column {
    const char *title;
    const char *key;
    bool right;
};

struct view {
    const struct field *fields;
    size_t nfields;
    const struct column *columns;
    size_t ncolumns;
    const char *quiet_key;
    size_t row_size;
};

static void set_str(struct value *v, const char *s)
{
    v->type = V_STR;
    v->s = s;
    v->absent = !s || !s[0];
}

static void set_uint(struct value *v, uint64_t u)
{
    v->type = V_UINT;
    v->u = u;
}

static void set_bytes(struct value *v, uint64_t u)
{
    v->type = V_BYTES;
    v->u = u;
}

static void set_rate(struct value *v, uint64_t bytes_per_second)
{
    v->type = V_RATE;
    v->u = bytes_per_second;
}

static void set_time(struct value *v, uint64_t wall_ns)
{
    v->type = V_TIME;
    v->u = wall_ns;
    v->absent = wall_ns == 0;
}

static void set_bool(struct value *v, bool b)
{
    v->type = V_BOOL;
    v->b = b;
}

static void set_addr(struct value *v, const struct ft_endpoint *ep)
{
    ft_addr_format(ep, v->buf, sizeof(v->buf));
    set_str(v, v->buf);
    v->absent = ep->family == 0;
}

static void set_port(struct value *v, const struct ft_endpoint *ep)
{
    set_uint(v, ep->port);
    v->absent = ep->port == 0;
}

static void set_endpoint(struct value *v, const struct ft_endpoint *ep)
{
    if (ep->family == 0 && ep->port == 0)
        ft_strlcpy(v->buf, "*", sizeof(v->buf));
    else
        ft_endpoint_format(ep, v->buf, sizeof(v->buf));
    set_str(v, v->buf);
}

static void set_proto(struct value *v, uint16_t proto)
{
    char tmp[8];
    ft_strlcpy(v->buf, ft_proto_name(proto, tmp), sizeof(v->buf));
    set_str(v, v->buf);
    v->absent = proto == 0;
}

static void set_user(struct value *v, uint32_t uid)
{
    static uint32_t cached_uid = UINT32_MAX;
    static char cached_name[64];

    if (uid != cached_uid || !cached_name[0]) {
        const struct passwd *pw = getpwuid((uid_t)uid);
        if (pw)
            ft_strlcpy(cached_name, pw->pw_name, sizeof(cached_name));
        else
            snprintf(cached_name, sizeof(cached_name), "%" PRIu32, uid);
        cached_uid = uid;
    }
    set_str(v, cached_name);
}

static void set_id(struct value *v, uint64_t id)
{
    set_uint(v, id);
    v->absent = id == 0;
}

#define ROW(type) const struct type *r = row

static void p_pid(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->pid);
}
static void p_ppid(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->ppid);
}
static void p_name(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_str(v, r->comm);
}
static void p_user(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_user(v, r->uid);
}
static void p_uid(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->uid);
}
static void p_gid(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->gid);
}
static void p_exe(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_str(v, r->exe);
}
static void p_tx(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_bytes(v, r->tx_bytes);
}
static void p_rx(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_bytes(v, r->rx_bytes);
}

static void p_tx_rate(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_rate(v, r->tx_rate);
}

static void p_rx_rate(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_rate(v, r->rx_rate);
}

static void p_conns(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->connections);
}

static void p_transfers(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->files_sent);
}

static void p_started(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_time(v, r->start_wall_ns);
}

static void p_status(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_str(v, (r->flags & FT_PROC_EXITED) ? "exited" : "running");
}

static void p_cgroup(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->cgroup_id);
    v->absent = r->cgroup_id == 0;
}

static void p_pidns(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->pidns);
    v->absent = r->pidns == 0;
}

static void p_mntns(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->mntns);
    v->absent = r->mntns == 0;
}

static void p_netns(const void *row, struct value *v)
{
    ROW(ft_row_process);
    set_uint(v, r->netns);
    v->absent = r->netns == 0;
}

static const struct field process_fields[] = {
    {"pid", 0, p_pid},
    {"ppid", 0, p_ppid},
    {"name", 0, p_name},
    {"user", 0, p_user},
    {"uid", 0, p_uid},
    {"gid", 0, p_gid},
    {"executable", 0, p_exe},
    {"outbound_bytes", 0, p_tx},
    {"inbound_bytes", 0, p_rx},
    {"outbound_bytes_per_second", 0, p_tx_rate},
    {"inbound_bytes_per_second", 0, p_rx_rate},
    {"connections", 0, p_conns},
    {"transfers", 0, p_transfers},
    {"started", 0, p_started},
    {"status", 0, p_status},
    {"cgroup_id", 0, p_cgroup},
    {"pid_namespace", 0, p_pidns},
    {"mount_namespace", 0, p_mntns},
    {"network_namespace", 0, p_netns},
};

static const struct column process_columns[] = {
    {"PID", "pid", false},
    {"PPID", "ppid", false},
    {"PROCESS", "name", false},
    {"USER", "user", false},
    {"OUTBOUND", "outbound_bytes", true},
    {"INBOUND", "inbound_bytes", true},
};

static void c_proto(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_proto(v, r->proto);
}

static void c_pid(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_uint(v, r->pid);
    v->absent = r->pid == 0;
}

static void c_process(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_str(v, r->comm);
}

static void c_local(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_endpoint(v, &r->local);
}

static void c_remote(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_endpoint(v, &r->remote);
}

static void c_laddr(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_addr(v, &r->local);
}

static void c_lport(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_port(v, &r->local);
}

static void c_raddr(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_addr(v, &r->remote);
}

static void c_rport(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_port(v, &r->remote);
}

static void c_state(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_str(v, ft_sock_state_name((enum ft_sock_state)r->state));
}

static void c_tx(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_bytes(v, r->tx_bytes);
}

static void c_rx(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_bytes(v, r->rx_bytes);
}

static void c_tx_rate(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_rate(v, r->tx_rate);
}

static void c_rx_rate(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_rate(v, r->rx_rate);
}

static void c_sock(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_id(v, r->sock_id);
}

static void c_first(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_time(v, r->first_wall_ns);
}

static void c_last(const void *row, struct value *v)
{
    ROW(ft_row_connection);
    set_time(v, r->last_wall_ns);
}

static const struct field connection_fields[] = {
    {"socket_id", 0, c_sock},
    {"protocol", F_UPPER, c_proto},
    {"pid", 0, c_pid},
    {"process", 0, c_process},
    {"@local", F_VIRTUAL, c_local},
    {"@remote", F_VIRTUAL, c_remote},
    {"local_address", 0, c_laddr},
    {"local_port", 0, c_lport},
    {"remote_address", 0, c_raddr},
    {"remote_port", 0, c_rport},
    {"state", F_UPPER, c_state},
    {"sent_bytes", 0, c_tx},
    {"received_bytes", 0, c_rx},
    {"sent_bytes_per_second", 0, c_tx_rate},
    {"received_bytes_per_second", 0, c_rx_rate},
    {"first_seen", 0, c_first},
    {"last_seen", 0, c_last},
};

static const struct column connection_columns[] = {
    {"PROTO", "protocol", false}, {"PID", "pid", false},        {"PROCESS", "process", false},
    {"LOCAL", "@local", false},   {"REMOTE", "@remote", false}, {"STATE", "state", false},
};

static void f_proto(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_proto(v, r->proto);
}
static void f_pid(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_uint(v, r->pid);
}
static void f_process(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_str(v, r->comm);
}
static void f_tx(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_bytes(v, r->tx_bytes);
}
static void f_rx(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_bytes(v, r->rx_bytes);
}
static void f_tx_rate(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_rate(v, r->tx_rate);
}

static void f_rx_rate(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_rate(v, r->rx_rate);
}

static void f_txops(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_uint(v, r->tx_ops);
}
static void f_rxops(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_uint(v, r->rx_ops);
}

static void f_local(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_endpoint(v, &r->local);
}

static void f_remote(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_endpoint(v, &r->remote);
}

static void f_laddr(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_addr(v, &r->local);
}

static void f_lport(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_port(v, &r->local);
}

static void f_raddr(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_addr(v, &r->remote);
}

static void f_rport(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_port(v, &r->remote);
}

static void f_sock(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_id(v, r->sock_id);
}

static void f_id(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_id(v, r->id);
}

static void f_first(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_time(v, r->first_wall_ns);
}

static void f_last(const void *row, struct value *v)
{
    ROW(ft_row_flow);
    set_time(v, r->last_wall_ns);
}

static const struct field flow_fields[] = {
    {"flow_id", 0, f_id},
    {"socket_id", 0, f_sock},
    {"protocol", F_UPPER, f_proto},
    {"pid", 0, f_pid},
    {"process", 0, f_process},
    {"@local", F_VIRTUAL, f_local},
    {"@remote", F_VIRTUAL, f_remote},
    {"local_address", 0, f_laddr},
    {"local_port", 0, f_lport},
    {"remote_address", 0, f_raddr},
    {"remote_port", 0, f_rport},
    {"sent_bytes", 0, f_tx},
    {"received_bytes", 0, f_rx},
    {"sent_bytes_per_second", 0, f_tx_rate},
    {"received_bytes_per_second", 0, f_rx_rate},
    {"send_operations", 0, f_txops},
    {"receive_operations", 0, f_rxops},
    {"first_seen", 0, f_first},
    {"last_seen", 0, f_last},
};

static const struct column flow_columns[] = {
    {"PROCESS", "process", false}, {"PROTO", "protocol", false},
    {"LOCAL", "@local", false},    {"REMOTE", "@remote", false},
    {"SENT", "sent_bytes", true},  {"RECEIVED", "received_bytes", true},
};

static struct ft_host_info host_info;

void ft_transfer_id_format(const struct ft_row_transfer *row, char *buf, size_t size)
{
    /* Bytes with no associated file are identified by their socket. */
    snprintf(buf, size, (row->flags & FT_XFER_FILE_KNOWN) ? "tr_%" PRIx64 : "tr_s%" PRIx64,
             row->id);
}

static void t_event(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, (r->flags & FT_XFER_ACTIVE) ? "transfer.progress" : "transfer.completed");
}

static void t_id(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    ft_transfer_id_format(r, v->buf, sizeof(v->buf));
    set_str(v, v->buf);
}

static void t_timestamp(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_time(v, r->last_wall_ns);
}

static void t_host(const void *row, struct value *v)
{
    (void)row;
    if (!host_info.hostname[0])
        ft_sysinfo_host(&host_info);
    set_str(v, host_info.hostname);
}

static void t_platform(const void *row, struct value *v)
{
    (void)row;
    set_str(v, ft_platform_name());
}

static void t_pid(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_uint(v, r->pid);
}
static void t_name(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, r->comm);
}
static void t_exe(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, r->exe);
}

static void t_ppid(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_uint(v, r->ppid);
    v->absent = r->ppid == 0;
}

static void t_path(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, r->path);
    v->absent = !(r->flags & FT_XFER_PATH_KNOWN);
}

static void t_inode(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_uint(v, r->ino);
    v->absent = !(r->flags & FT_XFER_FILE_KNOWN);
}

static void t_device(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_uint(v, r->dev);
    v->absent = !(r->flags & FT_XFER_FILE_KNOWN);
}

static void t_file_size(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_bytes(v, r->file_size);
    v->absent = !(r->flags & FT_XFER_PATH_KNOWN);
}

static void t_file_owner(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_user(v, r->file_uid);
    v->absent = !(r->flags & FT_XFER_PATH_KNOWN);
}

static void t_fs(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, r->fs_type);
}

static void t_deleted(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_bool(v, (r->flags & FT_XFER_FILE_DELETED) != 0);
    v->absent = !(r->flags & FT_XFER_FILE_KNOWN);
}

static void t_file_column(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    const char *deleted = (r->flags & FT_XFER_FILE_DELETED) ? " (deleted)" : "";

    if (r->flags & FT_XFER_PATH_KNOWN)
        snprintf(v->buf, sizeof(v->buf), "%s%s", r->path, deleted);
    else if (r->flags & FT_XFER_FILE_KNOWN)
        snprintf(v->buf, sizeof(v->buf), "(device %" PRIu64 " inode %" PRIu64 ")%s", r->dev, r->ino,
                 deleted);
    else
        ft_strlcpy(v->buf, "unknown", sizeof(v->buf));
    set_str(v, v->buf);
}

static void t_proto(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_proto(v, r->proto);
}

static void t_laddr(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_addr(v, &r->local);
}

static void t_lport(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_port(v, &r->local);
}

static void t_raddr(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_addr(v, &r->remote);
}

static void t_rport(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_port(v, &r->remote);
}

static void t_remote(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_endpoint(v, &r->remote);
}

static void t_sock(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_id(v, r->sock_id);
}

static void t_method(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, ft_method_name((enum ft_method)r->method));
    v->absent = r->method == FT_METHOD_NONE;
}

static void t_method_column(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, r->method == FT_METHOD_NONE ? "-" : ft_method_name((enum ft_method)r->method));
}

static void t_bytes(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_bytes(v, r->bytes);
}

static void t_read_bytes(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_bytes(v, r->read_bytes);
    v->absent = r->method != FT_METHOD_READ_SEND;
}

static void t_rate(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_rate(v, r->rate);
}

static void t_ops(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_uint(v, r->ops);
    v->absent = r->method == FT_METHOD_NONE;
}

static void t_duration(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    uint64_t ns = r->last_wall_ns > r->first_wall_ns ? r->last_wall_ns - r->first_wall_ns : 0;
    set_uint(v, ns / FT_NS_PER_MS);
}

static void t_state(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, (r->flags & FT_XFER_ACTIVE) ? "active" : "completed");
}

static void t_confidence(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_str(v, ft_confidence_name((enum ft_confidence)r->confidence));
}

static void t_confidence_column(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    snprintf(v->buf, sizeof(v->buf), "%s%s", ft_confidence_name((enum ft_confidence)r->confidence),
             (r->flags & FT_XFER_INCOMPLETE) ? "*" : "");
    set_str(v, v->buf);
}

static void t_evidence(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    v->type = V_LIST;
    v->nlist = ft_evidence_names(r->evidence, v->list, FT_ARRAY_LEN(v->list));
}

static void t_incomplete(const void *row, struct value *v)
{
    ROW(ft_row_transfer);
    set_bool(v, (r->flags & FT_XFER_INCOMPLETE) != 0);
}

static const struct field transfer_fields[] = {
    {"event", 0, t_event},
    {"transfer_id", 0, t_id},
    {"timestamp", 0, t_timestamp},
    {"host", 0, t_host},
    {"platform", 0, t_platform},
    {"process.pid", 0, t_pid},
    {"process.ppid", 0, t_ppid},
    {"process.name", 0, t_name},
    {"process.executable", 0, t_exe},
    {"file.path", 0, t_path},
    {"file.inode", 0, t_inode},
    {"file.device", 0, t_device},
    {"file.size", 0, t_file_size},
    {"file.owner", 0, t_file_owner},
    {"file.filesystem", 0, t_fs},
    {"file.deleted", 0, t_deleted},
    {"network.protocol", 0, t_proto},
    {"network.socket_id", 0, t_sock},
    {"network.local_address", 0, t_laddr},
    {"network.local_port", 0, t_lport},
    {"network.remote_address", 0, t_raddr},
    {"network.remote_port", 0, t_rport},
    {"transfer.method", 0, t_method},
    {"transfer.bytes", 0, t_bytes},
    {"transfer.bytes_read", 0, t_read_bytes},
    {"transfer.bytes_per_second", 0, t_rate},
    {"transfer.operations", 0, t_ops},
    {"transfer.duration_ms", 0, t_duration},
    {"transfer.state", 0, t_state},
    {"attribution.confidence", 0, t_confidence},
    {"attribution.evidence", 0, t_evidence},
    {"attribution.incomplete", 0, t_incomplete},
    {"@file", F_VIRTUAL, t_file_column},
    {"@remote", F_VIRTUAL, t_remote},
    {"@method", F_VIRTUAL, t_method_column},
    {"@confidence", F_VIRTUAL | F_UPPER, t_confidence_column},
};

static const struct column file_columns[] = {
    {"FILE", "@file", false},           {"PID", "process.pid", false},
    {"PROCESS", "process.name", false}, {"REMOTE", "@remote", false},
    {"SENT", "transfer.bytes", true},   {"CONFIDENCE", "@confidence", false},
};

static const struct column transfer_columns[] = {
    {"ID", "transfer_id", false},
    {"PROCESS", "process.name", false},
    {"FILE", "@file", false},
    {"REMOTE", "@remote", false},
    {"BYTES", "transfer.bytes", true},
    {"METHOD", "@method", false},
    {"CONFIDENCE", "@confidence", false},
};

static const struct view views[] = {
    [FT_VIEW_PROCESSES] = {process_fields, FT_ARRAY_LEN(process_fields), process_columns,
                           FT_ARRAY_LEN(process_columns), "pid", sizeof(struct ft_row_process)},
    [FT_VIEW_CONNECTIONS] = {connection_fields, FT_ARRAY_LEN(connection_fields), connection_columns,
                             FT_ARRAY_LEN(connection_columns), "socket_id",
                             sizeof(struct ft_row_connection)},
    [FT_VIEW_FLOWS] = {flow_fields, FT_ARRAY_LEN(flow_fields), flow_columns,
                       FT_ARRAY_LEN(flow_columns), "flow_id", sizeof(struct ft_row_flow)},
    [FT_VIEW_FILES] = {transfer_fields, FT_ARRAY_LEN(transfer_fields), file_columns,
                       FT_ARRAY_LEN(file_columns), "file.path", sizeof(struct ft_row_transfer)},
    [FT_VIEW_TRANSFERS] = {transfer_fields, FT_ARRAY_LEN(transfer_fields), transfer_columns,
                           FT_ARRAY_LEN(transfer_columns), "transfer_id",
                           sizeof(struct ft_row_transfer)},
};

static const struct field *find_field(const struct view *view, const char *key)
{
    for (size_t i = 0; i < view->nfields; i++) {
        if (strcmp(view->fields[i].key, key) == 0)
            return &view->fields[i];
    }
    return nullptr;
}

static void get_value(const struct field *f, const void *row, struct value *v)
{
    v->type = V_STR;
    v->absent = false;
    v->b = false;
    v->u = 0;
    v->s = nullptr;
    v->nlist = 0;
    f->get(row, v);
}

/* Text of a value for tables; exact is true for CSV and quiet output. */
static const char *value_text(const struct field *f, struct value *v, bool exact, char *buf,
                              size_t size)
{
    if (v->absent)
        return exact ? "" : "-";

    switch (v->type) {
    case V_STR:
        if (!exact && (f->flags & F_UPPER)) {
            size_t i = 0;
            for (; v->s[i] && i + 1 < size; i++)
                buf[i] = (char)toupper((unsigned char)v->s[i]);
            buf[i] = '\0';
            return buf;
        }
        return v->s;
    case V_UINT:
        snprintf(buf, size, "%" PRIu64, v->u);
        return buf;
    case V_BYTES:
        if (exact)
            snprintf(buf, size, "%" PRIu64, v->u);
        else
            ft_format_bytes(v->u, buf, size);
        return buf;
    case V_RATE:
        if (exact)
            snprintf(buf, size, "%" PRIu64, v->u);
        else
            ft_format_rate(v->u, buf, size);
        return buf;
    case V_TIME:
        if (exact)
            ft_format_time_rfc3339(v->u, buf, size);
        else
            ft_format_time_local(v->u, buf, size);
        return buf;
    case V_BOOL:
        return v->b ? (exact ? "true" : "yes") : (exact ? "false" : "no");
    case V_LIST: {
        size_t out = 0;
        buf[0] = '\0';
        for (size_t i = 0; i < v->nlist; i++) {
            int n =
                snprintf(buf + out, size - out, "%s%s", i ? (exact ? ";" : ", ") : "", v->list[i]);
            if (n < 0 || (size_t)n >= size - out)
                break;
            out += (size_t)n;
        }
        return buf;
    }
    }
    return "";
}

struct table_ctx {
    const struct view *view;
    const struct ft_rows *rows;
    const struct field **fields; /* per column */
    bool rank;
    size_t loaded;
    void *row;
    struct value *value;
};

static const char *table_cell(void *ctx, size_t r, size_t c, char *buf, size_t size)
{
    struct table_ctx *t = ctx;

    if (t->rank) {
        if (c == 0) {
            snprintf(buf, size, "%zu", r + 1);
            return buf;
        }
        c--;
    }
    if (t->loaded != r) {
        ft_rows_get(t->rows, r, t->row, t->view->row_size);
        t->loaded = r;
    }
    get_value(t->fields[c], t->row, t->value);
    return value_text(t->fields[c], t->value, false, buf, size);
}

static void render_table(const struct view *view, const struct ft_rows *rows,
                         const struct ft_output *out, bool rank, void *row, struct value *value)
{
    struct ft_column_spec specs[16];
    const struct field *fields[16];
    size_t ncols = 0;

    if (rank)
        specs[ncols++] = (struct ft_column_spec){"RANK", false};
    for (size_t i = 0; i < view->ncolumns && ncols < FT_ARRAY_LEN(specs); i++) {
        fields[i] = find_field(view, view->columns[i].key);
        specs[ncols++] = (struct ft_column_spec){view->columns[i].title, view->columns[i].right};
    }

    struct table_ctx ctx = {
        .view = view,
        .rows = rows,
        .fields = fields,
        .rank = rank,
        .loaded = SIZE_MAX,
        .row = row,
        .value = value,
    };
    ft_table_print(out->stream, specs, ncols, rows->count, table_cell, &ctx,
                   ft_term_styled(out->stream));
}

static void json_value(FILE *o, const struct field *f, struct value *v, char *buf, size_t size)
{
    switch (v->type) {
    case V_UINT:
    case V_BYTES:
    case V_RATE:
        fprintf(o, "%" PRIu64, v->u);
        break;
    case V_BOOL:
        fputs(v->b ? "true" : "false", o);
        break;
    case V_LIST:
        fputc('[', o);
        for (size_t i = 0; i < v->nlist; i++) {
            if (i)
                fputc(',', o);
            ft_json_string(o, v->list[i]);
        }
        fputc(']', o);
        break;
    default:
        ft_json_string(o, value_text(f, v, true, buf, size));
        break;
    }
}

/* Keys of the form "group.name" become members of a nested "group" object. */
static void json_object(FILE *o, const struct view *view, const void *row, struct value *v,
                        char *buf, size_t size)
{
    const char *group = nullptr;
    size_t group_len = 0;
    bool first_top = true;
    bool first_inner = true;

    fputc('{', o);
    for (size_t i = 0; i < view->nfields; i++) {
        const struct field *f = &view->fields[i];
        if (f->flags & F_VIRTUAL)
            continue;
        get_value(f, row, v);
        if (v->absent || (v->type == V_LIST && v->nlist == 0))
            continue;

        const char *dot = strchr(f->key, '.');
        size_t prefix_len = dot ? (size_t)(dot - f->key) : 0;
        const char *name = dot ? dot + 1 : f->key;

        bool same_group =
            group && prefix_len == group_len && strncmp(group, f->key, group_len) == 0;
        if (group && !same_group) {
            fputc('}', o);
            group = nullptr;
        }
        if (prefix_len && !group) {
            if (!first_top)
                fputc(',', o);
            first_top = false;
            fprintf(o, "\"%.*s\":{", (int)prefix_len, f->key);
            group = f->key;
            group_len = prefix_len;
            first_inner = true;
        }

        if (group) {
            if (!first_inner)
                fputc(',', o);
            first_inner = false;
        } else {
            if (!first_top)
                fputc(',', o);
            first_top = false;
        }
        fprintf(o, "\"%s\":", name);
        json_value(o, f, v, buf, size);
    }
    if (group)
        fputc('}', o);
    fputc('}', o);
}

void ft_view_render(enum ft_view_id id, const struct ft_rows *rows, const struct ft_output *out,
                    bool rank)
{
    const struct view *view = &views[id];
    FILE *o = out->stream;
    void *row = malloc(view->row_size);
    struct value *v = malloc(sizeof(*v));
    size_t size = FT_PATH_MAX + 64;
    char *buf = malloc(size);

    if (!row || !v || !buf) {
        free(row);
        free(v);
        free(buf);
        return;
    }

    switch (out->format) {
    case FT_FMT_TABLE:
        render_table(view, rows, out, rank, row, v);
        break;

    case FT_FMT_JSON:
    case FT_FMT_JSONL:
        if (out->format == FT_FMT_JSON)
            fputc('[', o);
        for (size_t r = 0; r < rows->count; r++) {
            ft_rows_get(rows, r, row, view->row_size);
            if (out->format == FT_FMT_JSON)
                fputs(r ? ",\n " : "\n ", o);
            json_object(o, view, row, v, buf, size);
            if (out->format == FT_FMT_JSONL)
                fputc('\n', o);
        }
        if (out->format == FT_FMT_JSON)
            fputs(rows->count ? "\n]\n" : "]\n", o);
        break;

    case FT_FMT_CSV: {
        bool first = true;
        for (size_t i = 0; i < view->nfields; i++) {
            if (view->fields[i].flags & F_VIRTUAL)
                continue;
            fprintf(o, "%s%s", first ? "" : ",", view->fields[i].key);
            first = false;
        }
        fputc('\n', o);
        for (size_t r = 0; r < rows->count; r++) {
            ft_rows_get(rows, r, row, view->row_size);
            first = true;
            for (size_t i = 0; i < view->nfields; i++) {
                const struct field *f = &view->fields[i];
                if (f->flags & F_VIRTUAL)
                    continue;
                if (!first)
                    fputc(',', o);
                first = false;
                get_value(f, row, v);
                ft_csv_field(o, value_text(f, v, true, buf, size));
            }
            fputc('\n', o);
        }
        break;
    }

    case FT_FMT_QUIET: {
        const struct field *f = find_field(view, view->quiet_key);
        for (size_t r = 0; r < rows->count; r++) {
            ft_rows_get(rows, r, row, view->row_size);
            get_value(f, row, v);
            if (!v->absent)
                fprintf(o, "%s\n", value_text(f, v, true, buf, size));
        }
        break;
    }
    }

    free(row);
    free(v);
    free(buf);
}
