#include "filetrace/capabilities.h"

#include <stdarg.h>
#include <stdio.h>

static const struct {
    const char *title;
    const char *key;
} features[FT_FEAT_COUNT] = {
    [FT_FEAT_PROCESS] = {"Process tracking", "process_tracking"},
    [FT_FEAT_FILE_OPEN] = {"File open tracking", "file_open_tracking"},
    [FT_FEAT_FILE_READ] = {"File read tracking", "file_read_tracking"},
    [FT_FEAT_FILE_WRITE] = {"File write tracking", "file_write_tracking"},
    [FT_FEAT_TCP] = {"TCP tracking", "tcp_tracking"},
    [FT_FEAT_UDP] = {"UDP tracking", "udp_tracking"},
    [FT_FEAT_IPV6] = {"IPv6", "ipv6"},
    [FT_FEAT_SENDFILE] = {"Sendfile attribution", "sendfile_attribution"},
    [FT_FEAT_READ_SEND] = {"Read+send correlation", "read_send_correlation"},
    [FT_FEAT_SPLICE] = {"Splice attribution", "splice_attribution"},
    [FT_FEAT_IO_URING] = {"io_uring attribution", "io_uring_attribution"},
    [FT_FEAT_MMAP] = {"Mmap provenance", "mmap_provenance"},
    [FT_FEAT_PACKET_EGRESS] = {"Packet-level egress", "packet_level_egress"},
    [FT_FEAT_NAMESPACES] = {"Container namespaces", "container_namespaces"},
    [FT_FEAT_DESTINATION_NAMES] = {"Destination names", "destination_names"},
    [FT_FEAT_PHP_SCRIPTS] = {"PHP request scripts", "php_request_scripts"},
};

const char *ft_feature_title(enum ft_feature f)
{
    return f < FT_FEAT_COUNT ? features[f].title : "";
}

const char *ft_feature_key(enum ft_feature f)
{
    return f < FT_FEAT_COUNT ? features[f].key : "";
}

const char *ft_cap_status_name(enum ft_cap_status s)
{
    switch (s) {
    case FT_CAP_FULL:
        return "FULL";
    case FT_CAP_PARTIAL:
        return "PARTIAL";
    case FT_CAP_DISABLED:
        return "DISABLED";
    default:
        return "UNAVAILABLE";
    }
}

void ft_capability_set(struct ft_capabilities *caps, enum ft_feature f, enum ft_cap_status status,
                       const char *reason_fmt, ...)
{
    va_list ap;
    if (f >= FT_FEAT_COUNT)
        return;
    caps->items[f].status = status;
    va_start(ap, reason_fmt);
    vsnprintf(caps->items[f].reason, sizeof(caps->items[f].reason), reason_fmt, ap);
    va_end(ap);
}

void ft_capability_set_all(struct ft_capabilities *caps, enum ft_cap_status status,
                           const char *reason)
{
    for (size_t f = 0; f < FT_FEAT_COUNT; f++)
        ft_capability_set(caps, (enum ft_feature)f, status, "%s", reason);
}
