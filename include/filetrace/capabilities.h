#ifndef FILETRACE_CAPABILITIES_H
#define FILETRACE_CAPABILITIES_H

#include "filetrace/base.h"

enum ft_feature : uint8_t {
    FT_FEAT_PROCESS,
    FT_FEAT_FILE_OPEN,
    FT_FEAT_FILE_READ,
    FT_FEAT_FILE_WRITE,
    FT_FEAT_TCP,
    FT_FEAT_UDP,
    FT_FEAT_IPV6,
    FT_FEAT_SENDFILE,
    FT_FEAT_READ_SEND,
    FT_FEAT_SPLICE,
    FT_FEAT_IO_URING,
    FT_FEAT_MMAP,
    FT_FEAT_PACKET_EGRESS,
    FT_FEAT_NAMESPACES,
    FT_FEAT_DESTINATION_NAMES,
    FT_FEAT_PHP_SCRIPTS,
    FT_FEAT_COUNT,
};

enum ft_cap_status : uint8_t {
    FT_CAP_FULL,
    FT_CAP_PARTIAL,
    FT_CAP_UNAVAILABLE,
    FT_CAP_DISABLED,
};

struct ft_capability {
    enum ft_cap_status status;
    char reason[188];
};

struct ft_capabilities {
    struct ft_capability items[FT_FEAT_COUNT];
};

const char *ft_feature_title(enum ft_feature f);
const char *ft_feature_key(enum ft_feature f);
const char *ft_cap_status_name(enum ft_cap_status s);

[[gnu::format(printf, 4, 5)]]
void ft_capability_set(struct ft_capabilities *caps, enum ft_feature f, enum ft_cap_status status,
                       const char *reason_fmt, ...);

void ft_capability_set_all(struct ft_capabilities *caps, enum ft_cap_status status,
                           const char *reason);

#endif
