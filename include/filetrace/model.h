#ifndef FILETRACE_MODEL_H
#define FILETRACE_MODEL_H

#include "filetrace/base.h"

#define FT_COMM_MAX 16
#define FT_EXE_MAX 256
#define FT_PATH_MAX 4096
#define FT_CMDLINE_MAX 4096
#define FT_FS_TYPE_MAX 16

#define FT_PROTO_TCP 6
#define FT_PROTO_UDP 17

enum ft_confidence : uint8_t {
    FT_CONF_UNKNOWN = 0,  /* no file could be associated with the bytes */
    FT_CONF_INFERRED = 1, /* association rests on ordering and timing */
    FT_CONF_STRONG = 2,   /* provenance followed through intermediate operations */
    FT_CONF_EXACT = 3,    /* a single file-to-socket operation was observed */
    FT_CONF_ANY = 0xff,
};

enum ft_method : uint8_t {
    FT_METHOD_NONE = 0,
    FT_METHOD_SENDFILE = 1,
    FT_METHOD_READ_SEND = 2, /* a read of the file followed by a send; named "read-write" */
    FT_METHOD_SPLICE = 3,
    FT_METHOD_MMAP = 4,
    FT_METHOD_IO_URING = 5,
    FT_METHOD_ANY = 0xff,
};

enum ft_sock_state : uint8_t {
    FT_SOCK_UNKNOWN = 0,
    FT_SOCK_CONNECTING = 1,
    FT_SOCK_ESTABLISHED = 2,
    FT_SOCK_LISTENING = 3,
    FT_SOCK_CLOSED = 4,
    FT_SOCK_ACTIVE = 5, /* connectionless socket with recent traffic */
    FT_SOCK_IDLE = 6,   /* connectionless socket without recent traffic */
    FT_SOCK_ANY = 0xff,
};

enum ft_mode : uint8_t {
    FT_MODE_MINIMAL = 0,  /* processes, sockets and network byte counts */
    FT_MODE_STANDARD = 1, /* adds file identity and file-to-network attribution */
};

enum ft_evidence : uint32_t {
    FT_EVD_DIRECT_TRANSFER = 1u << 0, /* kernel moved file data to the socket itself */
    FT_EVD_FILE_IDENTITY = 1u << 1,   /* file identified from the kernel file object */
    FT_EVD_SOCKET_IDENTITY = 1u << 2, /* socket identified by its kernel identity */
    FT_EVD_REMOTE_ENDPOINT = 1u << 3, /* socket identity resolved to an endpoint */
    FT_EVD_THREAD_SEQUENCE = 1u << 4, /* one thread read the file, then sent */
    FT_EVD_REPEATED = 1u << 5,        /* the read-then-send pattern repeated */
    FT_EVD_BYTE_BALANCE = 1u << 6,    /* bytes sent are close to bytes read */
};

struct ft_endpoint {
    uint8_t addr[16]; /* IPv4 in the first four bytes */
    uint16_t port;    /* host byte order */
    uint8_t family;   /* 0 unspecified, 4 or 6 */
    uint8_t pad;
};

struct ft_file_id {
    uint64_t dev; /* stat(2) st_dev encoding */
    uint64_t ino;
    uint32_t instance; /* tells apart successive files that were given the same inode number */
    uint32_t pad;
};

const char *ft_confidence_name(enum ft_confidence c);
bool ft_confidence_parse(const char *text, enum ft_confidence *c);

const char *ft_method_name(enum ft_method m);
bool ft_method_parse(const char *text, enum ft_method *m);

/* Whether any probe can attribute a transfer made this way. */
bool ft_method_observed(enum ft_method m);

const char *ft_mode_name(enum ft_mode m);
bool ft_mode_parse(const char *text, enum ft_mode *m);

const char *ft_sock_state_name(enum ft_sock_state s);
bool ft_sock_state_parse(const char *text, enum ft_sock_state *s);

/* Returns how many names were written. */
size_t ft_evidence_names(uint32_t mask, const char *names[], size_t max);
const char *ft_evidence_description(enum ft_evidence e);

const char *ft_proto_name(uint16_t proto, char buf[static 8]);
bool ft_proto_parse(const char *text, uint16_t *proto);

/* raw holds a network-order address; IPv4-mapped IPv6 collapses to IPv4. */
void ft_endpoint_set(struct ft_endpoint *ep, bool ipv6, const uint8_t raw[static 16],
                     uint16_t port);
bool ft_addr_parse(const char *text, struct ft_endpoint *ep);

/* "203.0.113.0/24", "2001:db8::/32" or a single address; bits is the prefix length. */
bool ft_prefix_parse(const char *text, struct ft_endpoint *net, uint8_t *bits);
bool ft_addr_in_prefix(const struct ft_endpoint *net, uint8_t bits, const struct ft_endpoint *ep);

bool ft_addr_is_set(const struct ft_endpoint *ep);
bool ft_addr_equal(const struct ft_endpoint *a, const struct ft_endpoint *b);
void ft_addr_format(const struct ft_endpoint *ep, char *buf, size_t size);
void ft_endpoint_format(const struct ft_endpoint *ep, char *buf, size_t size);

#endif
