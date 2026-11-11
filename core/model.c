#include "filetrace/model.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

static const char *const confidence_names[] = {"unknown", "inferred", "strong", "exact"};
static const char *const method_names[] = {"none", "sendfile", "read_send"};
static const char *const state_names[] = {"unknown", "connecting", "established", "listening",
                                          "closed",  "active",     "idle"};

static bool parse_name(const char *text, const char *const names[], size_t count, uint8_t *out)
{
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(text, names[i]) == 0) {
            *out = (uint8_t)i;
            return true;
        }
    }
    return false;
}

const char *ft_confidence_name(enum ft_confidence c)
{
    return c < FT_ARRAY_LEN(confidence_names) ? confidence_names[c] : "unknown";
}

bool ft_confidence_parse(const char *text, enum ft_confidence *c)
{
    uint8_t v;
    if (!parse_name(text, confidence_names, FT_ARRAY_LEN(confidence_names), &v))
        return false;
    *c = (enum ft_confidence)v;
    return true;
}

const char *ft_method_name(enum ft_method m)
{
    return m < FT_ARRAY_LEN(method_names) ? method_names[m] : "none";
}

bool ft_method_parse(const char *text, enum ft_method *m)
{
    uint8_t v;
    if (strcasecmp(text, "read+send") == 0 || strcasecmp(text, "read-send") == 0) {
        *m = FT_METHOD_READ_SEND;
        return true;
    }
    if (!parse_name(text, method_names, FT_ARRAY_LEN(method_names), &v) || v == FT_METHOD_NONE)
        return false;
    *m = (enum ft_method)v;
    return true;
}

const char *ft_mode_name(enum ft_mode m)
{
    return m == FT_MODE_MINIMAL ? "minimal" : "standard";
}

bool ft_mode_parse(const char *text, enum ft_mode *m)
{
    if (strcasecmp(text, "minimal") == 0) {
        *m = FT_MODE_MINIMAL;
        return true;
    }
    if (strcasecmp(text, "standard") == 0) {
        *m = FT_MODE_STANDARD;
        return true;
    }
    return false;
}

const char *ft_sock_state_name(enum ft_sock_state s)
{
    return s < FT_ARRAY_LEN(state_names) ? state_names[s] : "unknown";
}

bool ft_sock_state_parse(const char *text, enum ft_sock_state *s)
{
    uint8_t v;
    if (!parse_name(text, state_names, FT_ARRAY_LEN(state_names), &v) || v == FT_SOCK_UNKNOWN)
        return false;
    *s = (enum ft_sock_state)v;
    return true;
}

static const struct {
    enum ft_evidence bit;
    const char *name;
    const char *description;
} evidence_table[] = {
    {FT_EVD_DIRECT_TRANSFER, "direct_file_to_socket_transfer",
     "The kernel moved the file's data to the socket in a single operation."},
    {FT_EVD_FILE_IDENTITY, "file_identity",
     "The file was identified by device and inode from the kernel file object."},
    {FT_EVD_SOCKET_IDENTITY, "socket_identity",
     "The socket was identified by its kernel socket cookie."},
    {FT_EVD_REMOTE_ENDPOINT, "remote_endpoint",
     "The socket identity resolved to the remote endpoint."},
    {FT_EVD_THREAD_SEQUENCE, "thread_read_then_send",
     "One thread read the file and then sent on the socket with no receive in between."},
    {FT_EVD_REPEATED, "repeated_read_then_send", "The read-then-send sequence repeated."},
    {FT_EVD_BYTE_BALANCE, "byte_balance",
     "The bytes sent are close to the bytes read from the file."},
};

size_t ft_evidence_names(uint32_t mask, const char *names[], size_t max)
{
    size_t n = 0;
    for (size_t i = 0; i < FT_ARRAY_LEN(evidence_table) && n < max; i++) {
        if (mask & evidence_table[i].bit)
            names[n++] = evidence_table[i].name;
    }
    return n;
}

const char *ft_evidence_description(enum ft_evidence e)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(evidence_table); i++) {
        if (evidence_table[i].bit == e)
            return evidence_table[i].description;
    }
    return "";
}

const char *ft_proto_name(uint16_t proto, char buf[static 8])
{
    switch (proto) {
    case FT_PROTO_TCP:
        return "tcp";
    case FT_PROTO_UDP:
        return "udp";
    case 1:
        return "icmp";
    case 58:
        return "icmp6";
    case 132:
        return "sctp";
    case 262:
        return "mptcp";
    default:
        snprintf(buf, 8, "%u", proto);
        return buf;
    }
}

bool ft_proto_parse(const char *text, uint16_t *proto)
{
    if (strcasecmp(text, "tcp") == 0) {
        *proto = FT_PROTO_TCP;
        return true;
    }
    if (strcasecmp(text, "udp") == 0) {
        *proto = FT_PROTO_UDP;
        return true;
    }
    return false;
}

void ft_endpoint_set(struct ft_endpoint *ep, bool ipv6, const uint8_t raw[static 16], uint16_t port)
{
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    static const uint8_t zero[16] = {0};

    memset(ep, 0, sizeof(*ep));
    ep->port = port;
    if (ipv6 && memcmp(raw, mapped, sizeof(mapped)) == 0) {
        memcpy(ep->addr, raw + 12, 4);
        ep->family = 4;
    } else if (ipv6) {
        memcpy(ep->addr, raw, 16);
        ep->family = 6;
    } else {
        memcpy(ep->addr, raw, 4);
        ep->family = 4;
    }
    if (memcmp(ep->addr, zero, sizeof(zero)) == 0 && port == 0)
        ep->family = 0;
}

bool ft_addr_parse(const char *text, struct ft_endpoint *ep)
{
    memset(ep, 0, sizeof(*ep));
    if (inet_pton(AF_INET, text, ep->addr) == 1) {
        ep->family = 4;
        return true;
    }
    if (inet_pton(AF_INET6, text, ep->addr) == 1) {
        ep->family = 6;
        return true;
    }
    return false;
}

bool ft_prefix_parse(const char *text, struct ft_endpoint *net, uint8_t *bits)
{
    char addr[INET6_ADDRSTRLEN];
    const char *slash = strchr(text, '/');
    size_t len = slash ? (size_t)(slash - text) : strlen(text);

    if (len == 0 || len >= sizeof(addr))
        return false;
    memcpy(addr, text, len);
    addr[len] = '\0';
    if (!ft_addr_parse(addr, net))
        return false;

    unsigned width = net->family == 6 ? 128 : 32;
    if (!slash) {
        *bits = (uint8_t)width;
        return true;
    }

    char *end;
    unsigned long n = strtoul(slash + 1, &end, 10);
    if (slash[1] < '0' || slash[1] > '9' || *end != '\0' || n > width)
        return false;
    *bits = (uint8_t)n;
    return true;
}

bool ft_addr_in_prefix(const struct ft_endpoint *net, uint8_t bits, const struct ft_endpoint *ep)
{
    size_t whole = bits / 8;
    unsigned rest = bits % 8;

    if (net->family != ep->family || whole > sizeof(net->addr))
        return false;
    if (memcmp(net->addr, ep->addr, whole) != 0)
        return false;
    if (rest == 0)
        return true;
    unsigned mask = 0xffu << (8 - rest) & 0xffu;
    return ((unsigned)(net->addr[whole] ^ ep->addr[whole]) & mask) == 0;
}

bool ft_addr_is_set(const struct ft_endpoint *ep)
{
    return ep->family != 0;
}

bool ft_addr_equal(const struct ft_endpoint *a, const struct ft_endpoint *b)
{
    return a->family == b->family && memcmp(a->addr, b->addr, sizeof(a->addr)) == 0;
}

void ft_addr_format(const struct ft_endpoint *ep, char *buf, size_t size)
{
    if (ep->family == 0 ||
        !inet_ntop(ep->family == 6 ? AF_INET6 : AF_INET, ep->addr, buf, (socklen_t)size))
        ft_strlcpy(buf, "*", size);
}

void ft_endpoint_format(const struct ft_endpoint *ep, char *buf, size_t size)
{
    char addr[INET6_ADDRSTRLEN];
    char port[8];

    ft_addr_format(ep, addr, sizeof(addr));
    if (ep->port)
        snprintf(port, sizeof(port), "%u", ep->port);
    else
        ft_strlcpy(port, "*", sizeof(port));

    if (ep->family == 6)
        snprintf(buf, size, "[%s]:%s", addr, port);
    else
        snprintf(buf, size, "%s:%s", addr, port);
}
