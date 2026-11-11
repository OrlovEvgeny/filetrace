#include "unit/test.h"

#include "filetrace/model.h"

static void endpoints(void)
{
    static const uint8_t v4[16] = {10, 0, 0, 10};
    static const uint8_t mapped[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 42};
    static const uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t zero[16] = {0};
    struct ft_endpoint ep;
    struct ft_endpoint parsed;
    char buf[64];

    ft_endpoint_set(&ep, false, v4, 443);
    CHECK_U64(ep.family, 4);
    ft_endpoint_format(&ep, buf, sizeof(buf));
    CHECK_STR(buf, "10.0.0.10:443");

    /* An IPv4 peer of a dual-stack socket is reported as IPv4. */
    ft_endpoint_set(&ep, true, mapped, 52144);
    CHECK_U64(ep.family, 4);
    ft_endpoint_format(&ep, buf, sizeof(buf));
    CHECK_STR(buf, "203.0.113.42:52144");
    CHECK(ft_addr_parse("203.0.113.42", &parsed));
    CHECK(ft_addr_equal(&ep, &parsed));

    ft_endpoint_set(&ep, true, v6, 443);
    CHECK_U64(ep.family, 6);
    ft_endpoint_format(&ep, buf, sizeof(buf));
    CHECK_STR(buf, "[2001:db8::1]:443");
    CHECK(ft_addr_parse("2001:db8::1", &parsed));
    CHECK(ft_addr_equal(&ep, &parsed));

    ft_endpoint_set(&ep, false, zero, 0);
    CHECK(!ft_addr_is_set(&ep));
    ft_addr_format(&ep, buf, sizeof(buf));
    CHECK_STR(buf, "*");

    /* A wildcard bind still has a family and a port. */
    ft_endpoint_set(&ep, false, zero, 8080);
    CHECK_U64(ep.family, 4);
    ft_endpoint_format(&ep, buf, sizeof(buf));
    CHECK_STR(buf, "0.0.0.0:8080");

    CHECK(!ft_addr_parse("not-an-address", &parsed));
    CHECK(!ft_addr_parse("10.0.0.256", &parsed));
}

static void prefixes(void)
{
    struct ft_endpoint net;
    struct ft_endpoint ep;
    uint8_t bits = 0;

    CHECK(ft_prefix_parse("203.0.113.0/24", &net, &bits));
    CHECK_U64(bits, 24);
    CHECK(ft_addr_parse("203.0.113.42", &ep));
    CHECK(ft_addr_in_prefix(&net, bits, &ep));
    CHECK(ft_addr_parse("203.0.114.42", &ep));
    CHECK(!ft_addr_in_prefix(&net, bits, &ep));

    /* A prefix that ends inside a byte compares only its leading bits. */
    CHECK(ft_prefix_parse("10.64.0.0/10", &net, &bits));
    CHECK(ft_addr_parse("10.127.255.255", &ep));
    CHECK(ft_addr_in_prefix(&net, bits, &ep));
    CHECK(ft_addr_parse("10.128.0.0", &ep));
    CHECK(!ft_addr_in_prefix(&net, bits, &ep));

    CHECK(ft_prefix_parse("192.0.2.10", &net, &bits));
    CHECK_U64(bits, 32);
    CHECK(ft_prefix_parse("2001:db8::/32", &net, &bits));
    CHECK_U64(bits, 32);
    CHECK(ft_addr_parse("2001:db8:ffff::1", &ep));
    CHECK(ft_addr_in_prefix(&net, bits, &ep));
    CHECK(ft_addr_parse("203.0.113.42", &ep));
    CHECK(!ft_addr_in_prefix(&net, bits, &ep));

    CHECK(ft_prefix_parse("0.0.0.0/0", &net, &bits));
    CHECK(ft_addr_in_prefix(&net, bits, &ep));

    CHECK(!ft_prefix_parse("203.0.113.0/33", &net, &bits));
    CHECK(!ft_prefix_parse("203.0.113.0/", &net, &bits));
    CHECK(!ft_prefix_parse("203.0.113.0/2x", &net, &bits));
    CHECK(!ft_prefix_parse("/24", &net, &bits));
}

static void names(void)
{
    enum ft_confidence conf;
    enum ft_method method;
    enum ft_sock_state state;
    enum ft_mode mode;
    uint16_t proto;
    char buf[8];

    CHECK(ft_confidence_parse("EXACT", &conf));
    CHECK(conf == FT_CONF_EXACT);
    CHECK(ft_confidence_parse("inferred", &conf));
    CHECK(conf == FT_CONF_INFERRED);
    CHECK(!ft_confidence_parse("certain", &conf));
    CHECK_STR(ft_confidence_name(FT_CONF_STRONG), "strong");

    CHECK(ft_method_parse("sendfile", &method));
    CHECK(method == FT_METHOD_SENDFILE);
    CHECK(ft_method_parse("read-write", &method));
    CHECK(method == FT_METHOD_READ_SEND);
    CHECK_STR(ft_method_name(FT_METHOD_READ_SEND), "read-write");
    CHECK(ft_method_observed(method));
    /* Named so that a query can ask for them; no probe attributes them. */
    CHECK(ft_method_parse("io_uring", &method));
    CHECK(!ft_method_observed(method));
    CHECK(!ft_method_parse("read_send", &method));
    CHECK(!ft_method_parse("none", &method));

    CHECK(ft_sock_state_parse("established", &state));
    CHECK(state == FT_SOCK_ESTABLISHED);
    CHECK(!ft_sock_state_parse("unknown", &state));

    CHECK(ft_mode_parse("minimal", &mode));
    CHECK(mode == FT_MODE_MINIMAL);
    CHECK(!ft_mode_parse("detailed", &mode));

    CHECK(ft_proto_parse("TCP", &proto));
    CHECK_U64(proto, FT_PROTO_TCP);
    CHECK(!ft_proto_parse("icmp", &proto));
    CHECK_STR(ft_proto_name(FT_PROTO_UDP, buf), "udp");
    CHECK_STR(ft_proto_name(47, buf), "47");
}

static void evidence(void)
{
    const char *list[8];
    size_t n = ft_evidence_names(FT_EVD_DIRECT_TRANSFER | FT_EVD_SOCKET_IDENTITY, list, 8);

    CHECK_U64(n, 2);
    CHECK_STR(list[0], "direct_file_to_socket_transfer");
    CHECK_STR(list[1], "socket_identity");
    CHECK_U64(ft_evidence_names(0, list, 8), 0);
    CHECK(ft_evidence_description(FT_EVD_THREAD_SEQUENCE)[0] != '\0');
}

void test_model(void)
{
    endpoints();
    prefixes();
    names();
    evidence();
}
