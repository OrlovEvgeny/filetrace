#include "unit/test.h"

#include "ui/top/filter.h"

static struct ft_endpoint address(const char *text, uint16_t port)
{
    struct ft_endpoint ep;
    CHECK(ft_addr_parse(text, &ep));
    ep.port = port;
    return ep;
}

/* A php-fpm worker sending an invoice to a public client. */
static struct ft_top_subject invoice(const struct ft_endpoint *remote)
{
    return (struct ft_top_subject){
        .pid = 18822,
        .pid_text = "18822",
        .uid = 33,
        .uid_known = true,
        .user = "www-data",
        .title = "php-fpm: pool www",
        .comm = "php-fpm8.3",
        .script = "/srv/app/public/download.php",
        .path = "/srv/app/storage/invoices/2026/11/INV-48213.pdf",
        .remote = remote,
        .remote_text = "92.68.14.201:52110",
        .host = "client.example.net",
        .is_public = true,
        .method = FT_METHOD_READ_SEND,
        .confidence = FT_CONF_INFERRED,
        .rate = 1800 * 1024,
    };
}

static bool matches(const char *expression, const struct ft_top_subject *s)
{
    struct ft_error err = {0};
    struct ft_top_filter *f = ft_top_filter_compile(expression, &err);
    if (!f) {
        fprintf(stderr, "filter '%s' failed: %s\n", expression, err.msg);
        return false;
    }
    bool matched = ft_top_filter_match(f, s);
    ft_top_filter_free(f);
    return matched;
}

static void keys(void)
{
    struct ft_endpoint remote = address("92.68.14.201", 52110);
    struct ft_top_subject s = invoice(&remote);

    CHECK(matches("", &s));
    CHECK(matches("pid:18822", &s));
    CHECK(matches("pid:1,18822,7", &s));
    CHECK(!matches("pid:1882", &s));
    CHECK(!matches("!pid:18822", &s));

    CHECK(matches("user:www", &s));
    CHECK(matches("user:WWW-DATA", &s));
    CHECK(matches("user:33", &s));
    CHECK(!matches("user:root", &s));
    CHECK(matches("!user:root", &s));
    CHECK(matches("user:www-*", &s));
    CHECK(!matches("user:www", &(struct ft_top_subject){.user = ""}));

    CHECK(matches("proc:pool", &s));
    CHECK(matches("proc:php-fpm8.3", &s));
    CHECK(matches("proc:php-fpm:*", &s));
    CHECK(!matches("proc:nginx", &s));

    CHECK(matches("script:download", &s));
    CHECK(matches("script:*/download.php", &s));
    CHECK(!matches("script:*/DOWNLOAD.php", &s));
    s.script = "";
    CHECK(!matches("script:*", &s));
    CHECK(matches("!script:download", &s));
    s = invoice(&remote);

    CHECK(matches("file:invoices", &s));
    CHECK(matches("file:/srv/app/storage/**", &s));
    CHECK(matches("file:*.pdf", &s));
    CHECK(!matches("file:/srv/app/storage", &(struct ft_top_subject){.path = "/srv/app/x"}));
    CHECK(!matches("file:/srv/app/*.csv", &s));

    CHECK(matches("dest:public", &s));
    CHECK(!matches("dest:private", &s));
    CHECK(matches("dest:92.68.0.0/16", &s));
    CHECK(matches("dest:92.68.14.201", &s));
    CHECK(!matches("dest:10.0.0.0/8", &s));
    CHECK(matches("dest:client.example", &s));
    CHECK(matches("dest::52110", &s));
    CHECK(matches("dest:*.net", &s));
    CHECK(!matches("dest:2001:db8::/32", &s));
    struct ft_endpoint v6 = address("2001:db8::7", 443);
    struct ft_top_subject ipv6 = {.remote = &v6, .remote_text = "[2001:db8::7]:443"};
    CHECK(matches("dest:2001:db8::/32", &ipv6));
    CHECK(matches("dest:private", &(struct ft_top_subject){.remote = &remote}));
    CHECK(!matches("dest:public", &(struct ft_top_subject){.remote_text = "*"}));

    CHECK(matches("method:rw", &s));
    CHECK(matches("method:read-write", &s));
    CHECK(!matches("method:sendfile", &s));
    CHECK(matches("!method:sendfile", &s));

    CHECK(matches("conf:inferred", &s));
    CHECK(!matches("conf:exact", &s));
    CHECK(matches("conf:INFERRED", &s));

    CHECK(matches("rate:>1M", &s));
    CHECK(matches("rate:>=1800K", &s));
    CHECK(!matches("rate:>1800K", &s));
    CHECK(matches("rate:<2M/s", &s));
    CHECK(matches("rate:<=1800K", &s));
    CHECK(!matches("rate:<10K", &s));
    CHECK(matches("rate:1M", &s));
    CHECK(matches("rate:=1800K", &s));
}

static void words(void)
{
    struct ft_endpoint remote = address("92.68.14.201", 52110);
    struct ft_top_subject s = invoice(&remote);

    /* A bare word looks at every column, ignoring case. */
    CHECK(matches("1882", &s));
    CHECK(matches("WWW-data", &s));
    CHECK(matches("pool", &s));
    CHECK(matches("download.php", &s));
    CHECK(matches("inv-48213", &s));
    CHECK(matches("92.68.14", &s));
    CHECK(matches("example", &s));
    CHECK(matches("read-write", &s));
    CHECK(matches("inferred", &s));
    CHECK(!matches("nginx", &s));
    CHECK(!matches("php8", &s));
    CHECK(matches("!nginx", &s));
    /* A bare word is never a glob. */
    CHECK(!matches("*.pdf", &s));

    /* Terms are joined with AND. */
    CHECK(matches("file:/srv/app/storage/** dest:public !user:root rate:>1M php", &s));
    CHECK(!matches("file:/srv/app/storage/** dest:private", &s));

    /* Quotes keep spaces in a value, and a backslash keeps a quote. */
    s.path = "/srv/my files/report \"q3\".csv";
    CHECK(matches("file:\"/srv/my files/*\"", &s));
    CHECK(matches("\"my files\"", &s));
    CHECK(matches("file:\"report \\\"q3\\\"\"", &s));
    CHECK(!matches("file:\"/srv/other files/*\"", &s));
    CHECK(matches("!\"other files\"", &s));
}

static const char *failure(const char *expression)
{
    static struct ft_error err;
    struct ft_top_filter *f = ft_top_filter_compile(expression, &err);
    if (f) {
        ft_top_filter_free(f);
        return "";
    }
    CHECK_U64(err.code, FT_EXIT_USAGE);
    return err.msg;
}

static void errors(void)
{
    CHECK_STR(failure("usr:root"), "unknown filter key 'usr' (expected pid, user, proc, script, "
                                   "file, dest, method, conf or rate)");
    CHECK_STR(failure("file:"), "empty value in 'file:'");
    CHECK_STR(failure("!dest:"), "empty value in '!dest:'");
    CHECK_STR(failure("pid:12x"),
              "bad process id in 'pid:12x' (expected numbers separated by commas)");
    CHECK_STR(failure("pid:1,,2"),
              "bad process id in 'pid:1,,2' (expected numbers separated by commas)");
    CHECK_STR(failure("method:ftp"),
              "unknown method in 'method:ftp' (expected sendfile, rw, splice, mmap or io_uring)");
    CHECK_STR(failure("conf:sure"),
              "unknown confidence in 'conf:sure' (expected exact, strong, inferred or unknown)");
    CHECK_STR(failure("rate:>fast"),
              "bad rate in 'rate:>fast' (expected a comparison and a size, such as >1M)");
    CHECK_STR(failure("rate:>"),
              "bad rate in 'rate:>' (expected a comparison and a size, such as >1M)");
    CHECK_STR(failure("file:\"/srv/my files"), "unterminated quote in 'file:\"/srv/my files'");
    CHECK_STR(failure("php !"), "nothing to negate in '!'");
    /* Text before a colon that is not a word stays a bare word. */
    CHECK_STR(failure("10.0.5.22:45910 2001:db8::1"), "");

    struct ft_error err = {0};
    struct ft_top_filter *f = ft_top_filter_compile("file:*.log pid:7", &err);
    CHECK(f != nullptr);
    CHECK_U64(ft_top_filter_fields(f),
              FT_TOP_FIELD_BIT(FT_TOP_FIELD_FILE) | FT_TOP_FIELD_BIT(FT_TOP_FIELD_PID));
    CHECK(!ft_top_filter_restrict(f, FT_TOP_FIELD_BIT(FT_TOP_FIELD_FILE), "Leaders", &err));
    CHECK_STR(err.msg, "'pid:7' does not apply to Leaders");
    ft_top_filter_free(f);
}

static struct ft_query pushed(const char *expression)
{
    struct ft_error err = {0};
    struct ft_query q;
    struct ft_top_filter *f = ft_top_filter_compile(expression, &err);

    ft_query_init(&q, FT_Q_TRANSFERS);
    CHECK(f != nullptr);
    ft_top_filter_pushdown(f, &q);
    ft_top_filter_free(f);
    return q;
}

static void pushdown(void)
{
    struct ft_query q = pushed("pid:2214 dest:10.0.0.0/8 script:*/export.php method:sendfile "
                               "conf:exact user:root php");
    CHECK_U64(q.pid, 2214);
    CHECK_U64(q.remote.family, 4);
    CHECK_U64(q.remote.addr[0], 10);
    CHECK_U64(q.remote_host_bits, 24);
    CHECK_STR(q.script, "*/export.php");
    CHECK_U64(q.method, FT_METHOD_SENDFILE);
    CHECK_U64(q.confidence, FT_CONF_EXACT);
    CHECK_STR(q.process, "");

    q = pushed("dest:2001:db8::/32");
    CHECK_U64(q.remote.family, 6);
    CHECK_U64(q.remote_host_bits, 96);
    q = pushed("dest:10.0.5.22");
    CHECK_U64(q.remote_host_bits, 0);
    CHECK_U64(q.remote.port, 0);

    /* Negated, repeated or approximate terms stay with the client. */
    q = pushed("!pid:2214 !dest:10.0.0.0/8 !script:*.php !method:sendfile !conf:exact");
    CHECK_U64(q.pid, 0);
    CHECK_U64(q.remote.family, 0);
    CHECK_STR(q.script, "");
    CHECK_U64(q.method, FT_METHOD_ANY);
    CHECK_U64(q.confidence, FT_CONF_ANY);
    q = pushed("pid:1 pid:2 dest:10.0.0.0/8 dest:public method:rw method:sendfile");
    CHECK_U64(q.pid, 0);
    CHECK_U64(q.remote.family, 0);
    CHECK_U64(q.method, FT_METHOD_ANY);
    q = pushed("pid:1,2 dest:public script:export");
    CHECK_U64(q.pid, 0);
    CHECK_U64(q.remote.family, 0);
    CHECK_STR(q.script, "");
    q = pushed("dest:client.example");
    CHECK_U64(q.remote.family, 0);
}

static void needles(void)
{
    struct ft_error err = {0};
    struct ft_top_filter *f =
        ft_top_filter_compile("!user:root file:/srv/app/storage/** Php", &err);
    size_t len = 0;
    size_t start = 0;
    size_t end = 0;

    const char *needle = ft_top_filter_needle(f, FT_TOP_FIELD_FILE, &len);
    CHECK(needle && len == strlen("/srv/app/storage/") &&
          strncmp(needle, "/srv/app/storage/", len) == 0);
    needle = ft_top_filter_needle(f, FT_TOP_FIELD_USER, &len);
    CHECK(needle && len == 3 && strncmp(needle, "Php", len) == 0);
    ft_top_filter_free(f);

    CHECK(ft_top_find("/srv/app/public/download.php", "PHP", 3, &start, &end));
    CHECK_U64(start, 25);
    CHECK_U64(end, 28);
    CHECK(!ft_top_find("/srv/app", "php", 3, &start, &end));
    CHECK(!ft_top_find("/srv/app", "", 0, &start, &end));
}

void test_top_filter(void)
{
    keys();
    words();
    errors();
    pushdown();
    needles();
}
