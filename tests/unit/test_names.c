#include "unit/test.h"

#include "filetrace/names.h"

#include <stdio.h>

static void check_kind(const char *text, enum ft_name_kind kind, const char *kept)
{
    char out[FT_NAME_MAX];
    CHECK_U64(ft_name_normalise(text, out), kind);
    CHECK_STR(out, kept);
}

static void normalised(void)
{
    char longest[FT_NAME_MAX + 2];
    char out[FT_NAME_MAX];

    check_kind("Files.Example.COM", FT_NAME_HOST, "files.example.com");
    check_kind("files.example.com.", FT_NAME_HOST, "files.example.com");
    check_kind("db", FT_NAME_HOST, "db");
    check_kind("_sip._tcp.example.org", FT_NAME_HOST, "_sip._tcp.example.org");
    check_kind("xn--bcher-kva.example", FT_NAME_HOST, "xn--bcher-kva.example");
    check_kind("host-1.rack7", FT_NAME_HOST, "host-1.rack7");
    check_kind("0xcafe.example", FT_NAME_HOST, "0xcafe.example");

    /* What the resolver takes for an address is no name, in whatever form it is written. */
    check_kind("", FT_NAME_ADDRESS, "");
    check_kind(".", FT_NAME_ADDRESS, "");
    check_kind("203.0.113.25", FT_NAME_ADDRESS, "");
    check_kind("127.1", FT_NAME_ADDRESS, "");
    check_kind("2130706433", FT_NAME_ADDRESS, "");
    check_kind("0x7f.0.0.1", FT_NAME_ADDRESS, "");
    check_kind("0x7F000001", FT_NAME_ADDRESS, "");
    check_kind("example.123", FT_NAME_ADDRESS, "");
    check_kind("::1", FT_NAME_ADDRESS, "");
    check_kind("2001:db8::25", FT_NAME_ADDRESS, "");
    check_kind("fe80::1%eth0", FT_NAME_ADDRESS, "");

    check_kind("two words.example", FT_NAME_REFUSED, "");
    check_kind("caf\xc3\xa9.example", FT_NAME_REFUSED, "");
    check_kind("esc\x1b[31m.example", FT_NAME_REFUSED, "");
    check_kind("user@example.com", FT_NAME_REFUSED, "");
    check_kind("a/b", FT_NAME_REFUSED, "");

    memset(longest, 'a', sizeof(longest));
    longest[FT_NAME_MAX - 1] = '\0';
    CHECK_U64(ft_name_normalise(longest, out), FT_NAME_HOST);
    CHECK_U64(strlen(out), FT_NAME_MAX - 1);
    longest[FT_NAME_MAX - 1] = '.';
    longest[FT_NAME_MAX] = '\0';
    CHECK_U64(ft_name_normalise(longest, out), FT_NAME_HOST);
    CHECK_U64(strlen(out), FT_NAME_MAX - 1);
    longest[FT_NAME_MAX - 1] = 'a';
    CHECK_U64(ft_name_normalise(longest, out), FT_NAME_REFUSED);
    CHECK_STR(out, "");
}

static struct ft_name_ref intern_numbered(struct ft_names *n, unsigned i)
{
    char name[32];
    snprintf(name, sizeof(name), "host%u.example", i);
    return ft_names_intern(n, name);
}

static void one_name_one_slot(void)
{
    struct ft_names *n = ft_names_create(8);
    struct ft_name_ref a = ft_names_intern(n, "files.example.com");
    struct ft_name_ref b = ft_names_intern(n, "FILES.example.com.");
    struct ft_name_ref c = ft_names_intern(n, "cdn.example.com");

    CHECK(a.id != 0);
    CHECK_U64(b.id, a.id);
    CHECK_U64(b.generation, a.generation);
    CHECK(c.id != a.id);
    CHECK_U64(ft_names_count(n), 2);
    CHECK_U64(ft_names_capacity(n), 8);
    CHECK_STR(ft_names_text(n, a.id), "files.example.com");
    CHECK_U64(ft_names_resolve(n, a), a.id);
    CHECK_U64(ft_names_resolve(n, (struct ft_name_ref){0}), 0);
    CHECK_U64(ft_names_resolve(n, (struct ft_name_ref){.id = 7, .generation = 1}), 0);

    /* An address is passed over; only what could not be a name is counted. */
    CHECK_U64(ft_names_intern(n, "10.0.0.5").id, 0);
    CHECK_U64(ft_names_intern(n, "::1").id, 0);
    CHECK_U64(ft_names_invalid(n), 0);
    CHECK_U64(ft_names_intern(n, "no name").id, 0);
    CHECK_U64(ft_names_invalid(n), 1);
    CHECK_U64(ft_names_count(n), 2);
    ft_names_destroy(n);

    CHECK(ft_names_create(0) == nullptr);
}

static void unused_longest_goes_first(void)
{
    struct ft_names *n = ft_names_create(4);
    struct ft_name_ref refs[4];

    for (unsigned i = 0; i < 4; i++)
        refs[i] = intern_numbered(n, i);
    /* Looking a name up again is a use of it. */
    CHECK_U64(intern_numbered(n, 0).id, refs[0].id);

    struct ft_name_ref fifth = intern_numbered(n, 4);
    CHECK_U64(fifth.id, refs[1].id);
    CHECK(fifth.generation != refs[1].generation);
    CHECK_U64(ft_names_resolve(n, refs[1]), 0);
    CHECK_U64(ft_names_resolve(n, refs[0]), refs[0].id);
    CHECK_U64(ft_names_resolve(n, fifth), fifth.id);
    CHECK_STR(ft_names_text(n, fifth.id), "host4.example");
    CHECK_U64(ft_names_count(n), 4);
    CHECK_U64(ft_names_forgotten(n), 1);

    /* The forgotten name comes back as another name would, in the next slot to go. */
    struct ft_name_ref again = intern_numbered(n, 1);
    CHECK_U64(again.id, refs[2].id);
    CHECK_U64(ft_names_forgotten(n), 2);
    ft_names_destroy(n);
}

static void held_names_stay(void)
{
    struct ft_names *n = ft_names_create(3);
    struct ft_name_ref held = ft_names_intern(n, "upstream.example");

    ft_names_hold(n, held.id);
    ft_names_hold(n, held.id);
    for (unsigned i = 0; i < 100; i++)
        CHECK(intern_numbered(n, i).id != held.id);
    CHECK_U64(ft_names_resolve(n, held), held.id);
    CHECK_STR(ft_names_text(n, held.id), "upstream.example");
    CHECK_U64(ft_names_forgotten(n), 98);

    /* Let go by one holder of two, it still stays; let go by both, its release is its last use. */
    ft_names_release(n, held.id);
    intern_numbered(n, 200);
    CHECK_U64(ft_names_resolve(n, held), held.id);
    ft_names_release(n, held.id);
    intern_numbered(n, 201);
    intern_numbered(n, 202);
    CHECK_U64(ft_names_resolve(n, held), held.id);
    intern_numbered(n, 203);
    CHECK_U64(ft_names_resolve(n, held), 0);
    ft_names_destroy(n);
}

static void all_held_refuses(void)
{
    struct ft_names *n = ft_names_create(2);
    struct ft_name_ref a = intern_numbered(n, 0);
    struct ft_name_ref b = intern_numbered(n, 1);

    ft_names_hold(n, a.id);
    ft_names_hold(n, b.id);
    CHECK_U64(intern_numbered(n, 2).id, 0);
    CHECK_U64(ft_names_refused(n), 1);
    CHECK_U64(ft_names_forgotten(n), 0);
    /* A held name is still found. */
    CHECK_U64(intern_numbered(n, 1).id, b.id);

    ft_names_release(n, a.id);
    struct ft_name_ref c = intern_numbered(n, 2);
    CHECK_U64(c.id, a.id);
    CHECK_U64(ft_names_resolve(n, a), 0);
    CHECK_U64(ft_names_refused(n), 1);
    ft_names_destroy(n);
}

static void check_shown(const struct ft_remote_names *n, const char *shown, const char *name,
                        enum ft_name_source source)
{
    char buf[3 * FT_NAME_MAX];

    ft_remote_name_format(n, buf, sizeof(buf));
    CHECK_STR(buf, shown);
    CHECK_STR(ft_remote_name(n), name);
    CHECK_U64(ft_remote_name_source(n), source);
}

static void shown_by_what_is_known(void)
{
    struct ft_remote_names n = {.tls = ""};
    check_shown(&n, "", "", FT_NAME_SOURCE_NONE);

    n = (struct ft_remote_names){
        .tls = "", .resolved = {"files.example.com"}, .listed = 1, .count = 1};
    check_shown(&n, "files.example.com", "files.example.com", FT_NAME_SOURCE_LOOKUP);

    n = (struct ft_remote_names){
        .tls = "", .resolved = {"cdn.example.com", "static.example.com"}, .listed = 2, .count = 2};
    check_shown(&n, "cdn.example.com (+1)", "cdn.example.com", FT_NAME_SOURCE_LOOKUP);

    /* More were looked up than a row lists. */
    n.count = 7;
    check_shown(&n, "cdn.example.com (+6)", "cdn.example.com", FT_NAME_SOURCE_LOOKUP);

    n = (struct ft_remote_names){.tls = "files.example.com",
                                 .resolved = {"cdn.example.com", "files.example.com"},
                                 .listed = 2,
                                 .count = 2};
    check_shown(&n, "files.example.com", "files.example.com", FT_NAME_SOURCE_LOOKUP_TLS);

    n = (struct ft_remote_names){.tls = "files.example.com"};
    check_shown(&n, "files.example.com", "files.example.com", FT_NAME_SOURCE_TLS);

    n = (struct ft_remote_names){
        .tls = "s3.example.com", .resolved = {"proxy.corp.example"}, .listed = 1, .count = 1};
    check_shown(&n, "s3.example.com via proxy.corp.example", "s3.example.com", FT_NAME_SOURCE_TLS);

    n = (struct ft_remote_names){.tls = "s3.example.com",
                                 .resolved = {"proxy.corp.example", "gw.corp.example"},
                                 .listed = 2,
                                 .count = 3};
    check_shown(&n, "s3.example.com via proxy.corp.example (+2)", "s3.example.com",
                FT_NAME_SOURCE_TLS);

    CHECK_STR(ft_name_source_name(FT_NAME_SOURCE_NONE), "");
    CHECK_STR(ft_name_source_name(FT_NAME_SOURCE_LOOKUP), "lookup");
    CHECK_STR(ft_name_source_name(FT_NAME_SOURCE_TLS), "tls");
    CHECK_STR(ft_name_source_name(FT_NAME_SOURCE_LOOKUP_TLS), "lookup+tls");

    char cut[12];
    ft_remote_name_format(&n, cut, sizeof(cut));
    CHECK_STR(cut, "s3.example.");
}

void test_names(void)
{
    shown_by_what_is_known();
    normalised();
    one_name_one_slot();
    unused_longest_goes_first();
    held_names_stay();
    all_held_refuses();
}
