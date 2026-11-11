#include "unit/test.h"

#include "filetrace/format.h"

static void bytes(void)
{
    char buf[32];

    ft_format_bytes(0, buf, sizeof(buf));
    CHECK_STR(buf, "0 B");
    ft_format_bytes(1023, buf, sizeof(buf));
    CHECK_STR(buf, "1023 B");
    ft_format_bytes(12288, buf, sizeof(buf));
    CHECK_STR(buf, "12.0 KB");
    ft_format_bytes(89128960, buf, sizeof(buf));
    CHECK_STR(buf, "85.0 MB");
    ft_format_bytes(1524713390, buf, sizeof(buf));
    CHECK_STR(buf, "1.42 GB");
    ft_format_bytes(440401920, buf, sizeof(buf));
    CHECK_STR(buf, "420 MB");

    ft_format_rate(512, buf, sizeof(buf));
    CHECK_STR(buf, "512 B/s");
    ft_format_rate(1258291, buf, sizeof(buf));
    CHECK_STR(buf, "1.20 MB/s");
}

static void sizes(void)
{
    uint64_t v = 0;

    CHECK(ft_parse_size("4096", &v));
    CHECK_U64(v, 4096);
    CHECK(ft_parse_size("1KB", &v));
    CHECK_U64(v, 1024);
    CHECK(ft_parse_size("100MB", &v));
    CHECK_U64(v, 104857600);
    CHECK(ft_parse_size("1.5gb", &v));
    CHECK_U64(v, 1610612736);
    CHECK(ft_parse_size("1TB", &v));
    CHECK_U64(v, 1099511627776);
    CHECK(!ft_parse_size("MB", &v));
    CHECK(!ft_parse_size("-1", &v));
    CHECK(!ft_parse_size("10XB", &v));
    CHECK(!ft_parse_size("", &v));
}

static void durations(void)
{
    uint64_t v = 0;
    char buf[32];

    CHECK(ft_parse_duration("10s", &v));
    CHECK_U64(v, 10 * FT_NS_PER_SEC);
    CHECK(ft_parse_duration("5m", &v));
    CHECK_U64(v, 300 * FT_NS_PER_SEC);
    CHECK(ft_parse_duration("24h", &v));
    CHECK_U64(v, 86400 * FT_NS_PER_SEC);
    CHECK(ft_parse_duration("7d", &v));
    CHECK_U64(v, 7 * 86400 * FT_NS_PER_SEC);
    CHECK(ft_parse_duration("250ms", &v));
    CHECK_U64(v, 250 * FT_NS_PER_MS);
    CHECK(!ft_parse_duration("10", &v));
    CHECK(!ft_parse_duration("h", &v));
    CHECK(!ft_parse_duration("5 m", &v));

    ft_format_duration(42 * FT_NS_PER_SEC, buf, sizeof(buf));
    CHECK_STR(buf, "42s");
    ft_format_duration((3 * 3600 + 42 * 60) * FT_NS_PER_SEC, buf, sizeof(buf));
    CHECK_STR(buf, "3h 42m");
    ft_format_duration((2 * 86400 + 4 * 3600) * FT_NS_PER_SEC, buf, sizeof(buf));
    CHECK_STR(buf, "2d 4h");
}

static void timestamps(void)
{
    uint64_t v = 0;
    char buf[40];

    CHECK(ft_parse_time_rfc3339("2026-11-10T21:42:11.210Z", &v));
    CHECK_U64(v, UINT64_C(1794346931210000000));
    ft_format_time_rfc3339(v, buf, sizeof(buf));
    CHECK_STR(buf, "2026-11-10T21:42:11.210Z");

    CHECK(ft_parse_time_rfc3339("2026-11-10T23:42:11+02:00", &v));
    CHECK_U64(v, UINT64_C(1794346931000000000));
    CHECK(ft_parse_time_rfc3339("1970-01-01T00:00:01Z", &v));
    CHECK_U64(v, FT_NS_PER_SEC);

    CHECK(!ft_parse_time_rfc3339("2026-11-10", &v));
    CHECK(!ft_parse_time_rfc3339("2026-11-10T21:42:11", &v));
    CHECK(!ft_parse_time_rfc3339("2026-13-10T21:42:11Z", &v));
    CHECK(!ft_parse_time_rfc3339("yesterday", &v));
}

static void numbers(void)
{
    uint32_t small = 0;
    char buf[32];

    CHECK(ft_parse_u32("1842", &small));
    CHECK_U64(small, 1842);
    CHECK(!ft_parse_u32("4294967296", &small));
    CHECK(!ft_parse_u32("12x", &small));
    CHECK(!ft_parse_u32("-3", &small));

    ft_format_count(1284920, buf, sizeof(buf));
    CHECK_STR(buf, "1,284,920");
    ft_format_count(110, buf, sizeof(buf));
    CHECK_STR(buf, "110");
    ft_format_count(1000, buf, sizeof(buf));
    CHECK_STR(buf, "1,000");
}

static void globs(void)
{
    CHECK(ft_glob_match("/data/report.csv", "/data/report.csv"));
    CHECK(!ft_glob_match("/data/report.csv", "/data/report.csv.bak"));
    CHECK(ft_glob_match("/data/*", "/data/export/report.csv"));
    CHECK(ft_glob_match("*.csv", "/data/report.csv"));
    CHECK(ft_glob_match("/data/*/report.???", "/data/export/report.csv"));
    CHECK(!ft_glob_match("/tmp/*", "/data/report.csv"));
    CHECK(ft_glob_match("nginx", "nginx"));
    CHECK(!ft_glob_match("nginx", "nginx2"));
    CHECK(ft_glob_match("*", ""));
}

void test_format(void)
{
    bytes();
    sizes();
    durations();
    timestamps();
    numbers();
    globs();
}
