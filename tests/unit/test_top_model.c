#include "unit/test.h"

#include "ui/top/model.h"

static const char *size_text(uint64_t bytes)
{
    static char buf[32];
    ft_top_format_size(bytes, buf, sizeof(buf));
    return buf;
}

static const char *age_text(uint64_t ns)
{
    static char buf[32];
    ft_top_format_age(ns, buf, sizeof(buf));
    return buf;
}

static const char *percent_text(double share)
{
    static char buf[32];
    ft_top_format_percent(share, buf, sizeof(buf));
    return buf;
}

static void units(void)
{
    constexpr uint64_t K = 1024;
    constexpr uint64_t M = K * K;
    constexpr uint64_t G = M * K;
    constexpr uint64_t T = G * K;
    char rate[32];

    CHECK_STR(size_text(0), "0B");
    CHECK_STR(size_text(512), "512B");
    CHECK_STR(size_text(1023), "1023B");
    CHECK_STR(size_text(K), "1K");
    CHECK_STR(size_text(51 * K + 200), "51K");
    CHECK_STR(size_text(922 * K), "922K");
    CHECK_STR(size_text(1023 * K), "1023K");
    /* 1023.5K would print as 1024K, so it is the first size shown in M. */
    CHECK_STR(size_text(1023 * K + 511), "1023K");
    CHECK_STR(size_text(1023 * K + 512), "1.0M");
    CHECK_STR(size_text(38 * M + 400 * K), "38.4M");
    CHECK_STR(size_text(1023 * M), "1023.0M");
    CHECK_STR(size_text(G - 1), "1.0G");
    CHECK_STR(size_text(2 * G + 100 * M), "2.1G");
    CHECK_STR(size_text(1023 * G), "1023.0G");
    CHECK_STR(size_text(T), "1.00T");
    CHECK_STR(size_text(T + 860 * G), "1.84T");

    ft_top_format_rate(72 * M + 300 * K, rate, sizeof(rate));
    CHECK_STR(rate, "72.3M/s");
    ft_top_format_rate(410 * K, rate, sizeof(rate));
    CHECK_STR(rate, "410K/s");

    CHECK_STR(age_text(0), "0.0s");
    CHECK_STR(age_text(300 * FT_NS_PER_MS), "0.3s");
    CHECK_STR(age_text(9 * FT_NS_PER_SEC), "9.0s");
    CHECK_STR(age_text(10 * FT_NS_PER_SEC - 1), "9.9s");
    CHECK_STR(age_text(10 * FT_NS_PER_SEC), "10s");
    CHECK_STR(age_text(21 * FT_NS_PER_SEC + 900 * FT_NS_PER_MS), "21s");
    CHECK_STR(age_text(60 * FT_NS_PER_SEC - 1), "59s");
    CHECK_STR(age_text(60 * FT_NS_PER_SEC), "1:00");
    CHECK_STR(age_text(297 * FT_NS_PER_SEC), "4:57");
    CHECK_STR(age_text(3599 * FT_NS_PER_SEC), "59:59");
    CHECK_STR(age_text(3600 * FT_NS_PER_SEC), "1h00");
    CHECK_STR(age_text(86399 * FT_NS_PER_SEC), "23h59");
    CHECK_STR(age_text(86400 * FT_NS_PER_SEC), "1d00");
    CHECK_STR(age_text((3 * 86400 + 4 * 3600 + 59) * FT_NS_PER_SEC), "3d04");

    CHECK_STR(percent_text(0.0), "  0%");
    CHECK_STR(percent_text(0.05), "  5%");
    CHECK_STR(percent_text(0.634), " 63%");
    CHECK_STR(percent_text(0.996), " 99%");
    CHECK_STR(percent_text(1.0), "100%");
    CHECK_STR(percent_text(1.7), "100%");
    CHECK_STR(percent_text(-0.2), "  0%");
}

void test_top_model(void)
{
    units();
}
