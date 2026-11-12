#include "cmd/cli.h"

#include "filetrace/format.h"
#include "ui/top/top.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct choice {
    const char *name;
    int value;
};

static const struct choice modes[] = {
    {"transfers", FT_TOP_TRANSFERS},       {"processes", FT_TOP_PROCESSES},
    {"destinations", FT_TOP_DESTINATIONS}, {"files", FT_TOP_FILES},
    {"leaders", FT_TOP_LEADERS},
};

static const struct choice sorts[] = {
    {"rate", FT_TOP_SORT_RATE},         {"bytes", FT_TOP_SORT_BYTES},
    {"progress", FT_TOP_SORT_PROGRESS}, {"age", FT_TOP_SORT_AGE},
    {"pid", FT_TOP_SORT_PID},           {"user", FT_TOP_SORT_USER},
    {"proc", FT_TOP_SORT_PROCESS},      {"script", FT_TOP_SORT_SCRIPT},
    {"file", FT_TOP_SORT_FILE},         {"size", FT_TOP_SORT_SIZE},
    {"dest", FT_TOP_SORT_DESTINATION},  {"method", FT_TOP_SORT_METHOD},
    {"conf", FT_TOP_SORT_CONFIDENCE},
};

static const struct choice groups[] = {
    {"none", FT_TOP_GROUP_NONE},     {"process", FT_TOP_GROUP_PROCESS},
    {"script", FT_TOP_GROUP_SCRIPT}, {"dest", FT_TOP_GROUP_DESTINATION},
    {"dir", FT_TOP_GROUP_DIRECTORY}, {"subnet", FT_TOP_GROUP_SUBNET},
};

static const struct choice windows[] = {
    {"1m", FT_WINDOW_1M}, {"5m", FT_WINDOW_5M},   {"15m", FT_WINDOW_15M},
    {"1h", FT_WINDOW_1H}, {"24h", FT_WINDOW_24H}, {"7d", FT_WINDOW_7D},
};

static const struct choice measures[] = {
    {"bytes", FT_SORT_BYTES},
    {"transfers", FT_SORT_TRANSFERS},
    {"dests", FT_SORT_DESTINATIONS},
};

static const struct choice colors[] = {
    {"auto", FT_TOP_COLOR_AUTO},
    {"always", FT_TOP_COLOR_ALWAYS},
    {"never", FT_TOP_COLOR_NEVER},
};

/* The options the reports take and the live view lacks, with the report that shows each one. */
static const struct {
    const char *name;
    const char *subject;
} report_options[] = {
    {"--since", "processes"},   {"--until", "processes"}, {"--pid", "processes"},
    {"--process", "processes"}, {"--name", "processes"},  {"--protocol", "files"},
    {"--format", "processes"},  {"--jsonl", "processes"}, {"--output", "processes"},
};

constexpr uint32_t LIMIT_MAX = 1000;
constexpr size_t SCRIPT_MAX = sizeof(((struct ft_query *)nullptr)->script);

struct top_args {
    struct ft_top_options opt;
    const char *expression;   /* --filter */
    const char *remote;       /* --remote */
    const char *script;       /* --script */
    const char *leaders_only; /* the first of --window, --by and --limit that was given */
    bool mode_given;
    bool leaders;
    bool sort_given;
};

static int bad_value(const char *option, const char *value, const char *expected)
{
    ft_usage_error("top", "invalid value '%s' for %s (expected %s)", value, option, expected);
    return -1;
}

/* Returns 1 with *value set, -1 after reporting a value that is not among the choices. */
static int choose(const struct choice *choices, size_t count, const char *option, const char *text,
                  int *value)
{
    char expected[160] = "";
    size_t len = 0;

    for (size_t i = 0; i < count; i++) {
        if (strcmp(choices[i].name, text) == 0) {
            *value = choices[i].value;
            return 1;
        }
        int n = snprintf(expected + len, sizeof(expected) - len, "%s%s",
                         i == 0 ? "" : (i == count - 1 ? " or " : ", "), choices[i].name);
        if (n > 0 && (size_t)n < sizeof(expected) - len)
            len += (size_t)n;
    }
    return bad_value(option, text, expected);
}

/* Whether the current argument is the option, bare or with "=value". */
static bool names(const struct ft_args *a, const char *name)
{
    const char *arg = ft_args_peek(a);
    size_t len = strlen(name);
    return arg && strncmp(arg, name, len) == 0 && (arg[len] == '\0' || arg[len] == '=');
}

static int set_remote(struct top_args *t, const char *value)
{
    struct ft_endpoint net;
    uint8_t bits;

    if (!ft_prefix_parse(value, &net, &bits))
        return bad_value("--remote", value, "an IP address or CIDR network");
    t->remote = value;
    return 1;
}

static int set_script(struct top_args *t, const char *value)
{
    if (value[0] == '\0')
        return bad_value("--script", value, "a pattern");
    if (strlen(value) >= SCRIPT_MAX)
        return bad_value("--script", value, "a shorter pattern");
    if (strchr(value, '"'))
        return bad_value("--script", value, "a pattern without double quotes");
    t->script = value;
    return 1;
}

static int set_delay(struct top_args *t, const char *value)
{
    uint64_t ns;

    if (!ft_parse_duration(value, &ns) || ns < FT_TOP_DELAY_MIN_NS || ns > FT_TOP_DELAY_MAX_NS)
        return bad_value("--delay", value, "a duration from 500ms to 10s");
    t->opt.delay_ns = ns;
    return 1;
}

static int set_limit(struct top_args *t, const char *value)
{
    uint32_t n;

    if (!ft_parse_u32(value, &n) || n < 1 || n > LIMIT_MAX)
        return bad_value("--limit", value, "a number from 1 to 1000");
    t->opt.limit = n;
    return 1;
}

static int parse_choice_option(struct top_args *t, struct ft_args *a)
{
    struct ft_top_options *o = &t->opt;
    const char *v;
    int choice;
    int r;

    if ((r = ft_args_value(a, "--mode", &v)) != 0) {
        if (r < 0 || choose(modes, FT_ARRAY_LEN(modes), "--mode", v, &choice) < 0)
            return -1;
        o->mode = (enum ft_top_mode)choice;
        t->mode_given = true;
    } else if ((r = ft_args_value(a, "--sort", &v)) != 0) {
        if (r < 0 || choose(sorts, FT_ARRAY_LEN(sorts), "--sort", v, &choice) < 0)
            return -1;
        o->sort = (enum ft_top_sort)choice;
        t->sort_given = true;
    } else if ((r = ft_args_value(a, "--group", &v)) != 0) {
        if (r < 0 || choose(groups, FT_ARRAY_LEN(groups), "--group", v, &choice) < 0)
            return -1;
        o->group = (enum ft_top_group)choice;
    } else if ((r = ft_args_value(a, "--color", &v)) != 0) {
        if (r < 0 || choose(colors, FT_ARRAY_LEN(colors), "--color", v, &choice) < 0)
            return -1;
        o->color = (enum ft_top_color)choice;
    } else if ((r = ft_args_value(a, "--window", &v)) != 0) {
        if (r < 0 || choose(windows, FT_ARRAY_LEN(windows), "--window", v, &choice) < 0)
            return -1;
        o->window = (enum ft_leader_window)choice;
        t->leaders_only = t->leaders_only ? t->leaders_only : "--window";
    } else if ((r = ft_args_value(a, "--by", &v)) != 0) {
        if (r < 0 || choose(measures, FT_ARRAY_LEN(measures), "--by", v, &choice) < 0)
            return -1;
        o->by = (enum ft_sort)choice;
        t->leaders_only = t->leaders_only ? t->leaders_only : "--by";
    } else {
        return 0;
    }
    return 1;
}

/* Returns 1 for a consumed option, 0 for an unknown argument, -1 after reporting a bad one. */
static int parse_option(struct top_args *t, struct ft_args *a)
{
    const char *v;
    int r;

    if (ft_args_flag(a, "--leaders")) {
        t->leaders = true;
        return 1;
    }
    if (ft_args_flag(a, "--tree")) {
        t->opt.tree = true;
        return 1;
    }
    if (ft_args_flag(a, "--reverse")) {
        t->opt.reverse = true;
        return 1;
    }
    if (ft_args_flag(a, "--once")) {
        t->opt.once = true;
        return 1;
    }
    if (ft_args_flag(a, "--json")) {
        t->opt.json = true;
        return 1;
    }
    if (ft_args_flag(a, "--resolve-hostnames")) {
        t->opt.resolve = true;
        return 1;
    }
    if ((r = parse_choice_option(t, a)) != 0)
        return r;

    if ((r = ft_args_value(a, "--filter", &v)) != 0) {
        if (r > 0)
            t->expression = v;
        return r;
    }
    if ((r = ft_args_value(a, "--remote", &v)) != 0)
        return r < 0 ? -1 : set_remote(t, v);
    if ((r = ft_args_value(a, "--script", &v)) != 0)
        return r < 0 ? -1 : set_script(t, v);
    if ((r = ft_args_value(a, "--delay", &v)) != 0)
        return r < 0 ? -1 : set_delay(t, v);
    if ((r = ft_args_value(a, "--limit", &v)) != 0) {
        if (r < 0)
            return -1;
        t->leaders_only = t->leaders_only ? t->leaders_only : "--limit";
        return set_limit(t, v);
    }
    return 0;
}

static int refuse(const struct ft_args *a)
{
    for (size_t i = 0; i < FT_ARRAY_LEN(report_options); i++) {
        if (names(a, report_options[i].name))
            return ft_usage_error("top", "%s applies to a report: filetrace top %s %s ...",
                                  report_options[i].name, report_options[i].subject,
                                  report_options[i].name);
    }
    return ft_usage_error("top", "unknown argument '%s' for 'top'", ft_args_peek(a));
}

/* Settles the mode and refuses the options the settled mode lacks. */
static int check(struct top_args *t)
{
    struct ft_top_options *o = &t->opt;

    if (t->leaders) {
        if (t->mode_given && o->mode != FT_TOP_LEADERS)
            return ft_usage_error("top", "--leaders conflicts with --mode %s",
                                  ft_top_mode_name(o->mode));
        o->mode = FT_TOP_LEADERS;
    }
    if (o->tree && !t->mode_given && !t->leaders)
        o->mode = FT_TOP_PROCESSES;

    if (o->tree && o->mode != FT_TOP_PROCESSES)
        return ft_usage_error("top", "--tree does not apply to the %s mode (use --mode processes)",
                              ft_top_mode_name(o->mode));
    if (o->mode == FT_TOP_LEADERS && t->sort_given)
        return ft_usage_error("top", "--sort does not apply to the leaders mode (use --by)");
    if (o->mode != FT_TOP_LEADERS && t->leaders_only)
        return ft_usage_error("top", "%s does not apply to the %s mode (use --leaders)",
                              t->leaders_only, ft_top_mode_name(o->mode));
    return FT_EXIT_OK;
}

/* The expression, then the terms the shortcut options stand for; nullptr when none. */
static int join_filter(const struct top_args *t, char **out)
{
    const struct {
        const char *key;
        const char *value;
    } terms[] = {{"dest", t->remote}, {"script", t->script}};
    size_t size = strlen(t->expression ? t->expression : "") + 1;
    size_t len = 0;
    char *text;

    /* A term takes a separator, its key, a colon, its value and a pair of quotes. */
    for (size_t i = 0; i < FT_ARRAY_LEN(terms); i++) {
        if (terms[i].value)
            size += strlen(terms[i].key) + strlen(terms[i].value) + 4;
    }
    *out = nullptr;
    if (size == 1)
        return FT_EXIT_OK;
    text = malloc(size);
    if (!text) {
        fprintf(stderr, "filetrace: out of memory\n");
        return FT_EXIT_ERROR;
    }
    if (t->expression)
        len = (size_t)snprintf(text, size, "%s", t->expression);
    for (size_t i = 0; i < FT_ARRAY_LEN(terms); i++) {
        if (!terms[i].value)
            continue;
        bool quoted = strpbrk(terms[i].value, " \t") != nullptr;
        len += (size_t)snprintf(text + len, size - len, "%s%s:%s%s%s", len ? " " : "", terms[i].key,
                                quoted ? "\"" : "", terms[i].value, quoted ? "\"" : "");
    }
    *out = text;
    return FT_EXIT_OK;
}

int ft_cmd_top(const struct ft_cli *cli, struct ft_args *a)
{
    struct top_args t = {0};
    struct ft_session session;
    char *filter;
    int code;

    /* A subject starts a report; options and nothing at all start the live view. */
    const char *first = ft_args_peek(a);
    if (first && first[0] != '-')
        return ft_cmd_top_report(cli, a);

    ft_top_options_defaults(&t.opt);
    while (!ft_args_done(a)) {
        int r = parse_option(&t, a);
        if (r < 0)
            return FT_EXIT_USAGE;
        if (r == 0)
            return refuse(a);
    }
    code = check(&t);
    if (code != FT_EXIT_OK)
        return code;
    code = join_filter(&t, &filter);
    if (code != FT_EXIT_OK)
        return code;
    t.opt.filter = filter;
    if (!t.opt.json && !isatty(STDOUT_FILENO))
        t.opt.once = true;

    code = ft_session_open(cli, true, &session);
    if (code == FT_EXIT_OK) {
        code = ft_top_run(&session, cli, &t.opt);
        ft_session_close(&session);
    }
    free(filter);
    return code;
}
