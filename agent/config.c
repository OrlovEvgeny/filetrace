#include "agent/config.h"

#include "filetrace/format.h"
#include "filetrace/net.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

const char *ft_config_default_path(void)
{
    const char *env = getenv("FILETRACE_CONFIG");
    return env && env[0] ? env : "/etc/filetrace/config.toml";
}

/* Files that programs read on their way to a connection and that nobody sends by reading them:
 * trust stores, resolver files, time zones, locale data, interpreter configuration, compiled
 * modules, the data files that libraries load whole as they start, and what a JVM loads from
 * its JDK. */
static const char *const default_background_paths[] = {
    "/etc/ssl/certs/*",
    "/etc/ssl/cert.pem",
    "/etc/pki/tls/certs/*",
    "/etc/pki/ca-trust/extracted/*",
    "/etc/ca-certificates/extracted/*",
    "/usr/share/ca-certificates/*",
    "/usr/local/share/ca-certificates/*",
    "/etc/pki/ca-trust/source/*",
    "/usr/share/pki/ca-trust-source/*",
    "/etc/pki/trust/*",
    "/usr/share/pki/trust/*",
    "/etc/ca-certificates/trust-source/*",
    "/etc/ssl/openssl.cnf",
    "/etc/pki/tls/openssl.cnf",
    "/usr/lib/ssl/openssl.cnf",
    "/etc/php/*",
    "*/php.ini",
    "/etc/hosts",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
    "/etc/gai.conf",
    "/etc/mime.types",
    "/usr/share/zoneinfo/*",
    "/etc/localtime",
    "/usr/lib/locale/*",
    "*.mo",
    "*.pyc",
    "*/cacert.pem",
    "*/cacerts",
    "*/ca-bundle.crt",
    "*/ca-certificates.crt",
    "*/endpoints.json",
    "*/partitions.json",
    "*/sdk-default-configuration.json",
    "*/service-2.json",
    "*/service-2.json.gz",
    "*/endpoint-rule-set-1.json",
    "*/endpoint-rule-set-1.json.gz",
    "/usr/lib/jvm/*",
    "/usr/lib64/jvm/*",
    "/usr/java/*",
    "/usr/local/openjdk-*",
    "/opt/java/*",
    "/etc/java*",
    /* By name, so that a JVM's own files count from their first read in a container too. */
    "*/modules",
    "*/libnet.so",
    "*/libnio.so",
    "*/libextnet.so",
    "*/libjimage.so",
    "*/net.properties",
    "*/java.security",
    "*.policy",
    "*.jsa",
};

/* Files that programs load as they run and that people also send: account databases, source
 * modules, shared libraries. */
static const char *const default_strict_paths[] = {
    "/etc/passwd", "/etc/group", "*.py", "*.rb", "*.js",  "*.mjs", "*.cjs",  "*.node",
    "*.jar",       "*.class",    "*.pm", "*.pl", "*.php", "*.so",  "*.so.*",
};

static_assert(FT_ARRAY_LEN(default_background_paths) <= FT_CONFIG_MAX_PATTERNS);
static_assert(FT_ARRAY_LEN(default_strict_paths) <= FT_CONFIG_MAX_PATTERNS);

static bool patterns_set(char **items, size_t *count, const char *const *from, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        items[i] = strdup(from[i]);
        if (!items[i])
            return false;
        (*count)++;
    }
    return true;
}

struct ft_config *ft_config_new(void)
{
    struct ft_config *cfg = calloc(1, sizeof(*cfg));
    if (!cfg)
        return nullptr;

    ft_agent_config_defaults(&cfg->agent);
    ft_strlcpy(cfg->socket_path, ft_default_socket_path(), sizeof(cfg->socket_path));
    cfg->agent.socket_path = cfg->socket_path;
    cfg->agent.state_cfg.exclude_processes = (const char *const *)cfg->exclude_processes;
    cfg->agent.state_cfg.exclude_paths = (const char *const *)cfg->exclude_paths;
    cfg->agent.state_cfg.no_minimum_paths = (const char *const *)cfg->no_minimum_paths;
    cfg->agent.backend_cfg.background_paths = (const char *const *)cfg->background_paths;
    cfg->agent.backend_cfg.strict_paths = (const char *const *)cfg->strict_paths;
    if (!patterns_set(cfg->background_paths, &cfg->background_path_count, default_background_paths,
                      FT_ARRAY_LEN(default_background_paths)) ||
        !patterns_set(cfg->strict_paths, &cfg->strict_path_count, default_strict_paths,
                      FT_ARRAY_LEN(default_strict_paths))) {
        ft_config_free(cfg);
        return nullptr;
    }
    cfg->enabled = true;
    cfg->log_level = FT_LOG_INFO;
    cfg->correlation_enabled = true;
    cfg->track_read = true;
    cfg->track_sendfile = true;
    cfg->track_process_lifecycle = true;
    cfg->names_enabled = true;
    cfg->names_lookups = true;
    cfg->names_tls = true;
    cfg->timestamps = true;
    ft_strlcpy(cfg->format, "table", sizeof(cfg->format));
    ft_strlcpy(cfg->storage_path, "/var/lib/filetrace", sizeof(cfg->storage_path));
    cfg->storage_retention_ns = 7 * 24 * 3600 * FT_NS_PER_SEC;
    return cfg;
}

static void patterns_clear(char **items, size_t *count)
{
    for (size_t i = 0; i < *count; i++)
        free(items[i]);
    *count = 0;
}

void ft_config_free(struct ft_config *cfg)
{
    if (!cfg)
        return;
    patterns_clear(cfg->exclude_processes, &cfg->exclude_process_count);
    patterns_clear(cfg->exclude_paths, &cfg->exclude_path_count);
    patterns_clear(cfg->no_minimum_paths, &cfg->no_minimum_path_count);
    patterns_clear(cfg->background_paths, &cfg->background_path_count);
    patterns_clear(cfg->strict_paths, &cfg->strict_path_count);
    free(cfg);
}

[[gnu::format(printf, 2, 3)]]
static void warn(struct ft_config *cfg, const char *fmt, ...);

void ft_config_finish(struct ft_config *cfg)
{
    struct ft_backend_config *backend = &cfg->agent.backend_cfg;
    struct ft_state_config *state = &cfg->agent.state_cfg;

    backend->track_read = cfg->correlation_enabled && cfg->track_read;
    backend->track_sendfile = cfg->correlation_enabled && cfg->track_sendfile;
    state->exclude_process_count = cfg->exclude_process_count;
    state->exclude_path_count = cfg->exclude_path_count;
    state->no_minimum_path_count = cfg->no_minimum_path_count;
    backend->background_path_count = cfg->background_path_count;
    backend->strict_path_count = cfg->strict_path_count;
    state->names = cfg->names_enabled;
    backend->lookup_names = cfg->names_enabled && cfg->names_lookups;
    backend->tls_names = cfg->names_enabled && cfg->names_tls;
    if (backend->mode == FT_MODE_MINIMAL && cfg->names_set && cfg->names_enabled)
        warn(cfg, "[names] has no effect in minimal mode: names come from probes that only "
                  "standard mode attaches");

    /* Minimal mode queues only process and socket events, far fewer than standard mode. */
    if (backend->mode == FT_MODE_MINIMAL) {
        if (!cfg->queue_size_set)
            backend->queue_bytes = 1024u * 1024u;
        if (!cfg->event_log_size_set)
            state->event_log_bytes = 256u * 1024u;
    }
}

enum value_type : uint8_t {
    VALUE_STRING,
    VALUE_BOOL,
    VALUE_INTEGER,
    VALUE_STRINGS,
};

struct value {
    enum value_type type;
    bool boolean;
    int64_t integer;
    char string[512];
    char *items[FT_CONFIG_MAX_PATTERNS];
    size_t count;
};

struct parser {
    const char *path;
    const char *p;
    unsigned line;
    struct ft_error *err;
};

[[gnu::format(printf, 2, 3)]]
static bool fail(struct parser *ps, const char *fmt, ...)
{
    char what[400];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(what, sizeof(what), fmt, ap);
    va_end(ap);
    ft_error_set(ps->err, FT_EXIT_CONFIG, "%s:%u: %s", ps->path, ps->line, what);
    return false;
}

static void skip_blanks(struct parser *ps)
{
    while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\r')
        ps->p++;
    if (*ps->p == '#') {
        while (*ps->p && *ps->p != '\n')
            ps->p++;
    }
}

/* Also crosses line ends, as the inside of an array may. */
static void skip_lines(struct parser *ps)
{
    for (;;) {
        skip_blanks(ps);
        if (*ps->p != '\n')
            return;
        ps->p++;
        ps->line++;
    }
}

static bool parse_name(struct parser *ps, char *out, size_t size)
{
    size_t n = 0;

    while (isalnum((unsigned char)*ps->p) || *ps->p == '_' || *ps->p == '-') {
        if (n + 1 >= size)
            return fail(ps, "the name is too long");
        out[n++] = *ps->p++;
    }
    out[n] = '\0';
    return n > 0 || fail(ps, "expected a name");
}

static bool parse_string(struct parser *ps, char *out, size_t size)
{
    char quote = *ps->p++;
    size_t n = 0;

    for (;;) {
        char c = *ps->p;
        if (c == '\0' || c == '\n')
            return fail(ps, "the string is not closed");
        ps->p++;
        if (c == quote)
            break;
        if (c == '\\' && quote == '"') {
            c = *ps->p++;
            if (c == 'n')
                c = '\n';
            else if (c == 't')
                c = '\t';
            else if (c != '\\' && c != '"')
                return fail(ps, "unknown escape in a string");
        }
        if (n + 1 >= size)
            return fail(ps, "the string is too long");
        out[n++] = c;
    }
    out[n] = '\0';
    return true;
}

static void value_release(struct value *v)
{
    for (size_t i = 0; i < v->count; i++)
        free(v->items[i]);
    v->count = 0;
}

static bool parse_value(struct parser *ps, struct value *v)
{
    char c = *ps->p;

    v->count = 0;
    if (c == '"' || c == '\'') {
        v->type = VALUE_STRING;
        return parse_string(ps, v->string, sizeof(v->string));
    }
    if (c == '[') {
        v->type = VALUE_STRINGS;
        ps->p++;
        for (;;) {
            skip_lines(ps);
            if (*ps->p == ']') {
                ps->p++;
                return true;
            }
            if (*ps->p != '"' && *ps->p != '\'')
                return fail(ps, "expected a string in the list");
            if (v->count == FT_CONFIG_MAX_PATTERNS)
                return fail(ps, "the list has more than %d entries", FT_CONFIG_MAX_PATTERNS);
            if (!parse_string(ps, v->string, sizeof(v->string)))
                return false;
            v->items[v->count] = strdup(v->string);
            if (!v->items[v->count])
                return fail(ps, "out of memory");
            v->count++;
            skip_lines(ps);
            if (*ps->p == ',')
                ps->p++;
            else if (*ps->p != ']')
                return fail(ps, "expected ',' or ']' in the list");
        }
    }
    if (strncmp(ps->p, "true", 4) == 0 && !isalnum((unsigned char)ps->p[4])) {
        v->type = VALUE_BOOL;
        v->boolean = true;
        ps->p += 4;
        return true;
    }
    if (strncmp(ps->p, "false", 5) == 0 && !isalnum((unsigned char)ps->p[5])) {
        v->type = VALUE_BOOL;
        v->boolean = false;
        ps->p += 5;
        return true;
    }
    if (isdigit((unsigned char)c) || c == '-' || c == '+') {
        char digits[32];
        size_t n = 0;

        if (c == '-' || c == '+')
            digits[n++] = *ps->p++;
        while (isdigit((unsigned char)*ps->p) || *ps->p == '_') {
            if (*ps->p != '_' && n + 1 < sizeof(digits))
                digits[n++] = *ps->p;
            ps->p++;
        }
        digits[n] = '\0';
        if (*ps->p == '.' || isalpha((unsigned char)*ps->p))
            return fail(ps, "expected a whole number; quote sizes and durations, as in \"64MB\"");
        errno = 0;
        v->type = VALUE_INTEGER;
        v->integer = strtoll(digits, nullptr, 10);
        return errno == 0 || fail(ps, "the number is out of range");
    }
    return fail(ps, "expected a string, a number, true, false or a list of strings");
}

static bool want_bool(const struct value *v, bool *out, char *why, size_t size)
{
    if (v->type != VALUE_BOOL) {
        snprintf(why, size, "expected true or false");
        return false;
    }
    *out = v->boolean;
    return true;
}

static bool want_string(const struct value *v, char *out, size_t out_size, char *why, size_t size)
{
    if (v->type != VALUE_STRING || !v->string[0] || strlen(v->string) >= out_size) {
        snprintf(why, size, "expected a string of at most %zu characters", out_size - 1);
        return false;
    }
    ft_strlcpy(out, v->string, out_size);
    return true;
}

static bool want_count(const struct value *v, uint64_t min, uint64_t max, uint64_t *out, char *why,
                       size_t size)
{
    if (v->type != VALUE_INTEGER || v->integer < 0 || (uint64_t)v->integer < min ||
        (uint64_t)v->integer > max) {
        snprintf(why, size, "expected a whole number from %" PRIu64 " to %" PRIu64, min, max);
        return false;
    }
    *out = (uint64_t)v->integer;
    return true;
}

/* A size is a number of bytes or a quoted size such as "64MB"; zero_too allows turning it off. */
static bool want_size(const struct value *v, uint64_t min, uint64_t max, bool zero_too,
                      uint64_t *out, char *why, size_t size)
{
    char lo[32];
    char hi[32];
    uint64_t bytes = 0;
    bool ok = v->type == VALUE_INTEGER ? v->integer >= 0 : v->type == VALUE_STRING;

    if (ok && v->type == VALUE_INTEGER)
        bytes = (uint64_t)v->integer;
    else if (ok)
        ok = ft_parse_size(v->string, &bytes);
    if (ok && ((bytes >= min && bytes <= max) || (zero_too && bytes == 0))) {
        *out = bytes;
        return true;
    }
    ft_format_bytes(min, lo, sizeof(lo));
    ft_format_bytes(max, hi, sizeof(hi));
    snprintf(why, size, "expected a size from %s to %s, such as \"4MB\"%s", lo, hi,
             zero_too ? ", or 0" : "");
    return false;
}

static bool want_duration(const struct value *v, uint64_t min_ns, uint64_t max_ns, uint64_t *out,
                          char *why, size_t size)
{
    char lo[32];
    char hi[32];
    uint64_t ns = 0;

    if (v->type == VALUE_STRING && ft_parse_duration(v->string, &ns) && ns >= min_ns &&
        ns <= max_ns) {
        *out = ns;
        return true;
    }
    if (min_ns < FT_NS_PER_SEC)
        snprintf(lo, sizeof(lo), "%" PRIu64 "ms", min_ns / FT_NS_PER_MS);
    else
        ft_format_duration(min_ns, lo, sizeof(lo));
    ft_format_duration(max_ns, hi, sizeof(hi));
    snprintf(why, size, "expected a quoted duration from %s to %s, such as \"250ms\"", lo, hi);
    return false;
}

static bool want_patterns(struct value *v, char **items, size_t *count, char *why, size_t size)
{
    if (v->type != VALUE_STRINGS) {
        snprintf(why, size, "expected a list of strings, such as [\"/proc/*\"]");
        return false;
    }
    for (size_t i = 0; i < v->count; i++) {
        if (!v->items[i][0]) {
            snprintf(why, size, "a pattern is empty");
            return false;
        }
    }
    patterns_clear(items, count);
    for (size_t i = 0; i < v->count; i++)
        items[i] = v->items[i];
    *count = v->count;
    v->count = 0;
    return true;
}

[[gnu::format(printf, 2, 3)]]
static void warn(struct ft_config *cfg, const char *fmt, ...)
{
    va_list ap;

    if (cfg->warning_count == FT_CONFIG_MAX_WARNINGS)
        return;
    va_start(ap, fmt);
    vsnprintf(cfg->warnings[cfg->warning_count++], sizeof(cfg->warnings[0]), fmt, ap);
    va_end(ap);
}

/* A setting this build cannot honour is kept, and asking for it is answered with a warning. */
static bool want_unavailable(struct ft_config *cfg, const struct value *v, bool *out,
                             const char *name, const char *reason, char *why, size_t size)
{
    if (!want_bool(v, out, why, size))
        return false;
    if (*out)
        warn(cfg, "%s = true is ignored: %s", name, reason);
    return true;
}

constexpr uint64_t KB = 1024;
constexpr uint64_t MB = 1024 * 1024;

static bool apply_agent(struct ft_config *cfg, const char *key, struct value *v, char *why,
                        size_t size, bool *known)
{
    struct ft_backend_config *backend = &cfg->agent.backend_cfg;
    char text[32];
    uint64_t n;

    if (strcmp(key, "enabled") == 0)
        return want_bool(v, &cfg->enabled, why, size);
    if (strcmp(key, "mode") == 0) {
        if (want_string(v, text, sizeof(text), why, size) && ft_mode_parse(text, &backend->mode))
            return true;
        snprintf(why, size, "expected \"minimal\" or \"standard\"");
        return false;
    }
    if (strcmp(key, "probes") == 0) {
        if (want_string(v, text, sizeof(text), why, size) &&
            ft_probes_parse(text, &backend->probes))
            return true;
        snprintf(why, size, "expected \"auto\", \"trampoline\" or \"kprobe\"");
        return false;
    }
    if (strcmp(key, "socket") == 0)
        return want_string(v, cfg->socket_path, sizeof(cfg->socket_path), why, size);
    if (strcmp(key, "ring_buffer_size") == 0) {
        if (!want_size(v, 64 * KB, 1024 * MB, false, &n, why, size))
            return false;
        backend->queue_bytes = (uint32_t)n;
        cfg->queue_size_set = true;
        return true;
    }
    if (strcmp(key, "event_batch_size") == 0) {
        if (!want_count(v, 16, 65536, &n, why, size))
            return false;
        backend->drain_batch = (uint32_t)n;
        return true;
    }
    if (strcmp(key, "flush_interval") == 0) {
        if (!want_duration(v, 10 * FT_NS_PER_MS, 60 * FT_NS_PER_SEC, &n, why, size))
            return false;
        cfg->agent.flush_interval_ms = (uint32_t)(n / FT_NS_PER_MS);
        return true;
    }
    if (strcmp(key, "event_log_size") == 0) {
        if (!want_size(v, 64 * KB, 256 * MB, true, &n, why, size))
            return false;
        cfg->agent.state_cfg.event_log_bytes = (size_t)n;
        cfg->event_log_size_set = true;
        return true;
    }
    if (strcmp(key, "log_level") == 0) {
        if (want_string(v, text, sizeof(text), why, size) &&
            ft_log_level_parse(text, &cfg->log_level))
            return true;
        snprintf(why, size, "expected \"error\", \"warn\", \"info\" or \"debug\"");
        return false;
    }
    *known = false;
    return false;
}

static bool apply_network(struct ft_config *cfg, const char *key, struct value *v, char *why,
                          size_t size, bool *known)
{
    struct ft_state_config *state = &cfg->agent.state_cfg;
    bool *ignore = strcmp(key, "tcp") == 0    ? &state->ignore_tcp
                   : strcmp(key, "udp") == 0  ? &state->ignore_udp
                   : strcmp(key, "ipv4") == 0 ? &state->ignore_ipv4
                   : strcmp(key, "ipv6") == 0 ? &state->ignore_ipv6
                                              : nullptr;
    bool on;

    if (ignore) {
        if (!want_bool(v, &on, why, size))
            return false;
        *ignore = !on;
        return true;
    }
    if (strcmp(key, "tc_egress") == 0)
        return want_unavailable(cfg, v, &cfg->tc_egress, "[network] tc_egress",
                                "bytes are counted at the socket, not per packet", why, size);
    *known = false;
    return false;
}

static bool apply_file(struct ft_config *cfg, const char *key, struct value *v, char *why,
                       size_t size, bool *known)
{
    if (strcmp(key, "track_read") == 0)
        return want_bool(v, &cfg->track_read, why, size);
    if (strcmp(key, "track_sendfile") == 0)
        return want_bool(v, &cfg->track_sendfile, why, size);
    if (strcmp(key, "track_open") == 0)
        return want_unavailable(cfg, v, &cfg->track_open, "[file] track_open",
                                "opens are not traced; a file is identified when it is read "
                                "or sent",
                                why, size);
    if (strcmp(key, "track_mmap") == 0)
        return want_unavailable(cfg, v, &cfg->track_mmap, "[file] track_mmap",
                                "data read through memory mappings is not observed", why, size);
    if (strcmp(key, "track_splice") == 0)
        return want_unavailable(cfg, v, &cfg->track_splice, "[file] track_splice",
                                "transfers through pipes with splice are not followed", why, size);
    *known = false;
    return false;
}

static bool apply_correlation(struct ft_config *cfg, const char *key, struct value *v, char *why,
                              size_t size, bool *known)
{
    struct ft_state_config *state = &cfg->agent.state_cfg;
    char text[32];
    uint64_t n;

    if (strcmp(key, "enabled") == 0)
        return want_bool(v, &cfg->correlation_enabled, why, size);
    if (strcmp(key, "window") == 0)
        return want_duration(v, FT_NS_PER_MS, 60 * FT_NS_PER_SEC,
                             &cfg->agent.backend_cfg.corr_window_ns, why, size);
    if (strcmp(key, "confidence_threshold") == 0) {
        enum ft_confidence level;
        if (want_string(v, text, sizeof(text), why, size) && ft_confidence_parse(text, &level) &&
            level != FT_CONF_UNKNOWN) {
            state->min_confidence = level;
            return true;
        }
        snprintf(why, size, "expected \"inferred\", \"strong\" or \"exact\"");
        return false;
    }
    if (strcmp(key, "inferred_min_bytes") == 0)
        return want_size(v, 0, 1024 * MB, false, &state->inferred_min_bytes, why, size);
    if (strcmp(key, "inferred_min_percent") == 0) {
        if (!want_count(v, 0, 100, &n, why, size))
            return false;
        state->inferred_min_permille = (uint32_t)n * 10;
        return true;
    }
    if (strcmp(key, "no_minimum_paths") == 0)
        return want_patterns(v, cfg->no_minimum_paths, &cfg->no_minimum_path_count, why, size);
    if (strcmp(key, "background_paths") == 0)
        return want_patterns(v, cfg->background_paths, &cfg->background_path_count, why, size);
    if (strcmp(key, "strict_paths") == 0)
        return want_patterns(v, cfg->strict_paths, &cfg->strict_path_count, why, size);
    if (strcmp(key, "track_fd_lifecycle") == 0)
        return want_unavailable(cfg, v, &cfg->track_fd_lifecycle,
                                "[correlation] track_fd_lifecycle",
                                "descriptors are not followed; transfers are keyed on the "
                                "kernel's file and socket objects",
                                why, size);
    if (strcmp(key, "track_io_uring") == 0)
        return want_unavailable(cfg, v, &cfg->track_io_uring, "[correlation] track_io_uring",
                                "file reads through io_uring are not observed", why, size);
    if (strcmp(key, "track_process_lifecycle") == 0) {
        if (!want_bool(v, &cfg->track_process_lifecycle, why, size))
            return false;
        if (!cfg->track_process_lifecycle)
            warn(cfg, "[correlation] track_process_lifecycle = false is ignored: process "
                      "lifetimes are always followed");
        return true;
    }
    *known = false;
    return false;
}

static bool apply_storage(struct ft_config *cfg, const char *key, struct value *v, char *why,
                          size_t size, bool *known)
{
    if (strcmp(key, "enabled") == 0)
        return want_unavailable(cfg, v, &cfg->storage_enabled, "[storage] enabled",
                                "history is kept in memory only and starts when the agent does",
                                why, size);
    if (strcmp(key, "path") == 0)
        return want_string(v, cfg->storage_path, sizeof(cfg->storage_path), why, size);
    if (strcmp(key, "retention") == 0)
        return want_duration(v, FT_NS_PER_SEC, 3650 * 24 * 3600 * FT_NS_PER_SEC,
                             &cfg->storage_retention_ns, why, size);
    *known = false;
    return false;
}

static bool apply_limits(struct ft_config *cfg, const char *key, struct value *v, char *why,
                         size_t size, bool *known)
{
    struct ft_state_config *state = &cfg->agent.state_cfg;
    struct ft_backend_config *backend = &cfg->agent.backend_cfg;
    size_t *table = strcmp(key, "processes") == 0       ? &state->max_processes
                    : strcmp(key, "sockets") == 0       ? &state->max_sockets
                    : strcmp(key, "flows") == 0         ? &state->max_flows
                    : strcmp(key, "files") == 0         ? &state->max_files
                    : strcmp(key, "transfers") == 0     ? &state->max_transfers
                    : strcmp(key, "metric_series") == 0 ? &state->max_metric_series
                                                        : nullptr;
    uint32_t *map = strcmp(key, "kernel_counters") == 0 ? &backend->agg_entries
                    : strcmp(key, "kernel_files") == 0  ? &backend->known_files
                                                        : nullptr;
    uint64_t min = 64;
    uint64_t max = 4 * 1024 * 1024;
    uint64_t n;

    if (strcmp(key, "file_rankings") == 0) {
        constexpr uint64_t MAX_RANKED = 1024 * 1024;
        bool off = v->type == VALUE_INTEGER && v->integer == 0;
        if (!off && !want_count(v, 64, MAX_RANKED, &n, why, size)) {
            snprintf(why, size, "expected 0 or a whole number from 64 to %" PRIu64, MAX_RANKED);
            return false;
        }
        state->leader_entries = off ? 0 : (size_t)n;
        return true;
    }
    if (strcmp(key, "names") == 0) {
        table = &state->max_names;
        min = 1;
    } else if (strcmp(key, "name_lookups") == 0) {
        table = &state->max_name_lookups;
        min = 1;
    } else if (strcmp(key, "name_libraries") == 0) {
        map = &backend->name_libraries;
        min = 1;
        max = 4096;
    }
    if (!table && !map) {
        *known = false;
        return false;
    }
    if (!want_count(v, min, max, &n, why, size))
        return false;
    if (table)
        *table = (size_t)n;
    else
        *map = (uint32_t)n;
    return true;
}

static bool apply_output(struct ft_config *cfg, const char *key, struct value *v, char *why,
                         size_t size, bool *known)
{
    static const char *const formats[] = {"table", "json", "jsonl", "csv", "quiet"};
    char text[sizeof(cfg->format)];

    if (strcmp(key, "timestamps") == 0)
        return want_bool(v, &cfg->timestamps, why, size);
    if (strcmp(key, "format") == 0) {
        bool is_string = want_string(v, text, sizeof(text), why, size);
        for (size_t i = 0; is_string && i < FT_ARRAY_LEN(formats); i++) {
            if (strcmp(text, formats[i]) == 0) {
                ft_strlcpy(cfg->format, text, sizeof(cfg->format));
                return true;
            }
        }
        snprintf(why, size, "expected \"table\", \"json\", \"jsonl\", \"csv\" or \"quiet\"");
        return false;
    }
    *known = false;
    return false;
}

static bool apply_filters(struct ft_config *cfg, const char *key, struct value *v, char *why,
                          size_t size, bool *known)
{
    if (strcmp(key, "exclude_processes") == 0)
        return want_patterns(v, cfg->exclude_processes, &cfg->exclude_process_count, why, size);
    if (strcmp(key, "exclude_paths") == 0)
        return want_patterns(v, cfg->exclude_paths, &cfg->exclude_path_count, why, size);
    *known = false;
    return false;
}

static bool apply_process(struct ft_config *cfg, const char *key, struct value *v, char *why,
                          size_t size, bool *known)
{
    if (strcmp(key, "arguments") == 0)
        return want_bool(v, &cfg->agent.state_cfg.command_line_arguments, why, size);
    if (strcmp(key, "php_scripts") == 0)
        return want_bool(v, &cfg->agent.backend_cfg.php_scripts, why, size);
    *known = false;
    return false;
}

static bool apply_names(struct ft_config *cfg, const char *key, struct value *v, char *why,
                        size_t size, bool *known)
{
    uint64_t *max_age = &cfg->agent.state_cfg.name_max_age_ns;

    cfg->names_set = true;
    if (strcmp(key, "enabled") == 0)
        return want_bool(v, &cfg->names_enabled, why, size);
    if (strcmp(key, "lookups") == 0)
        return want_bool(v, &cfg->names_lookups, why, size);
    if (strcmp(key, "tls") == 0)
        return want_bool(v, &cfg->names_tls, why, size);
    if (strcmp(key, "max_age") == 0) {
        constexpr uint64_t LONGEST_NS = 3650 * 24 * 3600 * FT_NS_PER_SEC;

        /* Zero keeps a lookup for as long as its process runs the program that made it. */
        if (v->type == VALUE_INTEGER ? v->integer == 0
                                     : v->type == VALUE_STRING && strcmp(v->string, "0") == 0) {
            *max_age = 0;
            return true;
        }
        if (want_duration(v, FT_NS_PER_SEC, LONGEST_NS, max_age, why, size))
            return true;
        snprintf(why, size,
                 "expected a quoted duration from 1s to 3650d, such as \"10m\", or \"0\" for no "
                 "limit");
        return false;
    }
    *known = false;
    return false;
}

static bool apply_prometheus(struct ft_config *cfg, const char *key, struct value *v, char *why,
                             size_t size, bool *known)
{
    struct ft_prometheus_config *prometheus = &cfg->agent.prometheus;

    if (strcmp(key, "enabled") == 0)
        return want_bool(v, &prometheus->enabled, why, size);
    if (strcmp(key, "listen") == 0)
        return want_string(v, prometheus->listen, sizeof(prometheus->listen), why, size);
    *known = false;
    return false;
}

static bool apply_otlp(struct ft_config *cfg, const char *key, struct value *v, char *why,
                       size_t size, bool *known)
{
    struct ft_otlp_config *otlp = &cfg->agent.otlp;
    uint64_t n;

    if (strcmp(key, "enabled") == 0)
        return want_bool(v, &otlp->enabled, why, size);
    if (strcmp(key, "endpoint") == 0)
        return want_string(v, otlp->endpoint, sizeof(otlp->endpoint), why, size);
    if (strcmp(key, "logs") == 0)
        return want_bool(v, &otlp->logs, why, size);
    if (strcmp(key, "metrics") == 0)
        return want_bool(v, &otlp->metrics, why, size);
    if (strcmp(key, "file_paths") == 0)
        return want_bool(v, &otlp->file_paths, why, size);
    if (strcmp(key, "command_line") == 0)
        return want_bool(v, &otlp->command_line, why, size);
    if (strcmp(key, "events") == 0) {
        uint32_t types = 0;

        for (size_t i = 0; v->type == VALUE_STRINGS && i < v->count; i++) {
            enum ft_record_type type;
            if (!ft_record_type_parse(v->items[i], &type)) {
                snprintf(why, size, "\"%s\" is not an event type; see 'filetrace help events'",
                         v->items[i]);
                return false;
            }
            types |= 1u << type;
        }
        if (v->type != VALUE_STRINGS) {
            snprintf(why, size, "expected a list of event types, such as [\"file_transfer\"]");
            return false;
        }
        otlp->event_types = types;
        return true;
    }
    if (strcmp(key, "batch_size") == 0) {
        if (!want_count(v, 16, 4096, &n, why, size))
            return false;
        otlp->batch_size = (uint32_t)n;
        return true;
    }
    if (strcmp(key, "flush_interval") == 0)
        return want_duration(v, 100 * FT_NS_PER_MS, 3600 * FT_NS_PER_SEC, &otlp->flush_interval_ns,
                             why, size);
    if (strcmp(key, "metrics_interval") == 0)
        return want_duration(v, FT_NS_PER_SEC, 3600 * FT_NS_PER_SEC, &otlp->metrics_interval_ns,
                             why, size);
    if (strcmp(key, "timeout") == 0)
        return want_duration(v, FT_NS_PER_SEC, 300 * FT_NS_PER_SEC, &otlp->timeout_ns, why, size);
    *known = false;
    return false;
}

static bool apply_grpc(struct ft_config *cfg, const char *key, struct value *v, char *why,
                       size_t size, bool *known)
{
    struct ft_api_config *api = &cfg->agent.api;

    if (strcmp(key, "enabled") == 0)
        return want_bool(v, &api->enabled, why, size);
    if (strcmp(key, "listen") == 0)
        return want_string(v, api->listen, sizeof(api->listen), why, size);
    *known = false;
    return false;
}

static const struct {
    const char *name;
    bool (*apply)(struct ft_config *cfg, const char *key, struct value *v, char *why, size_t size,
                  bool *known);
} sections[] = {
    {"agent", apply_agent},
    {"network", apply_network},
    {"file", apply_file},
    {"correlation", apply_correlation},
    {"storage", apply_storage},
    {"limits", apply_limits},
    {"output", apply_output},
    {"filters", apply_filters},
    {"process", apply_process},
    {"names", apply_names},
    {"prometheus", apply_prometheus},
    {"otlp", apply_otlp},
    {"grpc", apply_grpc},
};

static bool parse(struct parser *ps, struct ft_config *cfg)
{
    struct value *v = calloc(1, sizeof(*v));
    size_t section = FT_ARRAY_LEN(sections);
    char name[64];
    bool ok = true;

    if (!v)
        return fail(ps, "out of memory");

    while (ok) {
        skip_lines(ps);
        if (*ps->p == '\0')
            break;

        if (*ps->p == '[') {
            ps->p++;
            ok = parse_name(ps, name, sizeof(name));
            if (ok && *ps->p != ']')
                ok = fail(ps, "expected ']' after the section name");
            if (!ok)
                break;
            ps->p++;
            for (section = 0; section < FT_ARRAY_LEN(sections); section++) {
                if (strcmp(sections[section].name, name) == 0)
                    break;
            }
            if (section == FT_ARRAY_LEN(sections))
                ok = fail(ps, "unknown section [%s]", name);
        } else {
            char why[200] = "";
            bool known = true;

            ok = parse_name(ps, name, sizeof(name));
            if (ok && section == FT_ARRAY_LEN(sections))
                ok = fail(ps, "'%s' is set before any [section]", name);
            if (!ok)
                break;
            skip_blanks(ps);
            if (*ps->p != '=') {
                ok = fail(ps, "expected '=' after '%s'", name);
                break;
            }
            ps->p++;
            skip_blanks(ps);
            unsigned line = ps->line;
            ok = parse_value(ps, v);
            if (ok && !sections[section].apply(cfg, name, v, why, sizeof(why), &known)) {
                ps->line = line;
                ok = known ? fail(ps, "[%s] %s: %s", sections[section].name, name, why)
                           : fail(ps, "unknown setting '%s' in [%s]", name, sections[section].name);
            }
            value_release(v);
        }
        if (!ok)
            break;
        skip_blanks(ps);
        if (*ps->p != '\n' && *ps->p != '\0')
            ok = fail(ps, "unexpected text after the value");
    }
    value_release(v);
    free(v);
    return ok;
}

/* The exporters check their addresses again when they start; this catches them in validate. */
static int check_addresses(const struct ft_config *cfg, const char *path, struct ft_error *err)
{
    const struct ft_agent_config *agent = &cfg->agent;
    struct ft_net_addr addr;

    if (agent->prometheus.enabled &&
        (!ft_net_addr_parse(agent->prometheus.listen, &addr) || ft_net_addr_is_unix(&addr)))
        return ft_error_set(err, FT_EXIT_CONFIG,
                            "%s: [prometheus] listen = \"%s\" is not an address and port, such "
                            "as \"127.0.0.1:9464\".",
                            path, agent->prometheus.listen);
    if (agent->otlp.enabled && (agent->otlp.logs || agent->otlp.metrics) &&
        !ft_net_addr_parse(agent->otlp.endpoint, &addr))
        return ft_error_set(err, FT_EXIT_CONFIG,
                            "%s: [otlp] endpoint = \"%s\" is not a numeric address and port, "
                            "such as \"127.0.0.1:4317\", nor \"unix:\" and a socket path.",
                            path, agent->otlp.endpoint);
    if (agent->api.enabled && !ft_net_addr_parse(agent->api.listen, &addr))
        return ft_error_set(err, FT_EXIT_CONFIG,
                            "%s: [grpc] listen = \"%s\" is neither \"unix:\" and a socket path "
                            "nor a numeric address and port, such as \"127.0.0.1:9500\".",
                            path, agent->api.listen);
    return FT_EXIT_OK;
}

/*
 * The account databases were background files in a default list that configuration files copied;
 * their uploads are what people look for, so they are strict files whichever list names them.
 */
static void move_account_databases(struct ft_config *cfg)
{
    static const char *const moved[] = {"/etc/passwd", "/etc/group"};
    for (size_t m = 0; m < FT_ARRAY_LEN(moved); m++) {
        for (size_t i = 0; i < cfg->background_path_count; i++) {
            if (strcmp(cfg->background_paths[i], moved[m]) != 0)
                continue;
            char *pattern = cfg->background_paths[i];
            memmove(&cfg->background_paths[i], &cfg->background_paths[i + 1],
                    (cfg->background_path_count - i - 1) * sizeof(cfg->background_paths[0]));
            cfg->background_path_count--;
            bool held = false;
            for (size_t j = 0; j < cfg->strict_path_count; j++)
                held |= strcmp(cfg->strict_paths[j], pattern) == 0;
            if (!held && cfg->strict_path_count < FT_CONFIG_MAX_PATTERNS)
                cfg->strict_paths[cfg->strict_path_count++] = pattern;
            else
                free(pattern);
            warn(cfg,
                 "[correlation] background_paths names %s, which is taken as one of strict_paths: "
                 "its uploads are reported",
                 moved[m]);
            break;
        }
    }
}

int ft_config_load(struct ft_config *cfg, const char *path, struct ft_error *err)
{
    constexpr long MAX_FILE_BYTES = 256 * 1024;
    bool may_be_absent = path == nullptr;

    if (!path)
        path = ft_config_default_path();

    FILE *f = fopen(path, "re");
    if (!f) {
        if (errno == ENOENT && may_be_absent)
            return FT_EXIT_OK;
        return ft_error_set(err, FT_EXIT_CONFIG, "Cannot read the configuration file %s: %s", path,
                            strerror(errno));
    }

    char *text = malloc((size_t)MAX_FILE_BYTES + 1);
    size_t n = text ? fread(text, 1, (size_t)MAX_FILE_BYTES + 1, f) : 0;
    bool read_error = ferror(f) != 0;
    fclose(f);
    if (!text || read_error || n > (size_t)MAX_FILE_BYTES) {
        free(text);
        return ft_error_set(err, FT_EXIT_CONFIG, "Cannot read the configuration file %s: %s", path,
                            n > (size_t)MAX_FILE_BYTES ? "it is too large" : "read error");
    }
    text[n] = '\0';

    struct parser ps = {.path = path, .p = text, .line = 1, .err = err};
    bool ok = parse(&ps, cfg);
    free(text);
    if (!ok)
        return FT_EXIT_CONFIG;
    move_account_databases(cfg);
    int code = check_addresses(cfg, path, err);
    if (code != FT_EXIT_OK)
        return code;
    ft_strlcpy(cfg->source, path, sizeof(cfg->source));
    return FT_EXIT_OK;
}

static const char *yes_no(bool value)
{
    return value ? "true" : "false";
}

static void print_string(FILE *o, const char *key, const char *value)
{
    fprintf(o, "%s = \"", key);
    for (const char *p = value; *p; p++) {
        if (*p == '"' || *p == '\\')
            fputc('\\', o);
        fputc(*p, o);
    }
    fputs("\"\n", o);
}

/* Whole units where the value allows, so that what is printed reads back the same. */
static void print_size(FILE *o, const char *key, uint64_t bytes)
{
    if (bytes && bytes % MB == 0)
        fprintf(o, "%s = \"%" PRIu64 "MB\"\n", key, bytes / MB);
    else if (bytes && bytes % KB == 0)
        fprintf(o, "%s = \"%" PRIu64 "KB\"\n", key, bytes / KB);
    else
        fprintf(o, "%s = %" PRIu64 "\n", key, bytes);
}

static void print_duration(FILE *o, const char *key, uint64_t ns)
{
    constexpr uint64_t DAY = 24 * 3600 * FT_NS_PER_SEC;

    if (ns % DAY == 0)
        fprintf(o, "%s = \"%" PRIu64 "d\"\n", key, ns / DAY);
    else if (ns % FT_NS_PER_SEC == 0)
        fprintf(o, "%s = \"%" PRIu64 "s\"\n", key, ns / FT_NS_PER_SEC);
    else
        fprintf(o, "%s = \"%" PRIu64 "ms\"\n", key, ns / FT_NS_PER_MS);
}

static void print_patterns(FILE *o, const char *key, char *const *items, size_t count)
{
    fprintf(o, "%s = [", key);
    for (size_t i = 0; i < count; i++) {
        fprintf(o, "%s\"", i ? ", " : "");
        for (const char *p = items[i]; *p; p++) {
            if (*p == '"' || *p == '\\')
                fputc('\\', o);
            fputc(*p, o);
        }
        fputc('"', o);
    }
    fputs("]\n", o);
}

static const char *log_level_name(enum ft_log_level level)
{
    switch (level) {
    case FT_LOG_ERROR:
        return "error";
    case FT_LOG_WARN:
        return "warn";
    case FT_LOG_DEBUG:
        return "debug";
    default:
        return "info";
    }
}

void ft_config_print(const struct ft_config *cfg, FILE *o)
{
    const struct ft_backend_config *backend = &cfg->agent.backend_cfg;
    const struct ft_state_config *state = &cfg->agent.state_cfg;
    static const char unavailable[] = "# Not available in this build; true is ignored with a "
                                      "warning.\n";

    fputs("[agent]\n", o);
    fprintf(o, "enabled = %s\n", yes_no(cfg->enabled));
    print_string(o, "mode", ft_mode_name(backend->mode));
    print_string(o, "probes", ft_probes_name(backend->probes));
    print_string(o, "socket", cfg->socket_path);
    print_size(o, "ring_buffer_size", backend->queue_bytes);
    fprintf(o, "event_batch_size = %u\n", backend->drain_batch);
    print_duration(o, "flush_interval", (uint64_t)cfg->agent.flush_interval_ms * FT_NS_PER_MS);
    print_size(o, "event_log_size", state->event_log_bytes);
    print_string(o, "log_level", log_level_name(cfg->log_level));

    fputs("\n[network]\n", o);
    fprintf(o, "tcp = %s\n", yes_no(!state->ignore_tcp));
    fprintf(o, "udp = %s\n", yes_no(!state->ignore_udp));
    fprintf(o, "ipv4 = %s\n", yes_no(!state->ignore_ipv4));
    fprintf(o, "ipv6 = %s\n", yes_no(!state->ignore_ipv6));
    fputs(unavailable, o);
    fprintf(o, "tc_egress = %s\n", yes_no(cfg->tc_egress));

    fputs("\n[file]\n", o);
    fprintf(o, "track_read = %s\n", yes_no(cfg->track_read));
    fprintf(o, "track_sendfile = %s\n", yes_no(cfg->track_sendfile));
    fputs(unavailable, o);
    fprintf(o, "track_open = %s\n", yes_no(cfg->track_open));
    fprintf(o, "track_mmap = %s\n", yes_no(cfg->track_mmap));
    fprintf(o, "track_splice = %s\n", yes_no(cfg->track_splice));

    fputs("\n[correlation]\n", o);
    fprintf(o, "enabled = %s\n", yes_no(cfg->correlation_enabled));
    print_duration(o, "window", backend->corr_window_ns);
    print_string(o, "confidence_threshold", ft_confidence_name(state->min_confidence));
    print_size(o, "inferred_min_bytes", state->inferred_min_bytes);
    fprintf(o, "inferred_min_percent = %u\n", state->inferred_min_permille / 10);
    print_patterns(o, "no_minimum_paths", cfg->no_minimum_paths, cfg->no_minimum_path_count);
    print_patterns(o, "background_paths", cfg->background_paths, cfg->background_path_count);
    print_patterns(o, "strict_paths", cfg->strict_paths, cfg->strict_path_count);
    fputs("# Always on.\n", o);
    fprintf(o, "track_process_lifecycle = %s\n", yes_no(cfg->track_process_lifecycle));
    fputs(unavailable, o);
    fprintf(o, "track_fd_lifecycle = %s\n", yes_no(cfg->track_fd_lifecycle));
    fprintf(o, "track_io_uring = %s\n", yes_no(cfg->track_io_uring));

    fputs("\n[storage]\n", o);
    fputs("# Not available in this build: history is kept in memory and starts when the\n"
          "# agent does.\n",
          o);
    fprintf(o, "enabled = %s\n", yes_no(cfg->storage_enabled));
    print_string(o, "path", cfg->storage_path);
    print_duration(o, "retention", cfg->storage_retention_ns);

    fputs("\n[limits]\n", o);
    fprintf(o, "processes = %zu\n", state->max_processes);
    fprintf(o, "sockets = %zu\n", state->max_sockets);
    fprintf(o, "flows = %zu\n", state->max_flows);
    fprintf(o, "files = %zu\n", state->max_files);
    fprintf(o, "transfers = %zu\n", state->max_transfers);
    fprintf(o, "kernel_counters = %u\n", backend->agg_entries);
    fprintf(o, "kernel_files = %u\n", backend->known_files);
    fprintf(o, "metric_series = %zu\n", state->max_metric_series);
    fprintf(o, "names = %zu\n", state->max_names);
    fprintf(o, "name_lookups = %zu\n", state->max_name_lookups);
    fprintf(o, "name_libraries = %u\n", backend->name_libraries);
    fprintf(o, "file_rankings = %zu\n", state->leader_entries);

    fputs("\n[output]\n", o);
    print_string(o, "format", cfg->format);
    fprintf(o, "timestamps = %s\n", yes_no(cfg->timestamps));

    fputs("\n[filters]\n", o);
    print_patterns(o, "exclude_processes", cfg->exclude_processes, cfg->exclude_process_count);
    print_patterns(o, "exclude_paths", cfg->exclude_paths, cfg->exclude_path_count);

    fputs("\n[process]\n", o);
    fprintf(o, "arguments = %s\n", yes_no(state->command_line_arguments));
    fprintf(o, "php_scripts = %s\n", yes_no(backend->php_scripts));

    fputs("\n[names]\n", o);
    fputs("# Standard mode only.\n", o);
    fprintf(o, "enabled = %s\n", yes_no(cfg->names_enabled));
    fprintf(o, "lookups = %s\n", yes_no(cfg->names_lookups));
    fprintf(o, "tls = %s\n", yes_no(cfg->names_tls));
    if (state->name_max_age_ns)
        print_duration(o, "max_age", state->name_max_age_ns);
    else
        fputs("max_age = \"0\"\n", o);

    fputs("\n[prometheus]\n", o);
    fprintf(o, "enabled = %s\n", yes_no(cfg->agent.prometheus.enabled));
    print_string(o, "listen", cfg->agent.prometheus.listen);

    const struct ft_otlp_config *otlp = &cfg->agent.otlp;
    fputs("\n[otlp]\n", o);
    fprintf(o, "enabled = %s\n", yes_no(otlp->enabled));
    fputs("# gRPC without TLS: a collector on this host, by numeric address or \"unix:\" path.\n",
          o);
    print_string(o, "endpoint", otlp->endpoint);
    fprintf(o, "logs = %s\n", yes_no(otlp->logs));
    fprintf(o, "metrics = %s\n", yes_no(otlp->metrics));
    fputs("events = [", o);
    for (int type = 1, listed = 0; type < FT_REC_TYPE_COUNT; type++) {
        if (otlp->event_types & (1u << type))
            fprintf(o, "%s\"%s\"", listed++ ? ", " : "",
                    ft_record_type_name((enum ft_record_type)type));
    }
    fputs("]\n", o);
    fprintf(o, "file_paths = %s\n", yes_no(otlp->file_paths));
    fprintf(o, "command_line = %s\n", yes_no(otlp->command_line));
    fprintf(o, "batch_size = %u\n", otlp->batch_size);
    print_duration(o, "flush_interval", otlp->flush_interval_ns);
    print_duration(o, "metrics_interval", otlp->metrics_interval_ns);
    print_duration(o, "timeout", otlp->timeout_ns);

    fputs("\n[grpc]\n", o);
    fprintf(o, "enabled = %s\n", yes_no(cfg->agent.api.enabled));
    fputs("# A \"unix:\" socket admits root and the agent's user; an address and port, anyone.\n",
          o);
    print_string(o, "listen", cfg->agent.api.listen);
}
