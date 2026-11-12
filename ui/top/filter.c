#include "ui/top/filter.h"

#include "filetrace/format.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

enum test : uint8_t {
    TEST_TEXT, /* a substring, ignoring case */
    TEST_GLOB, /* ft_glob_match over the whole field */
    TEST_PIDS,
    TEST_UID, /* a number: the uid, or a user of that name */
    TEST_PUBLIC,
    TEST_PRIVATE,
    TEST_PREFIX,
    TEST_CODE, /* a method or a confidence */
    TEST_RATE,
};

enum compare : uint8_t {
    CMP_GT,
    CMP_GE,
    CMP_LT,
    CMP_LE,
    CMP_EQ,
};

struct term {
    char *source; /* as typed, for messages */
    char *value;  /* without quotes */
    char *needle; /* value in lower case */
    size_t needle_len;
    uint32_t *pids;
    size_t npids;
    struct ft_endpoint net;
    uint64_t rate;
    uint32_t uid;
    enum ft_top_field field;
    enum test test;
    enum compare cmp;
    uint8_t bits;
    uint8_t code;
    bool negate;
};

struct ft_top_filter {
    char *text;
    struct term *terms;
    size_t count;
    uint32_t fields;
};

static const char *const field_keys[FT_TOP_FIELD_COUNT] = {
    [FT_TOP_FIELD_PID] = "pid",       [FT_TOP_FIELD_USER] = "user", [FT_TOP_FIELD_PROC] = "proc",
    [FT_TOP_FIELD_SCRIPT] = "script", [FT_TOP_FIELD_FILE] = "file", [FT_TOP_FIELD_DEST] = "dest",
    [FT_TOP_FIELD_METHOD] = "method", [FT_TOP_FIELD_CONF] = "conf", [FT_TOP_FIELD_RATE] = "rate",
};

static unsigned char lower(char c)
{
    return (unsigned char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
}

static bool is_letter(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool ft_top_find(const char *text, const char *needle, size_t needle_len, size_t *start,
                 size_t *end)
{
    if (!text || !needle || needle_len == 0)
        return false;
    for (const char *p = text; *p; p++) {
        size_t i = 0;
        while (i < needle_len && p[i] && lower(p[i]) == lower(needle[i]))
            i++;
        if (i == needle_len) {
            *start = (size_t)(p - text);
            *end = *start + needle_len;
            return true;
        }
        if (!p[i])
            return false;
    }
    return false;
}

/* needle is already in lower case and not empty. */
static bool contains(const char *text, const char *needle, size_t n)
{
    if (!text)
        return false;
    for (const char *p = text; *p; p++) {
        if (lower(*p) != (unsigned char)needle[0])
            continue;
        size_t i = 1;
        while (i < n && p[i] && lower(p[i]) == (unsigned char)needle[i])
            i++;
        if (i == n)
            return true;
        if (!p[i])
            return false;
    }
    return false;
}

static void term_free(struct term *t)
{
    free(t->source);
    free(t->value);
    free(t->needle);
    free(t->pids);
}

void ft_top_filter_free(struct ft_top_filter *f)
{
    if (!f)
        return;
    for (size_t i = 0; i < f->count; i++)
        term_free(&f->terms[i]);
    free(f->terms);
    free(f->text);
    free(f);
}

static char *copy_span(const char *s, size_t n)
{
    char *out = malloc(n + 1);
    if (out) {
        memcpy(out, s, n);
        out[n] = '\0';
    }
    return out;
}

/* Returns -1 when memory runs out, 0 for a bad list, 1 when parsed. */
static int parse_pids(struct term *t)
{
    size_t n = 1;
    for (const char *p = t->value; *p; p++)
        n += *p == ',';
    t->pids = calloc(n, sizeof(*t->pids));
    if (!t->pids)
        return -1;

    char *item = t->value;
    for (;;) {
        char *comma = strchr(item, ',');
        if (comma)
            *comma = '\0';
        uint32_t pid = 0;
        bool ok = ft_parse_u32(item, &pid) && pid != 0;
        if (comma)
            *comma = ',';
        if (!ok)
            return 0;
        t->pids[t->npids++] = pid;
        if (!comma)
            return 1;
        item = comma + 1;
    }
}

static bool parse_rate(struct term *t)
{
    static const struct {
        const char *text;
        enum compare cmp;
    } ops[] = {{">=", CMP_GE}, {"<=", CMP_LE}, {">", CMP_GT}, {"<", CMP_LT}, {"=", CMP_EQ}};
    const char *p = t->value;
    char size[64];

    t->cmp = CMP_GE;
    for (size_t i = 0; i < FT_ARRAY_LEN(ops); i++) {
        size_t n = strlen(ops[i].text);
        if (strncmp(p, ops[i].text, n) == 0) {
            t->cmp = ops[i].cmp;
            p += n;
            break;
        }
    }
    size_t len = strlen(p);
    if (len >= 2 && p[len - 2] == '/' && (p[len - 1] == 's' || p[len - 1] == 'S'))
        len -= 2;
    if (len == 0 || len >= sizeof(size))
        return false;
    memcpy(size, p, len);
    size[len] = '\0';
    return ft_parse_size(size, &t->rate);
}

static bool parse_method(const char *text, uint8_t *code)
{
    enum ft_method m;
    if (strcasecmp(text, "rw") == 0) {
        *code = FT_METHOD_READ_SEND;
        return true;
    }
    if (!ft_method_parse(text, &m))
        return false;
    *code = m;
    return true;
}

static bool parse_confidence(const char *text, uint8_t *code)
{
    enum ft_confidence c;
    if (!ft_confidence_parse(text, &c))
        return false;
    *code = c;
    return true;
}

/* Sets the test of a term whose field and value are known. */
static bool compile_value(struct term *t, struct ft_error *err)
{
    t->test = strpbrk(t->value, "*?") && t->field != FT_TOP_FIELD_ANY ? TEST_GLOB : TEST_TEXT;
    switch (t->field) {
    case FT_TOP_FIELD_PID: {
        t->test = TEST_PIDS;
        int parsed = parse_pids(t);
        if (parsed > 0)
            return true;
        if (parsed < 0)
            ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        else
            ft_error_set(err, FT_EXIT_USAGE,
                         "bad process id in '%s' (expected numbers separated by commas)",
                         t->source);
        return false;
    }
    case FT_TOP_FIELD_USER:
        if (ft_parse_u32(t->value, &t->uid))
            t->test = TEST_UID;
        return true;
    case FT_TOP_FIELD_DEST:
        if (strcasecmp(t->value, "public") == 0)
            t->test = TEST_PUBLIC;
        else if (strcasecmp(t->value, "private") == 0)
            t->test = TEST_PRIVATE;
        else if (ft_prefix_parse(t->value, &t->net, &t->bits))
            t->test = TEST_PREFIX;
        return true;
    case FT_TOP_FIELD_METHOD:
        t->test = TEST_CODE;
        if (parse_method(t->value, &t->code))
            return true;
        ft_error_set(err, FT_EXIT_USAGE,
                     "unknown method in '%s' (expected sendfile, rw, splice, mmap or io_uring)",
                     t->source);
        return false;
    case FT_TOP_FIELD_CONF:
        t->test = TEST_CODE;
        if (parse_confidence(t->value, &t->code))
            return true;
        ft_error_set(err, FT_EXIT_USAGE,
                     "unknown confidence in '%s' (expected exact, strong, inferred or unknown)",
                     t->source);
        return false;
    case FT_TOP_FIELD_RATE:
        t->test = TEST_RATE;
        if (parse_rate(t))
            return true;
        ft_error_set(err, FT_EXIT_USAGE,
                     "bad rate in '%s' (expected a comparison and a size, such as >1M)", t->source);
        return false;
    default:
        return true;
    }
}

/* The next term from *p, unquoted into buf; key_len is the length of a "key:" prefix or 0. */
static bool next_term(const char **p, char *buf, size_t *len, size_t *key_len, const char **start,
                      const char **stop, struct ft_error *err)
{
    const char *s = *p;
    bool quoted = false;
    size_t n = 0;

    *key_len = 0;
    *start = s;
    while (*s && (quoted || *s != ' ')) {
        if (*s == '"') {
            quoted = !quoted;
            s++;
            continue;
        }
        if (quoted && *s == '\\' && s[1]) {
            s++;
        } else if (!quoted && *s == ':' && *key_len == 0 && n > 0) {
            bool letters = true;
            for (size_t i = 0; i < n && letters; i++)
                letters = is_letter(buf[i]) || (i == 0 && buf[i] == '!');
            if (letters && !(n == 1 && buf[0] == '!'))
                *key_len = n + 1;
        }
        buf[n++] = *s++;
    }
    buf[n] = '\0';
    *stop = s;
    *p = s;
    *len = n;
    if (quoted) {
        ft_error_set(err, FT_EXIT_USAGE, "unterminated quote in '%.*s'", (int)(s - *start), *start);
        return false;
    }
    return true;
}

static bool compile_term(struct term *t, const char *start, const char *stop, const char *token,
                         size_t len, size_t key_len, struct ft_error *err)
{
    t->source = copy_span(start, (size_t)(stop - start));
    if (!t->source) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return false;
    }
    if (token[0] == '!') {
        t->negate = true;
        token++;
        len--;
        if (key_len)
            key_len--;
    }
    if (len == 0) {
        ft_error_set(err, FT_EXIT_USAGE, "nothing to negate in '%s'", t->source);
        return false;
    }

    t->field = FT_TOP_FIELD_ANY;
    if (key_len) {
        size_t key = key_len - 1;
        bool known = false;
        for (size_t f = 0; f < FT_TOP_FIELD_ANY && !known; f++) {
            if (strlen(field_keys[f]) == key && strncasecmp(token, field_keys[f], key) == 0) {
                t->field = (enum ft_top_field)f;
                known = true;
            }
        }
        if (!known) {
            ft_error_set(err, FT_EXIT_USAGE,
                         "unknown filter key '%.*s' (expected pid, user, proc, script, file, "
                         "dest, method, conf or rate)",
                         (int)key, token);
            return false;
        }
        token += key_len;
        len -= key_len;
        if (len == 0) {
            ft_error_set(err, FT_EXIT_USAGE, "empty value in '%s'", t->source);
            return false;
        }
    }

    t->value = copy_span(token, len);
    t->needle = copy_span(token, len);
    if (!t->value || !t->needle) {
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return false;
    }
    for (size_t i = 0; i < len; i++)
        t->needle[i] = (char)lower(t->needle[i]);
    t->needle_len = len;
    return compile_value(t, err);
}

struct ft_top_filter *ft_top_filter_compile(const char *expression, struct ft_error *err)
{
    const char *text = expression ? expression : "";
    struct ft_top_filter *f = calloc(1, sizeof(*f));
    size_t max_terms = 1;
    char *buf = nullptr;

    for (const char *p = text; *p; p++)
        max_terms += *p == ' ';
    if (f) {
        f->text = copy_span(text, strlen(text));
        f->terms = calloc(max_terms, sizeof(*f->terms));
        buf = malloc(strlen(text) + 1);
    }
    if (!f || !f->text || !f->terms || !buf) {
        free(buf);
        ft_top_filter_free(f);
        ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
        return nullptr;
    }

    const char *p = text;
    for (;;) {
        while (*p == ' ')
            p++;
        if (!*p)
            break;
        const char *start;
        const char *stop;
        size_t len;
        size_t key_len;
        struct term *t = &f->terms[f->count++];
        if (!next_term(&p, buf, &len, &key_len, &start, &stop, err) ||
            !compile_term(t, start, stop, buf, len, key_len, err)) {
            free(buf);
            ft_top_filter_free(f);
            return nullptr;
        }
        f->fields |= FT_TOP_FIELD_BIT(t->field);
    }
    free(buf);
    return f;
}

const char *ft_top_filter_text(const struct ft_top_filter *f)
{
    return f ? f->text : "";
}

bool ft_top_filter_empty(const struct ft_top_filter *f)
{
    return !f || f->count == 0;
}

uint32_t ft_top_filter_fields(const struct ft_top_filter *f)
{
    return f ? f->fields : 0;
}

bool ft_top_filter_restrict(const struct ft_top_filter *f, uint32_t allowed, const char *where,
                            struct ft_error *err)
{
    for (size_t i = 0; f && i < f->count; i++) {
        if (!(allowed & FT_TOP_FIELD_BIT(f->terms[i].field))) {
            ft_error_set(err, FT_EXIT_USAGE, "'%s' does not apply to %s", f->terms[i].source,
                         where);
            return false;
        }
    }
    return true;
}

static bool text_holds(const struct term *t, const char *field)
{
    if (!field)
        return false;
    if (t->test == TEST_GLOB)
        return ft_glob_match(t->value, field);
    return contains(field, t->needle, t->needle_len);
}

static bool rate_holds(const struct term *t, uint64_t rate)
{
    switch (t->cmp) {
    case CMP_GT:
        return rate > t->rate;
    case CMP_LT:
        return rate < t->rate;
    case CMP_LE:
        return rate <= t->rate;
    case CMP_EQ:
        return rate == t->rate;
    default:
        return rate >= t->rate;
    }
}

static bool dest_holds(const struct term *t, const struct ft_endpoint *remote, bool is_public,
                       const char *remote_text, const char *host)
{
    bool known = remote && remote->family != 0;
    switch (t->test) {
    case TEST_PUBLIC:
        return known && is_public;
    case TEST_PRIVATE:
        return known && !is_public;
    case TEST_PREFIX:
        return known && ft_addr_in_prefix(&t->net, t->bits, remote);
    default:
        return text_holds(t, host) || text_holds(t, remote_text);
    }
}

static bool term_holds(const struct term *t, const struct ft_top_subject *s)
{
    switch (t->field) {
    case FT_TOP_FIELD_PID:
        for (size_t i = 0; i < t->npids; i++) {
            if (t->pids[i] == s->pid)
                return true;
        }
        return false;
    case FT_TOP_FIELD_USER:
        if (t->test == TEST_UID)
            return (s->uid_known && s->uid == t->uid) ||
                   (s->user && strcmp(s->user, t->value) == 0);
        return text_holds(t, s->user);
    case FT_TOP_FIELD_PROC:
        return text_holds(t, s->title) || text_holds(t, s->comm);
    case FT_TOP_FIELD_SCRIPT:
        return s->script && s->script[0] && text_holds(t, s->script);
    case FT_TOP_FIELD_FILE:
        return text_holds(t, s->path);
    case FT_TOP_FIELD_DEST:
        return dest_holds(t, s->remote, s->is_public, s->remote_text, s->host);
    case FT_TOP_FIELD_METHOD:
        return s->method == t->code;
    case FT_TOP_FIELD_CONF:
        return s->confidence == t->code;
    case FT_TOP_FIELD_RATE:
        return rate_holds(t, s->rate);
    default:
        return contains(s->pid_text, t->needle, t->needle_len) ||
               contains(s->user, t->needle, t->needle_len) ||
               contains(s->title, t->needle, t->needle_len) ||
               contains(s->script, t->needle, t->needle_len) ||
               contains(s->path, t->needle, t->needle_len) ||
               contains(s->remote_text, t->needle, t->needle_len) ||
               contains(s->host, t->needle, t->needle_len) ||
               contains(ft_method_name((enum ft_method)s->method), t->needle, t->needle_len) ||
               contains(ft_confidence_name((enum ft_confidence)s->confidence), t->needle,
                        t->needle_len);
    }
}

bool ft_top_filter_match(const struct ft_top_filter *f, const struct ft_top_subject *s)
{
    for (size_t i = 0; f && i < f->count; i++) {
        if (term_holds(&f->terms[i], s) == f->terms[i].negate)
            return false;
    }
    return true;
}

static bool any_sender(const struct term *t, const struct ft_top_leader_subject *s, bool bare)
{
    for (size_t i = 0; i < s->nsenders; i++) {
        if (bare ? contains(s->senders[i], t->needle, t->needle_len) : text_holds(t, s->senders[i]))
            return true;
    }
    return false;
}

static bool leader_term_holds(const struct term *t, const struct ft_top_leader_subject *s)
{
    switch (t->field) {
    case FT_TOP_FIELD_PROC:
        return any_sender(t, s, false);
    case FT_TOP_FIELD_FILE:
        return text_holds(t, s->text);
    case FT_TOP_FIELD_DEST:
        return dest_holds(t, s->remote, s->remote && !ft_addr_is_private(s->remote), s->remote_text,
                          s->host);
    case FT_TOP_FIELD_METHOD:
        return s->method == t->code;
    case FT_TOP_FIELD_CONF:
        return s->confidence == t->code;
    case FT_TOP_FIELD_ANY:
        return contains(s->text, t->needle, t->needle_len) || any_sender(t, s, true) ||
               contains(s->remote_text, t->needle, t->needle_len) ||
               contains(s->host, t->needle, t->needle_len) ||
               contains(ft_method_name((enum ft_method)s->method), t->needle, t->needle_len) ||
               contains(ft_confidence_name((enum ft_confidence)s->confidence), t->needle,
                        t->needle_len);
    default:
        return !t->negate;
    }
}

bool ft_top_filter_match_leader(const struct ft_top_filter *f,
                                const struct ft_top_leader_subject *s)
{
    for (size_t i = 0; f && i < f->count; i++) {
        if (leader_term_holds(&f->terms[i], s) == f->terms[i].negate)
            return false;
    }
    return true;
}

/* The only term on field, when there is exactly one and it is not negated. */
static const struct term *sole_term(const struct ft_top_filter *f, enum ft_top_field field)
{
    const struct term *found = nullptr;
    for (size_t i = 0; i < f->count; i++) {
        if (f->terms[i].field != field)
            continue;
        if (found || f->terms[i].negate)
            return nullptr;
        found = &f->terms[i];
    }
    return found;
}

void ft_top_filter_pushdown(const struct ft_top_filter *f, struct ft_query *q)
{
    const struct term *t;

    if (!f)
        return;
    if ((t = sole_term(f, FT_TOP_FIELD_PID)) && t->npids == 1)
        q->pid = t->pids[0];
    if ((t = sole_term(f, FT_TOP_FIELD_DEST)) && t->test == TEST_PREFIX) {
        unsigned width = t->net.family == 6 ? 128 : 32;
        q->remote = t->net;
        q->remote.port = 0;
        q->remote_host_bits = (uint8_t)(width - t->bits);
    }
    /* The agent matches a script by glob, case and all; a substring has no equivalent. */
    if ((t = sole_term(f, FT_TOP_FIELD_SCRIPT)) && t->test == TEST_GLOB &&
        strlen(t->value) < sizeof(q->script))
        ft_strlcpy(q->script, t->value, sizeof(q->script));
    if ((t = sole_term(f, FT_TOP_FIELD_METHOD)))
        q->method = t->code;
    if ((t = sole_term(f, FT_TOP_FIELD_CONF)))
        q->confidence = t->code;
}

const char *ft_top_filter_needle(const struct ft_top_filter *f, enum ft_top_field field,
                                 size_t *len)
{
    const char *bare = nullptr;
    size_t bare_len = 0;

    for (size_t i = 0; f && i < f->count; i++) {
        const struct term *t = &f->terms[i];
        if (t->negate)
            continue;
        if (t->field == FT_TOP_FIELD_ANY && !bare) {
            bare = t->value;
            bare_len = t->needle_len;
        }
        if (t->field != field || (t->test != TEST_TEXT && t->test != TEST_GLOB))
            continue;
        size_t n = t->test == TEST_GLOB ? strcspn(t->value, "*?") : t->needle_len;
        if (n > 0) {
            *len = n;
            return t->value;
        }
    }
    *len = bare_len;
    return bare;
}
