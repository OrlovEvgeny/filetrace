#include "filetrace/process.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

size_t ft_command_line(const char *args, size_t len, bool arguments, char *out, size_t size)
{
    size_t n = 0;

    if (size == 0)
        return 0;
    for (size_t i = 0; i < len && n + 1 < size; i++) {
        unsigned char c = (unsigned char)args[i];
        bool separator = c == '\0' || c == ' ';
        if (!arguments && separator)
            break;
        out[n++] = (char)(c < 0x20 || c == 0x7f ? ' ' : c);
    }
    while (n && out[n - 1] == ' ')
        n--;
    out[n] = '\0';
    return n;
}

/* How an interpreter reads its options, enough to find the first argument that is not one. */
struct grammar {
    const char *value;    /* short options taking a value, attached or as the next argument */
    const char *attached; /* short options whose optional value is the rest of the argument */
    const char *digits;   /* short options followed by optional digits */
    const char *code;     /* short options whose value is code to run instead of a script */
    const char *input;    /* short options that read the program from standard input */
    const char *file;     /* short options whose value is the script */
    char module;          /* the short option whose value names a module to run */
    const char *const *long_value; /* long options taking the next argument unless given "=" */
    const char *const *long_code;
    bool plus;          /* '+' also starts an option, as in a shell */
    bool dashdash_ends; /* a bare "--" leaves no script: the program comes from standard input */
};

static const char *const python_long_value[] = {"--check-hash-based-pycs", nullptr};
static const struct grammar python = {
    .value = "WX",
    .code = "c",
    .module = 'm',
    .long_value = python_long_value,
};

static const char *const php_long_value[] = {"--rf", "--rc", "--re", "--rz", "--ri", nullptr};
static const struct grammar php = {
    .value = "cdztSBE",
    .code = "rR",
    .file = "fF",
    .long_value = php_long_value,
    .dashdash_ends = true,
};

static const char *const node_long_value[] = {
    "--require",
    "--import",
    "--loader",
    "--experimental-loader",
    "--conditions",
    "--input-type",
    "--title",
    "--env-file",
    "--watch-path",
    "--inspect-port",
    "--icu-data-dir",
    "--openssl-config",
    "--report-dir",
    "--diagnostic-dir",
    "--redirect-warnings",
    "--disable-warning",
    nullptr,
};
static const char *const node_long_code[] = {"--eval", "--print", nullptr};
static const struct grammar node = {
    .value = "rC",
    .code = "ep",
    .long_value = node_long_value,
    .long_code = node_long_code,
};

static const char *const ruby_long_value[] = {
    "--enable", "--disable", "--encoding", "--external-encoding", "--internal-encoding", nullptr,
};
static const struct grammar ruby = {
    .value = "CEIr",
    .attached = "FKTWix",
    .digits = "0",
    .code = "e",
    .long_value = ruby_long_value,
};

static const struct grammar perl = {
    .value = "I",
    .attached = "CDFMVdimx",
    .digits = "0l",
    .code = "eE",
};

static const char *const shell_long_value[] = {"--rcfile", "--init-file", nullptr};
static const struct grammar shell = {
    .value = "oO",
    .code = "c",
    .input = "s",
    .long_value = shell_long_value,
    .plus = true,
};

static const struct grammar lua = {
    .value = "jl",
    .attached = "O",
    .code = "e",
};

static const struct interpreter {
    const char *name;
    bool versioned; /* a version may follow the name, as in python3.12 */
    const struct grammar *grammar;
} interpreters[] = {
    {"python", true, &python}, {"pypy", true, &python}, {"php", true, &php},
    {"php-cgi", true, &php},   {"node", true, &node},   {"nodejs", true, &node},
    {"ruby", true, &ruby},     {"perl", true, &perl},   {"lua", true, &lua},
    {"luajit", true, &lua},    {"sh", false, &shell},   {"bash", false, &shell},
    {"dash", false, &shell},   {"ash", false, &shell},  {"ksh", false, &shell},
    {"mksh", false, &shell},   {"zsh", false, &shell},
};

/* "3", "3.12" or "3.13t": digits and dots, then perhaps one ABI letter. */
static bool is_version(const char *s)
{
    if (!isdigit((unsigned char)*s))
        return false;
    while (isdigit((unsigned char)*s) || *s == '.')
        s++;
    return *s == '\0' || (strchr("dmtu", *s) && s[1] == '\0');
}

static const struct grammar *grammar_of(const char *path)
{
    char name[64];
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    size_t len = strcspn(base, " ");

    if (*base == '-') {
        base++;
        len--;
    }
    if (len == 0 || len >= sizeof(name))
        return nullptr;
    memcpy(name, base, len);
    name[len] = '\0';

    for (size_t i = 0; i < FT_ARRAY_LEN(interpreters); i++) {
        const struct interpreter *it = &interpreters[i];
        size_t n = strlen(it->name);
        if (strncmp(name, it->name, n) != 0)
            continue;
        if (name[n] == '\0' || (it->versioned && is_version(name + n)))
            return it->grammar;
    }
    return nullptr;
}

static bool listed(const char *const *names, const char *arg, size_t len)
{
    for (; names && *names; names++) {
        if (strlen(*names) == len && strncmp(*names, arg, len) == 0)
            return true;
    }
    return false;
}

static bool has(const char *set, char c)
{
    return set && c && strchr(set, c);
}

enum found : uint8_t {
    FOUND_NOTHING,
    FOUND_SCRIPT,
    FOUND_MODULE,
};

/* Walks the options as the interpreter would; *what is the script or the module named. */
static enum found find_script(const struct grammar *g, const char *const *argv, size_t argc,
                              const char **what)
{
    bool options = true;

    for (size_t i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (!options || !((a[0] == '-' || (g->plus && a[0] == '+')) && a[1])) {
            if (options && strcmp(a, "-") == 0)
                return FOUND_NOTHING;
            *what = a;
            return FOUND_SCRIPT;
        }
        if (strcmp(a, "--") == 0) {
            if (g->dashdash_ends)
                return FOUND_NOTHING;
            options = false;
            continue;
        }
        if (a[0] == '-' && a[1] == '-') {
            size_t len = strcspn(a, "=");
            if (listed(g->long_code, a, len))
                return FOUND_NOTHING;
            if (!a[len] && listed(g->long_value, a, len))
                i++;
            continue;
        }
        for (size_t j = 1; a[j]; j++) {
            char c = a[j];
            if (has(g->code, c) || has(g->input, c))
                return FOUND_NOTHING;
            if (has(g->value, c) || has(g->file, c) || c == g->module) {
                const char *value = a[j + 1] ? a + j + 1 : i + 1 < argc ? argv[++i] : nullptr;
                if (!value)
                    return FOUND_NOTHING;
                *what = value;
                if (c == g->module)
                    return FOUND_MODULE;
                if (has(g->file, c))
                    return FOUND_SCRIPT;
                break;
            }
            if (has(g->digits, c)) {
                if (c == '0' && a[j + 1] == 'x') {
                    for (j++; isxdigit((unsigned char)a[j + 1]); j++)
                        ;
                } else {
                    while (a[j + 1] >= '0' && a[j + 1] <= '7')
                        j++;
                }
                continue;
            }
            if (has(g->attached, c))
                break;
        }
    }
    return FOUND_NOTHING;
}

/* Appends the components of path to the absolute path in out, resolving "." and "..". */
static bool append_path(char *out, size_t *n, size_t size, const char *path)
{
    for (const char *p = path; *p;) {
        while (*p == '/')
            p++;
        size_t len = strcspn(p, "/");
        if (len == 0)
            break;
        if (len == 2 && p[0] == '.' && p[1] == '.') {
            while (*n > 1 && out[*n - 1] != '/')
                (*n)--;
            if (*n > 1)
                (*n)--;
        } else if (!(len == 1 && p[0] == '.')) {
            size_t slash = *n > 1 ? 1 : 0;
            if (*n + slash + len >= size)
                return false;
            if (slash)
                out[(*n)++] = '/';
            memcpy(out + *n, p, len);
            *n += len;
        }
        p += len;
    }
    out[*n] = '\0';
    return true;
}

/* As os.path.abspath does: by name alone, without following links. */
static void resolve(const char *script, const char *cwd, char *out, size_t size)
{
    bool relative = script[0] != '/';
    size_t n = 1;

    if (size < 2 || (relative && cwd[0] != '/')) {
        ft_strlcpy(out, script, size);
        return;
    }
    out[0] = '/';
    if ((relative && !append_path(out, &n, size, cwd)) || !append_path(out, &n, size, script))
        ft_strlcpy(out, script, size);
}

bool ft_script_derive(const char *exe, const char *args, size_t len, const char *cwd, char *out,
                      size_t size)
{
    static const char fpm[] = "php-fpm: ";
    static const char pool[] = "pool ";
    constexpr size_t MAX_ARGS = 64;
    const char *argv[MAX_ARGS];
    size_t argc = 0;

    /* Padding left behind by a rewritten title ends the list. */
    for (size_t at = 0; at < len && argc < MAX_ARGS; at += strlen(args + at) + 1) {
        if (args[at + strspn(args + at, " ")] == '\0')
            break;
        argv[argc++] = args + at;
    }
    if (argc == 0 || size == 0)
        return false;

    /* PHP-FPM names each worker after its pool once it has forked. */
    if (strncmp(argv[0], fpm, sizeof(fpm) - 1) == 0) {
        const char *name = argv[0] + sizeof(fpm) - 1;
        size_t n = strlen(name);
        if (strncmp(name, pool, sizeof(pool) - 1) != 0)
            return false;
        name += sizeof(pool) - 1;
        n -= sizeof(pool) - 1;
        while (n && name[n - 1] == ' ')
            n--;
        if (n == 0)
            return false;
        snprintf(out, size, "pool:%.*s", (int)n, name);
        return true;
    }
    /* Any other title a process gave itself hides its arguments. */
    if (strchr(argv[0], ' '))
        return false;

    const struct grammar *g = grammar_of(exe ? exe : "");
    if (!g)
        g = grammar_of(argv[0]);
    if (!g)
        return false;

    const char *what = nullptr;
    switch (find_script(g, argv, argc, &what)) {
    case FOUND_SCRIPT:
        resolve(what, cwd ? cwd : "", out, size);
        return true;
    case FOUND_MODULE:
        snprintf(out, size, "module:%s", what);
        return true;
    default:
        return false;
    }
}
