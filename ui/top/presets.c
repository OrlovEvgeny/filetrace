#include "ui/top/presets.h"

#include "filetrace/model.h"

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool too_long(struct ft_error *err)
{
    ft_error_set(err, FT_EXIT_ERROR, "The path of the filter presets is too long");
    return false;
}

static bool config_home(char *buf, size_t size, struct ft_error *err)
{
    const char *xdg = getenv("XDG_CONFIG_HOME");
    const char *home = getenv("HOME");
    struct passwd pw;
    struct passwd *found = nullptr;
    char pwbuf[1024];
    int n;

    /* The base directory specification ignores a relative path. */
    if (xdg && xdg[0] == '/') {
        n = snprintf(buf, size, "%s", xdg);
        return n >= 0 && (size_t)n < size ? true : too_long(err);
    }
    if ((!home || !home[0]) && getpwuid_r(getuid(), &pw, pwbuf, sizeof(pwbuf), &found) == 0 &&
        found)
        home = found->pw_dir;
    if (!home || !home[0]) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot find the home directory for the filter presets");
        return false;
    }
    n = snprintf(buf, size, "%s/.config", home);
    return n >= 0 && (size_t)n < size ? true : too_long(err);
}

static bool presets_dir(char *buf, size_t size, struct ft_error *err)
{
    char base[FT_PATH_MAX];

    if (!config_home(base, sizeof(base), err))
        return false;
    int n = snprintf(buf, size, "%s/filetrace", base);
    return n >= 0 && (size_t)n < size ? true : too_long(err);
}

bool ft_top_presets_path(char *buf, size_t size, struct ft_error *err)
{
    char dir[FT_PATH_MAX];

    if (!presets_dir(dir, sizeof(dir), err))
        return false;
    int n = snprintf(buf, size, "%s/top-presets", dir);
    return n >= 0 && (size_t)n < size ? true : too_long(err);
}

/* Cuts the line at its end and at its first tab; false for a line that holds no preset. */
static bool split(char *line, char **name, char **expression)
{
    line[strcspn(line, "\r\n")] = '\0';
    char *tab = strchr(line, '\t');
    if (!tab || tab == line)
        return false;
    *tab = '\0';
    *name = line;
    *expression = tab + 1;
    return true;
}

static bool append(struct ft_top_presets *p, const char *name, const char *expression)
{
    struct ft_top_preset *items = realloc(p->items, (p->count + 1) * sizeof(*items));

    if (!items)
        return false;
    p->items = items;
    char *n = strdup(name);
    char *e = strdup(expression);
    if (!n || !e) {
        free(n);
        free(e);
        return false;
    }
    items[p->count++] = (struct ft_top_preset){.name = n, .expression = e};
    return true;
}

void ft_top_presets_free(struct ft_top_presets *presets)
{
    for (size_t i = 0; i < presets->count; i++) {
        free(presets->items[i].name);
        free(presets->items[i].expression);
    }
    free(presets->items);
    *presets = (struct ft_top_presets){0};
}

bool ft_top_presets_load(struct ft_top_presets *out, struct ft_error *err)
{
    char path[FT_PATH_MAX];
    char *line = nullptr;
    size_t cap = 0;
    bool ok = true;

    *out = (struct ft_top_presets){0};
    if (!ft_top_presets_path(path, sizeof(path), err))
        return false;
    FILE *f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT)
            return true;
        ft_error_set(err, FT_EXIT_ERROR, "Cannot read %s: %s", path, strerror(errno));
        return false;
    }
    while (ok && getline(&line, &cap, f) >= 0) {
        char *name;
        char *expression;
        if (split(line, &name, &expression) && !append(out, name, expression)) {
            ft_error_set(err, FT_EXIT_ERROR, "Out of memory");
            ok = false;
        }
    }
    if (ok && ferror(f)) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot read %s: %s", path, strerror(errno));
        ok = false;
    }
    free(line);
    fclose(f);
    if (!ok)
        ft_top_presets_free(out);
    return ok;
}

static bool make_dir(const char *path, struct ft_error *err)
{
    if (mkdir(path, 0700) == 0 || errno == EEXIST)
        return true;
    ft_error_set(err, FT_EXIT_ERROR, "Cannot create %s: %s", path, strerror(errno));
    return false;
}

/* Copies the lines of the file at path to out, the preset of the name replaced by its new text. */
static bool rewrite(const char *path, FILE *out, const char *name, const char *expression,
                    struct ft_error *err)
{
    size_t name_len = strlen(name);
    bool replaced = false;
    char *line = nullptr;
    size_t cap = 0;
    ssize_t len;
    FILE *in = fopen(path, "r");

    if (!in && errno != ENOENT) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot read %s: %s", path, strerror(errno));
        return false;
    }
    while (in && (len = getline(&line, &cap, in)) >= 0) {
        const char *tab = strchr(line, '\t');
        if (tab && (size_t)(tab - line) == name_len && memcmp(line, name, name_len) == 0) {
            if (!replaced)
                fprintf(out, "%s\t%s\n", name, expression);
            replaced = true;
            continue;
        }
        fputs(line, out);
        if (len > 0 && line[len - 1] != '\n')
            fputc('\n', out);
    }
    bool failed = in && ferror(in);
    free(line);
    if (in)
        fclose(in);
    if (failed) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot read %s: %s", path, strerror(errno));
        return false;
    }
    if (!replaced)
        fprintf(out, "%s\t%s\n", name, expression);
    return true;
}

bool ft_top_presets_save(const char *name, const char *expression, struct ft_error *err)
{
    char base[FT_PATH_MAX];
    char dir[FT_PATH_MAX];
    char path[FT_PATH_MAX];
    char temp[FT_PATH_MAX];

    if (!name[0] || strpbrk(name, "\t\r\n")) {
        ft_error_set(err, FT_EXIT_USAGE, "A preset name cannot be empty or hold a tab");
        return false;
    }
    if (strpbrk(expression, "\r\n")) {
        ft_error_set(err, FT_EXIT_USAGE, "A filter cannot span lines");
        return false;
    }
    if (!config_home(base, sizeof(base), err) || !presets_dir(dir, sizeof(dir), err) ||
        !ft_top_presets_path(path, sizeof(path), err) || !make_dir(base, err) ||
        !make_dir(dir, err))
        return false;
    int n = snprintf(temp, sizeof(temp), "%s/.top-presets.XXXXXX", dir);
    if (n < 0 || (size_t)n >= sizeof(temp))
        return too_long(err);

    int fd = mkstemp(temp);
    if (fd < 0) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot write in %s: %s", dir, strerror(errno));
        return false;
    }
    FILE *out = fdopen(fd, "w");
    if (!out) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot write %s: %s", temp, strerror(errno));
        close(fd);
        unlink(temp);
        return false;
    }
    bool ok = rewrite(path, out, name, expression, err);
    if (ok && (fflush(out) != 0 || ferror(out) || fsync(fd) != 0)) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot write %s: %s", temp, strerror(errno));
        ok = false;
    }
    if (fclose(out) != 0 && ok) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot write %s: %s", temp, strerror(errno));
        ok = false;
    }
    if (ok && rename(temp, path) != 0) {
        ft_error_set(err, FT_EXIT_ERROR, "Cannot replace %s: %s", path, strerror(errno));
        ok = false;
    }
    if (!ok)
        unlink(temp);
    return ok;
}

bool ft_top_presets_find(const char *name, char *expression, size_t size, struct ft_error *err)
{
    struct ft_top_presets p;
    char names[320] = "";
    size_t len = 0;

    if (!ft_top_presets_load(&p, err))
        return false;
    for (size_t i = 0; i < p.count; i++) {
        if (strcmp(p.items[i].name, name) != 0)
            continue;
        bool fits = strlen(p.items[i].expression) < size;
        if (fits)
            ft_strlcpy(expression, p.items[i].expression, size);
        else
            ft_error_set(err, FT_EXIT_USAGE, "filter preset '%s' is longer than %zu bytes", name,
                         size - 1);
        ft_top_presets_free(&p);
        return fits;
    }

    /* Each name is added only while the "…" for the ones after it still fits. */
    for (size_t i = 0; i < p.count; i++) {
        const char *sep = i ? ", " : "";
        if (len + strlen(sep) + strlen(p.items[i].name) + sizeof(", …") > sizeof(names)) {
            ft_strlcpy(names + len, i ? ", …" : "…", sizeof(names) - len);
            break;
        }
        int n = snprintf(names + len, sizeof(names) - len, "%s%s", sep, p.items[i].name);
        len += n > 0 ? (size_t)n : 0;
    }
    if (p.count == 0)
        ft_error_set(err, FT_EXIT_USAGE,
                     "unknown filter preset '%s': none are saved (Ctrl-S in the F4 filter prompt "
                     "saves one)",
                     name);
    else
        ft_error_set(err, FT_EXIT_USAGE, "unknown filter preset '%s' (saved: %s)", name, names);
    ft_top_presets_free(&p);
    return false;
}
