#include "backends/linux/linux.h"

#include "filetrace/base.h"
#include "filetrace/format.h"

#include <bpf/bpf.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "backends/linux/bpf/abi.h"

#define MAX_DEPTH 8

struct key_set {
    struct ft_bpf_background_key *keys;
    size_t count;
    size_t capacity;
    bool full;
};

static void add_file(struct key_set *set, const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return;
    if (set->count == set->capacity) {
        set->full = true;
        return;
    }
    /* The kernel packs dev_t as major:12 minor:20; stat(2) reports makedev(). */
    set->keys[set->count++] = (struct ft_bpf_background_key){
        .ino = (uint64_t)st.st_ino,
        .dev = (uint32_t)((major(st.st_dev) << 20) | minor(st.st_dev)),
    };
}

/* Adds every regular file under dir whose path matches the pattern, following file links. */
static void walk(struct key_set *set, const char *pattern, const char *dir, int depth)
{
    DIR *d = opendir(dir);
    if (!d)
        return;

    struct dirent *e;
    char path[PATH_MAX];
    while ((e = readdir(d)) != nullptr && !set->full) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if ((size_t)snprintf(path, sizeof(path), "%s/%s", strcmp(dir, "/") == 0 ? "" : dir,
                             e->d_name) >= sizeof(path))
            continue;
        bool subdir = e->d_type == DT_DIR;
        struct stat st;
        if (e->d_type == DT_UNKNOWN && lstat(path, &st) == 0)
            subdir = S_ISDIR(st.st_mode);
        if (subdir) {
            if (depth < MAX_DEPTH)
                walk(set, pattern, path, depth + 1);
        } else if (ft_glob_match(pattern, path)) {
            add_file(set, path);
        }
    }
    closedir(d);
}

static void expand(struct key_set *set, const char *pattern)
{
    const char *star = strchr(pattern, '*');
    if (!star) {
        add_file(set, pattern);
        return;
    }

    /* Walk from the deepest directory the pattern names before its first wildcard. */
    char dir[PATH_MAX];
    size_t len = (size_t)(star - pattern);
    while (len > 0 && pattern[len - 1] != '/')
        len--;
    if (len == 0 || len >= sizeof(dir))
        return;
    memcpy(dir, pattern, len);
    dir[len > 1 ? len - 1 : len] = '\0';
    walk(set, pattern, dir, 0);
}

static int key_cmp(const void *a, const void *b)
{
    const struct ft_bpf_background_key *x = a;
    const struct ft_bpf_background_key *y = b;
    if (x->dev != y->dev)
        return x->dev < y->dev ? -1 : 1;
    if (x->ino != y->ino)
        return x->ino < y->ino ? -1 : 1;
    return 0;
}

static bool contains(const struct key_set *set, const struct ft_bpf_background_key *key)
{
    return bsearch(key, set->keys, set->count, sizeof(*key), key_cmp) != nullptr;
}

static bool plain(const char *text)
{
    return text[0] && !strpbrk(text, "*?/");
}

/*
 * The length of the text after the leading "*" of a pattern that names a file by the end of its
 * name ("*.ext") or by a part of it ("*text*", then *inside), or 0.
 */
static size_t name_part(const char *p, bool *inside)
{
    size_t n = strlen(p);
    *inside = n > 2 && p[0] == '*' && p[n - 1] == '*';
    size_t len = *inside ? n - 2 : n - 1;
    if (p[0] != '*' || len == 0 || (!*inside && p[1] != '.'))
        return 0;
    for (size_t i = 1; i <= len; i++) {
        if (strchr("*?/", p[i]))
            return 0;
    }
    return len;
}

/*
 * Whether the kernel names the file by the pattern from the file's name alone; counts suffixes in
 * the order ft_linux_background_names loads them.
 */
static bool kernel_named(const char *p, const char *name, uint32_t *suffixes)
{
    if (strncmp(p, "*/", 2) == 0 && plain(p + 2))
        return strlen(p + 2) < FT_BPF_BACKGROUND_NAME;
    bool inside;
    size_t part = name_part(p, &inside);
    if (!part || part > FT_BPF_BACKGROUND_SUFFIX)
        return false;
    if ((*suffixes)++ >= FT_BPF_BACKGROUND_SUFFIXES || strlen(name) >= FT_BPF_BACKGROUND_NAME)
        return false;
    /* The part the path matched may stand in a directory's name, which the kernel does not see. */
    char text[FT_BPF_BACKGROUND_SUFFIX + 1] = {0};
    memcpy(text, p + 1, part);
    return !inside || strstr(name, text);
}

/* -1 when no pattern names the path, 0 when the first that does is the kernel's, 1 otherwise. */
static int first_match(const char *const *patterns, size_t count, const char *path,
                       const char *name, uint32_t *suffixes)
{
    for (size_t i = 0; i < count; i++) {
        bool named = kernel_named(patterns[i], name, suffixes);
        if (ft_glob_match(patterns[i], path))
            return named ? 0 : 1;
    }
    return -1;
}

static uint64_t refused;

static void table_full(void)
{
    static bool warned;
    refused++;
    if (!warned)
        ft_log(FT_LOG_WARN,
               "[correlation] the table of listed files is full (%d): a file made from now on "
               "that a pattern names by its directory is read as any other file",
               FT_BPF_BACKGROUND_MAX);
    warned = true;
}

void ft_linux_background_learn(int map_fd, const struct ft_backend_config *cfg, uint64_t ino,
                               uint32_t dev, const char *path)
{
    const char *slash = strrchr(path, '/');
    const char *name = slash ? slash + 1 : path;
    uint32_t suffixes = 0;
    uint8_t value = FT_BPF_BACKGROUND_LEARNED;
    int match =
        first_match(cfg->background_paths, cfg->background_path_count, path, name, &suffixes);
    if (match < 0) {
        match = first_match(cfg->strict_paths, cfg->strict_path_count, path, name, &suffixes);
        value |= FT_BPF_BACKGROUND_STRICT;
    }
    /* What the kernel matches by name it learns into background_named, which makes room. */
    if (match <= 0)
        return;
    struct ft_bpf_background_key key = {.ino = ino, .dev = dev};
    if (bpf_map_update_elem(map_fd, &key, &value, BPF_NOEXIST) != 0 && errno == E2BIG)
        table_full();
}

size_t ft_linux_background_count(int map_fd, uint64_t *refused_out)
{
    struct ft_bpf_background_key key;
    struct ft_bpf_background_key next;
    size_t count = 0;
    bool more = bpf_map_get_next_key(map_fd, nullptr, &key) == 0;
    while (more) {
        count++;
        more = bpf_map_get_next_key(map_fd, &key, &next) == 0;
        key = next;
    }
    *refused_out = refused;
    return count;
}

static void scan(struct key_set *set, const char *const *patterns, size_t count)
{
    for (size_t i = 0; i < count && !set->full; i++)
        expand(set, patterns[i]);
    qsort(set->keys, set->count, sizeof(*set->keys), key_cmp);
}

/* Writes the keys with the value, once each; returns how many the map took. */
static size_t store(int map_fd, const struct key_set *set, uint8_t value)
{
    size_t held = 0;
    for (size_t i = 0; i < set->count; i++) {
        if (i > 0 && key_cmp(&set->keys[i - 1], &set->keys[i]) == 0)
            continue;
        if (bpf_map_update_elem(map_fd, &set->keys[i], &value, BPF_ANY) == 0)
            held++;
        else if (errno == E2BIG)
            table_full();
    }
    return held;
}

size_t ft_linux_background_load(int map_fd, const struct ft_backend_config *cfg, bool *truncated)
{
    struct key_set background = {.capacity = FT_BPF_BACKGROUND_MAX};
    struct key_set strict = {.capacity = FT_BPF_BACKGROUND_MAX};
    *truncated = false;
    background.keys = calloc(background.capacity, sizeof(*background.keys));
    strict.keys = calloc(strict.capacity, sizeof(*strict.keys));
    if (!background.keys || !strict.keys) {
        free(background.keys);
        free(strict.keys);
        return 0;
    }
    scan(&background, cfg->background_paths, cfg->background_path_count);
    scan(&strict, cfg->strict_paths, cfg->strict_path_count);

    /* Drop what the patterns no longer name before adding what they do. */
    struct ft_bpf_background_key key;
    struct ft_bpf_background_key next;
    bool more = bpf_map_get_next_key(map_fd, nullptr, &key) == 0;
    while (more) {
        more = bpf_map_get_next_key(map_fd, &key, &next) == 0;
        uint8_t source = 0;
        bool learned = bpf_map_lookup_elem(map_fd, &key, &source) == 0 &&
                       (source & ~FT_BPF_BACKGROUND_STRICT) == FT_BPF_BACKGROUND_LEARNED;
        if (!learned && !contains(&background, &key) && !contains(&strict, &key))
            bpf_map_delete_elem(map_fd, &key);
        key = next;
    }
    /* A file both lists name is background. */
    size_t held = store(map_fd, &strict, FT_BPF_BACKGROUND_SCANNED | FT_BPF_BACKGROUND_STRICT);
    held += store(map_fd, &background, FT_BPF_BACKGROUND_SCANNED);
    *truncated = background.full || strict.full;
    free(background.keys);
    free(strict.keys);
    return held;
}

static void load_names(int names_fd, int suffixes_fd, const char *const *patterns, size_t count,
                       uint8_t kind, uint32_t *suffixes, size_t *held)
{
    for (size_t i = 0; i < count; i++) {
        const char *p = patterns[i];
        bool named = strncmp(p, "*/", 2) == 0 && plain(p + 2);
        bool inside;
        size_t part = name_part(p, &inside);
        if ((named && strlen(p + 2) >= FT_BPF_BACKGROUND_NAME) ||
            (part && (part > FT_BPF_BACKGROUND_SUFFIX || *suffixes >= FT_BPF_BACKGROUND_SUFFIXES)))
            ft_log(
                FT_LOG_WARN,
                "[correlation] \"%s\" names a file from its second read only: the kernel matches "
                "%d suffixes of up to %d characters and names of up to %d",
                p, FT_BPF_BACKGROUND_SUFFIXES, FT_BPF_BACKGROUND_SUFFIX,
                FT_BPF_BACKGROUND_NAME - 1);
        if (named && strlen(p + 2) < FT_BPF_BACKGROUND_NAME) {
            char name[FT_BPF_BACKGROUND_NAME] = {0};
            memcpy(name, p + 2, strlen(p + 2));
            if (bpf_map_update_elem(names_fd, name, &kind, BPF_NOEXIST) == 0)
                (*held)++;
        } else if (part && part <= FT_BPF_BACKGROUND_SUFFIX &&
                   *suffixes < FT_BPF_BACKGROUND_SUFFIXES) {
            struct ft_bpf_background_suffix suffix = {
                .len = (uint32_t)part, .kind = kind, .inside = inside};
            memcpy(suffix.text, p + 1, part);
            if (bpf_map_update_elem(suffixes_fd, suffixes, &suffix, BPF_ANY) == 0) {
                (*suffixes)++;
                (*held)++;
            }
        }
    }
}

size_t ft_linux_background_names(int names_fd, int suffixes_fd, const struct ft_backend_config *cfg)
{
    size_t held = 0;
    uint32_t suffixes = 0;

    /* Background goes first: suffixes match in order, and a name already held stays. */
    load_names(names_fd, suffixes_fd, cfg->background_paths, cfg->background_path_count,
               FT_BPF_LISTED_BACKGROUND, &suffixes, &held);
    load_names(names_fd, suffixes_fd, cfg->strict_paths, cfg->strict_path_count,
               FT_BPF_LISTED_STRICT, &suffixes, &held);
    return held;
}
