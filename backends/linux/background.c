#include "backends/linux/linux.h"

#include "filetrace/format.h"

#include <bpf/bpf.h>
#include <dirent.h>
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

void ft_linux_background_learn(int map_fd, const char *const *patterns, size_t count, uint64_t ino,
                               uint32_t dev, const char *path)
{
    for (size_t i = 0; i < count; i++) {
        if (ft_glob_match(patterns[i], path)) {
            struct ft_bpf_background_key key = {.ino = ino, .dev = dev};
            uint8_t learned = FT_BPF_BACKGROUND_LEARNED;
            bpf_map_update_elem(map_fd, &key, &learned, BPF_NOEXIST);
            return;
        }
    }
}

size_t ft_linux_background_load(int map_fd, const char *const *patterns, size_t count,
                                bool *truncated)
{
    struct key_set set = {.capacity = FT_BPF_BACKGROUND_MAX};
    *truncated = false;
    set.keys = calloc(set.capacity, sizeof(*set.keys));
    if (!set.keys)
        return 0;
    for (size_t i = 0; i < count && !set.full; i++)
        expand(&set, patterns[i]);
    qsort(set.keys, set.count, sizeof(*set.keys), key_cmp);

    /* Drop what the patterns no longer name before adding what they do. */
    struct ft_bpf_background_key key;
    struct ft_bpf_background_key next;
    bool more = bpf_map_get_next_key(map_fd, nullptr, &key) == 0;
    while (more) {
        more = bpf_map_get_next_key(map_fd, &key, &next) == 0;
        uint8_t source = 0;
        bool learned =
            bpf_map_lookup_elem(map_fd, &key, &source) == 0 && source == FT_BPF_BACKGROUND_LEARNED;
        if (!learned && !contains(&set, &key))
            bpf_map_delete_elem(map_fd, &key);
        key = next;
    }
    uint8_t scanned = FT_BPF_BACKGROUND_SCANNED;
    size_t held = 0;
    for (size_t i = 0; i < set.count; i++) {
        if (i > 0 && key_cmp(&set.keys[i - 1], &set.keys[i]) == 0)
            continue;
        if (bpf_map_update_elem(map_fd, &set.keys[i], &scanned, BPF_ANY) == 0)
            held++;
    }
    *truncated = set.full;
    free(set.keys);
    return held;
}

static bool plain(const char *text)
{
    return text[0] && !strpbrk(text, "*?/");
}

size_t ft_linux_background_names(int names_fd, int suffixes_fd, const char *const *patterns,
                                 size_t count)
{
    size_t held = 0;
    uint32_t suffixes = 0;
    uint8_t one = 1;

    for (size_t i = 0; i < count; i++) {
        const char *p = patterns[i];
        if (strncmp(p, "*/", 2) == 0 && plain(p + 2) && strlen(p + 2) < FT_BPF_BACKGROUND_NAME) {
            char name[FT_BPF_BACKGROUND_NAME] = {0};
            memcpy(name, p + 2, strlen(p + 2));
            if (bpf_map_update_elem(names_fd, name, &one, BPF_ANY) == 0)
                held++;
        } else if (p[0] == '*' && p[1] == '.' && plain(p + 1) &&
                   strlen(p + 1) <= FT_BPF_BACKGROUND_SUFFIX &&
                   suffixes < FT_BPF_BACKGROUND_SUFFIXES) {
            struct ft_bpf_background_suffix suffix = {.len = (uint32_t)strlen(p + 1)};
            memcpy(suffix.text, p + 1, suffix.len);
            if (bpf_map_update_elem(suffixes_fd, &suffixes, &suffix, BPF_ANY) == 0) {
                suffixes++;
                held++;
            }
        }
    }
    return held;
}
