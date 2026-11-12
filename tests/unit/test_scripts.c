#include "unit/test.h"

#include "filetrace/scripts.h"

#include <stdio.h>
#include <stdlib.h>

/* What the kernel keeps: the id of each path's hash, issued in order and kept while in use. */
struct kernel {
    uint64_t hashes[8192];
    uint32_t ids[8192];
    size_t count;
    uint32_t last;
};

static void kernel_forget(struct kernel *k, uint64_t hash)
{
    for (size_t i = 0; i < k->count; i++) {
        if (k->hashes[i] == hash) {
            k->hashes[i] = k->hashes[--k->count];
            k->ids[i] = k->ids[k->count];
            return;
        }
    }
}

/* A request runs the script: the kernel names it by id, telling the agent the first time. */
static uint32_t request(struct kernel *k, struct ft_script_names *n, uint64_t hash,
                        const char *path)
{
    for (size_t i = 0; i < k->count; i++) {
        if (k->hashes[i] == hash)
            return k->ids[i];
    }
    uint32_t id = ++k->last;
    uint64_t evicted = 0;
    if (ft_script_names_put(n, id, hash, path, &evicted))
        kernel_forget(k, evicted);
    if (k->count < FT_ARRAY_LEN(k->hashes)) {
        k->hashes[k->count] = hash;
        k->ids[k->count++] = id;
    }
    return id;
}

static const char *name_of(const struct ft_script_names *n, uint32_t id)
{
    const char *path = ft_script_names_get(n, id);
    return path ? path : "(none)";
}

/* A script in use the whole time keeps its name however many others come and go. */
static void busy_script_keeps_its_name(void)
{
    constexpr size_t SLOTS = 64;
    struct ft_script_names *n = ft_script_names_create(SLOTS);
    struct kernel *k = calloc(1, sizeof(*k));
    char path[64];

    uint32_t id = request(k, n, 1, "/var/www/app/index.php");
    CHECK_STR(name_of(n, id), "/var/www/app/index.php");
    for (uint64_t i = 0; i < 3 * SLOTS; i++) {
        snprintf(path, sizeof(path), "artisan-%llu", (unsigned long long)i);
        request(k, n, 1000 + i, path);
        id = request(k, n, 1, "/var/www/app/index.php");
        CHECK_STR(name_of(n, id), "/var/www/app/index.php");
    }
    CHECK(k->last > SLOTS);

    /* An id whose slot went to another is not given another's path. */
    CHECK(ft_script_names_get(n, 2) == nullptr);
    CHECK(ft_script_names_get(n, 0) == nullptr);
    free(k);
    ft_script_names_destroy(n);
}

void test_scripts(void)
{
    busy_script_keeps_its_name();
}
