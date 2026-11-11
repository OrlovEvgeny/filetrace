#include "unit/test.h"

#include "filetrace/table.h"

struct entry {
    uint64_t value;
};

static void count_evictions(void *value, void *ctx)
{
    const struct entry *e = value;
    uint64_t *sum = ctx;
    *sum += e->value;
}

static void insert_find(void)
{
    struct ft_table *t = ft_table_create(8, sizeof(uint32_t), sizeof(struct entry));
    bool created = false;
    uint32_t key = 7;

    CHECK(t != nullptr);
    CHECK(ft_table_find(t, &key) == nullptr);

    struct entry *e = ft_table_insert(t, &key, &created);
    CHECK(created);
    CHECK_U64(e->value, 0);
    e->value = 99;

    struct entry *again = ft_table_insert(t, &key, &created);
    CHECK(!created);
    CHECK(again == e);
    CHECK_U64(((struct entry *)ft_table_find(t, &key))->value, 99);
    CHECK_U64(*(const uint32_t *)ft_table_key(t, e), 7);
    CHECK_U64(ft_table_count(t), 1);

    ft_table_remove(t, &key);
    CHECK(ft_table_find(t, &key) == nullptr);
    CHECK_U64(ft_table_count(t), 0);
    ft_table_destroy(t);
}

static void eviction_order(void)
{
    struct ft_table *t = ft_table_create(3, sizeof(uint32_t), sizeof(struct entry));
    uint64_t evicted = 0;

    ft_table_on_evict(t, count_evictions, &evicted);
    for (uint32_t k = 1; k <= 3; k++) {
        struct entry *e = ft_table_insert(t, &k, nullptr);
        e->value = k * 10;
    }

    /* Using key 1 leaves key 2 as the least recently used. */
    uint32_t one = 1;
    uint32_t two = 2;
    uint32_t four = 4;
    CHECK(ft_table_touch(t, &one) != nullptr);
    ft_table_insert(t, &four, nullptr);

    CHECK(ft_table_find(t, &two) == nullptr);
    CHECK(ft_table_find(t, &one) != nullptr);
    CHECK_U64(evicted, 20);
    CHECK_U64(ft_table_evictions(t), 1);
    CHECK_U64(ft_table_count(t), 3);

    /* Iteration runs from most to least recently used. */
    uint32_t order[3] = {0};
    size_t n = 0;
    for (struct entry *e = ft_table_first(t); e && n < 3; e = ft_table_next(t, e))
        order[n++] = *(const uint32_t *)ft_table_key(t, e);
    CHECK_U64(n, 3);
    CHECK_U64(order[0], 4);
    CHECK_U64(order[1], 1);
    CHECK_U64(order[2], 3);

    ft_table_destroy(t);
    CHECK_U64(evicted, 20 + 10 + 30);
}

static void churn(void)
{
    struct ft_table *t = ft_table_create(64, sizeof(uint64_t), sizeof(struct entry));

    for (uint64_t k = 0; k < 10000; k++) {
        struct entry *e = ft_table_insert(t, &k, nullptr);
        e->value = k;
        if (k % 3 == 0)
            ft_table_remove(t, &k);
    }
    CHECK(ft_table_count(t) <= 64);

    /* Every surviving entry is still reachable under its own key. */
    size_t seen = 0;
    for (struct entry *e = ft_table_first(t); e; e = ft_table_next(t, e)) {
        uint64_t key = *(const uint64_t *)ft_table_key(t, e);
        CHECK(ft_table_find(t, &key) == e);
        CHECK_U64(e->value, key);
        seen++;
    }
    CHECK_U64(seen, ft_table_count(t));

    ft_table_clear(t);
    CHECK_U64(ft_table_count(t), 0);
    CHECK(ft_table_first(t) == nullptr);
    ft_table_destroy(t);
}

void test_table(void)
{
    insert_find();
    eviction_order();
    churn();
    CHECK(ft_table_create(0, 4, 4) == nullptr);
}
