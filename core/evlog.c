#include "filetrace/state.h"

#include <stdlib.h>
#include <string.h>

/* Records lie end to end in a ring, each behind its size, and may wrap around its end. */
struct ft_evlog {
    unsigned char *buf;
    size_t capacity;
    size_t head;
    size_t used;
    uint64_t records;
    uint64_t discarded;
};

struct ft_evlog *ft_evlog_create(size_t bytes)
{
    struct ft_evlog *log = calloc(1, sizeof(*log));
    if (!log)
        return nullptr;
    log->buf = malloc(bytes ? bytes : 1);
    log->capacity = bytes;
    if (!log->buf) {
        free(log);
        return nullptr;
    }
    return log;
}

void ft_evlog_destroy(struct ft_evlog *log)
{
    if (!log)
        return;
    free(log->buf);
    free(log);
}

size_t ft_evlog_capacity(const struct ft_evlog *log)
{
    return log->capacity;
}

uint64_t ft_evlog_records(const struct ft_evlog *log)
{
    return log->records;
}

uint64_t ft_evlog_discarded(const struct ft_evlog *log)
{
    return log->discarded;
}

static void ring_write(struct ft_evlog *log, size_t pos, const void *src, size_t n)
{
    size_t first = log->capacity - pos < n ? log->capacity - pos : n;
    memcpy(log->buf + pos, src, first);
    memcpy(log->buf, (const unsigned char *)src + first, n - first);
}

static void ring_read(const struct ft_evlog *log, size_t pos, void *dst, size_t n)
{
    size_t first = log->capacity - pos < n ? log->capacity - pos : n;
    memcpy(dst, log->buf + pos, first);
    memcpy((unsigned char *)dst + first, log->buf, n - first);
}

static size_t stored_size(const struct ft_evlog *log, size_t pos)
{
    uint32_t size;
    ring_read(log, pos, &size, sizeof(size));
    return sizeof(size) + size;
}

void ft_evlog_append(struct ft_evlog *log, const struct ft_row_event *row, size_t size)
{
    uint32_t header = (uint32_t)size;
    size_t need = sizeof(header) + size;

    if (need > log->capacity)
        return;
    while (log->capacity - log->used < need) {
        size_t oldest = stored_size(log, log->head);
        log->head = (log->head + oldest) % log->capacity;
        log->used -= oldest;
        log->records--;
        log->discarded++;
    }

    size_t tail = (log->head + log->used) % log->capacity;
    ring_write(log, tail, &header, sizeof(header));
    ring_write(log, (tail + sizeof(header)) % log->capacity, row, size);
    log->used += need;
    log->records++;
}

void ft_evlog_rewind(const struct ft_evlog *log, struct ft_evlog_cursor *cur)
{
    cur->pos = log->head;
    cur->remaining = log->used;
}

bool ft_evlog_peek(const struct ft_evlog *log, const struct ft_evlog_cursor *cur,
                   struct ft_row_event *out)
{
    if (cur->remaining == 0)
        return false;
    size_t size = stored_size(log, cur->pos) - sizeof(uint32_t);
    if (size > sizeof(*out))
        size = sizeof(*out);
    ring_read(log, (cur->pos + sizeof(uint32_t)) % log->capacity, out, size);
    return true;
}

void ft_evlog_advance(const struct ft_evlog *log, struct ft_evlog_cursor *cur)
{
    size_t size = stored_size(log, cur->pos);
    cur->pos = (cur->pos + size) % log->capacity;
    cur->remaining -= size;
}
