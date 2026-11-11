#ifndef FILETRACE_POLLER_H
#define FILETRACE_POLLER_H

#include "filetrace/base.h"

#include <poll.h>

#define FT_POLLER_MAX 128
#define FT_POLLER_NONE SIZE_MAX

/* One round of poll(2): descriptors are added before the wait and asked about after it. */
struct ft_poller {
    struct pollfd fds[FT_POLLER_MAX];
    size_t count;
    uint64_t wake_ns; /* monotonic time by which the wait ends */
};

void ft_poller_begin(struct ft_poller *p, uint64_t wake_ns);

/* Returns the slot to ask about after the wait, or FT_POLLER_NONE when the set is full. */
size_t ft_poller_add(struct ft_poller *p, int fd, short events);

void ft_poller_wake_by(struct ft_poller *p, uint64_t mono_ns);

/* Returns what poll(2) does. */
int ft_poller_wait(struct ft_poller *p, uint64_t now_ns);

short ft_poller_revents(const struct ft_poller *p, size_t slot);

#endif
