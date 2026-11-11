#include "filetrace/poller.h"

#include <limits.h>

void ft_poller_begin(struct ft_poller *p, uint64_t wake_ns)
{
    p->count = 0;
    p->wake_ns = wake_ns;
}

size_t ft_poller_add(struct ft_poller *p, int fd, short events)
{
    if (p->count == FT_POLLER_MAX)
        return FT_POLLER_NONE;
    p->fds[p->count] = (struct pollfd){.fd = fd, .events = events};
    return p->count++;
}

void ft_poller_wake_by(struct ft_poller *p, uint64_t mono_ns)
{
    if (mono_ns < p->wake_ns)
        p->wake_ns = mono_ns;
}

int ft_poller_wait(struct ft_poller *p, uint64_t now_ns)
{
    uint64_t ms = p->wake_ns > now_ns ? (p->wake_ns - now_ns + FT_NS_PER_MS - 1) / FT_NS_PER_MS : 0;

    return poll(p->fds, (nfds_t)p->count, ms > INT_MAX ? INT_MAX : (int)ms);
}

short ft_poller_revents(const struct ft_poller *p, size_t slot)
{
    return slot < p->count ? p->fds[slot].revents : 0;
}
