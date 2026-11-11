#include "cmd/cli.h"

#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

constexpr size_t MAX_ADDRESSES = 1024;
constexpr size_t WORKERS = 8;

enum lookup_state : uint8_t {
    LOOKUP_QUEUED,
    LOOKUP_NAMED,
    LOOKUP_NAMELESS,
};

struct lookup {
    struct ft_endpoint addr;
    enum lookup_state state;
    char name[256];
};

/* Entries are added and never removed, so a name handed out stays valid. */
static struct lookup lookups[MAX_ADDRESSES];
static size_t count;
static size_t next_queued;
static size_t unfinished;
static bool started;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queued = PTHREAD_COND_INITIALIZER;
static pthread_cond_t settled = PTHREAD_COND_INITIALIZER;

static bool same_address(const struct ft_endpoint *a, const struct ft_endpoint *b)
{
    return a->family == b->family && memcmp(a->addr, b->addr, sizeof(a->addr)) == 0;
}

static bool reverse_lookup(const struct ft_endpoint *addr, char *name, size_t size)
{
    struct sockaddr_storage ss = {0};
    socklen_t len;

    if (addr->family == 6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
        sin6->sin6_family = AF_INET6;
        memcpy(&sin6->sin6_addr, addr->addr, 16);
        len = sizeof(*sin6);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
        sin->sin_family = AF_INET;
        memcpy(&sin->sin_addr, addr->addr, 4);
        len = sizeof(*sin);
    }
    return getnameinfo((struct sockaddr *)&ss, len, name, (socklen_t)size, nullptr, 0,
                       NI_NAMEREQD) == 0;
}

static void *worker(void *arg)
{
    (void)arg;
    pthread_mutex_lock(&lock);
    for (;;) {
        while (next_queued == count)
            pthread_cond_wait(&queued, &lock);
        struct lookup *l = &lookups[next_queued++];
        struct ft_endpoint addr = l->addr;
        char name[sizeof(l->name)];

        pthread_mutex_unlock(&lock);
        bool named = reverse_lookup(&addr, name, sizeof(name));
        pthread_mutex_lock(&lock);

        if (named)
            memcpy(l->name, name, sizeof(l->name));
        l->state = named ? LOOKUP_NAMED : LOOKUP_NAMELESS;
        if (--unfinished == 0)
            pthread_cond_broadcast(&settled);
    }
    return nullptr;
}

static void start_workers(void)
{
    for (size_t i = 0; i < WORKERS; i++) {
        pthread_t thread;
        if (pthread_create(&thread, nullptr, worker, nullptr) == 0)
            pthread_detach(thread);
    }
    started = true;
}

const char *ft_resolver_name(const struct ft_endpoint *addr)
{
    const char *name = nullptr;

    if (addr->family == 0)
        return nullptr;
    pthread_mutex_lock(&lock);
    size_t i = 0;
    while (i < count && !same_address(&lookups[i].addr, addr))
        i++;
    if (i < count) {
        if (lookups[i].state == LOOKUP_NAMED)
            name = lookups[i].name;
    } else if (count < MAX_ADDRESSES) {
        if (!started)
            start_workers();
        lookups[count].addr = *addr;
        lookups[count].state = LOOKUP_QUEUED;
        count++;
        unfinished++;
        pthread_cond_signal(&queued);
    }
    pthread_mutex_unlock(&lock);
    return name;
}

void ft_resolver_wait(uint64_t timeout_ns)
{
    struct timespec deadline;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += (time_t)(timeout_ns / FT_NS_PER_SEC);
    deadline.tv_nsec += (long)(timeout_ns % FT_NS_PER_SEC);
    if (deadline.tv_nsec >= (long)FT_NS_PER_SEC) {
        deadline.tv_sec++;
        deadline.tv_nsec -= (long)FT_NS_PER_SEC;
    }

    pthread_mutex_lock(&lock);
    while (unfinished && pthread_cond_timedwait(&settled, &lock, &deadline) == 0)
        continue;
    pthread_mutex_unlock(&lock);
}
