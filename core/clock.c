#include "filetrace/clock.h"

#include <time.h>

#if defined(__linux__)
#define FT_MONO_CLOCK CLOCK_BOOTTIME
#else
#define FT_MONO_CLOCK CLOCK_MONOTONIC
#endif

static uint64_t read_clock(clockid_t id)
{
    struct timespec ts;
    if (clock_gettime(id, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * FT_NS_PER_SEC + (uint64_t)ts.tv_nsec;
}

uint64_t ft_clock_mono_ns(void)
{
    return read_clock(FT_MONO_CLOCK);
}

uint64_t ft_clock_wall_ns(void)
{
    return read_clock(CLOCK_REALTIME);
}

uint64_t ft_clock_mono_to_wall(uint64_t mono_ns)
{
    if (mono_ns == 0)
        return 0;
    uint64_t wall = ft_clock_wall_ns();
    uint64_t mono = ft_clock_mono_ns();
    return mono_ns >= mono ? wall + (mono_ns - mono) : wall - (mono - mono_ns);
}

uint64_t ft_clock_wall_to_mono(uint64_t wall_ns)
{
    uint64_t wall = ft_clock_wall_ns();
    uint64_t mono = ft_clock_mono_ns();
    if (wall_ns >= wall)
        return mono + (wall_ns - wall);
    uint64_t ago = wall - wall_ns;
    return ago >= mono ? 0 : mono - ago;
}
