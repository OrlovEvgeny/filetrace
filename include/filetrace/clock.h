#ifndef FILETRACE_CLOCK_H
#define FILETRACE_CLOCK_H

#include "filetrace/base.h"

/* The monotonic clock keeps counting through suspend; wall time is for presentation only. */
uint64_t ft_clock_mono_ns(void);
uint64_t ft_clock_wall_ns(void);

uint64_t ft_clock_mono_to_wall(uint64_t mono_ns);

/* Returns 0 for a time before the monotonic clock started. */
uint64_t ft_clock_wall_to_mono(uint64_t wall_ns);

#endif
