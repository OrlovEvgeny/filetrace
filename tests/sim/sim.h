#ifndef FILETRACE_SIM_H
#define FILETRACE_SIM_H

#include "backends/backend.h"

struct ft_sim_options {
    const char *scenario;
    uint64_t seed;
    uint64_t history_ns; /* past activity generated before the agent serves */
    uint32_t transfers;  /* concurrent transfers of the storm scenario */
    bool lossless;       /* no events are lost, so the agent never reports itself degraded */
};

/* Takes effect when the backend is opened. */
void ft_sim_configure(const struct ft_sim_options *opt);

const struct ft_backend_ops *ft_sim_backend(void);

#endif
