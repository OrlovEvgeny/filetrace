#ifndef FILETRACE_SIM_ENGINE_H
#define FILETRACE_SIM_ENGINE_H

#include "sim/scenario.h"

#include "filetrace/event.h"
#include "filetrace/process.h"

/* Advances the processes and generators of a scenario and emits what a collector would see. */
struct ft_sim_engine;

/* Starts the clock at start_ns and emits the processes that already run. */
struct ft_sim_engine *ft_sim_engine_create(const struct ft_sim_scenario *sc, uint64_t seed,
                                           uint64_t start_ns, const struct ft_sink *sink);
void ft_sim_engine_destroy(struct ft_sim_engine *e);

/*
 * Runs whole steps while their end is not after until_ns, then emits what a collector would have
 * seen: the queued events in order, and a flow and a transfer record per socket and file.
 */
void ft_sim_engine_run(struct ft_sim_engine *e, uint64_t until_ns, uint64_t step_ns);

/* Moves the clock forward without simulating the time skipped. */
void ft_sim_engine_skip_to(struct ft_sim_engine *e, uint64_t ns);

uint64_t ft_sim_engine_now(const struct ft_sim_engine *e);
uint64_t ft_sim_engine_events(const struct ft_sim_engine *e);

/* Events a kernel would have queued rather than counted: processes, sockets and files. */
uint64_t ft_sim_engine_queued_events(const struct ft_sim_engine *e);

bool ft_sim_engine_process(const struct ft_sim_engine *e, uint32_t pid, struct ft_ev_process *out);
bool ft_sim_engine_process_text(const struct ft_sim_engine *e, uint32_t pid,
                                struct ft_process_text *out);

#endif
