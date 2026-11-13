#ifndef FILETRACE_SIM_SCENARIO_H
#define FILETRACE_SIM_SCENARIO_H

#include "filetrace/model.h"

/* A process of the simulated host; count consecutive pids share one definition. */
struct ft_sim_process {
    uint32_t pid; /* 0 ends a table */
    uint32_t count;
    uint32_t ppid;
    uint32_t uid;
    const char *comm;
    const char *exe;
    const char *cmdline; /* arguments separated by spaces */
    bool title;          /* cmdline is a title the process set for itself: one argument */
    bool forked;         /* started by fork alone, so its own title is read once it has traffic */
    const char *cwd;
    const char *service; /* control group; a process without one takes its parent's */
    uint16_t listen_port;
    uint32_t age_s; /* how long it has been running when the scenario starts */
};

enum ft_sim_numbering : uint8_t {
    FT_SIM_NUMBER_NONE,
    FT_SIM_NUMBER_RANDOM,   /* a number between first and last */
    FT_SIM_NUMBER_SEQUENCE, /* first, then first + step, in the order the files are used */
    FT_SIM_NUMBER_EPOCH,    /* first + the periods elapsed, so all who start within one agree */
};

/* A kind of file a generator sends. */
struct ft_sim_flavor {
    unsigned weight; /* 0 ends a table */
    const char *path;
    const char *fs_type; /* nullptr: ext4 */
    enum ft_sim_numbering numbering;
    uint64_t first;
    union {
        uint64_t last;
        uint64_t step;
        uint64_t period_ms;
    };
    uint64_t size_min; /* bytes; a file's size follows from its path */
    uint64_t size_max;
    uint32_t rate_min; /* KiB/s */
    uint32_t rate_max;
    const char *script; /* the script of the request, or nullptr */
};

enum ft_sim_dest_kind : uint8_t {
    FT_SIM_DEST_LIST,          /* the generator's own addresses, one per slot in turn */
    FT_SIM_DEST_PUBLIC,        /* clients from a pool that favours a few */
    FT_SIM_DEST_PUBLIC_RANDOM, /* a public address drawn afresh each time */
    FT_SIM_DEST_PRIVATE,       /* 10.0.x.y */
};

struct ft_sim_dest {
    const char *addr; /* nullptr ends a list */
    uint16_t port;    /* 0: an ephemeral port */
    const char *name; /* what the process looks up to get the address; nullptr: nothing */
    const char *also; /* another name it has looked up to the same address */
    const char *tls;  /* the server name of its TLS handshake; nullptr: no TLS */
};

/*
 * A generator keeps `slots` transfers going: each slot waits a random pause, starts a transfer,
 * runs it until the file is sent, and waits again.
 */
struct ft_sim_generator {
    const char *name;     /* nullptr ends a table */
    uint32_t parent;      /* sends from any live child of this process */
    const uint32_t *pids; /* or from these, one per slot in turn; 0 ends the list */
    enum ft_method
        method;    /* FT_METHOD_NONE: what it sends is no file, only a flavor's size and rate */
    bool outbound; /* this host opens the connections */
    bool keep_socket;
    bool flavor_by_slot;
    uint32_t slots;
    uint32_t pause_min_ms;
    uint32_t pause_max_ms;
    uint32_t spread_ms; /* the first transfers start within this long; 0: the pause */
    enum ft_sim_dest_kind dest_kind;
    const struct ft_sim_dest *dests;
    uint16_t local_port; /* the service port of accepted connections */
    uint32_t chunk;      /* bytes per read or send call */
    bool rotates;        /* each file of a flavor is a different file under the same path */
    bool steady;         /* dips of the rate are shallow, so a fast stream stays fast */
    const struct ft_sim_flavor *flavors;
};

/* Occasionally an idle child of `parent` exits and another process takes its place. */
struct ft_sim_recycle {
    uint32_t parent; /* 0: nothing is replaced */
    uint32_t min_s;
    uint32_t max_s;
    uint32_t first_pid;
};

struct ft_sim_scenario {
    const char *name;
    const struct ft_sim_process *processes;
    struct ft_sim_generator *generators;
    struct ft_sim_recycle recycle;
};

bool ft_sim_scenario_known(const char *name);

/* nullptr for an unknown name; transfers is how many the storm scenario keeps concurrent. */
struct ft_sim_scenario *ft_sim_scenario_create(const char *name, uint32_t transfers);
void ft_sim_scenario_free(struct ft_sim_scenario *sc);

#endif
