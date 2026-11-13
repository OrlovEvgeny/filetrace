#ifndef FILETRACE_BACKEND_LINUX_H
#define FILETRACE_BACKEND_LINUX_H

#include "backends/backend.h"

struct bpf_object;
struct bpf_link;

enum ft_probe_group : uint8_t {
    FT_PG_PROCESS,
    FT_PG_TCP_STATE,
    FT_PG_NET, /* byte accounting; IPv4 and, in the kprobe set, TCP over IPv6 */
    FT_PG_NET_IPV6,
    FT_PG_FILE_READ,
    FT_PG_SENDFILE,
    FT_PG_FILE_END, /* notices when a deleted file's inode number becomes free */
    FT_PG_COUNT,
};

enum ft_probe_state : uint8_t {
    FT_PROBE_ATTACHED,
    FT_PROBE_NOT_NEEDED,    /* the selected mode does not use it */
    FT_PROBE_MISMATCH,      /* the kernel function has a different signature */
    FT_PROBE_NO_ACCOUNTING, /* the kernel does not count the bytes a task reads */
    FT_PROBE_LOAD_FAILED,
    FT_PROBE_ATTACH_FAILED,
};

struct ft_probe_def {
    const char *program;
    const char *target;
    const char *kind; /* "tracepoint", "fexit" or "kprobe" */
    uint8_t nargs;    /* expected parameter count of a traced function */
    enum ft_probe_group group;
    enum ft_mode min_mode;
};

struct ft_probe_set {
    enum ft_probes kind;
    const struct ft_probe_def *defs;
    size_t count;
    const unsigned char *object;
    size_t object_size;
};

#define FT_LINUX_MAX_PROBES 16

struct ft_probe_status {
    enum ft_probe_state state;
    int error; /* errno of a failed load or attach */
};

/* Whether a return probe leaves alive a process whose seccomp filter refuses its system call. */
enum ft_linux_returns : uint8_t {
    FT_RETURNS_NOT_TESTED, /* nothing that uses return probes is wanted */
    FT_RETURNS_NO_SYSCALL, /* this architecture returns from them without a system call */
    FT_RETURNS_SAFE,       /* such a process survived one */
    FT_RETURNS_UNSAFE,     /* such a process was killed */
    FT_RETURNS_UNKNOWN,    /* the test could not tell */
};

struct ft_linux_probes {
    const struct ft_probe_set *set;
    struct bpf_object *obj;
    struct bpf_link *links[FT_LINUX_MAX_PROBES];
    struct ft_probe_status status[FT_LINUX_MAX_PROBES];
    size_t listed_files;    /* files the background and strict lists resolved to */
    bool listed_truncated;  /* more than the kernel table holds */
    struct bpf_link *aging; /* the iterator that judges windows nothing touched lately */
    int aging_error;        /* errno of the kernel's refusal of it */
    bool lookups;           /* the programs that read getaddrinfo's results are loaded */
    int lookups_error;      /* errno of the kernel's refusal of them */
    enum ft_linux_returns returns;
    int returns_error; /* FT_RETURNS_UNKNOWN: what kept the test from telling */
};

/* Whether the loaded object carries the program that tests return probes. */
bool ft_linux_returns_tested(const struct ft_backend_config *cfg);

/* Tests return probes in a process of its own, before any is attached for real. */
void ft_linux_returns_test(struct ft_linux_probes *p, const struct ft_backend_config *cfg);
bool ft_linux_returns_allowed(const struct ft_linux_probes *p, const struct ft_backend_config *cfg);
/* Why the probes that need return probes are not attached. */
const char *ft_linux_returns_refusal(const struct ft_linux_probes *p, char *buf, size_t size);

/* Returns 0 once an object is loaded, even if single probes failed (see status); else -errno. */
int ft_linux_probes_load(const struct ft_backend_config *cfg, struct ft_linux_probes *out);
void ft_linux_probes_unload(struct ft_linux_probes *p);

const char *ft_linux_last_libbpf_message(void);

bool ft_linux_group_attached(const struct ft_linux_probes *p, enum ft_probe_group group);
bool ft_linux_network_attached(const struct ft_linux_probes *p);

/* libraries: the agent's counts of library files probed for names; nullptr when it has none. */
void ft_linux_capabilities(const struct ft_linux_probes *p, const struct ft_backend_config *cfg,
                           const struct ft_backend_stats *libraries, struct ft_capabilities *out);

void ft_linux_diagnose(const struct ft_backend_config *cfg, struct ft_diagnosis *out);

bool ft_linux_lookup_process(uint32_t pid, struct ft_ev_process *out);
bool ft_linux_read_process_text(uint32_t pid, struct ft_process_text *out);
/* Effective capabilities; CAP_SYS_ADMIN stands in for the other two. */
struct ft_linux_caps {
    bool sys_admin;
    bool bpf;
    bool perfmon;
};

void ft_linux_held_capabilities(struct ft_linux_caps *out);
bool ft_linux_privileged(void);
bool ft_linux_kernel_version(unsigned *major, unsigned *minor);
void ft_linux_fs_type(uint64_t magic, char *buf, size_t size);

/*
 * Points the background map at the regular files that [correlation] background_paths and
 * strict_paths name, resolved to their inodes, and drops keys the patterns do not name.
 * Returns how many files it holds; *truncated tells whether the patterns named more than the map
 * takes.
 */
size_t ft_linux_background_load(int map_fd, const struct ft_backend_config *cfg, bool *truncated);

/*
 * Adds a file the kernel reported to the background map when its path matches the patterns:
 * a file the agent cannot see, such as one inside a container, or one made after the last scan.
 */
void ft_linux_background_learn(int map_fd, const struct ft_backend_config *cfg, uint64_t ino,
                               uint32_t dev, const char *path);

/* Returns how many files the background map holds; *refused, how many it had no room for. */
size_t ft_linux_background_count(int map_fd, uint64_t *refused);

/*
 * Loads the patterns that name files wherever they are, "*" "/" name and "*" ".ext", for the
 * kernel to match the first time a thread reads such a file. Returns how many it holds.
 */
size_t ft_linux_background_names(int names_fd, int suffixes_fd,
                                 const struct ft_backend_config *cfg);

/*
 * Files that processes run or have mapped, probed with uprobes once per file, by kind: PHP
 * binaries, C libraries. A file is found through /proc and attached through a descriptor.
 */
struct ft_linux_prober;
struct bpf_program;

#define FT_LINUX_KIND_PROBES 2
/* Descriptors a probed file holds: a perf event and a BPF link for each of its probes. */
#define FT_LINUX_FILE_DESCRIPTORS (2 * FT_LINUX_KIND_PROBES)
#define FT_LINUX_PHP_FILES 64

/* A program attached to a function of each file of a kind. */
struct ft_linux_uprobe {
    struct bpf_program *prog;
    const char *func;
    bool retprobe;
};

struct ft_linux_probe_kind {
    const char *one;  /* a file of the kind, as messages name it: "the PHP binary" */
    const char *many; /* "PHP binaries" */
    size_t capacity;
    struct ft_linux_uprobe probes[FT_LINUX_KIND_PROBES]; /* unused ones have no program */
    bool every_process;                                  /* the maps of every process are read */
    bool (*runs)(const char *program);    /* the program file is of the kind; may be nullptr */
    bool (*maps_of)(const char *program); /* the maps of a process running it are read */
    /* A file mapped at path, whose base name is name, may be of the kind. */
    bool (*mapped)(const char *path, const char *name);
    /* The cookie of the probes, from the ELF file open at fd; 0 when it is not of the kind. */
    uint64_t (*cookie)(int fd);
    /* Reports a file probed, by the name the process pid knows it by. */
    void (*probed)(const char *name, uint32_t pid, uint64_t cookie);
};

struct ft_linux_prober *ft_linux_prober_create(void);
void ft_linux_prober_destroy(struct ft_linux_prober *p);

/* Returns the kind's index, or -1. */
int ft_linux_prober_add(struct ft_linux_prober *p, const struct ft_linux_probe_kind *kind);
size_t ft_linux_prober_count(const struct ft_linux_prober *p, int kind);

/*
 * A process started the program named so, by an exec or a fork at ts_ns: it is looked at by
 * the work after that, once. A process that ended is forgotten.
 */
void ft_linux_prober_started(struct ft_linux_prober *p, uint32_t pid, const char *program,
                             uint64_t ts_ns);
void ft_linux_prober_ended(struct ft_linux_prober *p, uint32_t pid);

/* Starts a pass over every running process not looked at yet, which the work carries on. */
void ft_linux_prober_rescan(struct ft_linux_prober *p);

/* Looks at the processes that started and at those of a pass, for a bounded time. */
void ft_linux_prober_work(struct ft_linux_prober *p, uint64_t now_ns);

/*
 * Reads which of names the 64-bit ELF file open at fd defines among its dynamic symbols, and
 * its machine; false when it has no dynamic symbols to read.
 */
bool ft_linux_elf_exports(int fd, const char *const *names, size_t count, bool *found,
                          uint16_t *machine);

/* C libraries probed for the names processes look up; returns the prober's kind, or -1. */
int ft_linux_lookups_open(struct bpf_object *obj, struct ft_linux_prober *prober, size_t capacity);

/* PHP binaries probed for the script each request runs. */
struct ft_linux_php;

struct ft_linux_php *ft_linux_php_open(struct bpf_object *obj, struct ft_linux_prober *prober);
void ft_linux_php_close(struct ft_linux_php *php);

/* Remembers the path the probes reported for a script id; nullptr for an unknown id. */
void ft_linux_php_script_seen(struct ft_linux_php *php, uint32_t id, uint32_t tgid, uint64_t hash,
                              const char *path, size_t len);
const char *ft_linux_php_script(const struct ft_linux_php *php, uint32_t id);

#endif
