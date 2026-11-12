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

struct ft_linux_probes {
    const struct ft_probe_set *set;
    struct bpf_object *obj;
    struct bpf_link *links[FT_LINUX_MAX_PROBES];
    struct ft_probe_status status[FT_LINUX_MAX_PROBES];
    size_t listed_files;   /* files the background and strict lists resolved to */
    bool listed_truncated; /* more than the kernel table holds */
};

/* Returns 0 once an object is loaded, even if single probes failed (see status); else -errno. */
int ft_linux_probes_load(const struct ft_backend_config *cfg, struct ft_linux_probes *out);
void ft_linux_probes_unload(struct ft_linux_probes *p);

const char *ft_linux_last_libbpf_message(void);

bool ft_linux_group_attached(const struct ft_linux_probes *p, enum ft_probe_group group);
bool ft_linux_network_attached(const struct ft_linux_probes *p);

void ft_linux_capabilities(const struct ft_linux_probes *p, const struct ft_backend_config *cfg,
                           struct ft_capabilities *out);

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

/*
 * Loads the patterns that name files wherever they are, "*" "/" name and "*" ".ext", for the
 * kernel to match the first time a thread reads such a file. Returns how many it holds.
 */
size_t ft_linux_background_names(int names_fd, int suffixes_fd,
                                 const struct ft_backend_config *cfg);

/* PHP binaries probed for the script each request runs. */
struct ft_linux_php;

struct ft_linux_php *ft_linux_php_open(struct bpf_object *obj);
void ft_linux_php_close(struct ft_linux_php *php);

/* Probes the PHP binaries that running processes execute or have mapped, once per inode. */
void ft_linux_php_scan(struct ft_linux_php *php);
void ft_linux_php_attach_pid(struct ft_linux_php *php, uint32_t pid);
size_t ft_linux_php_binaries(const struct ft_linux_php *php);

/* Remembers the path the probes reported for a script id; nullptr for an unknown id. */
void ft_linux_php_script_seen(struct ft_linux_php *php, uint32_t id, uint32_t tgid, uint64_t hash,
                              const char *path, size_t len);
const char *ft_linux_php_script(const struct ft_linux_php *php, uint32_t id);

#endif
