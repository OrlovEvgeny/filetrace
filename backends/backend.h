#ifndef FILETRACE_BACKEND_H
#define FILETRACE_BACKEND_H

#include "filetrace/capabilities.h"
#include "filetrace/event.h"
#include "filetrace/process.h"

/* How kernel functions are instrumented, where a platform offers a choice. */
enum ft_probes : uint8_t {
    FT_PROBES_AUTO = 0,
    FT_PROBES_TRAMPOLINE,
    FT_PROBES_KPROBE,
};

const char *ft_probes_name(enum ft_probes p);
bool ft_probes_parse(const char *text, enum ft_probes *p);

struct ft_backend_config {
    enum ft_mode mode;
    enum ft_probes probes;
    bool track_read;     /* follow reads of regular files, for read-write attribution */
    bool track_sendfile; /* follow sendfile, for exact attribution */
    uint32_t queue_bytes;
    uint32_t agg_entries;    /* distinct counters accumulated between flushes */
    uint32_t known_files;    /* file identities remembered as already described */
    uint32_t drain_batch;    /* counters read from the kernel per call */
    uint64_t corr_window_ns; /* longest read-to-send gap that still correlates */
    bool php_scripts;        /* probe PHP binaries for the script of each request */
    bool lookup_names;       /* probe C libraries for the names processes look up */
    bool tls_names;          /* probe TLS libraries for the server names clients ask for */
    uint32_t name_libraries; /* library files probed for either, at most */
    /* Attach return probes where the test of them at start found them unsafe. */
    bool force_return_probes;
    /* Borrowed patterns: files that are never taken as sent from a read and a send. */
    const char *const *background_paths;
    size_t background_path_count;
    /* Borrowed patterns: files taken as sent only when a send matches their own size. */
    const char *const *strict_paths;
    size_t strict_path_count;
};

void ft_backend_config_defaults(struct ft_backend_config *cfg);

enum ft_check_level : uint8_t {
    FT_CHECK_OK,
    FT_CHECK_WARN,
    FT_CHECK_FAIL,
};

struct ft_check {
    enum ft_check_level level;
    bool optional;
    bool probe; /* an instrumentation point that was loaded and attached for the check */
    char text[96];
    char detail[240];
};

#define FT_MAX_CHECKS 40

struct ft_diagnosis {
    char backend[48];
    struct ft_check checks[FT_MAX_CHECKS];
    size_t count;
    struct ft_capabilities caps;
    int exit_code; /* enum ft_exit */
    char result[128];
    char advice[400];
};

[[gnu::format(printf, 5, 6)]]
void ft_diagnosis_add(struct ft_diagnosis *d, enum ft_check_level level, bool optional,
                      const char *text, const char *detail_fmt, ...);

[[gnu::format(printf, 5, 6)]]
void ft_diagnosis_add_probe(struct ft_diagnosis *d, enum ft_check_level level, bool optional,
                            const char *text, const char *detail_fmt, ...);

struct ft_backend_stats {
    uint64_t events; /* records received from the kernel */
    uint64_t queue_bytes;
    uint64_t queue_peak_bytes;
    uint64_t listed_files;              /* the kernel's table of listed files: entries */
    uint64_t listed_capacity;           /* 0 when the backend keeps no such table */
    uint64_t listed_refused;            /* files it had no room for */
    uint64_t name_libraries;            /* library files probed for names */
    uint64_t name_library_capacity;     /* 0 when the backend probes none */
    uint64_t name_libraries_configured; /* more than the capacity when open files cut it */
    uint64_t name_libraries_forgotten;  /* probed files that made room for newer ones */
    uint64_t tls_libraries;             /* TLS library files probed for server names */
    uint64_t tls_library_capacity;      /* TLS library files that may be probed */
    /* probe runs the kernel declined to nest on a busy CPU (recursion_misses) */
    uint64_t probe_skips;
    uint64_t probe_skips_sent;
    uint64_t probe_skips_received;
    uint64_t probe_skips_read;
};

struct ft_backend;

struct ft_backend_ops {
    const char *name;

    /* Checks what this machine supports without leaving anything attached. */
    void (*diagnose)(const struct ft_backend_config *cfg, struct ft_diagnosis *out);

    struct ft_backend *(*open)(const struct ft_backend_config *cfg, const struct ft_sink *sink,
                               struct ft_error *err);

    /* Descriptor that becomes readable when events are queued, or -1. */
    int (*poll_fd)(struct ft_backend *b);

    void (*flush)(struct ft_backend *b);

    /* Optional: the backend's name including what it settled on at run time. */
    void (*describe)(struct ft_backend *b, char *buf, size_t size);

    void (*stats)(struct ft_backend *b, struct ft_backend_stats *out);
    void (*capabilities)(struct ft_backend *b, struct ft_capabilities *out);

    bool (*lookup_process)(uint32_t pid, struct ft_ev_process *out);

    /* Optional: a process's arguments and working directory. */
    bool (*read_process_text)(uint32_t pid, struct ft_process_text *out);

    void (*close)(struct ft_backend *b);
};

const struct ft_backend_ops *ft_backend_native(void);

#endif
