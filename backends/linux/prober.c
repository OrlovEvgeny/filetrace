#include "backends/linux/linux.h"

#include "filetrace/clock.h"
#include "filetrace/sysinfo.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "backends/linux/bpf/abi.h"

#define MAX_KINDS 4
#define MAX_SKIPPED 256
#define MAX_WARNED 64
#define MAX_SYMBOL_BYTES (2u << 20) /* libphp's take a tenth of it, the C libraries' less */
#define PENDING_MAX 4096
#define PID_LIMIT_MAX (4u << 20) /* the kernel's PID_MAX_LIMIT on 64-bit */
/*
 * The work reads /proc for at most this share of wall time, in slices of at most the budget,
 * however often processes that start wake it.
 */
#define WORK_PERCENT 10
#define WORK_BUDGET_NS (20 * FT_NS_PER_MS)
#define WORK_SLICE_MIN_NS (1 * FT_NS_PER_MS)
/* A loader maps the libraries in about this long; a process still loading is looked at again. */
#define SETTLE_NS (2 * FT_NS_PER_MS)
/* Slices of a pass are this far apart at least, however often looks wake the work. */
#define PASS_GAP_NS (90 * FT_NS_PER_MS)
#define RECHECK_MAX 1024
#define RECHECK_STEP_NS (1 * FT_NS_PER_MS)
/* A process is looked at again at four times its age from this one, for what it loads later. */
#define LATE_FIRST_NS (16 * FT_NS_PER_MS)
#define LATE_MAX_NS (512 * FT_NS_PER_MS)
/* A loader still mapping libraries this long after the exec is left to itself. */
#define LOADING_MAX_NS (1 * FT_NS_PER_SEC)
/* Reports of the same process looked at in one reading of its maps. */
#define TARGETS_MAX 16
/*
 * A report comes as the kernel begins a mapping, which a look can read before it is done: one that
 * does not see the file looks again, at doubling waits from this one, so many times.
 */
#define REPORT_STEP_NS (1 * FT_NS_PER_MS)
#define REPORT_TRIES 5
#define NOTED_MAX 256
#define NOTED_NS (60 * FT_NS_PER_SEC)
static_assert(NOTED_MAX <= FT_BPF_QUIET_MAX);
/* A quiet program has a prompt look again after this long, whatever its processes did meanwhile. */
#define QUIET_NS (10 * FT_NS_PER_SEC)
#define DELETED " (deleted)"
#define CANDIDATES_MAX 4 /* distinct files of the kinds a process is looked at for */
/* A full kind gives a file's place to a new one when no look has found it for this long. */
#define IDLE_NS (60 * FT_NS_PER_SEC)

/*
 * A file as probes see it. Uprobes attach to the file underneath overlayfs, which every
 * container of an image shares, while each container's overlay gives it a device of its own;
 * the inode number, size and time are the real file's. Elsewhere the device tells apart files
 * that agree in all of those, as snapshots and clones do.
 */
struct identity {
    uint64_t dev; /* 0 on overlayfs */
    uint64_t ino;
    uint64_t size;
    int64_t mtime_sec;
    int64_t mtime_nsec;
};

/* A file as a maps line names it, before it is opened. */
struct mapped_file {
    unsigned major;
    unsigned minor;
    unsigned long long ino;
};

struct probed {
    struct identity id;
    struct mapped_file mapped;       /* zero when it was found as a program rather than mapped */
    struct ft_linux_mapped reported; /* the report that named it, zero when none did */
    struct bpf_link *links[FT_LINUX_KIND_PROBES];
    uint64_t found_ns; /* when a look last found it mapped, or a call through it last ran */
};

struct kind {
    struct ft_linux_probe_kind def;
    struct probed *files;
    size_t count;
    size_t forgotten;    /* files that gave their place to newer ones */
    uint64_t probing_ns; /* time spent reading the files the kind probed and attaching to them */
    int reported_fd;     /* the probes' map of the files reported mapped, or -1 */
    uint64_t idle_ns;
    bool full_logged;
    struct identity skipped[MAX_SKIPPED]; /* not of the kind, or refused the probe */
    size_t skipped_count;
    struct identity warned[MAX_WARNED]; /* attaching to it failed, which was logged */
    size_t warned_count;
};

/* A process that started, to be looked at once its program has had a moment to load. */
struct pending {
    uint32_t pid;
    uint64_t ts_ns;
    struct ft_linux_program file; /* zero after a fork */
};

/*
 * A program noted for a while: missed, when its process ended before a look reached it, and its
 * next process is looked at early; or quiet, when a look found it maps only files probed or
 * skipped already, and each of its processes gets one look, with no wake of its own.
 */
struct noted {
    struct ft_linux_program file;
    uint64_t ns;
};

/*
 * A process looked at again: its loader was still mapping libraries, it may load more as it runs,
 * or a process of its program ended before a look reached it.
 */
struct recheck {
    uint32_t pid;
    struct ft_linux_program file;
    uint64_t ts_ns;
    uint64_t due_ns;
    bool dense;   /* its program was missed: looked at as it starts and at every doubling of age */
    bool reached; /* a look found it running */
    bool late;    /* it maps a file of a kind already: the look is for what it loads later */
};

/* A process that mapped an executable file no process was reported mapping before. */
struct report {
    uint32_t pid; /* 0 once a look at another report of its process took it */
    uint32_t tries;
    struct ft_linux_mapped file;
    uint64_t due_ns;
};

/* A reported file, as the look at the process that reported it finds it. */
struct target {
    struct ft_linux_mapped file;
    uint32_t tries;
    bool seen;            /* a maps line names it */
    bool open;            /* it is of a kind, and was neither probed nor skipped */
    struct probed *probe; /* its probes, when it is of a kind */
};

enum considered {
    CONSIDERED_KNOWN, /* probed or skipped before */
    CONSIDERED_NEW,   /* probed or skipped now */
    CONSIDERED_OPEN,  /* not probed: no room, or a passing error */
};

enum look {
    LOOK_GONE,    /* the process has ended */
    LOOK_NONE,    /* it maps no file of a kind */
    LOOK_LOADING, /* its loader has not mapped a C library yet */
    LOOK_FOUND,   /* it runs or maps a file of a kind */
    LOOK_CUT,     /* the time ran out before its maps were read */
};

struct ft_linux_prober {
    struct kind kinds[MAX_KINDS];
    size_t kind_count;
    uint8_t *seen; /* a bit per process ID looked at since its program started */
    uint32_t pid_limit;
    struct pending queue[PENDING_MAX];
    size_t head;
    size_t queued;
    struct report reports[PENDING_MAX];
    size_t report_head;
    size_t report_count;
    int reported_fd; /* the probes' map of the files reported mapped; -1 while starts are looked at
                      */
    struct target *targets; /* the reported files the running look looks for */
    size_t target_count;
    struct pending quiet_queue[PENDING_MAX]; /* processes of quiet programs */
    size_t quiet_head;
    size_t quiet_queued;
    DIR *pass;          /* a pass over /proc for the processes no event announced, while it runs */
    bool again;         /* a pass starts as soon as the one running, if any, is over */
    uint64_t pass_ns;   /* when a slice of the pass last ran */
    uint64_t credit_ns; /* time the work may spend now */
    uint64_t credit_at; /* when it was last brought up to date */
    struct recheck rechecks[RECHECK_MAX];
    size_t recheck_count;
    struct noted missed[NOTED_MAX];
    size_t missed_count;
    struct noted quiet[NOTED_MAX];
    size_t quiet_count;
    size_t forgotten; /* files the kinds gave up, when the quiet programs were last checked */
    int quiet_fd;     /* the probes' map of the quiet programs, whose execs do not wake the agent */
    bool fresh;       /* the look running found a file not probed or skipped before */
};

static bool read_at(int fd, void *buf, size_t size, uint64_t off)
{
    return pread(fd, buf, size, (off_t)off) == (ssize_t)size;
}

bool ft_linux_elf_exports(int fd, const char *const *names, size_t count, bool *found,
                          uint16_t *machine)
{
    Elf64_Ehdr eh;
    Elf64_Shdr *sections = nullptr;
    char *strings = nullptr;
    Elf64_Sym *syms = nullptr;
    bool read = false;

    memset(found, 0, count * sizeof(*found));
    if (!read_at(fd, &eh, sizeof(eh), 0) || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_shentsize != sizeof(Elf64_Shdr) ||
        eh.e_shnum == 0 || eh.e_shnum > 4096)
        goto done;
    if (machine)
        *machine = eh.e_machine;
    sections = calloc(eh.e_shnum, sizeof(*sections));
    if (!sections || !read_at(fd, sections, eh.e_shnum * sizeof(*sections), eh.e_shoff))
        goto done;

    for (size_t i = 0; i < eh.e_shnum; i++) {
        const Elf64_Shdr *dynsym = &sections[i];
        if (dynsym->sh_type != SHT_DYNSYM || dynsym->sh_link >= eh.e_shnum ||
            dynsym->sh_entsize != sizeof(Elf64_Sym))
            continue;
        const Elf64_Shdr *dynstr = &sections[dynsym->sh_link];
        if (dynsym->sh_size > MAX_SYMBOL_BYTES || dynstr->sh_size > MAX_SYMBOL_BYTES ||
            !dynstr->sh_size)
            break;
        syms = malloc(dynsym->sh_size);
        strings = malloc(dynstr->sh_size + 1);
        if (!syms || !strings || !read_at(fd, syms, dynsym->sh_size, dynsym->sh_offset) ||
            !read_at(fd, strings, dynstr->sh_size, dynstr->sh_offset))
            break;
        strings[dynstr->sh_size] = '\0';

        for (size_t j = 0; j < dynsym->sh_size / sizeof(Elf64_Sym); j++) {
            if (syms[j].st_name >= dynstr->sh_size || syms[j].st_shndx == SHN_UNDEF)
                continue;
            for (size_t k = 0; k < count; k++) {
                if (strcmp(strings + syms[j].st_name, names[k]) == 0)
                    found[k] = true;
            }
        }
        read = true;
        break;
    }

done:
    free(syms);
    free(strings);
    free(sections);
    return read;
}

int ft_linux_prober_add(struct ft_linux_prober *p, const struct ft_linux_probe_kind *def)
{
    if (!p || p->kind_count == MAX_KINDS || !def->capacity)
        return -1;
    struct kind *k = &p->kinds[p->kind_count];
    /* Hidden: the suite shortens the minute a full kind waits to give a file's place away. */
    const char *idle_ms = getenv("FILETRACE_TEST_LIBRARY_IDLE_MS");
    *k = (struct kind){
        .def = *def,
        .idle_ns = idle_ms ? strtoull(idle_ms, nullptr, 10) * FT_NS_PER_MS : IDLE_NS,
        .reported_fd = p->reported_fd,
    };
    k->files = calloc(def->capacity, sizeof(*k->files));
    if (!k->files)
        return -1;
    return (int)p->kind_count++;
}

size_t ft_linux_prober_count(const struct ft_linux_prober *p, int kind)
{
    return p && kind >= 0 && (size_t)kind < p->kind_count ? p->kinds[kind].count : 0;
}

size_t ft_linux_prober_forgotten(const struct ft_linux_prober *p, int kind)
{
    return p && kind >= 0 && (size_t)kind < p->kind_count ? p->kinds[kind].forgotten : 0;
}

void ft_linux_prober_used(struct ft_linux_prober *p, int kind, uint64_t cookie, uint64_t ts_ns)
{
    if (!p || kind < 0 || (size_t)kind >= p->kind_count)
        return;
    struct kind *k = &p->kinds[kind];
    if (k->def.place_cookie && cookie >= 1 && cookie <= k->count &&
        k->files[cookie - 1].found_ns < ts_ns)
        k->files[cookie - 1].found_ns = ts_ns;
}

static bool same(const struct identity *a, const struct identity *b)
{
    return a->dev == b->dev && a->ino == b->ino && a->size == b->size &&
           a->mtime_sec == b->mtime_sec && a->mtime_nsec == b->mtime_nsec;
}

static struct probed *probed_file(struct kind *k, const struct identity *id)
{
    for (size_t i = 0; i < k->count; i++) {
        if (same(&k->files[i].id, id))
            return &k->files[i];
    }
    return nullptr;
}

/* A file probed already, as a maps line names it: found again without opening it. */
static struct probed *refresh(struct kind *k, const struct mapped_file *mf)
{
    for (size_t i = 0; i < k->count; i++) {
        const struct mapped_file *m = &k->files[i].mapped;
        if (m->ino && m->ino == mf->ino && m->major == mf->major && m->minor == mf->minor) {
            k->files[i].found_ns = ft_clock_mono_ns();
            return &k->files[i];
        }
    }
    return nullptr;
}

/* A file the probes' map must report again when a process maps it next. */
static void unreport(int fd, const struct ft_linux_mapped *file)
{
    if (fd < 0 || !file->ino)
        return;
    struct ft_bpf_file_key key = {.ino = file->ino, .dev = file->dev, .gen = file->gen};
    bpf_map_delete_elem(fd, &key);
}

static bool skipped(const struct kind *k, const struct identity *id)
{
    for (size_t i = 0; i < k->skipped_count; i++) {
        if (same(&k->skipped[i], id))
            return true;
    }
    return false;
}

/* Where a new file goes: a free place, else that of the file least lately found. */
static struct probed *place(struct kind *k)
{
    if (k->count < k->def.capacity)
        return &k->files[k->count];
    struct probed *oldest = &k->files[0];
    for (size_t i = 1; i < k->count; i++) {
        if (k->files[i].found_ns < oldest->found_ns)
            oldest = &k->files[i];
    }
    return oldest;
}

static void skip(struct kind *k, const struct identity *id)
{
    size_t slot =
        k->skipped_count < MAX_SKIPPED ? k->skipped_count++ : (size_t)(id->ino % MAX_SKIPPED);
    k->skipped[slot] = *id;
}

/* Whether a failure to attach to the file is the first one to log. */
static bool first_warning(struct kind *k, const struct identity *id)
{
    for (size_t i = 0; i < k->warned_count; i++) {
        if (same(&k->warned[i], id))
            return false;
    }
    size_t slot = k->warned_count < MAX_WARNED ? k->warned_count++ : (size_t)(id->ino % MAX_WARNED);
    k->warned[slot] = *id;
    return true;
}

/* A shortage of descriptors or memory passes; the file is tried again at its next look. */
static bool transient(int error)
{
    return error == EMFILE || error == ENFILE || error == ENOMEM || error == EAGAIN;
}

static struct bpf_link *attach(const struct ft_linux_uprobe *probe, const char *path,
                               uint64_t cookie, int *error)
{
    /* libbpf refuses options whose padding is not zero, which an initializer leaves open. */
    struct bpf_uprobe_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.func_name = probe->func;
    opts.retprobe = probe->retprobe;
    opts.bpf_cookie = cookie;
    struct bpf_link *link = bpf_program__attach_uprobe_opts(probe->prog, -1, path, 0, &opts);
    *error = -(int)libbpf_get_error(link);
    return *error ? nullptr : link;
}

static void detach(struct probed *f)
{
    for (size_t i = FT_LINUX_KIND_PROBES; i-- > 0;) {
        bpf_link__destroy(f->links[i]);
        f->links[i] = nullptr;
    }
}

/* A path as a log line can carry it: bytes other than printable ASCII as \xNN. */
static void printable(const char *path, char *out, size_t size)
{
    size_t n = 0;
    for (const unsigned char *c = (const unsigned char *)path; *c && n + 5 < size; c++) {
        if (*c >= 0x20 && *c < 0x7f && *c != '\\')
            out[n++] = (char)*c;
        else
            n += (size_t)snprintf(out + n, size - n, "\\x%02x", *c);
    }
    out[n] = '\0';
}

/*
 * Probes the file that path leads to for one kind, once per file; mapped_as is how the process
 * knows it; *probe is set to its probes. path is a /proc link to the file the process runs or has
 * mapped, never a name it could replace, and the open does not wait on anything that is not a
 * regular file.
 */
static enum considered consider(struct kind *k, const char *path, const char *mapped_as,
                                const struct mapped_file *mf, uint32_t pid, struct probed **probe)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0)
        return CONSIDERED_OPEN;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return CONSIDERED_KNOWN;
    }
    struct statfs fs;
    bool overlay = fstatfs(fd, &fs) == 0 && fs.f_type == OVERLAYFS_SUPER_MAGIC;
    struct identity id = {
        .dev = overlay ? 0 : (uint64_t)st.st_dev,
        .ino = (uint64_t)st.st_ino,
        .size = (uint64_t)st.st_size,
        .mtime_sec = (int64_t)st.st_mtim.tv_sec,
        .mtime_nsec = (int64_t)st.st_mtim.tv_nsec,
    };
    uint64_t now = ft_clock_mono_ns();
    struct probed *found = probed_file(k, &id);
    if (found) {
        found->found_ns = now;
        *probe = found;
    }
    if (found || skipped(k, &id)) {
        close(fd);
        return CONSIDERED_KNOWN;
    }
    char name[512];
    printable(mapped_as, name, sizeof(name));
    struct probed *slot = place(k);
    bool full = k->count == k->def.capacity;
    if (full && now - slot->found_ns < k->idle_ns) {
        if (!k->full_logged)
            ft_log(FT_LOG_WARN,
                   "already probing %zu %s, each in use; %s and others are probed once one "
                   "has gone unused for a minute",
                   k->def.capacity, k->def.many, name);
        k->full_logged = true;
        close(fd);
        return CONSIDERED_OPEN;
    }

    const char *missing = nullptr;
    uint64_t cookie = k->def.cookie(fd, &missing);
    if (!cookie) {
        if (missing)
            ft_log(FT_LOG_INFO, "not probing %s: it does not export %s", name, missing);
        skip(k, &id);
        close(fd);
        return CONSIDERED_NEW;
    }

    /* Held open, the file stays reachable after the process that named it exits. */
    char held[32];
    snprintf(held, sizeof(held), "/proc/self/fd/%d", fd);
    struct probed fresh = {.id = id, .mapped = mf ? *mf : (struct mapped_file){0}, .found_ns = now};
    int error = 0;
    uint64_t attached = k->def.place_cookie ? (uint64_t)(slot - k->files) + 1 : cookie;
    for (size_t i = 0; i < FT_LINUX_KIND_PROBES && k->def.probes[i].prog && !error; i++)
        fresh.links[i] = attach(&k->def.probes[i], held, attached, &error);
    close(fd);
    if (error) {
        if (first_warning(k, &id))
            ft_log(FT_LOG_WARN, "cannot probe %s %s: %s", k->def.one, name,
                   ft_linux_last_libbpf_message());
        detach(&fresh);
        if (transient(error))
            return CONSIDERED_OPEN;
        skip(k, &id);
        return CONSIDERED_NEW;
    }
    k->probing_ns += ft_clock_mono_ns() - now;
    if (full) {
        ft_log(FT_LOG_INFO, "already probing %zu %s; the one unused longest makes room for %s",
               k->def.capacity, k->def.many, name);
        detach(slot);
        unreport(k->reported_fd, &slot->reported);
        k->forgotten++;
    } else {
        k->count++;
    }
    *slot = fresh;
    *probe = slot;
    k->def.probed(name, pid, cookie);
    return CONSIDERED_NEW;
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* The files of the kinds that look through this process's maps; a real process maps one of each. */
static enum look consider_mapped(struct ft_linux_prober *p, const bool *wanted, uint32_t pid,
                                 uint64_t until)
{
    char path[64];
    char line[PATH_MAX + 128];
    struct mapped_file candidates[CANDIDATES_MAX];
    size_t count = 0;
    size_t lines = 0;
    enum look result = LOOK_NONE;
    bool loader = false;
    bool every = false;
    bool every_found = false;

    for (size_t i = 0; i < p->kind_count; i++)
        every = every || p->kinds[i].def.every_program;
    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/maps", pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return LOOK_GONE;
    while (fgets(line, sizeof(line), f)) {
        if (++lines % 64 == 0 && ft_clock_mono_ns() >= until) {
            result = LOOK_CUT;
            break;
        }
        char range[64];
        char perms[8];
        struct mapped_file mf;
        int file_at = 0;
        if (sscanf(line, "%63s %7s %*s %x:%x %llu %n", range, perms, &mf.major, &mf.minor, &mf.ino,
                   &file_at) != 5 ||
            !file_at || !strchr(perms, 'x'))
            continue;
        struct target *t = nullptr;
        for (size_t i = 0; i < p->target_count && !t; i++) {
            if (p->targets[i].file.ino == mf.ino)
                t = &p->targets[i];
        }
        if (t)
            t->seen = true;
        char *file = line + file_at;
        file[strcspn(file, "\n")] = '\0';
        /* A library replaced by an upgrade stays mapped from its deleted file. */
        size_t len = strlen(file);
        if (len > strlen(DELETED) && strcmp(file + len - strlen(DELETED), DELETED) == 0)
            file[len - strlen(DELETED)] = '\0';
        if (file[0] != '/')
            continue;
        const char *name = base_name(file);
        /* The kernel maps a program's loader with it, and the loader maps the libraries. */
        loader = loader || strncmp(name, "ld-", 3) == 0 || strncmp(name, "ld.so", 5) == 0;
        bool matched = false;
        for (size_t i = 0; i < p->kind_count; i++) {
            const struct ft_linux_probe_kind *def = &p->kinds[i].def;
            bool kind = def->mapped(file, name);
            matched = matched || (wanted[i] && kind);
            every_found = every_found || (def->every_program && kind);
        }
        size_t at = 0;
        while (at < count && (candidates[at].ino != mf.ino || candidates[at].major != mf.major ||
                              candidates[at].minor != mf.minor))
            at++;
        if (!matched || at < count)
            continue;
        if (count == CANDIDATES_MAX)
            break;
        candidates[count++] = mf;
        /* The mapped file itself: a mount over its directory cannot put anything else there. */
        char mapped[128];
        snprintf(mapped, sizeof(mapped), "/proc/%" PRIu32 "/map_files/%s", pid, range);
        for (size_t i = 0; i < p->kind_count; i++) {
            if (!wanted[i] || !p->kinds[i].def.mapped(file, name))
                continue;
            struct probed *probe = refresh(&p->kinds[i], &mf);
            enum considered c = CONSIDERED_KNOWN;
            if (!probe)
                c = consider(&p->kinds[i], mapped, file, &mf, pid, &probe);
            p->fresh = p->fresh || c != CONSIDERED_KNOWN;
            if (t && c == CONSIDERED_OPEN)
                t->open = true;
            if (t && probe && !t->probe)
                t->probe = probe;
        }
    }
    fclose(f);
    if (result != LOOK_NONE)
        return result;
    if (loader && (every ? !every_found : !count))
        return LOOK_LOADING;
    return count ? LOOK_FOUND : LOOK_NONE;
}

/* A forked child maps what its parent maps, which the kinds of every process have looked at. */
static bool wants(const struct ft_linux_prober *p, const char *program, bool forked)
{
    for (size_t i = 0; i < p->kind_count; i++) {
        const struct ft_linux_probe_kind *def = &p->kinds[i].def;
        if ((def->every_process && !forked) || (def->runs && def->runs(program)) ||
            (def->maps_of && def->maps_of(program)))
            return true;
    }
    return false;
}

static bool seen(const struct ft_linux_prober *p, uint32_t pid)
{
    return pid < p->pid_limit && (p->seen[pid / 8] & (1u << (pid % 8)));
}

static void mark(struct ft_linux_prober *p, uint32_t pid, bool on)
{
    if (pid >= p->pid_limit)
        return;
    if (on)
        p->seen[pid / 8] |= (uint8_t)(1u << (pid % 8));
    else
        p->seen[pid / 8] &= (uint8_t)~(1u << (pid % 8));
}

/*
 * Probes the files of the kinds that the process runs or has mapped. A process the time ran out
 * on is not taken as looked at.
 */
static enum look look_at(struct ft_linux_prober *p, uint32_t pid, uint64_t until)
{
    char path[64];
    char exe[PATH_MAX];

    mark(p, pid, true);
    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/exe", pid);
    ssize_t n = readlink(path, exe, sizeof(exe) - 1);
    if (n <= 0)
        return LOOK_GONE;
    exe[n] = '\0';
    const char *name = base_name(exe);

    bool wanted[MAX_KINDS] = {false};
    bool maps = false;
    enum look result = LOOK_NONE;
    for (size_t i = 0; i < p->kind_count; i++) {
        const struct ft_linux_probe_kind *def = &p->kinds[i].def;
        if (def->runs && def->runs(name)) {
            struct probed *probe = nullptr;
            if (consider(&p->kinds[i], path, exe, nullptr, pid, &probe) != CONSIDERED_KNOWN)
                p->fresh = true;
            result = LOOK_FOUND;
        } else if (def->every_process || (def->maps_of && def->maps_of(name))) {
            maps = wanted[i] = true;
        }
    }
    enum look mapped = maps ? consider_mapped(p, wanted, pid, until) : LOOK_NONE;
    if (mapped == LOOK_CUT)
        mark(p, pid, false);
    return mapped == LOOK_NONE ? result : mapped;
}

static bool same_program(const struct ft_linux_program *a, const struct ft_linux_program *b,
                         bool mntns)
{
    return a->ino == b->ino && a->size == b->size && (!mntns || a->mntns == b->mntns);
}

static struct noted *noted(struct noted *set, size_t count, const struct ft_linux_program *file,
                           bool mntns)
{
    for (size_t i = 0; i < count; i++) {
        if (same_program(&set[i].file, file, mntns))
            return &set[i];
    }
    return nullptr;
}

/* Notes a program in a set, or with put false takes it out; returns the one that left, if any. */
static struct ft_linux_program note(struct noted *set, size_t *count,
                                    const struct ft_linux_program *file, bool mntns, bool put,
                                    uint64_t now)
{
    struct ft_linux_program left = {0};
    if (!file->ino)
        return left;
    struct noted *m = noted(set, *count, file, mntns);
    if (!put) {
        if (m) {
            left = m->file;
            *m = set[--*count];
        }
        return left;
    }
    if (!m && *count < NOTED_MAX)
        m = &set[(*count)++];
    if (!m) {
        m = &set[0];
        for (size_t i = 1; i < NOTED_MAX; i++) {
            if (set[i].ns < m->ns)
                m = &set[i];
        }
        left = m->file;
    }
    *m = (struct noted){.file = *file, .ns = now};
    return left;
}

static void quiet_map(struct ft_linux_prober *p, const struct ft_linux_program *file, bool on)
{
    if (p->quiet_fd < 0 || !file->ino)
        return;
    struct ft_bpf_program_key key = {.ino = file->ino, .size = file->size, .mntns = file->mntns};
    uint8_t one = 1;
    if (on)
        bpf_map_update_elem(p->quiet_fd, &key, &one, BPF_ANY);
    else
        bpf_map_delete_elem(p->quiet_fd, &key);
}

/*
 * Makes a program quiet for a while from now, or with put false takes it out. A program quiet
 * already stays so until its time is up: a change under it is seen once a while.
 */
static void note_quiet(struct ft_linux_prober *p, const struct ft_linux_program *file, bool put,
                       uint64_t now)
{
    if (put && noted(p->quiet, p->quiet_count, file, true))
        return;
    struct ft_linux_program left = note(p->quiet, &p->quiet_count, file, true, put, now);
    quiet_map(p, &left, false);
    if (put)
        quiet_map(p, file, true);
}

/* A program missed is looked at early next time, and quiet no longer. */
static void note_missed(struct ft_linux_prober *p, const struct ft_linux_program *file, bool put,
                        uint64_t now)
{
    note(p->missed, &p->missed_count, file, false, put, now);
    if (put)
        note_quiet(p, file, false, now);
}

/* Process IDs past this are looked at on every pass. */
static uint32_t pid_limit(void)
{
    unsigned long max = 0;
    FILE *f = fopen("/proc/sys/kernel/pid_max", "re");
    if (f) {
        if (fscanf(f, "%lu", &max) != 1)
            max = 0;
        fclose(f);
    }
    return max && max <= PID_LIMIT_MAX ? (uint32_t)max : PID_LIMIT_MAX;
}

struct ft_linux_prober *ft_linux_prober_create(void)
{
    struct ft_linux_prober *p = calloc(1, sizeof(*p));
    if (!p)
        return nullptr;
    p->pid_limit = pid_limit();
    p->credit_ns = WORK_BUDGET_NS;
    p->credit_at = ft_clock_mono_ns();
    p->quiet_fd = -1;
    p->reported_fd = -1;
    p->seen = calloc(p->pid_limit / 8 + 1, 1);
    if (!p->seen) {
        free(p);
        return nullptr;
    }
    return p;
}

void ft_linux_prober_started(struct ft_linux_prober *p, uint32_t pid, const char *program,
                             const struct ft_linux_program *file, uint64_t ts_ns)
{
    if (!p)
        return;
    mark(p, pid, false);
    /* A process is looked at when it maps a file the agent was not told about. */
    if (p->reported_fd >= 0 || !wants(p, program, !file))
        return;
    size_t forgotten = 0;
    for (size_t i = 0; i < p->kind_count; i++)
        forgotten += p->kinds[i].forgotten;
    /* A file given up may be one a quiet program maps. */
    if (forgotten != p->forgotten) {
        p->forgotten = forgotten;
        while (p->quiet_count)
            note_quiet(p, &p->quiet[0].file, false, ts_ns);
    }
    const struct noted *q = file ? noted(p->quiet, p->quiet_count, file, true) : nullptr;
    if (q && ts_ns < q->ns + QUIET_NS) {
        if (p->quiet_queued < PENDING_MAX)
            p->quiet_queue[(p->quiet_head + p->quiet_queued++) % PENDING_MAX] =
                (struct pending){.pid = pid, .ts_ns = ts_ns, .file = *file};
        return;
    }
    const struct noted *m = file ? noted(p->missed, p->missed_count, file, false) : nullptr;
    if (m && ts_ns < m->ns + NOTED_NS && p->recheck_count < RECHECK_MAX) {
        p->rechecks[p->recheck_count++] = (struct recheck){
            .pid = pid, .file = *file, .ts_ns = ts_ns, .due_ns = ts_ns, .dense = true};
        return;
    }
    /* A process that finds no room is left for the next pass. */
    if (p->queued == PENDING_MAX)
        return;
    p->queue[(p->head + p->queued++) % PENDING_MAX] = (struct pending){
        .pid = pid,
        .ts_ns = ts_ns,
        .file = file ? *file : (struct ft_linux_program){0},
    };
}

void ft_linux_prober_ended(struct ft_linux_prober *p, uint32_t pid)
{
    if (p)
        mark(p, pid, false);
}

bool ft_linux_prober_forget(struct ft_linux_prober *p)
{
    if (!p)
        return false;
    memset(p->seen, 0, p->pid_limit / 8 + 1);
    bool started = !p->again;
    p->again = true;
    return started;
}

static void start_pass(struct ft_linux_prober *p)
{
    if (!p->kind_count || p->pass)
        return;
    /* Outside the host's PID namespace no event names a process by its /proc entry. */
    if (!ft_sysinfo_host_pid_namespace())
        memset(p->seen, 0, p->pid_limit / 8 + 1);
    p->pass = opendir("/proc");
    p->again = false;
}

void ft_linux_prober_rescan(struct ft_linux_prober *p)
{
    /* Once processes report the files they map, only lost reports need a pass. */
    if (p && p->reported_fd < 0)
        start_pass(p);
}

void ft_linux_prober_report(struct ft_linux_prober *p, int map_fd)
{
    if (!p || map_fd < 0)
        return;
    p->reported_fd = map_fd;
    for (size_t i = 0; i < p->kind_count; i++)
        p->kinds[i].reported_fd = map_fd;
}

static void queue_report(struct ft_linux_prober *p, uint32_t pid,
                         const struct ft_linux_mapped *file, uint32_t tries, uint64_t due_ns)
{
    if (p->report_count == PENDING_MAX) {
        unreport(p->reported_fd, file);
        return;
    }
    p->reports[(p->report_head + p->report_count++) % PENDING_MAX] =
        (struct report){.pid = pid, .tries = tries, .file = *file, .due_ns = due_ns};
}

void ft_linux_prober_mapped(struct ft_linux_prober *p, uint32_t pid,
                            const struct ft_linux_mapped *file)
{
    if (p && pid)
        queue_report(p, pid, file, 0, 0);
}

/*
 * Takes the next entry of the pass, looking at its process unless seen; one the time ran out on
 * is left to the next pass. False once the pass is over.
 */
static bool pass_step(struct ft_linux_prober *p, uint64_t until)
{
    struct dirent *e = readdir(p->pass);
    if (!e) {
        closedir(p->pass);
        p->pass = nullptr;
        return false;
    }
    char *end;
    unsigned long pid = strtoul(e->d_name, &end, 10);
    if (isdigit((unsigned char)e->d_name[0]) && *end == '\0' && pid > 0 && pid <= UINT32_MAX &&
        !seen(p, (uint32_t)pid))
        look_at(p, (uint32_t)pid, until);
    return true;
}

/* The earliest time a look is due at, or 0 when none waits. */
static uint64_t next_due(const struct ft_linux_prober *p)
{
    uint64_t due = 0;
    for (size_t i = 0; i < p->report_count; i++) {
        const struct report *r = &p->reports[(p->report_head + i) % PENDING_MAX];
        if (r->pid && (!due || r->due_ns < due))
            due = r->due_ns ? r->due_ns : p->credit_at;
    }
    for (size_t i = 0; i < p->recheck_count; i++) {
        if (!due || p->rechecks[i].due_ns < due)
            due = p->rechecks[i].due_ns;
    }
    /* A program's loader maps its libraries just after the exec. */
    if (p->queued && (!due || p->queue[p->head].ts_ns + SETTLE_NS < due))
        due = p->queue[p->head].ts_ns + SETTLE_NS;
    return due;
}

static uint64_t later(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

/* The age at which a process is looked at next, after a look at this age found this; 0 for none. */
static uint64_t next_age(const struct recheck *r, enum look result, uint64_t age)
{
    switch (result) {
    case LOOK_CUT:
        return age + RECHECK_STEP_NS;
    case LOOK_LOADING:
        return age < LOADING_MAX_NS ? age + later(RECHECK_STEP_NS, age) : 0;
    case LOOK_FOUND: {
        uint64_t next =
            r->dense ? later(age + RECHECK_STEP_NS, 2 * age) : later(LATE_FIRST_NS, 4 * age);
        return next <= LATE_MAX_NS ? next : 0;
    }
    default:
        return 0;
    }
}

static enum look look_fresh(struct ft_linux_prober *p, uint32_t pid, uint64_t until)
{
    p->fresh = false;
    return look_at(p, pid, until);
}

/*
 * Looks at the processes that reported mapping a file, each once for all its reports. A file left
 * open, or one whose process ended first, is reported again at its next mapping.
 */
static void report_work(struct ft_linux_prober *p, uint64_t until)
{
    while (p->report_count && ft_clock_mono_ns() < until) {
        uint64_t now = ft_clock_mono_ns();
        uint32_t pid = 0;
        for (size_t i = 0; i < p->report_count && !pid; i++) {
            const struct report *r = &p->reports[(p->report_head + i) % PENDING_MAX];
            if (r->pid && r->due_ns <= now)
                pid = r->pid;
        }
        if (!pid)
            break;
        struct target targets[TARGETS_MAX];
        size_t n = 0;
        for (size_t i = 0; i < p->report_count && n < TARGETS_MAX; i++) {
            struct report *r = &p->reports[(p->report_head + i) % PENDING_MAX];
            if (r->pid == pid && r->due_ns <= now) {
                targets[n++] = (struct target){.file = r->file, .tries = r->tries};
                r->pid = 0;
            }
        }
        while (p->report_count && !p->reports[p->report_head].pid) {
            p->report_head = (p->report_head + 1) % PENDING_MAX;
            p->report_count--;
        }
        p->targets = targets;
        p->target_count = n;
        enum look result = look_fresh(p, pid, until);
        p->target_count = 0;
        for (size_t i = 0; i < n; i++) {
            struct target *t = &targets[i];
            if (result == LOOK_CUT)
                queue_report(p, pid, &t->file, t->tries, 0);
            else if (result == LOOK_GONE || t->open)
                unreport(p->reported_fd, &t->file);
            else if (!t->seen && t->tries + 1 < REPORT_TRIES)
                queue_report(p, pid, &t->file, t->tries + 1,
                             ft_clock_mono_ns() + (REPORT_STEP_NS << t->tries));
            else if (t->probe && !t->probe->reported.ino)
                t->probe->reported = t->file;
        }
    }
}

/* Takes what a look found, and has the process looked at again while it is due another. */
static void looked(struct ft_linux_prober *p, struct recheck r, enum look result, uint64_t now)
{
    uint64_t age = now > r.ts_ns ? now - r.ts_ns : 0;
    uint64_t next = next_age(&r, result, age);
    r.reached = r.reached || (result != LOOK_GONE && result != LOOK_CUT);
    r.late = result == LOOK_FOUND;
    if (result == LOOK_FOUND || result == LOOK_NONE)
        note_quiet(p, &r.file, !p->fresh, now);
    if (next && p->recheck_count < RECHECK_MAX) {
        mark(p, r.pid, false);
        r.due_ns = r.ts_ns + next;
        p->rechecks[p->recheck_count++] = r;
        return;
    }
    note_missed(p, &r.file, result == LOOK_GONE && !r.reached, now);
}

/* Looks at each process of a quiet program once; one that has ended by then is let go. */
static void quiet_work(struct ft_linux_prober *p, uint64_t until)
{
    while (p->quiet_queued && ft_clock_mono_ns() < until) {
        uint64_t now = ft_clock_mono_ns();
        struct pending next = p->quiet_queue[p->quiet_head];
        if (next.ts_ns + SETTLE_NS > now)
            break;
        enum look result = look_fresh(p, next.pid, until);
        if (result == LOOK_CUT)
            break;
        p->quiet_head = (p->quiet_head + 1) % PENDING_MAX;
        p->quiet_queued--;
        if (p->fresh)
            note_quiet(p, &next.file, false, now);
    }
}

/* A program's quiet time is up: its execs wake the agent again. */
static void quiet_expire(struct ft_linux_prober *p, uint64_t now)
{
    for (size_t i = 0; i < p->quiet_count;) {
        if (now < p->quiet[i].ns + QUIET_NS)
            i++;
        else
            note_quiet(p, &p->quiet[i].file, false, now);
    }
}

/*
 * Looks at the due processes of one class. Late looks the time does not reach are dropped: what
 * they would find, the next process that maps it shows.
 */
static void recheck_work(struct ft_linux_prober *p, bool late, uint64_t until)
{
    for (size_t i = 0; i < p->recheck_count;) {
        struct recheck r = p->rechecks[i];
        uint64_t now = ft_clock_mono_ns();
        if (r.late != late || r.due_ns > now || (!late && now >= until)) {
            i++;
            continue;
        }
        p->rechecks[i] = p->rechecks[--p->recheck_count];
        if (now >= until)
            note_missed(p, &r.file, false, now);
        else
            looked(p, r, look_fresh(p, r.pid, until), now);
    }
}

static uint64_t probing_ns(const struct ft_linux_prober *p)
{
    uint64_t total = 0;
    for (size_t i = 0; i < p->kind_count; i++)
        total += p->kinds[i].probing_ns;
    return total;
}

void ft_linux_prober_work(struct ft_linux_prober *p, uint64_t now_ns)
{
    if (!p)
        return;
    if (p->again)
        start_pass(p);
    uint64_t start = ft_clock_mono_ns();
    uint64_t probing = probing_ns(p);
    p->credit_ns += (start - p->credit_at) * WORK_PERCENT / 100;
    if (p->credit_ns > WORK_BUDGET_NS)
        p->credit_ns = WORK_BUDGET_NS;
    p->credit_at = start;
    uint64_t until = start + p->credit_ns;

    report_work(p, until);
    quiet_expire(p, start);
    recheck_work(p, false, until);
    while (p->queued && ft_clock_mono_ns() < until) {
        uint64_t now = ft_clock_mono_ns();
        if (p->queue[p->head].ts_ns + SETTLE_NS > now)
            break;
        struct pending next = p->queue[p->head];
        p->head = (p->head + 1) % PENDING_MAX;
        p->queued--;
        struct recheck r = {.pid = next.pid, .file = next.file, .ts_ns = next.ts_ns};
        looked(p, r, look_fresh(p, next.pid, until), now);
    }
    quiet_work(p, until);
    recheck_work(p, true, until);
    if (p->pass && now_ns - p->pass_ns >= PASS_GAP_NS) {
        p->pass_ns = now_ns;
        while (p->pass && ft_clock_mono_ns() < until && pass_step(p, until)) {
        }
    }

    /* A file probed is paid for once, not per process: the share does not count it. */
    uint64_t spent = ft_clock_mono_ns() - start - (probing_ns(p) - probing);
    p->credit_ns = spent < p->credit_ns ? p->credit_ns - spent : 0;
}

uint64_t ft_linux_prober_due(const struct ft_linux_prober *p)
{
    uint64_t due = p ? next_due(p) : 0;
    if (!due || p->credit_ns >= WORK_SLICE_MIN_NS)
        return due;
    /* Not before the share of time the work has left gives it a slice again. */
    uint64_t ready = p->credit_at + (WORK_SLICE_MIN_NS - p->credit_ns) * 100 / WORK_PERCENT;
    return later(due, ready);
}

void ft_linux_prober_quiet(struct ft_linux_prober *p, int map_fd)
{
    if (p)
        p->quiet_fd = map_fd;
}

void ft_linux_prober_destroy(struct ft_linux_prober *p)
{
    if (!p)
        return;
    if (p->pass)
        closedir(p->pass);
    for (size_t i = 0; i < p->kind_count; i++) {
        struct kind *k = &p->kinds[i];
        for (size_t j = 0; j < k->count; j++)
            detach(&k->files[j]);
        free(k->files);
    }
    free(p->seen);
    free(p);
}
