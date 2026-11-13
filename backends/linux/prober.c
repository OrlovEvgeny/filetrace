#include "backends/linux/linux.h"

#include "filetrace/clock.h"
#include "filetrace/sysinfo.h"

#include <bpf/libbpf.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_KINDS 4
#define MAX_SKIPPED 256
#define MAX_WARNED 64
#define MAX_SYMBOL_BYTES (2u << 20) /* libphp's take a tenth of it, the C libraries' less */
#define PENDING_MAX 4096
#define PID_LIMIT_MAX (4u << 20) /* the kernel's PID_MAX_LIMIT on 64-bit */
/* Time a flush gives to reading /proc, so that a host with many processes does not hold it. */
#define WORK_BUDGET_NS (20 * FT_NS_PER_MS)
#define SETTLE_NS (5 * FT_NS_PER_MS)
#define CANDIDATES_MAX 4 /* distinct files of the kinds a process is looked at for */
/* A full kind gives a file's place to a new one when no look has found it for this long. */
#define IDLE_NS (60 * FT_NS_PER_SEC)

/*
 * A file as probes see it. Uprobes attach to the file underneath overlayfs, which every
 * container of an image shares, while each container's overlay gives it a device of its own;
 * the inode number, size and time are the real file's.
 */
struct identity {
    uint64_t ino;
    uint64_t size;
    int64_t mtime_sec;
    int64_t mtime_nsec;
};

struct probed {
    struct identity id;
    struct bpf_link *links[FT_LINUX_KIND_PROBES];
    uint64_t found_ns; /* when a look last found a process mapping or running it */
};

struct kind {
    struct ft_linux_probe_kind def;
    struct probed *files;
    size_t count;
    size_t forgotten; /* files that gave their place to newer ones */
    bool full_logged;
    struct identity skipped[MAX_SKIPPED]; /* not of the kind, or refused the probe */
    size_t skipped_count;
    struct identity warned[MAX_WARNED]; /* attaching to it failed, which was logged */
    size_t warned_count;
};

/* A process that started, to be looked at once its program has had a moment to load. */
struct pending {
    uint32_t pid;
    bool retried; /* the time ran out once while its maps were read */
    uint64_t ts_ns;
};

struct ft_linux_prober {
    struct kind kinds[MAX_KINDS];
    size_t kind_count;
    uint8_t *seen; /* a bit per process ID looked at since its program started */
    uint32_t pid_limit;
    struct pending queue[PENDING_MAX];
    size_t head;
    size_t queued;
    DIR *pass; /* a pass over /proc for the processes no event announced, while it runs */
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
    *k = (struct kind){.def = *def};
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

static bool same(const struct identity *a, const struct identity *b)
{
    return a->ino == b->ino && a->size == b->size && a->mtime_sec == b->mtime_sec &&
           a->mtime_nsec == b->mtime_nsec;
}

static struct probed *probed_file(struct kind *k, const struct identity *id)
{
    for (size_t i = 0; i < k->count; i++) {
        if (same(&k->files[i].id, id))
            return &k->files[i];
    }
    return nullptr;
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

/*
 * Probes the file that path leads to for one kind, once per file; name is how the process knows
 * it. path is a /proc link to the file the process runs or has mapped, never a name it could
 * replace, and the open does not wait on anything that is not a regular file.
 */
static void consider(struct kind *k, const char *path, const char *name, uint32_t pid)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0)
        return;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return;
    }
    struct identity id = {
        .ino = (uint64_t)st.st_ino,
        .size = (uint64_t)st.st_size,
        .mtime_sec = (int64_t)st.st_mtim.tv_sec,
        .mtime_nsec = (int64_t)st.st_mtim.tv_nsec,
    };
    uint64_t now = ft_clock_mono_ns();
    struct probed *found = probed_file(k, &id);
    if (found)
        found->found_ns = now;
    if (found || skipped(k, &id)) {
        close(fd);
        return;
    }
    struct probed *slot = place(k);
    bool full = k->count == k->def.capacity;
    if (full && now - slot->found_ns < IDLE_NS) {
        if (!k->full_logged)
            ft_log(FT_LOG_WARN,
                   "already probing %zu %s, each in use; %s and others are probed once one "
                   "has gone unused for a minute",
                   k->def.capacity, k->def.many, name);
        k->full_logged = true;
        close(fd);
        return;
    }

    uint64_t cookie = k->def.cookie(fd);
    if (!cookie) {
        skip(k, &id);
        close(fd);
        return;
    }

    /* Held open, the file stays reachable after the process that named it exits. */
    char held[32];
    snprintf(held, sizeof(held), "/proc/self/fd/%d", fd);
    struct probed fresh = {.id = id, .found_ns = now};
    int error = 0;
    for (size_t i = 0; i < FT_LINUX_KIND_PROBES && k->def.probes[i].prog && !error; i++)
        fresh.links[i] = attach(&k->def.probes[i], held, cookie, &error);
    close(fd);
    if (error) {
        if (first_warning(k, &id))
            ft_log(FT_LOG_WARN, "cannot probe %s %s: %s", k->def.one, name,
                   ft_linux_last_libbpf_message());
        detach(&fresh);
        if (!transient(error))
            skip(k, &id);
        return;
    }
    if (full) {
        ft_log(FT_LOG_INFO, "already probing %zu %s; the one unused longest makes room for %s",
               k->def.capacity, k->def.many, name);
        detach(slot);
        k->forgotten++;
    } else {
        k->count++;
    }
    *slot = fresh;
    k->def.probed(name, pid, cookie);
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* A file as a maps line names it, before it is opened. */
struct mapped_file {
    unsigned major;
    unsigned minor;
    unsigned long long ino;
};

/*
 * The files of the kinds that look through this process's maps, among those it has mapped; a
 * real process maps one of each. False when the time ran out before the maps were read.
 */
static bool consider_mapped(struct ft_linux_prober *p, const bool *wanted, uint32_t pid,
                            uint64_t until)
{
    char path[64];
    char line[PATH_MAX + 128];
    struct mapped_file candidates[CANDIDATES_MAX];
    size_t count = 0;
    size_t lines = 0;
    bool finished = true;

    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/maps", pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return true;
    while (fgets(line, sizeof(line), f)) {
        if (++lines % 64 == 0 && ft_clock_mono_ns() >= until) {
            finished = false;
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
        char *file = line + file_at;
        file[strcspn(file, "\n")] = '\0';
        if (file[0] != '/')
            continue;
        const char *name = base_name(file);
        bool matched = false;
        for (size_t i = 0; i < p->kind_count; i++)
            matched = matched || (wanted[i] && p->kinds[i].def.mapped(file, name));
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
            if (wanted[i] && p->kinds[i].def.mapped(file, name))
                consider(&p->kinds[i], mapped, file, pid);
        }
    }
    fclose(f);
    return finished;
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
 * Probes the files of the kinds that the process runs or has mapped. False when the time ran
 * out before its maps were read: it is not taken as looked at.
 */
static bool look_at(struct ft_linux_prober *p, uint32_t pid, uint64_t until)
{
    char path[64];
    char exe[PATH_MAX];

    mark(p, pid, true);
    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/exe", pid);
    ssize_t n = readlink(path, exe, sizeof(exe) - 1);
    if (n <= 0)
        return true;
    exe[n] = '\0';
    const char *name = base_name(exe);

    bool wanted[MAX_KINDS] = {false};
    bool maps = false;
    for (size_t i = 0; i < p->kind_count; i++) {
        const struct ft_linux_probe_kind *def = &p->kinds[i].def;
        if (def->runs && def->runs(name))
            consider(&p->kinds[i], path, exe, pid);
        else if (def->every_process || (def->maps_of && def->maps_of(name)))
            maps = wanted[i] = true;
    }
    if (maps && !consider_mapped(p, wanted, pid, until)) {
        mark(p, pid, false);
        return false;
    }
    return true;
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
    p->seen = calloc(p->pid_limit / 8 + 1, 1);
    if (!p->seen) {
        free(p);
        return nullptr;
    }
    return p;
}

void ft_linux_prober_started(struct ft_linux_prober *p, uint32_t pid, const char *program,
                             bool forked, uint64_t ts_ns)
{
    if (!p)
        return;
    mark(p, pid, false);
    if (!wants(p, program, forked))
        return;
    /* A process that finds no room is left for the next pass. */
    if (p->queued == PENDING_MAX)
        return;
    p->queue[(p->head + p->queued++) % PENDING_MAX] = (struct pending){.pid = pid, .ts_ns = ts_ns};
}

void ft_linux_prober_ended(struct ft_linux_prober *p, uint32_t pid)
{
    if (p)
        mark(p, pid, false);
}

void ft_linux_prober_rescan(struct ft_linux_prober *p)
{
    if (!p || !p->kind_count || p->pass)
        return;
    /* Outside the host's PID namespace no event names a process by its /proc entry. */
    if (!ft_sysinfo_host_pid_namespace())
        memset(p->seen, 0, p->pid_limit / 8 + 1);
    p->pass = opendir("/proc");
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

void ft_linux_prober_work(struct ft_linux_prober *p, uint64_t now_ns)
{
    if (!p)
        return;
    uint64_t until = ft_clock_mono_ns() + WORK_BUDGET_NS;
    do {
        /* A program's loader maps its libraries just after the exec. */
        if (p->queued && p->queue[p->head].ts_ns + SETTLE_NS <= now_ns) {
            struct pending next = p->queue[p->head];
            p->head = (p->head + 1) % PENDING_MAX;
            p->queued--;
            if (!look_at(p, next.pid, until) && !next.retried) {
                /* Once more first thing at the next flush; after that it is left to a pass. */
                p->head = (p->head + PENDING_MAX - 1) % PENDING_MAX;
                p->queue[p->head] = next;
                p->queue[p->head].retried = true;
                p->queued++;
                break;
            }
        } else if (!p->pass || !pass_step(p, until)) {
            break;
        }
    } while (ft_clock_mono_ns() < until);
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
