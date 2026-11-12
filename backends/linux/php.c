#include "backends/linux/linux.h"

#include "filetrace/format.h"
#include "filetrace/scripts.h"
#include "filetrace/sysinfo.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ctype.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "backends/linux/bpf/abi.h"

#define MAX_BINARIES 64
#define MAX_SKIPPED 256
#define SCRIPT_SLOTS 4096
#define MAX_SYMBOL_BYTES (8u << 20)

/*
 * A binary as probes see it. Uprobes attach to the file underneath overlayfs, which every
 * container of an image shares, while each container's overlay gives it a device of its own;
 * the inode number, size and time are the real file's.
 */
struct php_identity {
    uint64_t ino;
    uint64_t size;
    int64_t mtime_sec;
    int64_t mtime_nsec;
};

struct php_binary {
    struct php_identity id;
    struct bpf_link *start;
    struct bpf_link *end;
};

struct ft_linux_php {
    struct bpf_program *start_prog;
    struct bpf_program *end_prog;
    int known_scripts_fd;
    struct php_binary binaries[MAX_BINARIES];
    size_t count;
    bool full_logged;
    struct php_identity skipped[MAX_SKIPPED]; /* not PHP, or refused the probe */
    size_t skipped_count;
    struct ft_script_names *names;
};

static bool read_at(int fd, void *buf, size_t size, uint64_t off)
{
    return pread(fd, buf, size, (off_t)off) == (ssize_t)size;
}

/*
 * The layout of php_execute_script's argument in the ELF file at path, from its dynamic
 * symbols; 0 if it does not export both functions the probes attach to.
 */
static int php_layout(const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;

    Elf64_Ehdr eh;
    Elf64_Shdr *sections = nullptr;
    char *names = nullptr;
    Elf64_Sym *syms = nullptr;
    int layout = 0;

    if (!read_at(fd, &eh, sizeof(eh), 0) || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_shentsize != sizeof(Elf64_Shdr) ||
        eh.e_shnum == 0 || eh.e_shnum > 4096)
        goto done;
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
        names = malloc(dynstr->sh_size + 1);
        if (!syms || !names || !read_at(fd, syms, dynsym->sh_size, dynsym->sh_offset) ||
            !read_at(fd, names, dynstr->sh_size, dynstr->sh_offset))
            break;
        names[dynstr->sh_size] = '\0';

        bool start = false;
        bool end = false;
        bool zend_string_names = false;
        for (size_t j = 0; j < dynsym->sh_size / sizeof(Elf64_Sym); j++) {
            if (syms[j].st_name >= dynstr->sh_size || syms[j].st_shndx == SHN_UNDEF)
                continue;
            const char *name = names + syms[j].st_name;
            if (strcmp(name, "php_execute_script") == 0)
                start = true;
            else if (strcmp(name, "php_request_shutdown") == 0)
                end = true;
            /* Added in PHP 8.1 with the zend_string name of zend_file_handle. */
            else if (strcmp(name, "zend_stream_init_filename_ex") == 0)
                zend_string_names = true;
        }
        if (start && end)
            layout = zend_string_names ? FT_BPF_PHP_ZEND_STRING : FT_BPF_PHP_CHAR_NAME;
        break;
    }

done:
    free(syms);
    free(names);
    free(sections);
    close(fd);
    return layout;
}

static bool same(const struct php_identity *a, const struct php_identity *b)
{
    return a->ino == b->ino && a->size == b->size && a->mtime_sec == b->mtime_sec &&
           a->mtime_nsec == b->mtime_nsec;
}

static bool known(const struct ft_linux_php *php, const struct php_identity *id)
{
    for (size_t i = 0; i < php->count; i++) {
        if (same(&php->binaries[i].id, id))
            return true;
    }
    for (size_t i = 0; i < php->skipped_count; i++) {
        if (same(&php->skipped[i], id))
            return true;
    }
    return false;
}

static void skip(struct ft_linux_php *php, const struct php_identity *id)
{
    size_t slot =
        php->skipped_count < MAX_SKIPPED ? php->skipped_count++ : (size_t)(id->ino % MAX_SKIPPED);
    php->skipped[slot] = *id;
}

static struct bpf_link *attach(struct bpf_program *prog, const char *path, const char *func,
                               bool retprobe, uint64_t cookie)
{
    /* libbpf refuses options whose padding is not zero, which an initializer leaves open. */
    struct bpf_uprobe_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.sz = sizeof(opts);
    opts.func_name = func;
    opts.retprobe = retprobe;
    opts.bpf_cookie = cookie;
    struct bpf_link *link = bpf_program__attach_uprobe_opts(prog, -1, path, 0, &opts);
    return libbpf_get_error(link) ? nullptr : link;
}

/*
 * Probes the PHP binary that path leads to, once per file; name is how the process knows it.
 * path is a /proc link to the file the process runs or has mapped, never a name it could
 * replace, and the open does not wait on anything that is not a regular file.
 */
static void consider(struct ft_linux_php *php, const char *path, const char *name, uint32_t pid)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0)
        return;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return;
    }
    struct php_identity id = {
        .ino = (uint64_t)st.st_ino,
        .size = (uint64_t)st.st_size,
        .mtime_sec = (int64_t)st.st_mtim.tv_sec,
        .mtime_nsec = (int64_t)st.st_mtim.tv_nsec,
    };
    if (known(php, &id)) {
        close(fd);
        return;
    }

    /* Held open, the binary stays reachable after the process that named it exits. */
    char held[32];
    snprintf(held, sizeof(held), "/proc/self/fd/%d", fd);
    int layout = php_layout(held);
    if (!layout) {
        skip(php, &id);
        close(fd);
        return;
    }
    if (php->count == MAX_BINARIES) {
        if (!php->full_logged)
            ft_log(FT_LOG_WARN, "already probing %d PHP binaries; %s and later ones are not probed",
                   MAX_BINARIES, name);
        php->full_logged = true;
        close(fd);
        return;
    }
    struct php_binary *b = &php->binaries[php->count];
    b->start = attach(php->start_prog, held, "php_execute_script", false, (uint64_t)layout);
    b->end = b->start ? attach(php->end_prog, held, "php_request_shutdown", true, 0) : nullptr;
    close(fd);
    if (!b->start || !b->end) {
        ft_log(FT_LOG_WARN, "cannot probe the PHP binary %s: %s", name,
               ft_linux_last_libbpf_message());
        bpf_link__destroy(b->start);
        skip(php, &id);
        return;
    }
    b->id = id;
    php->count++;
    ft_log(FT_LOG_INFO, "probing PHP requests in %s, as process %" PRIu32 " runs it (PHP %s)", name,
           pid, layout == FT_BPF_PHP_ZEND_STRING ? "8.1 or later" : "8.0 or earlier");
}

static bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static const char *base_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* The libraries that carry PHP into a web server, among those the process has mapped. */
static void consider_libraries(struct ft_linux_php *php, uint32_t pid)
{
    char path[64];
    char line[PATH_MAX + 128];
    char last[PATH_MAX] = "";

    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/maps", pid);
    FILE *f = fopen(path, "re");
    if (!f)
        return;
    while (fgets(line, sizeof(line), f)) {
        char range[64];
        char perms[8];
        int file_at = 0;
        if (sscanf(line, "%63s %7s %*s %*s %*s %n", range, perms, &file_at) != 2 || !file_at ||
            !strchr(perms, 'x'))
            continue;
        char *file = line + file_at;
        file[strcspn(file, "\n")] = '\0';
        const char *name = base_name(file);
        if (file[0] != '/' || !(starts_with(name, "libphp") || starts_with(name, "mod_php")) ||
            strcmp(file, last) == 0)
            continue;
        ft_strlcpy(last, file, sizeof(last));
        /* The mapped file itself: a mount over its directory cannot put anything else there. */
        char mapped[128];
        snprintf(mapped, sizeof(mapped), "/proc/%" PRIu32 "/map_files/%s", pid, range);
        consider(php, mapped, file, pid);
    }
    fclose(f);
}

void ft_linux_php_attach_pid(struct ft_linux_php *php, uint32_t pid)
{
    char path[64];
    char exe[PATH_MAX];

    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/exe", pid);
    ssize_t n = readlink(path, exe, sizeof(exe) - 1);
    if (n <= 0)
        return;
    exe[n] = '\0';
    const char *name = base_name(exe);
    if (starts_with(name, "php") || starts_with(name, "frankenphp"))
        consider(php, path, exe, pid);
    else if (strcmp(name, "apache2") == 0 || starts_with(name, "httpd"))
        consider_libraries(php, pid);
}

void ft_linux_php_scan(struct ft_linux_php *php)
{
    DIR *d = opendir("/proc");
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != nullptr) {
        if (!isdigit((unsigned char)e->d_name[0]))
            continue;
        char *end;
        unsigned long pid = strtoul(e->d_name, &end, 10);
        if (*end == '\0' && pid > 0 && pid <= UINT32_MAX)
            ft_linux_php_attach_pid(php, (uint32_t)pid);
    }
    closedir(d);
}

struct ft_linux_php *ft_linux_php_open(struct bpf_object *obj)
{
    struct bpf_program *start = bpf_object__find_program_by_name(obj, "ft_php_execute_script");
    struct bpf_program *end = bpf_object__find_program_by_name(obj, "ft_php_request_shutdown");
    struct bpf_map *scripts = bpf_object__find_map_by_name(obj, "known_scripts");
    if (!start || !end || !scripts || bpf_program__fd(start) < 0 || bpf_program__fd(end) < 0)
        return nullptr;
    struct ft_linux_php *php = calloc(1, sizeof(*php));
    if (!php)
        return nullptr;
    php->names = ft_script_names_create(SCRIPT_SLOTS);
    if (!php->names) {
        free(php);
        return nullptr;
    }
    php->start_prog = start;
    php->end_prog = end;
    php->known_scripts_fd = bpf_map__fd(scripts);
    return php;
}

size_t ft_linux_php_binaries(const struct ft_linux_php *php)
{
    return php ? php->count : 0;
}

void ft_linux_php_script_seen(struct ft_linux_php *php, uint32_t id, uint32_t tgid, uint64_t hash,
                              const char *path, size_t len)
{
    char full[FT_BPF_SCRIPT_MAX + PATH_MAX + 2];
    char name[FT_BPF_SCRIPT_MAX + 1];

    if (len > FT_BPF_SCRIPT_MAX)
        len = FT_BPF_SCRIPT_MAX;
    memcpy(name, path, len);
    name[len] = '\0';
    /* The CLI's name for a script read from standard input, which has no path. */
    if (strcmp(name, "Standard input code") == 0)
        return;
    ft_strlcpy(full, name, sizeof(full));

    /* The CLI runs a script as named on its command line, relative to where it was started. */
    if (name[0] != '/' && ft_sysinfo_host_pid_namespace()) {
        char link[64];
        char cwd[PATH_MAX];
        snprintf(link, sizeof(link), "/proc/%" PRIu32 "/cwd", tgid);
        ssize_t n = readlink(link, cwd, sizeof(cwd) - 1);
        if (n > 0) {
            cwd[n] = '\0';
            const char *rest = starts_with(name, "./") ? name + 2 : name;
            snprintf(full, sizeof(full), "%s%s%s", cwd, strcmp(cwd, "/") == 0 ? "" : "/", rest);
        }
    }

    uint64_t evicted = 0;
    if (ft_script_names_put(php->names, id, hash, full, &evicted))
        bpf_map_delete_elem(php->known_scripts_fd, &evicted);
}

const char *ft_linux_php_script(const struct ft_linux_php *php, uint32_t id)
{
    return php ? ft_script_names_get(php->names, id) : nullptr;
}

void ft_linux_php_close(struct ft_linux_php *php)
{
    if (!php)
        return;
    for (size_t i = 0; i < php->count; i++) {
        bpf_link__destroy(php->binaries[i].end);
        bpf_link__destroy(php->binaries[i].start);
    }
    ft_script_names_destroy(php->names);
    free(php);
}
