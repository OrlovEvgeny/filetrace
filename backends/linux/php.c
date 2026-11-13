#include "backends/linux/linux.h"

#include "filetrace/format.h"
#include "filetrace/scripts.h"
#include "filetrace/sysinfo.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "backends/linux/bpf/abi.h"

#define SCRIPT_SLOTS 4096

struct ft_linux_php {
    int known_scripts_fd;
    struct ft_script_names *names;
};

static bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

static bool php_runs(const char *program)
{
    return starts_with(program, "php") || starts_with(program, "frankenphp");
}

/* The web servers that carry PHP in a library. */
static bool php_maps_of(const char *program)
{
    return strcmp(program, "apache2") == 0 || starts_with(program, "httpd");
}

static bool php_mapped(const char *path, const char *name)
{
    (void)path;
    return starts_with(name, "libphp") || starts_with(name, "mod_php");
}

/*
 * The layout of php_execute_script's argument in the ELF file, from its dynamic symbols; 0 if it
 * does not export both functions the probes attach to.
 */
static uint64_t php_layout(int fd)
{
    static const char *const names[] = {
        "php_execute_script",
        "php_request_shutdown",
        /* Added in PHP 8.1 with the zend_string name of zend_file_handle. */
        "zend_stream_init_filename_ex",
    };
    bool found[FT_ARRAY_LEN(names)];

    if (!ft_linux_elf_exports(fd, names, FT_ARRAY_LEN(names), found, nullptr) || !found[0] ||
        !found[1])
        return 0;
    return found[2] ? FT_BPF_PHP_ZEND_STRING : FT_BPF_PHP_CHAR_NAME;
}

static void php_probed(const char *name, uint32_t pid, uint64_t layout)
{
    ft_log(FT_LOG_INFO, "probing PHP requests in %s, as process %" PRIu32 " runs it (PHP %s)", name,
           pid, layout == FT_BPF_PHP_ZEND_STRING ? "8.1 or later" : "8.0 or earlier");
}

struct ft_linux_php *ft_linux_php_open(struct bpf_object *obj, struct ft_linux_prober *prober)
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
    struct ft_linux_probe_kind kind = {
        .one = "the PHP binary",
        .many = "PHP binaries",
        .capacity = FT_LINUX_PHP_FILES,
        .probes = {{start, "php_execute_script", false}, {end, "php_request_shutdown", true}},
        .runs = php_runs,
        .maps_of = php_maps_of,
        .mapped = php_mapped,
        .cookie = php_layout,
        .probed = php_probed,
    };
    if (!php->names || ft_linux_prober_add(prober, &kind) < 0) {
        ft_script_names_destroy(php->names);
        free(php);
        return nullptr;
    }
    php->known_scripts_fd = bpf_map__fd(scripts);
    return php;
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
    ft_script_names_destroy(php->names);
    free(php);
}
