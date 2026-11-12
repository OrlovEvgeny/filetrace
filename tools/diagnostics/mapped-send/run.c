#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc < 5 || strcmp(argv[3], "--") ||
        (strcmp(argv[2], "fentry") && strcmp(argv[2], "kprobe"))) {
        fprintf(stderr, "usage: %s object.bpf.o fentry|kprobe -- command [args...]\n", argv[0]);
        return 2;
    }
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj || libbpf_get_error(obj))
        return 1;
    const char *name = !strcmp(argv[2], "fentry") ? "mapped_fentry" : "mapped_kprobe";
    struct bpf_program *prog, *selected = NULL;
    bpf_object__for_each_program(prog, obj)
    {
        int wanted = !strcmp(bpf_program__name(prog), name);
        bpf_program__set_autoload(prog, wanted);
        if (wanted)
            selected = prog;
    }
    int rc = 1, gate[2];
    struct bpf_link *link = NULL;
    pid_t child = -1;
    if (!selected || bpf_object__load(obj) || pipe(gate))
        goto done;
    child = fork();
    if (child == 0) {
        close(gate[1]);
        char go;
        ssize_t n;
        do {
            n = read(gate[0], &go, 1);
        } while (n < 0 && errno == EINTR);
        close(gate[0]);
        if (n != 1)
            _exit(125);
        execvp(argv[4], &argv[4]);
        _exit(127);
    }
    close(gate[0]);
    if (child < 0) {
        close(gate[1]);
        goto done;
    }
    uint32_t key = 0, pid = (uint32_t)child;
    if (bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "target"), &key, &pid, BPF_ANY)) {
        close(gate[1]);
        goto reap;
    }
    link = bpf_program__attach(selected);
    if (!link || libbpf_get_error(link)) {
        link = NULL;
        close(gate[1]);
        goto reap;
    }
    if (write(gate[1], "g", 1) != 1) {
        close(gate[1]);
        goto reap;
    }
    close(gate[1]);
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            goto done;
    }
    child = -1;
    rc = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
    const char *names[] = {"sends",           "unsupported",   "multi_vector",   "invalid_range",
                           "vma_miss",        "anonymous",     "unsafe_mapping", "non_regular",
                           "mapped_readonly", "observed_bytes"};
    int fd = bpf_object__find_map_fd_by_name(obj, "counts");
    for (key = 0; key < sizeof(names) / sizeof(names[0]); key++) {
        uint64_t value = 0;
        if (bpf_map_lookup_elem(fd, &key, &value)) {
            rc = 1;
            break;
        }
        printf("%s=%llu\n", names[key], (unsigned long long)value);
    }
    goto done;
reap:
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
    child = -1;
done:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return rc;
}
