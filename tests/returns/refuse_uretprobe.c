/*
 * ft_refuse_uretprobe <eperm|enosys> <command...>: runs the command under a seccomp filter that
 * refuses the x86-64 uretprobe system call with that error, as Docker's default profile (EPERM)
 * and podman's (ENOSYS) refuse a call they do not list.
 */
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#define URETPROBE_NR 335

int main(int argc, char **argv)
{
    unsigned int error;
    if (argc >= 3 && strcmp(argv[1], "eperm") == 0) {
        error = EPERM;
    } else if (argc >= 3 && strcmp(argv[1], "enosys") == 0) {
        error = ENOSYS;
    } else {
        fprintf(stderr, "usage: ft_refuse_uretprobe <eperm|enosys> <command...>\n");
        return 2;
    }

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, URETPROBE_NR, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | error),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) != 0) {
        perror("ft_refuse_uretprobe: seccomp");
        return 1;
    }
    execvp(argv[2], argv + 2);
    perror(argv[2]);
    return 127;
}
