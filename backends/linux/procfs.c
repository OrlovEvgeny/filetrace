#include "backends/linux/linux.h"

#include "filetrace/sysinfo.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

static bool read_file(const char *path, char *buf, size_t size)
{
    FILE *f = fopen(path, "re");
    if (!f)
        return false;
    size_t n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    return n > 0;
}

static uint32_t namespace_inode(uint32_t pid, const char *ns)
{
    char path[64];
    struct stat st;

    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/ns/%s", pid, ns);
    return stat(path, &st) == 0 ? (uint32_t)st.st_ino : 0;
}

bool ft_linux_lookup_process(uint32_t pid, struct ft_ev_process *out)
{
    char path[64];
    char buf[1024];

    if (!ft_sysinfo_host_pid_namespace())
        return false;

    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/stat", pid);
    if (!read_file(path, buf, sizeof(buf)))
        return false;

    /* The command name is parenthesised and may itself contain ')'. */
    char *open = strchr(buf, '(');
    char *close = strrchr(buf, ')');
    if (!open || !close || close < open)
        return false;

    memset(out, 0, sizeof(*out));
    out->pid = pid;
    *close = '\0';
    ft_strlcpy(out->comm, open + 1, sizeof(out->comm));

    unsigned ppid = 0;
    unsigned long long start_ticks = 0;
    /* Fields after the name: state ppid ... starttime is the 20th. */
    if (sscanf(close + 2,
               "%*c %u %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu",
               &ppid, &start_ticks) != 2)
        return false;
    out->ppid = ppid;

    long hz = sysconf(_SC_CLK_TCK);
    if (hz > 0)
        out->start_ns = start_ticks * (FT_NS_PER_SEC / (uint64_t)hz);

    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/status", pid);
    if (read_file(path, buf, sizeof(buf))) {
        unsigned real, effective;
        const char *line = strstr(buf, "\nUid:");
        if (line && sscanf(line, "\nUid: %u %u", &real, &effective) == 2)
            out->uid = effective;
        line = strstr(buf, "\nGid:");
        if (line && sscanf(line, "\nGid: %u %u", &real, &effective) == 2)
            out->gid = effective;
    }

    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/exe", pid);
    ssize_t n = readlink(path, out->exe, sizeof(out->exe) - 1);
    out->exe[n > 0 ? n : 0] = '\0';

    out->pidns = namespace_inode(pid, "pid");
    out->mntns = namespace_inode(pid, "mnt");
    out->netns = namespace_inode(pid, "net");
    return true;
}

bool ft_linux_read_process_text(uint32_t pid, struct ft_process_text *out)
{
    char path[64];
    size_t len = 0;

    if (!ft_sysinfo_host_pid_namespace())
        return false;

    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    while (len < sizeof(out->args) - 1) {
        ssize_t n = read(fd, out->args + len, sizeof(out->args) - 1 - len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        len += (size_t)n;
    }
    close(fd);
    out->args[len] = '\0';
    out->args_len = len;

    /* Reading another user's working directory takes CAP_SYS_PTRACE. */
    snprintf(path, sizeof(path), "/proc/%" PRIu32 "/cwd", pid);
    ssize_t n = readlink(path, out->cwd, sizeof(out->cwd) - 1);
    out->cwd[n > 0 ? n : 0] = '\0';
    return len > 0;
}

void ft_linux_held_capabilities(struct ft_linux_caps *out)
{
    constexpr unsigned long long CAP_SYS_ADMIN_BIT = 1ULL << 21;
    constexpr unsigned long long CAP_PERFMON_BIT = 1ULL << 38;
    constexpr unsigned long long CAP_BPF_BIT = 1ULL << 39;
    unsigned long long caps = 0;
    char buf[2048];

    if (read_file("/proc/self/status", buf, sizeof(buf))) {
        const char *line = strstr(buf, "\nCapEff:");
        if (!line || sscanf(line, "\nCapEff: %llx", &caps) != 1)
            caps = 0;
    }
    out->sys_admin = (caps & CAP_SYS_ADMIN_BIT) != 0;
    out->bpf = (caps & CAP_BPF_BIT) != 0;
    out->perfmon = (caps & CAP_PERFMON_BIT) != 0;
}

bool ft_linux_privileged(void)
{
    struct ft_linux_caps caps;

    ft_linux_held_capabilities(&caps);
    return caps.sys_admin || (caps.bpf && caps.perfmon);
}

bool ft_linux_kernel_version(unsigned *major, unsigned *minor)
{
    struct utsname u;
    return uname(&u) == 0 && sscanf(u.release, "%u.%u", major, minor) == 2;
}

void ft_linux_fs_type(uint64_t magic, char *buf, size_t size)
{
    static const struct {
        uint64_t magic;
        const char *name;
    } known[] = {
        {0xef53, "ext4"},         {0x58465342, "xfs"},      {0x9123683e, "btrfs"},
        {0x01021994, "tmpfs"},    {0x794c7630, "overlay"},  {0x6969, "nfs"},
        {0x65735546, "fuse"},     {0x73717368, "squashfs"}, {0xf2f52010, "f2fs"},
        {0x2fc12fc1, "zfs"},      {0x4d44, "vfat"},         {0x2011bab0, "exfat"},
        {0x5346544e, "ntfs"},     {0xff534d42, "cifs"},     {0xfe534d42, "smb2"},
        {0x01021997, "9p"},       {0x00c36400, "ceph"},     {0xe0f5e1e2, "erofs"},
        {0xca451a4e, "bcachefs"}, {0x858458f6, "ramfs"},
    };
    for (size_t i = 0; i < FT_ARRAY_LEN(known); i++) {
        if (known[i].magic == magic) {
            ft_strlcpy(buf, known[i].name, size);
            return;
        }
    }
    snprintf(buf, size, "0x%" PRIx64, magic);
}
