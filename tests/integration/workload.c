#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

[[noreturn]] static void die(const char *what)
{
    perror(what);
    exit(1);
}

static void make_file(const char *path, size_t size)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        die(path);

    char block[65536];
    for (size_t i = 0; i < sizeof(block); i++)
        block[i] = (char)('a' + i % 26);
    while (size) {
        size_t n = size < sizeof(block) ? size : sizeof(block);
        if (write(fd, block, n) != (ssize_t)n)
            die("write");
        size -= n;
    }
    close(fd);
}

static socklen_t loopback(bool ipv6, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof(*ss));
    if (ipv6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6;
        a->sin6_addr = in6addr_loopback;
        return sizeof(*a);
    }
    struct sockaddr_in *a = (struct sockaddr_in *)ss;
    a->sin_family = AF_INET;
    a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return sizeof(*a);
}

struct sink {
    pid_t pid;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int port;
};

/* With greet, the sink sends one line to each peer before discarding its input. */
static struct sink start_sink(int type, bool ipv6, bool greet)
{
    struct sink s = {0};
    int fd = socket(ipv6 ? AF_INET6 : AF_INET, type, 0);
    if (fd < 0)
        die("socket");

    s.addr_len = loopback(ipv6, &s.addr);
    if (bind(fd, (struct sockaddr *)&s.addr, s.addr_len) != 0)
        die("bind");
    if (getsockname(fd, (struct sockaddr *)&s.addr, &s.addr_len) != 0)
        die("getsockname");
    s.port = ntohs(ipv6 ? ((struct sockaddr_in6 *)&s.addr)->sin6_port
                        : ((struct sockaddr_in *)&s.addr)->sin_port);
    if (type == SOCK_STREAM && listen(fd, 64) != 0)
        die("listen");

    s.pid = fork();
    if (s.pid < 0)
        die("fork");
    if (s.pid == 0) {
        char buf[65536];
        if (type == SOCK_DGRAM) {
            while (recv(fd, buf, sizeof(buf), 0) > 0)
                continue;
            _exit(0);
        }
        for (;;) {
            int c = accept(fd, nullptr, nullptr);
            if (c < 0)
                _exit(0);
            if (greet && write(c, "hello\n", 6) != 6)
                _exit(1);
            while (read(c, buf, sizeof(buf)) > 0)
                continue;
            close(c);
        }
    }
    close(fd);
    return s;
}

static void stop_sink(const struct sink *s)
{
    kill(s->pid, SIGTERM);
    waitpid(s->pid, nullptr, 0);
}

static int connect_sink(const struct sink *s)
{
    int fd = socket(s->addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0)
        die("socket");
    if (connect(fd, (const struct sockaddr *)&s->addr, s->addr_len) != 0)
        die("connect");
    return fd;
}

static void sendfile_span(int sock, int file, size_t from, size_t to)
{
    off_t off = (off_t)from;
    while ((size_t)off < to) {
        ssize_t n = sendfile(sock, file, &off, to - (size_t)off);
        if (n <= 0)
            die("sendfile");
    }
}

static void sendfile_all(int sock, int file, size_t size)
{
    sendfile_span(sock, file, 0, size);
}

static void send_all(int sock, const char *buf, size_t size)
{
    while (size) {
        ssize_t n = send(sock, buf, size, 0);
        if (n <= 0)
            die("send");
        buf += n;
        size -= (size_t)n;
    }
}

static void read_send(int sock, int file, size_t chunk)
{
    char *buf = malloc(chunk);
    if (!buf)
        die("malloc");
    for (;;) {
        ssize_t n = read(file, buf, chunk);
        if (n < 0)
            die("read");
        if (n == 0)
            break;
        send_all(sock, buf, (size_t)n);
    }
    free(buf);
}

static int open_file(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        die(path);
    return fd;
}

static void report(const char *scenario, const char *path, size_t bytes, int port)
{
    printf("scenario=%s pid=%d port=%d bytes=%zu file=%s\n", scenario, (int)getpid(), port, bytes,
           path ? path : "-");
}

/* sendfile <path> <bytes> [ipv6] */
static void scenario_sendfile(const char *path, size_t size, bool ipv6)
{
    struct sink sink = start_sink(SOCK_STREAM, ipv6, false);
    make_file(path, size);

    int file = open_file(path);
    int sock = connect_sink(&sink);
    sendfile_all(sock, file, size);
    close(sock);
    close(file);
    report("sendfile", path, size, sink.port);
    stop_sink(&sink);
}

/* readsend <path> <bytes> <chunk> */
static void scenario_readsend(const char *path, size_t size, size_t chunk)
{
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    make_file(path, size);

    int file = open_file(path);
    int sock = connect_sink(&sink);
    read_send(sock, file, chunk);
    close(sock);
    close(file);
    report("readsend", path, size, sink.port);
    stop_sink(&sink);
}

/* readthenrecv <path> <bytes>: hears from the peer between the read and an unrelated send */
static void scenario_read_then_recv(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, true);
    make_file(path, size);

    int sock = connect_sink(&sink);
    int file = open_file(path);
    char *contents = malloc(size);
    char *unrelated = calloc(1, size);
    char greeting[6];
    if (!contents || !unrelated)
        die("malloc");
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    if (recv(sock, greeting, sizeof(greeting), MSG_WAITALL) != (ssize_t)sizeof(greeting))
        die("recv");
    send_all(sock, unrelated, size);
    close(sock);
    close(file);
    free(contents);
    free(unrelated);
    report("readthenrecv", path, size, sink.port);
    stop_sink(&sink);
}

/* readlittle <path> <bytes>: sends only a sliver of what it read */
static void scenario_read_little(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    make_file(path, size);

    int sock = connect_sink(&sink);
    int file = open_file(path);
    char *contents = malloc(size);
    if (!contents)
        die("malloc");
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    send_all(sock, contents, 2048);
    close(sock);
    close(file);
    free(contents);
    report("readlittle", path, size, sink.port);
    stop_sink(&sink);
}

/* fdreuse <dir> <count> <base-bytes>: descriptors are closed per file, so their numbers repeat */
static void scenario_fd_reuse(const char *dir, size_t count, size_t base)
{
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    char path[4096];

    for (size_t i = 0; i < count; i++) {
        size_t size = base + i * 4096;
        snprintf(path, sizeof(path), "%s/reuse-%zu.bin", dir, i);
        make_file(path, size);

        int file = open_file(path);
        int sock = connect_sink(&sink);
        sendfile_all(sock, file, size);
        close(sock);
        close(file);
        report("fdreuse", path, size, sink.port);
    }
    stop_sink(&sink);
}

/* rename <path> <new-path> <bytes>: renamed halfway through the transfer */
static void scenario_rename(const char *path, const char *renamed, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    make_file(path, size);

    int file = open_file(path);
    int sock = connect_sink(&sink);
    sendfile_span(sock, file, 0, size / 2);
    if (rename(path, renamed) != 0)
        die("rename");
    sendfile_span(sock, file, size / 2, size);
    close(sock);
    close(file);
    report("rename", renamed, size, sink.port);
    stop_sink(&sink);
}

/* unlink <path> <bytes>: sent after the last directory entry is removed */
static void scenario_unlink(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    make_file(path, size);

    int file = open_file(path);
    if (unlink(path) != 0)
        die("unlink");
    int sock = connect_sink(&sink);
    sendfile_all(sock, file, size);
    close(sock);
    close(file);
    report("unlink", path, size, sink.port);
    stop_sink(&sink);
}

/* udp <bytes> [ipv6]: unconnected datagram socket */
static void scenario_udp(size_t size, bool ipv6)
{
    struct sink sink = start_sink(SOCK_DGRAM, ipv6, false);
    int sock = socket(ipv6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    char datagram[1000];
    size_t sent = 0;

    if (sock < 0)
        die("socket");
    memset(datagram, 'u', sizeof(datagram));
    while (sent < size) {
        size_t n = size - sent < sizeof(datagram) ? size - sent : sizeof(datagram);
        if (sendto(sock, datagram, n, 0, (struct sockaddr *)&sink.addr, sink.addr_len) !=
            (ssize_t)n)
            die("sendto");
        sent += n;
    }
    close(sock);
    report("udp", nullptr, size, sink.port);
    usleep(100 * 1000);
    stop_sink(&sink);
}

/* child <path> <bytes>: a forked child transfers the file; the parent sends nothing */
static void scenario_child(const char *path, size_t size)
{
    pid_t pid = fork();
    if (pid < 0)
        die("fork");
    if (pid == 0) {
        scenario_sendfile(path, size, false);
        exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    printf("scenario=child parent=%d child=%d\n", (int)getpid(), (int)pid);
}

static size_t arg_size(const char *text)
{
    char *end;
    unsigned long long v = strtoull(text, &end, 10);
    if (*end != '\0' || end == text) {
        fprintf(stderr, "invalid number: %s\n", text);
        exit(2);
    }
    return (size_t)v;
}

int main(int argc, char **argv)
{
    const char *name = argc > 1 ? argv[1] : "";

    signal(SIGPIPE, SIG_IGN);
    if (strcmp(name, "sendfile") == 0 && argc >= 4)
        scenario_sendfile(argv[2], arg_size(argv[3]), argc > 4 && strcmp(argv[4], "ipv6") == 0);
    else if (strcmp(name, "readsend") == 0 && argc == 5)
        scenario_readsend(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readthenrecv") == 0 && argc == 4)
        scenario_read_then_recv(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readlittle") == 0 && argc == 4)
        scenario_read_little(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "fdreuse") == 0 && argc == 5)
        scenario_fd_reuse(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "rename") == 0 && argc == 5)
        scenario_rename(argv[2], argv[3], arg_size(argv[4]));
    else if (strcmp(name, "unlink") == 0 && argc == 4)
        scenario_unlink(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "udp") == 0 && argc >= 3)
        scenario_udp(arg_size(argv[2]), argc > 3 && strcmp(argv[3], "ipv6") == 0);
    else if (strcmp(name, "child") == 0 && argc == 4)
        scenario_child(argv[2], arg_size(argv[3]));
    else {
        fprintf(stderr, "usage: %s <scenario> <arguments>\n", argv[0]);
        return 2;
    }
    return 0;
}
