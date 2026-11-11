/* Times the system calls the probes attach to, in nanoseconds per call. */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

[[noreturn]] static void die(const char *what)
{
    perror(what);
    exit(1);
}

static double now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

/* A loopback TCP connection to a child that discards everything it receives. */
static int connect_to_sink(pid_t *sink)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(addr);
    int listener = socket(AF_INET, SOCK_STREAM, 0);

    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0 || getsockname(listener, (struct sockaddr *)&addr, &len) != 0)
        die("listen");

    *sink = fork();
    if (*sink < 0)
        die("fork");
    if (*sink == 0) {
        static char buf[1 << 20];
        int c = accept(listener, nullptr, nullptr);
        while (c >= 0 && read(c, buf, sizeof(buf)) > 0)
            continue;
        _exit(0);
    }
    close(listener);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    if (sock < 0 || connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("connect");
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return sock;
}

static int make_file(const char *path, size_t size)
{
    static char block[65536];
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);

    if (fd < 0)
        die(path);
    for (size_t done = 0; done < size; done += sizeof(block)) {
        if (write(fd, block, sizeof(block)) != (ssize_t)sizeof(block))
            die("write");
    }
    return fd;
}

static double bench_send(long count, size_t size)
{
    static char buf[65536];
    pid_t sink;
    int sock = connect_to_sink(&sink);

    double start = now_ns();
    for (long i = 0; i < count; i++) {
        if (send(sock, buf, size, 0) != (ssize_t)size)
            die("send");
    }
    double elapsed = now_ns() - start;

    close(sock);
    waitpid(sink, nullptr, 0);
    return elapsed / (double)count;
}

static double bench_read(const char *path, long count, size_t size)
{
    static char buf[65536];
    int fd = make_file(path, 1 << 20);

    double start = now_ns();
    for (long i = 0; i < count; i++) {
        if (pread(fd, buf, size, (off_t)((size_t)i * size % (1 << 20))) != (ssize_t)size)
            die("pread");
    }
    double elapsed = now_ns() - start;

    close(fd);
    unlink(path);
    return elapsed / (double)count;
}

/* The copy loop of a server without sendfile: one read and one send per chunk. */
static double bench_read_send(const char *path, long count, size_t size)
{
    static char buf[65536];
    pid_t sink;
    int fd = make_file(path, 1 << 20);
    int sock = connect_to_sink(&sink);

    double start = now_ns();
    for (long i = 0; i < count; i++) {
        if (pread(fd, buf, size, (off_t)((size_t)i * size % (1 << 20))) != (ssize_t)size)
            die("pread");
        if (send(sock, buf, size, 0) != (ssize_t)size)
            die("send");
    }
    double elapsed = now_ns() - start;

    close(sock);
    close(fd);
    unlink(path);
    waitpid(sink, nullptr, 0);
    return elapsed / (double)count;
}

static double bench_sendfile(const char *path, long count, size_t size)
{
    pid_t sink;
    int fd = make_file(path, 1 << 20);
    int sock = connect_to_sink(&sink);

    double start = now_ns();
    for (long i = 0; i < count; i++) {
        off_t off = (off_t)((size_t)i * size % (1 << 20));
        if (sendfile(sock, fd, &off, size) != (ssize_t)size)
            die("sendfile");
    }
    double elapsed = now_ns() - start;

    close(sock);
    close(fd);
    unlink(path);
    waitpid(sink, nullptr, 0);
    return elapsed / (double)count;
}

/* The fastest of several runs is the least disturbed by other activity. */
static double best_of(int runs, double (*fn)(const char *, long, size_t), const char *path,
                      long count, size_t size)
{
    double best = 0;
    for (int i = 0; i < runs; i++) {
        double ns = fn(path, count, size);
        if (i == 0 || ns < best)
            best = ns;
    }
    return best;
}

static double send_only(const char *path, long count, size_t size)
{
    (void)path;
    return bench_send(count, size);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "/var/tmp/filetrace-bench.bin";
    long scale = argc > 2 ? atol(argv[2]) : 1;

    signal(SIGPIPE, SIG_IGN);
    printf("send_1k %.0f\n", best_of(5, send_only, path, 400000 * scale, 1024));
    printf("pread_4k %.0f\n", best_of(5, bench_read, path, 2000000 * scale, 4096));
    printf("read_send_16k %.0f\n", best_of(5, bench_read_send, path, 200000 * scale, 16384));
    printf("sendfile_64k %.0f\n", best_of(5, bench_sendfile, path, 50000 * scale, 65536));
    return 0;
}
