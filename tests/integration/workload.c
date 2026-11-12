#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
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

/* steady <path> <bytes> <seconds>: announced first, then sent evenly over that time */
static void scenario_steady(const char *path, size_t size, size_t seconds)
{
    constexpr size_t SLICES_PER_SECOND = 20;
    struct timespec pause = {.tv_nsec = 1'000'000'000 / SLICES_PER_SECOND};
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    size_t slices = seconds ? seconds * SLICES_PER_SECOND : 1;

    make_file(path, size);
    int file = open_file(path);
    int sock = connect_sink(&sink);
    report("steady", path, size, sink.port);
    fflush(stdout);
    for (size_t i = 0; i < slices; i++) {
        sendfile_span(sock, file, size / slices * i,
                      i + 1 == slices ? size : size / slices * (i + 1));
        nanosleep(&pause, nullptr);
    }
    close(sock);
    close(file);
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

/*
 * readhandshake <path> <bytes> <bundle> <bundle bytes>: an upload over a fresh connection, as
 * an HTTPS client makes it. The file is read whole, then a CA bundle unless its size is 0;
 * then the peers trade a hello each way, and only then is the file sent.
 */
static void scenario_read_handshake(const char *path, size_t size, const char *bundle,
                                    size_t bundle_size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, true);
    make_file(path, size);

    char *contents = malloc(size);
    char *trust = malloc(bundle_size ? bundle_size : 1);
    char greeting[6];
    if (!contents || !trust)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    int ca = -1;
    if (bundle_size) {
        make_file(bundle, bundle_size);
        ca = open_file(bundle);
        if (read(ca, trust, bundle_size) != (ssize_t)bundle_size)
            die("read");
    }
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    if (recv(sock, greeting, sizeof(greeting), MSG_WAITALL) != (ssize_t)sizeof(greeting))
        die("recv");
    send_all(sock, contents, size);
    close(sock);
    if (ca >= 0)
        close(ca);
    close(file);
    free(contents);
    free(trust);
    report("readhandshake", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readmemory <path> <bytes>: reads the file, then connects, trades a hello each way and sends
 * that many bytes from memory, as a client that loads a module or a bundle before it uploads.
 */
static void scenario_read_memory(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, true);
    make_file(path, 25000);

    char *contents = malloc(25000);
    char *body = calloc(1, size);
    char greeting[6];
    if (!contents || !body)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, 25000) != 25000)
        die("read");
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    if (recv(sock, greeting, sizeof(greeting), MSG_WAITALL) != (ssize_t)sizeof(greeting))
        die("recv");
    send_all(sock, body, size);
    close(sock);
    close(file);
    free(contents);
    free(body);
    report("readmemory", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readrefused <path> <bytes>: like readhandshake without a bundle, but the first connection is
 * refused, as a client's first address can be, and the file goes out over the second.
 */
static void scenario_read_refused(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, true);
    make_file(path, size);

    /* A port that was just free on the sink's address, with nothing listening on it now. */
    struct sockaddr_storage closed = sink.addr;
    int probe = socket(sink.addr.ss_family, SOCK_STREAM, 0);
    socklen_t len = sink.addr_len;
    ((struct sockaddr_in *)&closed)->sin_port = 0;
    if (probe < 0 || bind(probe, (struct sockaddr *)&closed, len) != 0 ||
        getsockname(probe, (struct sockaddr *)&closed, &len) != 0)
        die("bind");
    close(probe);

    char *contents = malloc(size);
    char greeting[6];
    if (!contents)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    int refused = socket(sink.addr.ss_family, SOCK_STREAM, 0);
    if (refused < 0 || connect(refused, (struct sockaddr *)&closed, len) == 0)
        die("connect to a closed port");
    close(refused);
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    if (recv(sock, greeting, sizeof(greeting), MSG_WAITALL) != (ssize_t)sizeof(greeting))
        die("recv");
    send_all(sock, contents, size);
    close(sock);
    close(file);
    free(contents);
    report("readrefused", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readrecvelsewhere <path> <bytes> <bundle> <bundle bytes>: like readhandshake, but the hello
 * comes back on a second connection, and the file then goes out on the first.
 */
static void scenario_read_recv_elsewhere(const char *path, size_t size, const char *bundle,
                                         size_t bundle_size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    struct sink other = start_sink(SOCK_STREAM, false, true);
    make_file(path, size);
    make_file(bundle, bundle_size);

    char *contents = malloc(size);
    char *trust = malloc(bundle_size);
    char greeting[6];
    if (!contents || !trust)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    int ca = open_file(bundle);
    if (read(ca, trust, bundle_size) != (ssize_t)bundle_size)
        die("read");
    int sock = connect_sink(&sink);
    int elsewhere = connect_sink(&other);
    send_all(sock, "hello\n", 6);
    if (recv(elsewhere, greeting, sizeof(greeting), MSG_WAITALL) != (ssize_t)sizeof(greeting))
        die("recv");
    send_all(sock, contents, size);
    close(elsewhere);
    close(sock);
    close(ca);
    close(file);
    free(contents);
    free(trust);
    report("readrecvelsewhere", path, size, sink.port);
    stop_sink(&other);
    stop_sink(&sink);
}

/*
 * readbundle <path> <bytes> <bundle> <bundle bytes>: the file is read whole, then a CA bundle,
 * and the file is sent with nothing received in between.
 */
static void scenario_read_bundle(const char *path, size_t size, const char *bundle,
                                 size_t bundle_size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    make_file(path, size);
    make_file(bundle, bundle_size);

    char *contents = malloc(size);
    char *trust = malloc(bundle_size);
    if (!contents || !trust)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    int ca = open_file(bundle);
    if (read(ca, trust, bundle_size) != (ssize_t)bundle_size)
        die("read");
    int sock = connect_sink(&sink);
    send_all(sock, contents, size);
    close(sock);
    close(ca);
    close(file);
    free(contents);
    free(trust);
    report("readbundle", path, size, sink.port);
    stop_sink(&sink);
}

/* upload <path> <chunk>: sends a file that already exists, in reads of chunk bytes */
static void scenario_upload(const char *path, size_t chunk)
{
    struct sink sink = start_sink(SOCK_STREAM, false, false);
    int file = open_file(path);
    int sock = connect_sink(&sink);
    read_send(sock, file, chunk);
    close(sock);
    close(file);
    report("upload", path, 0, sink.port);
    stop_sink(&sink);
}

static void read_whole(const char *path)
{
    int file = open_file(path);
    char buf[65536];
    ssize_t n;
    while ((n = read(file, buf, sizeof(buf))) > 0) {
    }
    if (n < 0)
        die("read");
    close(file);
}

/* read <path>: reads the file and sends nothing */
static void scenario_read(const char *path)
{
    read_whole(path);
    printf("scenario=read pid=%d path=%s\n", (int)getpid(), path);
}

/*
 * nsread <dir> <mount point> <name>: reads dir/name through a bind mount of dir on the mount
 * point in a mount namespace of its own, as a process in a container sees its files.
 */
static void scenario_ns_read(const char *dir, const char *mount_point, const char *name)
{
    if (unshare(CLONE_NEWNS) != 0)
        die("unshare");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0)
        die("mount private");
    if (mount(dir, mount_point, nullptr, MS_BIND, nullptr) != 0)
        die("mount bind");

    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", mount_point, name);
    read_whole(path);
    printf("scenario=nsread pid=%d path=%s\n", (int)getpid(), path);
}

/*
 * fifolib <dir>: maps dir/libphp-ft.so as code, then in a mount namespace of its own leaves a
 * FIFO at that path, and forks: what a web server's maps name is not what is at the path.
 */
static void scenario_fifo_lib(const char *dir)
{
    char path[4096];
    snprintf(path, sizeof(path), "%s/libphp-ft.so", dir);
    make_file(path, 65536);
    int fd = open_file(path);
    void *code = mmap(nullptr, 65536, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (code == MAP_FAILED)
        die("mmap");
    close(fd);

    if (unshare(CLONE_NEWNS) != 0)
        die("unshare");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0)
        die("mount private");
    if (mount("tmpfs", dir, "tmpfs", 0, nullptr) != 0)
        die("mount tmpfs");
    if (mkfifo(path, 0644) != 0)
        die("mkfifo");

    pid_t child = fork();
    if (child < 0)
        die("fork");
    if (child == 0) {
        sleep(2);
        _exit(0);
    }
    waitpid(child, nullptr, 0);
    printf("scenario=fifolib pid=%d child=%d\n", (int)getpid(), (int)child);
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

static int listen_loopback(struct sockaddr_in *addr)
{
    socklen_t len = sizeof(*addr);
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    *addr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (fd < 0 || bind(fd, (struct sockaddr *)addr, sizeof(*addr)) != 0 || listen(fd, 1) != 0 ||
        getsockname(fd, (struct sockaddr *)addr, &len) != 0)
        die("listen");
    return fd;
}

/*
 * duplex <request-bytes> <reply-bytes>: a half-closed exchange in which the
 * reply is peeked at, awaited in full, and read after the connection ended
 */
static void scenario_duplex(size_t request, size_t reply)
{
    struct sockaddr_in addr;
    int listener = listen_loopback(&addr);
    char *buf = calloc(1, request > reply ? request : reply);
    if (!buf)
        die("malloc");

    pid_t server = fork();
    if (server < 0)
        die("fork");
    if (server == 0) {
        int c = accept(listener, nullptr, nullptr);
        int one = 1;
        char block[4096];
        size_t got = 0;

        setsockopt(c, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
        if (recv(c, block, 100, MSG_PEEK | MSG_WAITALL) != 100)
            _exit(1);
        for (ssize_t n; (n = read(c, block, sizeof(block))) > 0;)
            got += (size_t)n;
        /* The reply leaves in pieces so that the peer has to wait for all of it. */
        for (size_t off = 0; off < reply; off += reply / 3 + 1) {
            size_t n = reply - off < reply / 3 + 1 ? reply - off : reply / 3 + 1;
            send_all(c, buf + off, n);
            usleep(50 * 1000);
        }
        close(c);
        _exit(got == request ? 0 : 1);
    }
    close(listener);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 || connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("connect");
    send_all(sock, buf, request);
    shutdown(sock, SHUT_WR);

    int status;
    waitpid(server, &status, 0);
    usleep(100 * 1000);
    /* The peer has gone: the whole reply and its FIN are already queued. */
    if (recv(sock, buf, 10, MSG_PEEK) != 10)
        die("peek");
    if (recv(sock, buf, reply, MSG_WAITALL) != (ssize_t)reply)
        die("recv");
    if (recv(sock, buf, 1, 0) != 0)
        die("expected end of stream");
    close(sock);
    free(buf);
    printf("scenario=duplex pid=%d server=%d port=%d status=%d\n", (int)getpid(), (int)server,
           ntohs(addr.sin_port), WEXITSTATUS(status));
}

/* A sink behind small buffers, so that the sender's calls are cut short. */
static struct sink start_slow_sink(void)
{
    struct sockaddr_in addr;
    struct sink s = {0};
    int small = 4096;
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    socklen_t len = sizeof(addr);

    addr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    setsockopt(listener, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(listener, 1) != 0 || getsockname(listener, (struct sockaddr *)&addr, &len) != 0)
        die("listen");

    memcpy(&s.addr, &addr, sizeof(addr));
    s.addr_len = sizeof(addr);
    s.port = ntohs(addr.sin_port);
    s.pid = fork();
    if (s.pid < 0)
        die("fork");
    if (s.pid == 0) {
        char buf[8192];
        int c = accept(listener, nullptr, nullptr);
        while (c >= 0 && read(c, buf, sizeof(buf)) > 0)
            usleep(200);
        _exit(0);
    }
    close(listener);
    return s;
}

static int connect_nonblocking(const struct sink *s)
{
    int small = 4096;
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    if (sock < 0 || connect(sock, (const struct sockaddr *)&s->addr, s->addr_len) != 0)
        die("connect");
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
    return sock;
}

static void wait_writable(int sock)
{
    struct pollfd pfd = {.fd = sock, .events = POLLOUT};
    poll(&pfd, 1, 1000);
}

/* partialsend <path> <bytes>: every send is accepted only in part */
static void scenario_partial_send(const char *path, size_t size)
{
    struct sink sink = start_slow_sink();
    make_file(path, size);

    int file = open_file(path);
    int sock = connect_nonblocking(&sink);
    char *buf = malloc(262144);
    size_t calls = 0;
    if (!buf)
        die("malloc");

    for (ssize_t got; (got = read(file, buf, 262144)) > 0;) {
        for (size_t off = 0; off < (size_t)got;) {
            ssize_t n = send(sock, buf + off, (size_t)got - off, 0);
            calls++;
            if (n > 0)
                off += (size_t)n;
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                wait_writable(sock);
            else
                die("send");
        }
    }
    close(sock);
    close(file);
    free(buf);
    printf("scenario=partialsend pid=%d port=%d bytes=%zu calls=%zu file=%s\n", (int)getpid(),
           sink.port, size, calls, path);
    waitpid(sink.pid, nullptr, 0);
}

/* partialsendfile <path> <bytes>: every sendfile moves only part of what is left */
static void scenario_partial_sendfile(const char *path, size_t size)
{
    struct sink sink = start_slow_sink();
    make_file(path, size);

    int file = open_file(path);
    int sock = connect_nonblocking(&sink);
    size_t calls = 0;

    for (off_t off = 0; (size_t)off < size;) {
        ssize_t n = sendfile(sock, file, &off, size - (size_t)off);
        calls++;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            wait_writable(sock);
        else if (n <= 0)
            die("sendfile");
    }
    close(sock);
    close(file);
    printf("scenario=partialsendfile pid=%d port=%d bytes=%zu calls=%zu file=%s\n", (int)getpid(),
           sink.port, size, calls, path);
    waitpid(sink.pid, nullptr, 0);
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
    else if (strcmp(name, "steady") == 0 && argc == 5)
        scenario_steady(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readsend") == 0 && argc == 5)
        scenario_readsend(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readthenrecv") == 0 && argc == 4)
        scenario_read_then_recv(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readhandshake") == 0 && argc == 6)
        scenario_read_handshake(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "readmemory") == 0 && argc == 4)
        scenario_read_memory(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readrefused") == 0 && argc == 4)
        scenario_read_refused(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readrecvelsewhere") == 0 && argc == 6)
        scenario_read_recv_elsewhere(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "readbundle") == 0 && argc == 6)
        scenario_read_bundle(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "fifolib") == 0 && argc == 3)
        scenario_fifo_lib(argv[2]);
    else if (strcmp(name, "read") == 0 && argc == 3)
        scenario_read(argv[2]);
    else if (strcmp(name, "nsread") == 0 && argc == 5)
        scenario_ns_read(argv[2], argv[3], argv[4]);
    else if (strcmp(name, "upload") == 0 && argc == 4)
        scenario_upload(argv[2], arg_size(argv[3]));
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
    else if (strcmp(name, "duplex") == 0 && argc == 4)
        scenario_duplex(arg_size(argv[2]), arg_size(argv[3]));
    else if (strcmp(name, "partialsend") == 0 && argc == 4)
        scenario_partial_send(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "partialsendfile") == 0 && argc == 4)
        scenario_partial_sendfile(argv[2], arg_size(argv[3]));
    else {
        fprintf(stderr, "usage: %s <scenario> <arguments>\n", argv[0]);
        return 2;
    }
    return 0;
}
