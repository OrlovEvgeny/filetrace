#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
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

enum sink_mode {
    SINK_DISCARD, /* reads and discards what each peer sends */
    SINK_GREET,   /* sends one line to each peer first */
    SINK_ANSWER,  /* answers each read with one line, as a server answers requests */
    SINK_STALL,   /* greets each peer and reads nothing for two seconds */
    SINK_LATE,    /* answers each read, from half a second after the peer connected */
    SINK_HANGUP,  /* closes after its first read, saying nothing */
    SINK_RESET,   /* resets the connection after its first read */
    SINK_HOLD,    /* greets each peer and reads nothing for four seconds, into a small buffer */
};

static struct sink start_sink(int type, bool ipv6, enum sink_mode mode)
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
    int small = 2048;
    if (mode == SINK_HOLD && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) != 0)
        die("setsockopt");
    if (type == SOCK_STREAM && listen(fd, 64) != 0)
        die("listen");

    s.pid = fork();
    if (s.pid < 0)
        die("fork");
    if (s.pid == 0) {
        char buf[65536];
        if (type == SOCK_DGRAM) {
            struct sockaddr_storage peer;
            socklen_t len = sizeof(peer);
            while (recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &len) > 0) {
                if (mode == SINK_ANSWER &&
                    sendto(fd, "hello\n", 6, 0, (struct sockaddr *)&peer, len) != 6)
                    _exit(1);
                len = sizeof(peer);
            }
            _exit(0);
        }
        for (;;) {
            int c = accept(fd, nullptr, nullptr);
            if (c < 0)
                _exit(0);
            if ((mode == SINK_GREET || mode == SINK_STALL || mode == SINK_HOLD) &&
                write(c, "hello\n", 6) != 6)
                _exit(1);
            if (mode == SINK_STALL)
                sleep(2);
            if (mode == SINK_HOLD)
                sleep(4);
            if (mode == SINK_LATE)
                usleep(500 * 1000);
            if (mode == SINK_HANGUP || mode == SINK_RESET) {
                struct linger abort = {.l_onoff = 1, .l_linger = 0};
                if (read(c, buf, sizeof(buf)) > 0 && mode == SINK_RESET)
                    setsockopt(c, SOL_SOCKET, SO_LINGER, &abort, sizeof(abort));
                close(c);
                continue;
            }
            while (read(c, buf, sizeof(buf)) > 0) {
                if ((mode == SINK_ANSWER || mode == SINK_LATE) && write(c, "hello\n", 6) != 6)
                    _exit(1);
            }
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
    struct sink sink = start_sink(SOCK_STREAM, ipv6, SINK_DISCARD);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
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

/* When a client that uploads over a fresh connection reads its CA bundle. */
enum bundle_order {
    BUNDLE_AFTER_FILE,
    BUNDLE_FIRST,
    BUNDLE_AFTER_HELLO, /* as curl reads --cacert */
};

/*
 * readhandshake <path> <bytes> <bundle> <bundle bytes>: an upload over a fresh connection, as
 * an HTTPS client makes it. The file is read whole, then a CA bundle unless its size is 0;
 * then the peers trade a hello each way, and only then is the file sent. readbundlefirst reads
 * the bundle before the file, readbundlelate after sending the hello.
 */
static void scenario_read_handshake(const char *path, size_t size, const char *bundle,
                                    size_t bundle_size, enum bundle_order order)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    make_file(path, size);

    char *contents = malloc(size);
    char *trust = malloc(bundle_size ? bundle_size : 1);
    char greeting[6];
    if (!contents || !trust)
        die("malloc");
    int ca = -1;
    if (bundle_size) {
        make_file(bundle, bundle_size);
        ca = open_file(bundle);
        if (order == BUNDLE_FIRST && read(ca, trust, bundle_size) != (ssize_t)bundle_size)
            die("read");
    }
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    if (ca >= 0 && order == BUNDLE_AFTER_FILE &&
        read(ca, trust, bundle_size) != (ssize_t)bundle_size)
        die("read");
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    if (ca >= 0 && order == BUNDLE_AFTER_HELLO &&
        read(ca, trust, bundle_size) != (ssize_t)bundle_size)
        die("read");
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

static char *read_whole_file(const char *path, size_t size);

/*
 * readsendother <path> <bytes> <other> <other bytes>: over a connection that has already heard
 * from its peer, reads the file whole and sends nothing of it, as a checksum pass does, then
 * reads the other file and sends that, after reading a background file if one is named.
 * readloadsend sends the first file, as a program that loads a module between reading its
 * upload and sending it.
 */
static void scenario_read_send_other(const char *path, size_t size, const char *other,
                                     size_t other_size, bool send_first, const char *background)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    make_file(path, size);
    make_file(other, other_size);

    char *contents = malloc(size);
    char *upload = malloc(other_size);
    char greeting[6];
    if (!contents || !upload)
        die("malloc");
    int sock = connect_sink(&sink);
    if (recv(sock, greeting, sizeof(greeting), MSG_WAITALL) != (ssize_t)sizeof(greeting))
        die("recv");
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    int up = open_file(other);
    if (read(up, upload, other_size) != (ssize_t)other_size)
        die("read");
    if (background)
        free(read_whole_file(background, 2000));
    if (send_first)
        send_all(sock, contents, size);
    else
        send_all(sock, upload, other_size);
    close(sock);
    close(up);
    close(file);
    free(contents);
    free(upload);
    report("readsendother", other, other_size, sink.port);
    stop_sink(&sink);
}

/* Makes the file and reads it whole into memory. */
static char *read_whole_file(const char *path, size_t size)
{
    make_file(path, size);
    char *contents = malloc(size ? size : 1);
    if (!contents)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    close(file);
    return contents;
}

static void hear(int sock)
{
    char answer[6];
    if (recv(sock, answer, sizeof(answer), MSG_WAITALL) != (ssize_t)sizeof(answer))
        die("recv");
}

/*
 * readlookup <path> <bytes> and readnotify <path> <bytes>: read the file, send a datagram, as a
 * name lookup or a metric does, and with readlookup hear the answer; then connect, trade a
 * hello each way and send the file.
 */
static void scenario_read_lookup(const char *path, size_t size, bool answered)
{
    struct sink resolver = start_sink(SOCK_DGRAM, false, answered ? SINK_ANSWER : SINK_DISCARD);
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    char *contents = read_whole_file(path, size);
    char query[40] = {0};

    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0 || sendto(udp, query, sizeof(query), 0, (struct sockaddr *)&resolver.addr,
                          resolver.addr_len) != (ssize_t)sizeof(query))
        die("sendto");
    if (answered)
        hear(udp);
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    send_all(sock, contents, size);
    close(sock);
    close(udp);
    free(contents);
    report(answered ? "readlookup" : "readnotify", path, size, sink.port);
    stop_sink(&sink);
    stop_sink(&resolver);
}

/*
 * readretry <path> <bytes>: reads the file, connects, sends a hello and gives the connection
 * up, then sends the file over a second one after trading a hello each way.
 */
static void scenario_read_retry(const char *path, size_t size)
{
    struct sink first = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    char *contents = read_whole_file(path, size);
    char hello[1566] = {0};

    int abandoned = connect_sink(&first);
    send_all(abandoned, hello, sizeof(hello));
    close(abandoned);
    int sock = connect_sink(&sink);
    send_all(sock, hello, sizeof(hello));
    hear(sock);
    send_all(sock, contents, size);
    close(sock);
    free(contents);
    report("readretry", path, size, sink.port);
    stop_sink(&sink);
    stop_sink(&first);
}

/*
 * twoflights <path> <bytes>: opens two connections, reads the file, as a client reads a CA
 * file for each, and sends a hello on each before either answers; then a request on each.
 */
static void scenario_two_flights(const char *path, size_t size)
{
    struct sink one = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    struct sink two = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char hello[1566] = {0};
    char request[600] = {0};

    int a = connect_sink(&one);
    int b = connect_sink(&two);
    char *contents = read_whole_file(path, size);
    send_all(a, hello, sizeof(hello));
    send_all(b, hello, sizeof(hello));
    hear(a);
    hear(b);
    send_all(a, request, sizeof(request));
    send_all(b, request, sizeof(request));
    hear(a);
    hear(b);
    close(a);
    close(b);
    free(contents);
    report("twoflights", path, size, one.port);
    stop_sink(&two);
    stop_sink(&one);
}

/*
 * readsideconnect <path> <bytes>: over a connection that has heard from its peer, reads the
 * file, connects to another service and sends it a little, then sends the file over the first.
 */
static void scenario_read_side_connect(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    struct sink side = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    char note[80] = {0};

    int sock = connect_sink(&sink);
    hear(sock);
    char *contents = read_whole_file(path, size);
    int other = connect_sink(&side);
    send_all(other, note, sizeof(note));
    send_all(sock, contents, size);
    close(other);
    close(sock);
    free(contents);
    report("readsideconnect", path, size, sink.port);
    stop_sink(&side);
    stop_sink(&sink);
}

/*
 * readsidehandshake <path> <bytes>: reads the file, connects and trades a hello each way, then
 * makes a small request over a second connection, as a client checks a certificate's status,
 * and sends the file over the first.
 */
static void scenario_read_side_handshake(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    struct sink side = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char note[80] = {0};

    char *contents = read_whole_file(path, size);
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    int other = connect_sink(&side);
    send_all(other, note, sizeof(note));
    hear(other);
    send_all(sock, contents, size);
    close(other);
    close(sock);
    free(contents);
    report("readsidehandshake", path, size, sink.port);
    stop_sink(&side);
    stop_sink(&sink);
}

/*
 * twofiles <path> <other> <bytes>: over a fresh connection that never answers, reads and sends
 * one file whole, then the other.
 */
static void scenario_two_files(const char *path, const char *other, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    int sock = connect_sink(&sink);
    char *first = read_whole_file(path, size);
    send_all(sock, first, size);
    char *second = read_whole_file(other, size);
    send_all(sock, second, size);
    close(sock);
    free(first);
    free(second);
    report("twofiles", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readkeepalive <path> <bytes> <next bytes>: reads the file, connects, trades a hello each way,
 * sends the file and hears the answer, then makes another request over the same connection.
 */
static void scenario_read_keepalive(const char *path, size_t size, size_t next)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char *contents = read_whole_file(path, size);
    char *request = calloc(1, next);
    if (!request)
        die("malloc");

    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    send_all(sock, contents, size);
    hear(sock);
    send_all(sock, request, next);
    hear(sock);
    close(sock);
    free(contents);
    free(request);
    report("readkeepalive", path, size, sink.port);
    stop_sink(&sink);
}

static size_t arg_size(const char *text);

/*
 * respond <head> <reply> <rounds> <path> <bytes> [<path> <bytes>...]: answers requests over a
 * connection that has heard from its peer, as a server does. For each request it reads a file
 * whole and sends a head of that many bytes and then, with reply 0, the file, or else that many
 * bytes from memory; the next request ends the reply.
 */
static void scenario_respond(size_t head, size_t reply, size_t rounds, char **files, int nfiles)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char *header = calloc(1, head ? head : 1);
    char *body = calloc(1, reply ? reply : 1);
    if (!header || !body)
        die("malloc");

    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    for (size_t r = 0; r < rounds; r++) {
        for (int i = 0; i + 1 < nfiles; i += 2) {
            size_t size = arg_size(files[i + 1]);
            char *contents = read_whole_file(files[i], size);
            send_all(sock, header, head);
            if (reply)
                send_all(sock, body, reply);
            else
                send_all(sock, contents, size);
            hear(sock);
            free(contents);
        }
    }
    close(sock);
    free(header);
    free(body);
    report("respond", files[0], 0, sink.port);
    stop_sink(&sink);
}

/*
 * respondtwo <path> <bytes> <reply>: one thread serves two connections, as an event loop does.
 * It replies on the first as respond does, then hears a request on the second, and then sends
 * more on the first without hearing from it.
 */
static void scenario_respond_two(const char *path, size_t size, size_t reply)
{
    struct sink one = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    struct sink two = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char header[300] = {0};
    char *body = calloc(1, reply ? reply : 1);
    char *more = calloc(1, 20000);
    if (!body || !more)
        die("malloc");

    int a = connect_sink(&one);
    int b = connect_sink(&two);
    send_all(a, "hello\n", 6);
    hear(a);
    send_all(b, "hello\n", 6);
    hear(b);
    char *contents = read_whole_file(path, size);
    send_all(a, header, sizeof(header));
    if (reply)
        send_all(a, body, reply);
    else
        send_all(a, contents, size);
    send_all(b, "hello\n", 6);
    hear(b);
    send_all(a, more, 20000);
    close(b);
    close(a);
    free(contents);
    free(body);
    free(more);
    report("respondtwo", path, size, one.port);
    stop_sink(&two);
    stop_sink(&one);
}

/*
 * readstream <path> <bytes> <first>: reads the first bytes of the file, connects, then sends them
 * and the rest in pieces as it reads them. readsniff sends a request head instead of the first
 * bytes, which it only looked at.
 */
static void scenario_read_stream(const char *path, size_t size, size_t first, bool sniff)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    make_file(path, size);
    char buf[16384];
    char request[300] = {0};
    int file = open_file(path);
    char *head = malloc(first);
    if (!head || read(file, head, first) != (ssize_t)first)
        die("read");
    int sock = connect_sink(&sink);
    if (sniff)
        send_all(sock, request, sizeof(request));
    else
        send_all(sock, head, first);
    ssize_t n;
    while ((n = read(file, buf, sizeof(buf))) > 0)
        send_all(sock, buf, (size_t)n);
    close(sock);
    close(file);
    free(head);
    report("readstream", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readlater <path> <bytes> <other> <other bytes> <seconds> <send bytes>: over a connection that
 * has heard from its peer, reads both files, waits, then sends that many bytes from memory.
 */
static void scenario_read_later(const char *path, size_t size, const char *other, size_t other_size,
                                size_t seconds, size_t send)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    int sock = connect_sink(&sink);
    hear(sock);
    char *a = read_whole_file(path, size);
    char *b = read_whole_file(other, other_size);
    char *body = calloc(1, send);
    if (!body)
        die("malloc");
    sleep((unsigned)seconds);
    send_all(sock, body, send);
    close(sock);
    free(a);
    free(b);
    free(body);
    report("readlater", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * twodials <path> <bytes>: reads the file, connects and sends a line, then connects again, trades
 * a hello each way and sends a body of 100 KB from memory.
 */
static void scenario_two_dials(const char *path, size_t size)
{
    struct sink one = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    struct sink two = start_sink(SOCK_STREAM, false, SINK_GREET);
    char *contents = read_whole_file(path, size);
    char line[30] = {0};
    char *body = calloc(1, 100000);
    if (!body)
        die("malloc");
    int a = connect_sink(&one);
    send_all(a, line, sizeof(line));
    int b = connect_sink(&two);
    send_all(b, "hello\n", 6);
    hear(b);
    send_all(b, body, 100000);
    close(b);
    close(a);
    free(contents);
    free(body);
    report("twodials", path, size, two.port);
    stop_sink(&two);
    stop_sink(&one);
}

/* readsendfile <path> <bytes>: reads the file whole, connects, sends a head, then sendfile. */
static void scenario_read_sendfile(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    char *contents = read_whole_file(path, size);
    char head[300] = {0};
    int file = open_file(path);
    int sock = connect_sink(&sink);
    send_all(sock, head, sizeof(head));
    sendfile_all(sock, file, size);
    close(sock);
    close(file);
    free(contents);
    report("readsendfile", path, size, sink.port);
    stop_sink(&sink);
}

/* fanout <path> <bytes>: reads the file, connects to two servers and sends it to both. */
static void scenario_fan_out(const char *path, size_t size)
{
    struct sink one = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    struct sink two = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    char *contents = read_whole_file(path, size);
    int a = connect_sink(&one);
    int b = connect_sink(&two);
    send_all(a, contents, size);
    send_all(b, contents, size);
    close(b);
    close(a);
    free(contents);
    report("fanout", path, size, one.port);
    stop_sink(&two);
    stop_sink(&one);
}

/*
 * readchatty <path> <bytes>: reads the file, connects to two servers, sends the file to one and
 * makes 50 small requests of the other, each answered.
 */
static void scenario_read_chatty(const char *path, size_t size)
{
    struct sink one = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    struct sink two = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char *contents = read_whole_file(path, size);
    char request[200] = {0};
    int a = connect_sink(&one);
    int b = connect_sink(&two);
    send_all(a, contents, size);
    for (int i = 0; i < 50; i++) {
        send_all(b, request, sizeof(request));
        hear(b);
    }
    close(b);
    close(a);
    free(contents);
    report("readchatty", path, size, one.port);
    stop_sink(&two);
    stop_sink(&one);
}

/*
 * readtwo <path> <bytes> <other> <other bytes> <which>: reads both files, connects, trades a hello
 * each way and sends the first (which 1) or the second (which 2).
 */
static void scenario_read_two(const char *path, size_t size, const char *other, size_t other_size,
                              size_t which)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    char *a = read_whole_file(path, size);
    char *b = read_whole_file(other, other_size);
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    if (which == 1)
        send_all(sock, a, size);
    else
        send_all(sock, b, other_size);
    close(sock);
    free(a);
    free(b);
    report("readtwo", path, size, sink.port);
    stop_sink(&sink);
}

/* readsmall <path> <bytes>: reads a small file, connects, sends it and closes. */
static void scenario_read_small(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    char *contents = read_whole_file(path, size);
    int sock = connect_sink(&sink);
    send_all(sock, contents, size);
    close(sock);
    free(contents);
    report("readsmall", path, size, sink.port);
    stop_sink(&sink);
}

struct reader {
    int sock;
    int count;
};

static void *read_answers(void *arg)
{
    struct reader *r = arg;
    for (int i = 0; i < r->count; i++)
        hear(r->sock);
    return nullptr;
}

/*
 * readreplythread <path> <bytes>: reads the file, connects and sends it; another thread reads
 * the answers, while this one then makes 60 small requests over the same connection.
 */
static void scenario_read_reply_thread(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char *contents = read_whole_file(path, size);
    char request[1000] = {0};
    int sock = connect_sink(&sink);
    send_all(sock, contents, size);
    struct reader r = {.sock = sock, .count = 1};
    pthread_t answers;
    if (pthread_create(&answers, nullptr, read_answers, &r) != 0)
        die("pthread_create");
    pthread_join(answers, nullptr);
    for (int i = 0; i < 60; i++) {
        send_all(sock, request, sizeof(request));
        r.count = 1;
        if (pthread_create(&answers, nullptr, read_answers, &r) != 0)
            die("pthread_create");
        pthread_join(answers, nullptr);
    }
    close(sock);
    free(contents);
    report("readreplythread", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * sendlisted <before|after|heard> <path> <bytes> [<small> <small bytes>]: sends a file whole,
 * read before the connection, after it, or over one that has heard from its peer; a small
 * file is read first if one is named.
 */
static void scenario_send_listed(const char *shape, const char *path, size_t size,
                                 const char *small, size_t small_size)
{
    bool heard = strcmp(shape, "heard") == 0;
    bool before = strcmp(shape, "before") == 0;
    struct sink sink = start_sink(SOCK_STREAM, false, heard ? SINK_GREET : SINK_DISCARD);
    char *other = small ? read_whole_file(small, small_size) : nullptr;
    char *contents = before ? read_whole_file(path, size) : nullptr;
    int sock = connect_sink(&sink);
    if (heard)
        hear(sock);
    if (!contents)
        contents = read_whole_file(path, size);
    send_all(sock, contents, size);
    close(sock);
    free(contents);
    free(other);
    report("sendlisted", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readbigsmall <big> <big bytes> <small> <small bytes>: reads 4 KB of a large file, connects and
 * trades a hello each way, then reads the small file and sends it after a head, and hears the
 * answer.
 */
static void scenario_read_big_small(const char *big, size_t big_size, const char *small,
                                    size_t small_size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    make_file(big, big_size);
    char page[4096];
    char head[300] = {0};
    int db = open_file(big);
    if (pread(db, page, sizeof(page), 8192) != (ssize_t)sizeof(page))
        die("pread");
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    char *body = read_whole_file(small, small_size);
    send_all(sock, head, sizeof(head));
    send_all(sock, body, small_size);
    hear(sock);
    close(sock);
    close(db);
    free(body);
    report("readbigsmall", small, small_size, sink.port);
    stop_sink(&sink);
}

/*
 * readstreamother <path> <bytes> <other> <other bytes>: reads the file whole, connects, then
 * streams the other file in pieces and never hears from the peer, as a log shipper does.
 */
static void scenario_read_stream_other(const char *path, size_t size, const char *other,
                                       size_t other_size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    char *contents = read_whole_file(path, size);
    make_file(other, other_size);
    int sock = connect_sink(&sink);
    int file = open_file(other);
    read_send(sock, file, 16384);
    close(file);
    close(sock);
    free(contents);
    report("readstreamother", other, other_size, sink.port);
    stop_sink(&sink);
}

/*
 * parts <path> <bytes> <parts>: sends the file in parts, each read with pread and sent over a
 * fresh connection after hearing from its peer.
 */
static void scenario_parts(const char *path, size_t size, size_t parts)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    make_file(path, size);
    size_t part = size / parts;
    char *buf = malloc(part);
    int file = open_file(path);
    if (!buf)
        die("malloc");
    for (size_t i = 0; i < parts; i++) {
        if (pread(file, buf, part, (off_t)(i * part)) != (ssize_t)part)
            die("pread");
        int sock = connect_sink(&sink);
        hear(sock);
        send_all(sock, buf, part);
        close(sock);
    }
    close(file);
    free(buf);
    report("parts", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * insequence <path> <other> <bytes>: reads the file and sends it over a fresh connection after a
 * hello each way, then the same with the other file, of the same size.
 */
static void scenario_in_sequence(const char *path, const char *other, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    const char *files[2] = {path, other};
    for (int i = 0; i < 2; i++) {
        char *contents = read_whole_file(files[i], size);
        int sock = connect_sink(&sink);
        send_all(sock, "hello\n", 6);
        hear(sock);
        send_all(sock, contents, size);
        close(sock);
        free(contents);
    }
    report("insequence", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * stalesame <path> <other> <bytes> <seconds>: reads the file, waits, reads the other one of the
 * same size, connects, trades a hello each way and sends the first.
 */
static void scenario_stale_same(const char *path, const char *other, size_t size, size_t seconds)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    char *a = read_whole_file(path, size);
    sleep((unsigned)seconds);
    char *b = read_whole_file(other, size);
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    send_all(sock, a, size);
    close(sock);
    free(a);
    free(b);
    report("stalesame", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * spentthen <path> <bytes> <part>: over a connection that has heard from its peer, reads the
 * file and sends part of it; then connects again, trades a hello each way and sends a body of
 * the file's size from memory.
 */
static void scenario_spent_then(const char *path, size_t size, size_t part)
{
    struct sink first = start_sink(SOCK_STREAM, false, SINK_GREET);
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    int old = connect_sink(&first);
    hear(old);
    char *contents = read_whole_file(path, size);
    send_all(old, contents, part);
    char *body = calloc(1, size);
    if (!body)
        die("malloc");
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    send_all(sock, body, size);
    close(sock);
    close(old);
    free(contents);
    free(body);
    report("spentthen", path, size, sink.port);
    stop_sink(&sink);
    stop_sink(&first);
}

/* dialidle <path> <bytes> <seconds>: reads the file, connects, waits, then sends it. */
static void scenario_dial_idle(const char *path, size_t size, size_t seconds)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    char *contents = read_whole_file(path, size);
    int sock = connect_sink(&sink);
    sleep((unsigned)seconds);
    send_all(sock, "hello\n", 6);
    hear(sock);
    send_all(sock, contents, size);
    close(sock);
    free(contents);
    report("dialidle", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * headbody <path> <bytes> <fresh|heard|continue|early|split|split3>: connects, hearing from the
 * peer first with heard, then reads the file and sends a signed request head and the file as
 * its body, as an S3 client does, and closes. With continue, the peer answers the head before
 * the body is sent and answers the body, as with Expect: 100-continue; early is continue with
 * the file read before the connection is opened; split and split3 are early with the body sent
 * in two or three parts and an answer heard between them, as a TLS 1.3 client reads its session
 * tickets.
 */
static void scenario_head_body(const char *path, size_t size, const char *shape)
{
    bool heard = strcmp(shape, "heard") == 0;
    size_t parts = strcmp(shape, "split3") == 0 ? 3 : strcmp(shape, "split") == 0 ? 2 : 1;
    bool early = parts > 1 || strcmp(shape, "early") == 0;
    bool answered = early || strcmp(shape, "continue") == 0;
    struct sink sink = start_sink(SOCK_STREAM, false,
                                  heard      ? SINK_GREET
                                  : answered ? SINK_ANSWER
                                             : SINK_DISCARD);
    char head[1500];
    memset(head, 'H', sizeof(head));
    char *contents = early ? read_whole_file(path, size) : nullptr;
    int sock = connect_sink(&sink);
    if (heard)
        hear(sock);
    if (!early)
        contents = read_whole_file(path, size);
    send_all(sock, head, sizeof(head));
    if (answered)
        hear(sock);
    for (size_t i = 0; i < parts; i++) {
        size_t from = size * i / parts;
        size_t to = size * (i + 1) / parts;
        if (i)
            hear(sock);
        send_all(sock, contents + from, to - from);
    }
    if (answered)
        hear(sock);
    close(sock);
    free(contents);
    report("headbody", path, size, sink.port);
    stop_sink(&sink);
}

/* The size of the request head the PUT scenarios send before the file. */
enum {
    PUT_HEAD = 200
};

/*
 * twoputs <path> <bytes>: over one connection, twice reads the file and sends it after a request
 * head, hearing the answer each time, as curl -T f url1 -T f url2 does.
 */
static void scenario_two_puts(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    make_file(path, size);
    char *request = malloc(PUT_HEAD + size);
    if (!request)
        die("malloc");
    memset(request, 'H', PUT_HEAD);
    int file = open_file(path);
    int sock = connect_sink(&sink);
    for (int i = 0; i < 2; i++) {
        if (pread(file, request + PUT_HEAD, size, 0) != (ssize_t)size)
            die("pread");
        send_all(sock, request, PUT_HEAD + size);
        hear(sock);
    }
    close(sock);
    close(file);
    free(request);
    report("twoputs", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * uploadchat <path> <bytes> <exchanges>: reads the file, connects, sends it after a request head
 * and hears the answer, then makes small requests over the same connection, each answered, as a
 * keep-alive client goes on after a PUT.
 */
static void scenario_upload_chat(const char *path, size_t size, size_t exchanges)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char request[340];
    memset(request, 'q', sizeof(request));
    make_file(path, size);
    char *put = malloc(PUT_HEAD + size);
    if (!put)
        die("malloc");
    memset(put, 'H', PUT_HEAD);
    int file = open_file(path);
    if (read(file, put + PUT_HEAD, size) != (ssize_t)size)
        die("read");
    close(file);
    int sock = connect_sink(&sink);
    send_all(sock, put, PUT_HEAD + size);
    hear(sock);
    for (size_t i = 0; i < exchanges; i++) {
        send_all(sock, request, sizeof(request));
        hear(sock);
    }
    close(sock);
    free(put);
    report("uploadchat", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * sendfilethen <path> <bytes> <answered|unanswered>: reads the file, connects, sends it with
 * sendfile, with answered hears the answer, then sends as many bytes from memory over the same
 * connection.
 */
static void scenario_sendfile_then(const char *path, size_t size, bool answered)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char *contents = read_whole_file(path, size);
    int file = open_file(path);
    int sock = connect_sink(&sink);
    sendfile_all(sock, file, size);
    if (answered)
        hear(sock);
    memset(contents, 'm', size);
    send_all(sock, contents, size);
    hear(sock);
    close(sock);
    close(file);
    free(contents);
    report("sendfilethen", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readudp <path> <bytes> <datagram bytes> <datagrams>: connects a datagram socket, reads the file
 * and sends datagrams of its bytes, as a syslog or TFTP client does.
 */
static void scenario_read_udp(const char *path, size_t size, size_t datagram, size_t count)
{
    struct sink sink = start_sink(SOCK_DGRAM, false, SINK_DISCARD);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        die("socket");
    if (connect(sock, (struct sockaddr *)&sink.addr, sink.addr_len) != 0)
        die("connect");
    char *contents = read_whole_file(path, size);
    for (size_t i = 0; i < count; i++) {
        size_t at = i * datagram % size;
        size_t n = datagram < size - at ? datagram : size - at;
        if (send(sock, contents + at, n, 0) != (ssize_t)n)
            die("send");
    }
    close(sock);
    free(contents);
    report("readudp", path, size, sink.port);
    usleep(100 * 1000);
    stop_sink(&sink);
}

/*
 * readudptwo <path> <bytes>: connects two datagram sockets, reads the file and sends half of it
 * over each.
 */
static void scenario_read_udp_two(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_DGRAM, false, SINK_DISCARD);
    int socks[2];
    for (int i = 0; i < 2; i++) {
        socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
        if (socks[i] < 0)
            die("socket");
        if (connect(socks[i], (struct sockaddr *)&sink.addr, sink.addr_len) != 0)
            die("connect");
    }
    char *contents = read_whole_file(path, size);
    size_t half = size / 2;
    if (send(socks[0], contents, half, 0) != (ssize_t)half ||
        send(socks[1], contents + half, size - half, 0) != (ssize_t)(size - half))
        die("send");
    close(socks[0]);
    close(socks[1]);
    free(contents);
    report("readudptwo", path, size, sink.port);
    usleep(100 * 1000);
    stop_sink(&sink);
}

/*
 * framed <path> <bytes> <record bytes> <frame bytes>: over a connection that has heard from its
 * peer, reads the file and sends a request head and the file in records, each with a frame of its
 * own, as a TLS connection does.
 */
static void scenario_framed(const char *path, size_t size, size_t record, size_t frame)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    char head[200];
    memset(head, 'H', sizeof(head));
    char *out = malloc(record + frame);
    if (!out)
        die("malloc");
    memset(out, 'F', frame);
    int sock = connect_sink(&sink);
    hear(sock);
    char *contents = read_whole_file(path, size);
    send_all(sock, head, sizeof(head));
    for (size_t at = 0; at < size; at += record) {
        size_t n = size - at < record ? size - at : record;
        memcpy(out + frame, contents + at, n);
        send_all(sock, out, frame + n);
    }
    close(sock);
    free(out);
    free(contents);
    report("framed", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * sendbeside <path> <bytes> <strict> <strict bytes> <head bytes>: over a connection that has
 * heard from its peer, reads the file and then the strict one, and sends a head and the file.
 */
static void scenario_send_beside(const char *path, size_t size, const char *strict,
                                 size_t strict_size, size_t head)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    int sock = connect_sink(&sink);
    hear(sock);
    char *contents = read_whole_file(path, size);
    free(read_whole_file(strict, strict_size));
    char *request = calloc(1, head + size);
    if (!request)
        die("malloc");
    memcpy(request + head, contents, size);
    send_all(sock, request, head + size);
    close(sock);
    free(request);
    free(contents);
    report("sendbeside", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * servestrict <data> <data bytes> <script> <script bytes>: over a connection that has heard from
 * its peer, reads two pages of a large data file, then the script whole, and sends a response
 * head and the script, as a server answers with its own static code.
 */
static void scenario_serve_strict(const char *data, size_t data_size, const char *script,
                                  size_t script_size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    make_file(data, data_size);
    char page[4096];
    int sock = connect_sink(&sink);
    hear(sock);
    int db = open_file(data);
    for (int i = 0; i < 2; i++) {
        if (pread(db, page, sizeof(page), (off_t)(i * 65536)) != (ssize_t)sizeof(page))
            die("pread");
    }
    close(db);
    char *response = calloc(1, 300 + script_size);
    if (!response)
        die("malloc");
    char *contents = read_whole_file(script, script_size);
    memcpy(response + 300, contents, script_size);
    send_all(sock, response, 300 + script_size);
    close(sock);
    free(contents);
    free(response);
    report("servestrict", script, script_size, sink.port);
    stop_sink(&sink);
}

/*
 * streamafter <kept> <kept bytes> <path> <bytes>: over a connection that has heard from its
 * peer, reads a large file it keeps, sends a request head, then reads and sends the other file in
 * pieces of 16 KB.
 */
static void scenario_stream_after(const char *kept, size_t kept_size, const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    make_file(path, size);
    int sock = connect_sink(&sink);
    hear(sock);
    free(read_whole_file(kept, kept_size));
    char head[200];
    memset(head, 'H', sizeof(head));
    send_all(sock, head, sizeof(head));
    int file = open_file(path);
    read_send(sock, file, 16384);
    close(file);
    close(sock);
    report("streamafter", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readasks <path> <bytes> <first> <second> [reused|reusedsend]: reads the file whole, connects,
 * and sends two requests from memory, hearing the answer to each, then closes. reused: first
 * reads a 70000-byte file, deletes it and makes the file at once, so that it may take the
 * deleted file's inode number, and reports whether it did; reads it after the correlation
 * window. reusedsend: the same, with the file itself as the first request.
 */
static void scenario_read_asks(const char *path, size_t size, size_t first, size_t second,
                               bool reused, bool send_file)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char *request = calloc(1, first > second ? first : second);
    if (!request)
        die("malloc");
    ino_t deleted = 0;
    if (reused) {
        char before[PATH_MAX];
        struct stat st;
        snprintf(before, sizeof(before), "%s.deleted", path);
        free(read_whole_file(before, 70000));
        if (stat(before, &st) != 0 || unlink(before) != 0)
            die(before);
        deleted = st.st_ino;
        make_file(path, size);
        if (stat(path, &st) != 0)
            die(path);
        printf("reused=%d\n", st.st_ino == deleted);
        usleep(2600 * 1000);
    }
    char *contents = read_whole_file(path, size);
    int sock = connect_sink(&sink);
    send_all(sock, send_file ? contents : request, send_file ? size : first);
    hear(sock);
    send_all(sock, request, second);
    hear(sock);
    usleep(300 * 1000);
    close(sock);
    free(contents);
    free(request);
    report("readasks", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * metricfirst <path> <bytes>: over a connection that has heard from its peer, reads the file,
 * sends a datagram to a metrics daemon, then a response head and the file, and hears the answer.
 */
static void scenario_metric_first(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    struct sink metrics = start_sink(SOCK_DGRAM, false, SINK_DISCARD);
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp < 0)
        die("socket");
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    char *response = calloc(1, 300 + size);
    if (!response)
        die("malloc");
    char *contents = read_whole_file(path, size);
    memcpy(response + 300, contents, size);
    char metric[60];
    memset(metric, 'm', sizeof(metric));
    if (sendto(udp, metric, sizeof(metric), 0, (struct sockaddr *)&metrics.addr,
               metrics.addr_len) != (ssize_t)sizeof(metric))
        die("sendto");
    send_all(sock, response, 300 + size);
    hear(sock);
    close(sock);
    close(udp);
    free(contents);
    free(response);
    report("metricfirst", path, size, sink.port);
    usleep(100 * 1000);
    stop_sink(&metrics);
    stop_sink(&sink);
}

/*
 * resend <path> <bytes> <rounds> <heard|silent>: over a connection that has heard from its peer
 * once, or that never hears, reads the file and sends it, round after round, as a status file is
 * shipped.
 */
static void scenario_resend(const char *path, size_t size, size_t rounds, bool heard)
{
    struct sink sink = start_sink(SOCK_STREAM, false, heard ? SINK_GREET : SINK_DISCARD);
    make_file(path, size);
    char *contents = malloc(size);
    if (!contents)
        die("malloc");
    int sock = connect_sink(&sink);
    if (heard)
        hear(sock);
    int file = open_file(path);
    for (size_t i = 0; i < rounds; i++) {
        if (pread(file, contents, size, 0) != (ssize_t)size)
            die("pread");
        send_all(sock, contents, size);
        usleep(50 * 1000);
    }
    close(file);
    close(sock);
    free(contents);
    report("resend", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * tail <path> <bytes> <append bytes> <rounds>: over a connection that has heard from its peer and
 * never hears again, appends to the file and sends what was appended, round after round, as a
 * log shipper follows a log.
 */
static void scenario_tail(const char *path, size_t size, size_t append, size_t rounds)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    make_file(path, size);
    char *buf = malloc(append);
    if (!buf)
        die("malloc");
    memset(buf, 'l', append);
    int sock = connect_sink(&sink);
    hear(sock);
    int file = open_file(path);
    if (lseek(file, (off_t)size, SEEK_SET) < 0)
        die("lseek");
    for (size_t i = 0; i < rounds; i++) {
        int out = open(path, O_WRONLY | O_APPEND);
        if (out < 0 || write(out, buf, append) != (ssize_t)append)
            die("append");
        close(out);
        ssize_t n = read(file, buf, append);
        if (n != (ssize_t)append)
            die("read");
        send_all(sock, buf, append);
        usleep(20 * 1000);
    }
    close(file);
    close(sock);
    free(buf);
    report("tail", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * pieces <path> <bytes> <pieces> <milliseconds>: over a connection that has heard from its peer,
 * reads the file and sends it in pieces with a pause between them, then closes.
 */
static void scenario_pieces(const char *path, size_t size, size_t pieces, size_t pause_ms)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    int sock = connect_sink(&sink);
    hear(sock);
    char *contents = read_whole_file(path, size);
    size_t step = (size + pieces - 1) / pieces;
    for (size_t from = 0; from < size; from += step) {
        if (from)
            usleep((useconds_t)(pause_ms * 1000));
        send_all(sock, contents + from, size - from < step ? size - from : step);
    }
    sleep(1);
    close(sock);
    free(contents);
    report("pieces", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * holdopen <path> <bytes> <body bytes> <seconds>: over a connection that has heard from its peer,
 * reads the file and sends a body that starts with it, then keeps the connection open, never
 * hearing again.
 */
static void scenario_hold_open(const char *path, size_t size, size_t body, size_t seconds)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    int sock = connect_sink(&sink);
    hear(sock);
    char *contents = read_whole_file(path, size);
    char *out = calloc(1, body);
    if (!out)
        die("malloc");
    memcpy(out, contents, size < body ? size : body);
    send_all(sock, out, body);
    report("holdopen", path, size, sink.port);
    fflush(stdout);
    sleep((unsigned)seconds);
    close(sock);
    free(out);
    free(contents);
    stop_sink(&sink);
}

/* The three replies of a pool: a page from a template, a page with a small setting, a health check.
 */
static const struct {
    const char *name;
    size_t size;
    size_t reply;
} pool_shapes[] = {
    {"layout.tpl", 5000, 20300}, {"app.env", 1500, 20300}, {"health.yml", 5000, 2000}};

struct pool_worker {
    int sock;
    char path[4096];
    size_t size;
    size_t reply;
    size_t head; /* what goes before the file, when the reply is the file */
};

static void *pool_worker_main(void *arg)
{
    struct pool_worker *w = arg;
    char request[2];
    if (recv(w->sock, request, sizeof(request), MSG_WAITALL) != (ssize_t)sizeof(request))
        die("recv");
    char *contents = read_whole_file(w->path, w->size);
    char *out = calloc(1, w->reply);
    if (!out)
        die("malloc");
    memcpy(out + w->head, contents, w->size < w->reply - w->head ? w->size : w->reply - w->head);
    send_all(w->sock, out, w->reply);
    free(out);
    free(contents);
    return nullptr;
}

/*
 * poolreply <dir> <threads> [whole]: serves one kept-alive connection from a pool of threads in
 * turn, each hearing one request, reading a small file and answering with a reply far from its
 * size, a fifth of a second apart; with whole, the reply is the file after a head of 300 bytes.
 */
static void scenario_pool_reply(const char *dir, size_t threads, bool whole)
{
    size_t head = whole ? 300 : 0;
    struct sockaddr_storage addr;
    socklen_t len = loopback(false, &addr);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&addr, len) != 0 ||
        getsockname(listener, (struct sockaddr *)&addr, &len) != 0 || listen(listener, 1) != 0)
        die("listen");
    pid_t client = fork();
    if (client < 0)
        die("fork");
    if (client == 0) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0 || connect(sock, (struct sockaddr *)&addr, len) != 0)
            _exit(1);
        char *reply = malloc(65536);
        for (size_t i = 0; i < threads && reply; i++) {
            size_t want = whole ? pool_shapes[i % 3].size + head : pool_shapes[i % 3].reply;
            if (send(sock, "R\n", 2, 0) != 2 ||
                recv(sock, reply, want, MSG_WAITALL) != (ssize_t)want)
                _exit(1);
            usleep(200 * 1000);
        }
        _exit(0);
    }
    int sock = accept(listener, nullptr, nullptr);
    if (sock < 0)
        die("accept");
    for (size_t i = 0; i < threads; i++) {
        struct pool_worker w = {.sock = sock, .size = pool_shapes[i % 3].size};
        w.head = head;
        w.reply = whole ? w.size + head : pool_shapes[i % 3].reply;
        snprintf(w.path, sizeof(w.path), "%s/%zu-%s", dir, i, pool_shapes[i % 3].name);
        pthread_t thread;
        if (pthread_create(&thread, nullptr, pool_worker_main, &w) != 0)
            die("pthread_create");
        pthread_join(thread, nullptr);
    }
    waitpid(client, nullptr, 0);
    close(sock);
    close(listener);
    report("poolreply", dir, threads, 0);
}

/* Keeps the process on one CPU, where a socket closed is the likeliest memory for the next. */
static void one_cpu(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        die("sched_setaffinity");
}

static char *read_file(const char *path, size_t size)
{
    char *contents = malloc(size);
    if (!contents)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    close(file);
    return contents;
}

struct close_other {
    const char *path;
    size_t size;
    const struct sink *sink;
    int sock;
    bool again;
    pthread_barrier_t step;
};

static void *close_other_main(void *arg)
{
    struct close_other *o = arg;
    char *contents = read_file(o->path, o->size);
    send_all(o->sock, contents, o->size);
    free(contents);
    pthread_barrier_wait(&o->step);
    pthread_barrier_wait(&o->step);
    if (o->again) {
        contents = read_file(o->path, o->size);
        int sock = connect_sink(o->sink);
        send_all(sock, contents, o->size);
        close(sock);
        free(contents);
    }
    return nullptr;
}

/*
 * closeother <path> <bytes> [again]: a worker thread uploads the file over a connection nobody
 * answers and the main thread closes it; with again, the worker then uploads the file over a new
 * connection.
 */
static void scenario_close_other(const char *path, size_t size, bool again)
{
    one_cpu();
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    make_file(path, size);
    struct close_other o = {
        .path = path, .size = size, .sink = &sink, .sock = connect_sink(&sink), .again = again};
    if (pthread_barrier_init(&o.step, nullptr, 2) != 0)
        die("pthread_barrier_init");
    pthread_t worker;
    if (pthread_create(&worker, nullptr, close_other_main, &o) != 0)
        die("pthread_create");
    pthread_barrier_wait(&o.step);
    close(o.sock);
    usleep(100 * 1000);
    pthread_barrier_wait(&o.step);
    pthread_join(worker, nullptr);
    pthread_barrier_destroy(&o.step);
    report("closeother", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * resetretry <path> <bytes>: uploads the file over a connection whose peer resets it unanswered,
 * then at once over a new connection, likely made where the reset one was, whose peer answers.
 */
static void scenario_reset_retry(const char *path, size_t size)
{
    one_cpu();
    struct sink reset = start_sink(SOCK_STREAM, false, SINK_RESET);
    struct sink answer = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    make_file(path, size);
    char line[6];
    char *contents = read_file(path, size);
    int sock = connect_sink(&reset);
    send_all(sock, contents, size);
    if (recv(sock, line, sizeof(line), 0) > 0)
        die("the peer answered");
    close(sock);
    free(contents);

    contents = read_file(path, size);
    sock = connect_sink(&answer);
    send_all(sock, contents, size);
    if (recv(sock, line, sizeof(line), MSG_WAITALL) != (ssize_t)sizeof(line))
        die("recv");
    close(sock);
    free(contents);
    report("resetretry", path, size, answer.port);
    stop_sink(&reset);
    stop_sink(&answer);
}

/* The kernel's address of a connected IPv4 socket as /proc/net/tcp shows it, or 0. */
static unsigned long long sock_address(int sock)
{
    struct sockaddr_in local;
    struct sockaddr_in peer;
    socklen_t len = sizeof(local);
    if (getsockname(sock, (struct sockaddr *)&local, &len) != 0)
        return 0;
    len = sizeof(peer);
    if (getpeername(sock, (struct sockaddr *)&peer, &len) != 0)
        return 0;
    FILE *table = fopen("/proc/net/tcp", "r");
    if (!table)
        return 0;
    char line[512];
    unsigned long long found = 0;
    while (!found && fgets(line, sizeof(line), table)) {
        unsigned lport;
        unsigned rport;
        unsigned state;
        unsigned long long address;
        if (sscanf(line, " %*d: %*x:%x %*x:%x %x %*x:%*x %*x:%*x %*x %*u %*d %*u %*d %llx", &lport,
                   &rport, &state, &address) == 4 &&
            lport == ntohs(local.sin_port) && rport == ntohs(peer.sin_port) && state != 0x0a)
            found = address;
    }
    fclose(table);
    return found;
}

static void await_step(int fd)
{
    char c;
    if (read(fd, &c, 1) != 1)
        die("read");
}

static void take_step(int fd)
{
    if (write(fd, "", 1) != 1)
        die("write");
}

/* A server's listener, and the two clients of a round of a banner scenario. */
struct banner_round {
    int listener;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    pid_t first;
    pid_t next;
    int ended; /* readable once the first client ended its connection */
    int go;    /* lets the next client connect */
};

/*
 * Starts a round: the next client makes its socket at once and connects on the signal, then
 * reads the banner; the first client asks over its connection, hears a reply of 3300 bytes and
 * resets the connection, or closes it.
 */
static void banner_clients(struct banner_round *r, bool reset, size_t banner)
{
    int ready[2];
    int go[2];
    int ended[2];
    if (pipe(ready) != 0 || pipe(go) != 0 || pipe(ended) != 0)
        die("pipe");
    r->next = fork();
    if (r->next < 0)
        die("fork");
    if (r->next == 0) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        char *in = malloc(banner);
        char c;
        if (sock < 0 || !in || write(ready[1], "", 1) != 1 || read(go[0], &c, 1) != 1 ||
            connect(sock, (struct sockaddr *)&r->addr, r->addr_len) != 0 ||
            recv(sock, in, banner, MSG_WAITALL) != (ssize_t)banner)
            _exit(1);
        _exit(0);
    }
    await_step(ready[0]);
    r->first = fork();
    if (r->first < 0)
        die("fork");
    if (r->first == 0) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        char request[100] = {0};
        char reply[3300];
        struct linger abort = {.l_onoff = 1, .l_linger = 0};
        if (sock < 0 || connect(sock, (struct sockaddr *)&r->addr, r->addr_len) != 0 ||
            send(sock, request, sizeof(request), 0) != (ssize_t)sizeof(request) ||
            recv(sock, reply, sizeof(reply), MSG_WAITALL) != (ssize_t)sizeof(reply) ||
            (reset && setsockopt(sock, SOL_SOCKET, SO_LINGER, &abort, sizeof(abort)) != 0))
            _exit(1);
        close(sock);
        _exit(write(ended[1], "", 1) == 1 ? 0 : 1);
    }
    close(ready[0]);
    close(ready[1]);
    close(go[0]);
    close(ended[1]);
    r->go = go[1];
    r->ended = ended[0];
}

static void banner_clients_done(struct banner_round *r)
{
    int status;
    if (waitpid(r->first, &status, 0) != r->first || status != 0 ||
        waitpid(r->next, &status, 0) != r->next || status != 0)
        die("client");
    close(r->go);
    close(r->ended);
}

static void banner_listen(struct banner_round *r)
{
    r->addr_len = loopback(false, &r->addr);
    r->listener = socket(AF_INET, SOCK_STREAM, 0);
    if (r->listener < 0 || bind(r->listener, (struct sockaddr *)&r->addr, r->addr_len) != 0 ||
        getsockname(r->listener, (struct sockaddr *)&r->addr, &r->addr_len) != 0 ||
        listen(r->listener, 4) != 0)
        die("listen");
}

/* Hears what the peer says first and replies with the file of 3000 bytes after a head of 300. */
static void reply_with(int sock, const char *path, size_t heard)
{
    char request[100];
    if (heard > sizeof(request) || recv(sock, request, heard, MSG_WAITALL) != (ssize_t)heard)
        die("recv");
    char *contents = read_file(path, 3000);
    char reply[3300] = {0};
    memcpy(reply + 300, contents, 3000);
    send_all(sock, reply, sizeof(reply));
    free(contents);
}

static void send_banner(int sock, size_t size)
{
    char *banner = calloc(1, size);
    if (!banner)
        die("malloc");
    send_all(sock, banner, size);
    free(banner);
}

/*
 * resetbanner <dir> <rounds>: a server thread hears a request, reads <dir>/<i>-motd.txt (3000
 * bytes) and replies with it after a head of 300; the client resets the connection; the server
 * closes it, accepts the next connection and sends a banner of 2000 bytes from memory before
 * hearing anything. On one CPU, the next client's socket made before the reset one is freed, so
 * that the accepted connection likely gets its memory.
 */
static void scenario_reset_banner(const char *dir, size_t rounds)
{
    one_cpu();
    struct banner_round r;
    banner_listen(&r);
    size_t landed = 0;
    for (size_t i = 0; i < rounds; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%zu-motd.txt", dir, i);
        make_file(path, 3000);
        banner_clients(&r, true, 2000);
        int a = accept(r.listener, nullptr, nullptr);
        if (a < 0)
            die("accept");
        unsigned long long at = sock_address(a);
        reply_with(a, path, 100);
        await_step(r.ended);
        close(a);
        take_step(r.go);
        int b = accept(r.listener, nullptr, nullptr);
        if (b < 0)
            die("accept");
        send_banner(b, 2000);
        landed += at && at == sock_address(b);
        banner_clients_done(&r);
        close(b);
    }
    close(r.listener);
    printf("scenario=resetbanner pid=%d rounds=%zu landed=%zu\n", (int)getpid(), rounds, landed);
}

struct pool_banner {
    struct banner_round *round;
    const char *dir;
    size_t rounds;
    int sock;
    pthread_barrier_t step;
};

static void *pool_banner_main(void *arg)
{
    struct pool_banner *o = arg;
    for (size_t i = 0; i < o->rounds; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%zu-a.json", o->dir, i);
        pthread_barrier_wait(&o->step);
        reply_with(o->sock, path, 100);
        pthread_barrier_wait(&o->step);
        pthread_barrier_wait(&o->step);
        o->sock = accept(o->round->listener, nullptr, nullptr);
        if (o->sock < 0)
            die("accept");
        send_banner(o->sock, 5000);
        pthread_barrier_wait(&o->step);
    }
    return nullptr;
}

/*
 * closebanner <dir> <rounds>: a pool thread hears a request, reads <dir>/<i>-a.json (3000 bytes)
 * and replies with it after a head of 300; the client closes the connection, and then the main
 * thread; the pool thread accepts the next connection and sends a banner of 5000 bytes from
 * memory before hearing anything. On one CPU, as resetbanner.
 */
static void scenario_close_banner(const char *dir, size_t rounds)
{
    one_cpu();
    struct banner_round r;
    banner_listen(&r);
    struct pool_banner o = {.round = &r, .dir = dir, .rounds = rounds};
    if (pthread_barrier_init(&o.step, nullptr, 2) != 0)
        die("pthread_barrier_init");
    pthread_t worker;
    if (pthread_create(&worker, nullptr, pool_banner_main, &o) != 0)
        die("pthread_create");
    size_t landed = 0;
    for (size_t i = 0; i < rounds; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%zu-a.json", dir, i);
        make_file(path, 3000);
        banner_clients(&r, false, 5000);
        int a = accept(r.listener, nullptr, nullptr);
        if (a < 0)
            die("accept");
        unsigned long long at = sock_address(a);
        o.sock = a;
        pthread_barrier_wait(&o.step);
        pthread_barrier_wait(&o.step);
        await_step(r.ended);
        close(a);
        take_step(r.go);
        pthread_barrier_wait(&o.step);
        pthread_barrier_wait(&o.step);
        landed += at && at == sock_address(o.sock);
        banner_clients_done(&r);
        close(o.sock);
    }
    pthread_join(worker, nullptr);
    pthread_barrier_destroy(&o.step);
    close(r.listener);
    printf("scenario=closebanner pid=%d rounds=%zu landed=%zu\n", (int)getpid(), rounds, landed);
}

struct dial_reply {
    const char *dir;
    size_t rounds;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    int sock;
    unsigned long long address; /* of the connection the worker replied on */
    pthread_barrier_t step;
};

static void *dial_reply_main(void *arg)
{
    struct dial_reply *o = arg;
    char line[6];
    for (size_t i = 0; i < o->rounds; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%zu-c.json", o->dir, i);
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0 || connect(sock, (struct sockaddr *)&o->addr, o->addr_len) != 0)
            die("connect");
        o->sock = sock;
        o->address = sock_address(sock);
        reply_with(sock, path, sizeof(line));
        pthread_barrier_wait(&o->step);
        pthread_barrier_wait(&o->step);
        send_banner(o->sock, 2000);
        if (recv(o->sock, line, sizeof(line), MSG_WAITALL) != (ssize_t)sizeof(line))
            die("recv");
        pthread_barrier_wait(&o->step);
    }
    return nullptr;
}

/*
 * dialreply <dir> <rounds>: a worker hears a greeting, reads <dir>/<i>-c.json (3000 bytes) and
 * replies with it after a head of 300; the peer closes the connection, and then the main thread,
 * which reads a large file and connects again; the worker sends a request of 2000 bytes from
 * memory over the new connection and hears the answer. On one CPU, so that the new connection
 * likely gets the memory of the closed one.
 */
static void scenario_dial_reply(const char *dir, size_t rounds)
{
    one_cpu();
    char big[4096];
    snprintf(big, sizeof(big), "%s/big.bin", dir);
    make_file(big, 100000);
    struct dial_reply o = {.dir = dir, .rounds = rounds};
    o.addr_len = loopback(false, &o.addr);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0 || bind(listener, (struct sockaddr *)&o.addr, o.addr_len) != 0 ||
        getsockname(listener, (struct sockaddr *)&o.addr, &o.addr_len) != 0 ||
        listen(listener, 4) != 0)
        die("listen");
    int closed[2];
    if (pipe(closed) != 0)
        die("pipe");
    pid_t peer = fork();
    if (peer < 0)
        die("fork");
    if (peer == 0) {
        char buf[3300];
        for (size_t i = 0; i < rounds; i++) {
            int a = accept(listener, nullptr, nullptr);
            if (a < 0 || write(a, "hello\n", 6) != 6 || recv(a, buf, 3300, MSG_WAITALL) != 3300)
                _exit(1);
            close(a);
            if (write(closed[1], "", 1) != 1)
                _exit(1);
            int b = accept(listener, nullptr, nullptr);
            if (b < 0 || recv(b, buf, 2000, MSG_WAITALL) != 2000 || write(b, "hello\n", 6) != 6)
                _exit(1);
            while (recv(b, buf, sizeof(buf), 0) > 0) {
            }
            close(b);
        }
        _exit(0);
    }
    close(listener);
    for (size_t i = 0; i < rounds; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%zu-c.json", dir, i);
        make_file(path, 3000);
    }
    if (pthread_barrier_init(&o.step, nullptr, 2) != 0)
        die("pthread_barrier_init");
    pthread_t worker;
    if (pthread_create(&worker, nullptr, dial_reply_main, &o) != 0)
        die("pthread_create");
    size_t landed = 0;
    for (size_t i = 0; i < rounds; i++) {
        pthread_barrier_wait(&o.step);
        unsigned long long at = o.address;
        free(read_file(big, 100000));
        await_step(closed[0]);
        close(o.sock);
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0 || connect(sock, (struct sockaddr *)&o.addr, o.addr_len) != 0)
            die("connect");
        o.sock = sock;
        pthread_barrier_wait(&o.step);
        pthread_barrier_wait(&o.step);
        landed += at && at == sock_address(sock);
        close(sock);
    }
    pthread_join(worker, nullptr);
    pthread_barrier_destroy(&o.step);
    int status;
    if (waitpid(peer, &status, 0) != peer || status != 0)
        die("peer");
    printf("scenario=dialreply pid=%d rounds=%zu landed=%zu\n", (int)getpid(), rounds, landed);
}

struct side_send {
    int sock;
    size_t bytes;
};

static void *side_send_main(void *arg)
{
    struct side_send *s = arg;
    char *buf = calloc(1, s->bytes);
    if (!buf)
        die("malloc");
    send_all(s->sock, buf, s->bytes);
    free(buf);
    return nullptr;
}

/*
 * twosenders <path> <bytes> <own bytes> <other bytes>: over a connection that has heard from its
 * peer, reads the file and sends a few bytes, another thread sends its own on the same connection,
 * then the first hears the answer.
 */
static void scenario_two_senders(const char *path, size_t size, size_t own, size_t other)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    char *contents = read_whole_file(path, size);
    send_all(sock, contents, own < size ? own : size);
    struct side_send side = {.sock = sock, .bytes = other};
    pthread_t thread;
    if (pthread_create(&thread, nullptr, side_send_main, &side) != 0)
        die("pthread_create");
    pthread_join(thread, nullptr);
    hear(sock);
    close(sock);
    free(contents);
    report("twosenders", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * latebody <path> <bytes> <head bytes> <seconds> <body bytes>: over a connection that has heard
 * from its peer, reads the file, sends a head, waits, then sends a body from memory and hears.
 */
static void scenario_late_body(const char *path, size_t size, size_t head, size_t seconds,
                               size_t body)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    free(read_whole_file(path, size));
    char *out = calloc(1, head > body ? head : body);
    if (!out)
        die("malloc");
    send_all(sock, out, head);
    sleep((unsigned)seconds);
    send_all(sock, out, body);
    hear(sock);
    close(sock);
    free(out);
    report("latebody", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * slowflight <path> <bytes> <request bytes> <seconds>: connects to a peer that never answers,
 * reads the file and sends a request, then keeps the connection open.
 */
static void scenario_slow_flight(const char *path, size_t size, size_t request, size_t seconds)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    int sock = connect_sink(&sink);
    free(read_whole_file(path, size));
    char *out = calloc(1, request);
    if (!out)
        die("malloc");
    send_all(sock, out, request);
    report("slowflight", path, size, sink.port);
    fflush(stdout);
    sleep((unsigned)seconds);
    close(sock);
    free(out);
    stop_sink(&sink);
}

/*
 * cutreply <path> <bytes> <body bytes>: over a connection to a peer that stops reading, reads the
 * file and sends a body without blocking, so that the socket takes only part of it, then hears
 * from another peer and keeps the first connection open. A body of the file's size is the file.
 */
static void scenario_cut_reply(const char *path, size_t size, size_t body)
{
    struct sink stalled = start_sink(SOCK_STREAM, false, SINK_STALL);
    struct sink other = start_sink(SOCK_STREAM, false, SINK_GREET);
    int sock = connect_sink(&stalled);
    hear(sock);
    int small = 4096;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
    char *contents = read_whole_file(path, size);
    char *out = body == size ? contents : calloc(1, body);
    if (!out)
        die("malloc");
    ssize_t n = send(sock, out, body, 0);
    if (n <= 0 || (size_t)n >= body)
        die("send was not cut");
    if (out != contents)
        free(out);
    int side = connect_sink(&other);
    hear(side);
    report("cutreply", path, (size_t)n, stalled.port);
    fflush(stdout);
    sleep(10);
    close(side);
    close(sock);
    free(contents);
    stop_sink(&other);
    stop_sink(&stalled);
}

/*
 * readbeside <path> <bytes> <other> <other bytes>: reads the file, connects, reads the other file
 * and sends the first one in a single send, then closes.
 */
static void scenario_read_beside(const char *path, size_t size, const char *other,
                                 size_t other_size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    char *contents = read_whole_file(path, size);
    int sock = connect_sink(&sink);
    free(read_whole_file(other, other_size));
    send_all(sock, contents, size);
    close(sock);
    free(contents);
    report("readbeside", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * framedserve <path> <bytes>: over a connection that has heard from its peer, reads the file in
 * pieces of 64 KB, sends each in four writes and hears a small frame after it, as an HTTP/2
 * server waits for a window update.
 */
static void scenario_framed_serve(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    make_file(path, size);
    char *piece = malloc(65536);
    if (!piece)
        die("malloc");
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    int file = open_file(path);
    for (;;) {
        ssize_t n = read(file, piece, 65536);
        if (n < 0)
            die("read");
        if (n == 0)
            break;
        size_t quarter = ((size_t)n + 3) / 4;
        for (size_t at = 0; at < (size_t)n; at += quarter)
            send_all(sock, piece + at, (size_t)n - at < quarter ? (size_t)n - at : quarter);
        hear(sock);
    }
    close(file);
    close(sock);
    free(piece);
    report("framedserve", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * twosockets <path> <bytes> <other bytes>: over two connections that have heard from their peers,
 * reads the file once, sends it over the first and as many other bytes over the second, and
 * hears both.
 */
static void scenario_two_sockets(const char *path, size_t size, size_t other)
{
    struct sink first = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    struct sink second = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    int a = connect_sink(&first);
    int b = connect_sink(&second);
    send_all(a, "hello\n", 6);
    hear(a);
    send_all(b, "hello\n", 6);
    hear(b);
    char *contents = read_whole_file(path, size);
    char *bytes = calloc(1, other);
    if (!bytes)
        die("malloc");
    send_all(a, contents, size);
    send_all(b, bytes, other);
    hear(a);
    hear(b);
    close(a);
    close(b);
    free(bytes);
    free(contents);
    report("twosockets", path, size, first.port);
    stop_sink(&second);
    stop_sink(&first);
}

/* readmany <dir> <count> <suffix>: makes count small files in dir named with suffix, reads each. */
static void scenario_read_many(const char *dir, size_t count, const char *suffix)
{
    char path[4096];
    char byte;
    for (size_t i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/f%zu%s", dir, i, suffix);
        make_file(path, 1);
        int fd = open_file(path);
        if (read(fd, &byte, 1) != 1)
            die("read");
        close(fd);
    }
    report("readmany", dir, count, 0);
}

/*
 * putnext <path> <bytes>: connects, reads the file, sends a request head, the file and a last
 * chunk before the peer answers, hears the answer, then sends the next request at once.
 */
static void scenario_put_next(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_LATE);
    char head[200];
    char chunk[5];
    char *next = calloc(1, 3000);
    if (!next)
        die("malloc");
    memset(head, 'H', sizeof(head));
    memset(chunk, '0', sizeof(chunk));
    int sock = connect_sink(&sink);
    char *contents = read_whole_file(path, size);
    send_all(sock, head, sizeof(head));
    send_all(sock, contents, size);
    send_all(sock, chunk, sizeof(chunk));
    hear(sock);
    send_all(sock, next, 3000);
    hear(sock);
    close(sock);
    free(contents);
    free(next);
    report("putnext", path, size, sink.port);
    stop_sink(&sink);
}

static void *hear_main(void *arg)
{
    hear(*(int *)arg);
    return nullptr;
}

/*
 * readerthread <path> <bytes>: over a connection that has heard from its peer, a writer reads the
 * file and sends a head and the file in two parts, while a reader thread hears an answer between
 * the sends.
 */
static void scenario_reader_thread(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    char head[300] = {0};
    int sock = connect_sink(&sink);
    send_all(sock, "hello\n", 6);
    hear(sock);
    char *contents = read_whole_file(path, size);
    size_t first = size < 16384 ? size / 2 : 16384;
    send_all(sock, head, sizeof(head));
    for (int i = 0; i < 2; i++) {
        pthread_t reader;
        if (pthread_create(&reader, nullptr, hear_main, &sock) != 0)
            die("pthread_create");
        pthread_join(reader, nullptr);
        if (i == 0)
            send_all(sock, contents, first);
        else
            send_all(sock, contents + first, size - first);
    }
    close(sock);
    free(contents);
    report("readerthread", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * stallsend <path> <bytes>: over a connection to a peer that reads nothing for two seconds, reads
 * the file and sends it in one blocking send, then keeps the connection open.
 */
static void scenario_stall_send(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_STALL);
    int sock = connect_sink(&sink);
    hear(sock);
    char *contents = read_whole_file(path, size);
    send_all(sock, contents, size);
    report("stallsend", path, size, sink.port);
    fflush(stdout);
    sleep(6);
    close(sock);
    free(contents);
    stop_sink(&sink);
}

/*
 * sendfileeof <path> <bytes>: reads the file, connects, calls sendfile at the end of the file,
 * which moves nothing, then sends what it read.
 */
static void scenario_sendfile_eof(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    char *contents = read_whole_file(path, size);
    int file = open_file(path);
    int sock = connect_sink(&sink);
    off_t end = (off_t)size;
    if (sendfile(sock, file, &end, size) != 0)
        die("sendfile");
    send_all(sock, contents, size);
    close(sock);
    close(file);
    free(contents);
    report("sendfileeof", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readmemory <path> <file bytes> <body bytes>: reads the file, then connects, sends a hello the
 * size of a TLS ClientHello with a post-quantum key share, hears one back and sends the body
 * from memory, as a client that loads a module, a service model or a bundle before it uploads.
 */
static void scenario_read_memory(const char *path, size_t file_size, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    make_file(path, file_size);

    char *contents = malloc(file_size);
    char *body = calloc(1, size);
    char hello[1566] = {0};
    char greeting[6];
    if (!contents || !body)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, file_size) != (ssize_t)file_size)
        die("read");
    int sock = connect_sink(&sink);
    send_all(sock, hello, sizeof(hello));
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
 * exchange <path> <file bytes> <requests> <request bytes>: reads the file, then connects and
 * makes small requests, each answered, as a program that reads its configuration and then
 * talks to an API.
 */
static void scenario_exchange(const char *path, size_t file_size, size_t requests, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    make_file(path, file_size);

    char *contents = malloc(file_size);
    char *request = calloc(1, size);
    char answer[6];
    if (!contents || !request)
        die("malloc");
    int file = open_file(path);
    if (read(file, contents, file_size) != (ssize_t)file_size)
        die("read");
    int sock = connect_sink(&sink);
    for (size_t i = 0; i < requests; i++) {
        send_all(sock, request, size);
        if (recv(sock, answer, sizeof(answer), MSG_WAITALL) != (ssize_t)sizeof(answer))
            die("recv");
    }
    close(sock);
    close(file);
    free(contents);
    free(request);
    report("exchange", path, file_size, sink.port);
    stop_sink(&sink);
}

/*
 * readhello <path> <bytes> <upload>: connects, reads the file, then sends a hello the size of a
 * TLS ClientHello and hears one back, as curl reads --cacert. Then it sends a request; with
 * upload the request is the file, and the connection closes after the answer.
 */
static void scenario_read_hello(const char *path, size_t size, bool upload)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    make_file(path, size);

    char *contents = malloc(size);
    char hello[1566] = {0};
    char request[600] = {0};
    char answer[6];
    if (!contents)
        die("malloc");
    int sock = connect_sink(&sink);
    int file = open_file(path);
    if (read(file, contents, size) != (ssize_t)size)
        die("read");
    if (upload)
        send_all(sock, contents, size);
    else
        send_all(sock, hello, sizeof(hello));
    if (recv(sock, answer, sizeof(answer), MSG_WAITALL) != (ssize_t)sizeof(answer))
        die("recv");
    if (!upload) {
        send_all(sock, request, sizeof(request));
        if (recv(sock, answer, sizeof(answer), MSG_WAITALL) != (ssize_t)sizeof(answer))
            die("recv");
    }
    close(sock);
    close(file);
    free(contents);
    report("readhello", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * flightend <path> <bytes> <close|hangup|reset|abort>: reads the file and sends it as all a fresh
 * connection sends, to a peer that never answers; then this side closes, the peer closes first,
 * the peer resets, or this side aborts with a reset.
 */
static void scenario_flight_end(const char *path, size_t size, const char *how)
{
    bool hangup = strcmp(how, "hangup") == 0;
    bool reset = strcmp(how, "reset") == 0;
    struct sink sink = start_sink(SOCK_STREAM, false,
                                  hangup  ? SINK_HANGUP
                                  : reset ? SINK_RESET
                                          : SINK_DISCARD);
    int sock = connect_sink(&sink);
    char *contents = read_whole_file(path, size);
    send_all(sock, contents, size);
    if (hangup || reset) {
        char byte;
        if (recv(sock, &byte, 1, 0) > 0)
            die("the peer answered");
    } else {
        usleep(200 * 1000);
    }
    if (strcmp(how, "abort") == 0) {
        struct linger abort = {.l_onoff = 1, .l_linger = 0};
        setsockopt(sock, SOL_SOCKET, SO_LINGER, &abort, sizeof(abort));
    }
    close(sock);
    free(contents);
    report("flightend", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * readtwice <path> <bytes> <send bytes> <fresh|heard>: reads the file twice, then sends that much
 * from memory, as a request over a fresh connection, or as a reply over one that heard a request
 * first and hears the answer after.
 */
static void scenario_read_twice(const char *path, size_t size, size_t send, bool heard)
{
    struct sink sink = start_sink(SOCK_STREAM, false, heard ? SINK_ANSWER : SINK_DISCARD);
    int sock = connect_sink(&sink);
    if (heard) {
        send_all(sock, "hello\n", 6);
        hear(sock);
    }
    free(read_whole_file(path, size));
    free(read_whole_file(path, size));
    char *out = calloc(1, send);
    if (!out)
        die("malloc");
    send_all(sock, out, send);
    if (heard)
        hear(sock);
    usleep(200 * 1000);
    close(sock);
    free(out);
    report("readtwice", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * twocopies <path> <bytes>: over a fresh connection, sends the file whole, then reads it again
 * from its start and sends it in pieces, and closes.
 */
static void scenario_two_copies(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    int sock = connect_sink(&sink);
    char *contents = read_whole_file(path, size);
    send_all(sock, contents, size);
    int file = open_file(path);
    read_send(sock, file, 16384);
    close(file);
    usleep(200 * 1000);
    close(sock);
    free(contents);
    report("twocopies", path, 2 * size, sink.port);
    stop_sink(&sink);
}

/*
 * failedsend <path> <bytes> <other> <other bytes>: over a fresh connection, reads the file and
 * gives a send of it that fails before taking anything; then reads the other file and sends
 * 30000 bytes from memory, and closes.
 */
static void scenario_failed_send(const char *path, size_t size, const char *other,
                                 size_t other_size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    int sock = connect_sink(&sink);
    free(read_whole_file(path, size));
    /* An address the process does not map: the kernel copies nothing and fails the send. */
    if (send(sock, (const void *)8, size, 0) >= 0)
        die("the send did not fail");
    free(read_whole_file(other, other_size));
    char *out = calloc(1, 30000);
    if (!out)
        die("malloc");
    send_all(sock, out, 30000);
    usleep(200 * 1000);
    close(sock);
    free(out);
    report("failedsend", other, other_size, sink.port);
    stop_sink(&sink);
}

/*
 * stalledpage <path>: over a connection that heard from its peer, reads a template about the size
 * of what the socket takes before the peer stops reading, then sends a page of a megabyte from
 * memory in one blocking send, which the peer leaves untaken for four seconds; then closes.
 */
static void scenario_stalled_page(const char *path)
{
    struct sink measure = start_sink(SOCK_STREAM, false, SINK_HOLD);
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_HOLD);
    int small = 4096;
    size_t page = 1048576;
    char *out = calloc(1, page);
    if (!out)
        die("malloc");

    int probe = connect_sink(&measure);
    setsockopt(probe, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    fcntl(probe, F_SETFL, fcntl(probe, F_GETFL) | O_NONBLOCK);
    usleep(100 * 1000);
    size_t taken = 0;
    for (ssize_t n; (n = send(probe, out + taken, page - taken, 0)) > 0;)
        taken += (size_t)n;
    close(probe);
    if (taken < 4000 || taken > 40000)
        die("the socket took an unexpected amount before blocking");

    int sock = connect_sink(&sink);
    hear(sock);
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    size_t size = taken - 1000;
    free(read_whole_file(path, size));
    send_all(sock, out, page);
    close(sock);
    free(out);
    report("stalledpage", path, size, sink.port);
    stop_sink(&sink);
    stop_sink(&measure);
}

/*
 * replypieces <path> <bytes> <head bytes> <tail bytes> <hear|wait>: over a connection that has
 * heard from its peer, reads the file in pieces of 16384 bytes and sends each as it is read, with
 * the head from memory between the first read and its piece and the tail from memory after the
 * last; then hears the answer, or keeps the connection open for three seconds, and closes.
 */
static void scenario_reply_pieces(const char *path, size_t size, size_t head, size_t tail,
                                  bool answered)
{
    struct sink sink = start_sink(SOCK_STREAM, false, answered ? SINK_ANSWER : SINK_GREET);
    char *extra = calloc(1, head + tail + 1);
    char piece[16384];
    if (!extra)
        die("malloc");
    make_file(path, size);

    int sock = connect_sink(&sink);
    if (answered)
        send_all(sock, "hello\n", 6);
    hear(sock);
    int file = open_file(path);
    for (ssize_t n; (n = read(file, piece, sizeof(piece))) > 0;) {
        send_all(sock, extra, head);
        head = 0;
        send_all(sock, piece, (size_t)n);
    }
    send_all(sock, extra, tail);
    if (answered)
        hear(sock);
    else
        sleep(3);
    close(sock);
    close(file);
    free(extra);
    report("replypieces", path, size, sink.port);
    stop_sink(&sink);
}

static int listen_loopback(struct sockaddr_in *addr);

/*
 * pagestall <path> <bytes> <seconds>: over a connection that has heard from its peer, reads a
 * template of that many bytes and sends a page of a megabyte from memory, its first piece the
 * template's size and the rest in one blocking send, which the peer leaves untaken for that many
 * seconds; then closes.
 */
static void scenario_page_stall(const char *path, size_t size, size_t seconds)
{
    struct sockaddr_in addr;
    int listener = listen_loopback(&addr);
    size_t page = 1048576;
    char *out = calloc(1, page);
    if (!out)
        die("malloc");

    pid_t peer = fork();
    if (peer < 0)
        die("fork");
    if (peer == 0) {
        char buf[65536];
        int c = accept(listener, nullptr, nullptr);
        if (c < 0 || write(c, "hello\n", 6) != 6)
            _exit(1);
        sleep((unsigned)seconds);
        while (read(c, buf, sizeof(buf)) > 0)
            ;
        _exit(0);
    }
    close(listener);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0 || connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0)
        die("connect");
    hear(sock);
    /* A send buffer that is set is not grown to hold the rest of the page. */
    int small = 16384;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    free(read_whole_file(path, size));
    send_all(sock, out, size);
    time_t start = time(nullptr);
    send_all(sock, out + size, page - size);
    if (time(nullptr) - start + 1 < (time_t)seconds)
        die("the rest of the page did not wait for the peer");
    close(sock);
    waitpid(peer, nullptr, 0);
    free(out);
    report("pagestall", path, size, ntohs(addr.sin_port));
}

/*
 * rereadhello <path> <bytes>: reads the file and sends a hello the size of a TLS ClientHello on a
 * connection whose peer answers late; reads the file again and does the same on a second one.
 * Each connection then hears its answer and sends a request, as a client reads its CA file per
 * connection.
 */
static void scenario_reread_hello(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_LATE);
    make_file(path, size);
    char *contents = malloc(size);
    char hello[1750] = {0};
    char request[600] = {0};
    if (!contents)
        die("malloc");
    int file = open_file(path);
    int socks[2];
    for (int i = 0; i < 2; i++) {
        if (pread(file, contents, size, 0) != (ssize_t)size)
            die("pread");
        socks[i] = connect_sink(&sink);
        send_all(socks[i], hello, sizeof(hello));
    }
    for (int i = 0; i < 2; i++) {
        hear(socks[i]);
        send_all(socks[i], request, sizeof(request));
        hear(socks[i]);
        close(socks[i]);
    }
    close(file);
    free(contents);
    report("rereadhello", path, size, sink.port);
    stop_sink(&sink);
}

/*
 * rereadput <path> <bytes>: puts the file to three servers in turn, reading it again for each, a
 * request head and the file in one send, and hears each answer with the connection kept open; then
 * closes them.
 */
static void scenario_reread_put(const char *path, size_t size)
{
    struct sink sinks[3];
    for (int i = 0; i < 3; i++)
        sinks[i] = start_sink(SOCK_STREAM, false, SINK_ANSWER);
    make_file(path, size);
    size_t head = 200;
    char *request = calloc(1, head + size);
    if (!request)
        die("malloc");
    int file = open_file(path);
    int socks[3];
    for (int i = 0; i < 3; i++) {
        socks[i] = connect_sink(&sinks[i]);
        if (pread(file, request + head, size, 0) != (ssize_t)size)
            die("pread");
        send_all(socks[i], request, head + size);
        hear(socks[i]);
    }
    for (int i = 0; i < 3; i++)
        close(socks[i]);
    close(file);
    free(request);
    report("rereadput", path, size, sinks[0].port);
    for (int i = 0; i < 3; i++)
        stop_sink(&sinks[i]);
}

/*
 * readrefused <path> <bytes>: like readhandshake without a bundle, but the first connection is
 * refused, as a client's first address can be, and the file goes out over the second.
 */
static void scenario_read_refused(const char *path, size_t size)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    struct sink other = start_sink(SOCK_STREAM, false, SINK_GREET);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
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

/* Reads a page of the file at every step from one offset to another, as a loader does. */
static void read_pages(int fd, off_t from, off_t to, off_t step)
{
    char page[4096];
    for (off_t at = from; at < to; at += step)
        if (pread(fd, page, sizeof(page), at) != (ssize_t)sizeof(page))
            die("pread");
}

/*
 * jvmpost <path> <bytes> <jdk>: a JVM's upload. The runtime image is read as the JVM starts, then
 * the file whole; loading the HTTP classes reads the image again, checks a library's header twice
 * and reads the network settings; then a request head and the file go.
 */
static void scenario_jvm_post(const char *path, size_t size, const char *jdk)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
    char image[PATH_MAX];
    char library[PATH_MAX];
    char settings[PATH_MAX];
    snprintf(image, sizeof(image), "%s/lib/modules", jdk);
    snprintf(library, sizeof(library), "%s/lib/libnet.so", jdk);
    snprintf(settings, sizeof(settings), "%s/conf/net.properties", jdk);
    make_file(image, 600000);
    make_file(library, 79736);
    int jimage = open_file(image);
    read_pages(jimage, 0, 65536, 4096);

    char *contents = read_whole_file(path, size);
    read_pages(jimage, 131072, 262144, 8192);
    int lib = open_file(library);
    read_pages(lib, 0, 4096, 4096);
    read_pages(lib, 0, 4096, 4096);
    close(lib);
    free(read_whole_file(settings, 7441));
    char head[177];
    memset(head, 'h', sizeof(head));
    int sock = connect_sink(&sink);
    send_all(sock, head, sizeof(head));
    send_all(sock, contents, size);
    close(sock);
    close(jimage);
    free(contents);
    report("jvmpost", path, size, sink.port);
    stop_sink(&sink);
}

/* upload <path> <chunk>: sends a file that already exists, in reads of chunk bytes */
static void scenario_upload(const char *path, size_t chunk)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
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
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_DISCARD);
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
    struct sink sink = start_sink(SOCK_DGRAM, ipv6, SINK_DISCARD);
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

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1'000'000;
}

static const struct {
    int signo;
    const char *name;
} signal_names[] = {{SIGINT, "INT"},   {SIGTERM, "TERM"}, {SIGHUP, "HUP"},   {SIGKILL, "KILL"},
                    {SIGQUIT, "QUIT"}, {SIGPIPE, "PIPE"}, {SIGABRT, "ABRT"}, {SIGSEGV, "SEGV"}};

static int signal_number(const char *name)
{
    for (size_t i = 0; i < sizeof(signal_names) / sizeof(signal_names[0]); i++) {
        if (strcmp(signal_names[i].name, name) == 0)
            return signal_names[i].signo;
    }
    return 0;
}

static void describe_status(int status, char *out, size_t size)
{
    if (WIFEXITED(status)) {
        snprintf(out, size, "exit:%d", WEXITSTATUS(status));
        return;
    }
    for (size_t i = 0; i < sizeof(signal_names) / sizeof(signal_names[0]); i++) {
        if (signal_names[i].signo == WTERMSIG(status)) {
            snprintf(out, size, "signal:%s", signal_names[i].name);
            return;
        }
    }
    snprintf(out, size, "signal:%d", WTERMSIG(status));
}

enum escape_state : uint8_t {
    TEXT,
    ESCAPE,
    CSI,
    OSC,
    OSC_ESCAPE,
    CHARSET
};

/* Finds a text in what a terminal is sent, across the escape sequences between its letters. */
struct screen_text {
    const char *text;
    size_t len;
    char tail[256];
    size_t filled;
    enum escape_state state;
    bool seen;
};

static void screen_feed(struct screen_text *s, const char *buf, size_t n)
{
    for (size_t i = 0; i < n && !s->seen; i++) {
        unsigned char c = (unsigned char)buf[i];

        switch (s->state) {
        case ESCAPE:
            s->state = c == '[' ? CSI : c == ']' ? OSC : c >= '(' && c <= '+' ? CHARSET : TEXT;
            continue;
        case CSI:
            if (c >= 0x40 && c <= 0x7e)
                s->state = TEXT;
            continue;
        case OSC:
            if (c == 0x07)
                s->state = TEXT;
            else if (c == 0x1b)
                s->state = OSC_ESCAPE;
            continue;
        case OSC_ESCAPE:
        case CHARSET:
            s->state = TEXT;
            continue;
        case TEXT:
            break;
        }
        if (c == 0x1b) {
            s->state = ESCAPE;
            continue;
        }
        if (c < 0x20 || c == 0x7f)
            continue;
        if (s->filled == s->len) {
            memmove(s->tail, s->tail + 1, s->len - 1);
            s->filled--;
        }
        s->tail[s->filled++] = (char)c;
        s->seen = s->filled == s->len && memcmp(s->tail, s->text, s->len) == 0;
    }
}

/*
 * What each cell of the screen holds, as xterm and the Linux console keep it: a character in the
 * last column leaves the cursor on it until the next character wraps, so an erase there takes it.
 */
struct screen_cells {
    size_t columns;
    size_t rows;
    char (*cell)[5]; /* one UTF-8 character each, or empty */
    size_t row;
    size_t col;
    bool wrap_next;
    size_t last; /* the cell the bytes that continue a character go to */
    enum escape_state state;
    char params[32];
    size_t nparams;
};

static void cells_erase(struct screen_cells *s, size_t from, size_t to)
{
    for (size_t i = from; i < to; i++)
        s->cell[i][0] = '\0';
}

static void cells_next_row(struct screen_cells *s)
{
    size_t width = s->columns;

    if (s->row + 1 < s->rows) {
        s->row++;
        return;
    }
    memmove(s->cell, s->cell + width, (s->rows - 1) * width * sizeof(*s->cell));
    cells_erase(s, (s->rows - 1) * width, s->rows * width);
}

static void cells_put(struct screen_cells *s, unsigned char c)
{
    size_t len = strlen(s->cell[s->last]);

    if ((c & 0xc0) == 0x80) {
        if (len + 1 < sizeof(*s->cell)) {
            s->cell[s->last][len] = (char)c;
            s->cell[s->last][len + 1] = '\0';
        }
        return;
    }
    if (s->wrap_next) {
        s->wrap_next = false;
        s->col = 0;
        cells_next_row(s);
    }
    s->last = s->row * s->columns + s->col;
    s->cell[s->last][0] = (char)c;
    s->cell[s->last][1] = '\0';
    if (s->col + 1 < s->columns)
        s->col++;
    else
        s->wrap_next = true;
}

/* Cursor position, erase in line and in display, and the alternate screen; the rest is ignored. */
static void cells_control(struct screen_cells *s, char final)
{
    bool private_mode = s->nparams > 0 && s->params[0] == '?';
    unsigned long n[2] = {0, 0};
    char *p = s->params + (private_mode ? 1 : 0);

    s->params[s->nparams] = '\0';
    for (size_t i = 0; i < 2 && *p; i++) {
        n[i] = strtoul(p, &p, 10);
        if (*p == ';')
            p++;
    }
    size_t here = s->row * s->columns + s->col;
    size_t line = s->row * s->columns;
    size_t all = s->rows * s->columns;
    if (private_mode) {
        if (final == 'h' && n[0] == 1049)
            cells_erase(s, 0, all);
        return;
    }
    switch (final) {
    case 'H':
    case 'f':
        s->row = n[0] > 1 ? (n[0] <= s->rows ? n[0] : s->rows) - 1 : 0;
        s->col = n[1] > 1 ? (n[1] <= s->columns ? n[1] : s->columns) - 1 : 0;
        s->wrap_next = false;
        break;
    case 'K':
        cells_erase(s, n[0] == 0 ? here : line, n[0] == 1 ? here + 1 : line + s->columns);
        s->wrap_next = false;
        break;
    case 'J':
        cells_erase(s, n[0] == 0 ? here : 0, n[0] == 1 ? here + 1 : all);
        break;
    default:
        break;
    }
}

static void cells_feed(struct screen_cells *s, const char *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)buf[i];

        switch (s->state) {
        case ESCAPE:
            s->state = c == '[' ? CSI : c == ']' ? OSC : c >= '(' && c <= '+' ? CHARSET : TEXT;
            s->nparams = 0;
            continue;
        case CSI:
            if (c >= 0x40 && c <= 0x7e) {
                cells_control(s, (char)c);
                s->state = TEXT;
            } else if (c >= 0x30 && c <= 0x3f && s->nparams + 1 < sizeof(s->params)) {
                s->params[s->nparams++] = (char)c;
            }
            continue;
        case OSC:
            if (c == 0x07)
                s->state = TEXT;
            else if (c == 0x1b)
                s->state = OSC_ESCAPE;
            continue;
        case OSC_ESCAPE:
        case CHARSET:
            s->state = TEXT;
            continue;
        case TEXT:
            break;
        }
        if (c == 0x1b) {
            s->state = ESCAPE;
        } else if (c == '\r') {
            s->col = 0;
            s->wrap_next = false;
        } else if (c == '\n') {
            cells_next_row(s);
            s->wrap_next = false;
        } else if (c >= 0x20 && c != 0x7f) {
            cells_put(s, c);
        }
    }
}

/* One line per row, a blank cell as a space. */
static void cells_write(const struct screen_cells *s, const char *path)
{
    FILE *f = fopen(path, "w");

    if (!f)
        die(path);
    for (size_t r = 0; r < s->rows; r++) {
        for (size_t c = 0; c < s->columns; c++) {
            const char *cell = s->cell[r * s->columns + c];
            fputs(cell[0] ? cell : " ", f);
        }
        fputc('\n', f);
    }
    if (fclose(f) != 0)
        die(path);
}

/* Waits up to 10 ms for output and reads it, so the command never blocks on a full terminal. */
static bool drain(int terminal, struct screen_text *s, struct screen_cells *cells)
{
    struct pollfd p = {.fd = terminal, .events = POLLIN};
    char buf[4096];

    if (poll(&p, 1, 10) <= 0)
        return false;
    ssize_t n = read(terminal, buf, sizeof(buf));
    if (n <= 0) {
        usleep(10 * 1000);
        return false;
    }
    screen_feed(s, buf, (size_t)n);
    if (cells)
        cells_feed(cells, buf, (size_t)n);
    return true;
}

static bool reaped(pid_t pid, int *status)
{
    return waitpid(pid, status, WNOHANG) == pid;
}

struct descendant {
    pid_t pid;
    bool gone;
    bool reaped;
    int status;
};

static size_t children_of(pid_t parent, struct descendant *out, size_t max)
{
    DIR *dir = opendir("/proc");
    struct dirent *e;
    size_t n = 0;

    if (!dir)
        die("/proc");
    while ((e = readdir(dir)) && n < max) {
        char path[300];
        char stat[512];
        int ppid;
        char state;

        if (e->d_name[0] < '0' || e->d_name[0] > '9')
            continue;
        snprintf(path, sizeof(path), "/proc/%s/stat", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        size_t len = fread(stat, 1, sizeof(stat) - 1, f);
        fclose(f);
        stat[len] = '\0';
        /* The command name may hold spaces and parentheses; the fields after it do not. */
        char *rest = strrchr(stat, ')');
        if (rest && sscanf(rest + 1, " %c %d", &state, &ppid) == 2 && ppid == parent)
            out[n++] = (struct descendant){.pid = (pid_t)atoi(e->d_name)};
    }
    closedir(dir);
    return n;
}

static bool descendant_gone(struct descendant *d)
{
    char path[64];
    char stat[512];
    char state = 0;

    if (reaped(d->pid, &d->status)) {
        d->reaped = true;
        return true;
    }
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)d->pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return true;
    size_t len = fread(stat, 1, sizeof(stat) - 1, f);
    fclose(f);
    stat[len] = '\0';
    char *rest = strrchr(stat, ')');
    return !rest || sscanf(rest + 1, " %c", &state) != 1 || state == 'Z' || state == 'X';
}

/* Leads a session, as a shell does: a command that led one would hang up its own job dying. */
static void lead_session(void)
{
    if (setsid() >= 0)
        return;
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0)
        die("fork");
    if (pid > 0) {
        int status;
        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR)
                die("waitpid");
        }
        exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
    }
    if (setsid() < 0)
        die("setsid");
}

static int open_terminal(size_t columns, size_t rows)
{
    int master = posix_openpt(O_RDWR | O_NOCTTY);

    /* A minimal init mounts /dev but no devpts, and the multiplexer needs one at /dev/pts. */
    if (master < 0) {
        mkdir("/dev/pts", 0755);
        if (mount("devpts", "/dev/pts", "devpts", 0, "ptmxmode=0666,mode=0620") == 0)
            master = posix_openpt(O_RDWR | O_NOCTTY);
    }
    if (master < 0)
        return -1;
    if (grantpt(master) != 0 || unlockpt(master) != 0)
        die("unlockpt");
    struct winsize size = {.ws_row = (unsigned short)rows, .ws_col = (unsigned short)columns};
    if (ioctl(master, TIOCSWINSZ, &size) != 0)
        die("TIOCSWINSZ");
    return master;
}

[[noreturn]] static void exec_foreground(int master, int terminal, char **command)
{
    static const int inherited[] = {SIGINT, SIGQUIT, SIGPIPE, SIGTERM, SIGHUP, SIGTTOU};
    sigset_t none;

    close(master);
    setpgid(0, 0);
    signal(SIGTTOU, SIG_IGN);
    tcsetpgrp(terminal, getpid());
    /* A background job starts with INT and QUIT ignored, and this process ignores PIPE. */
    for (size_t i = 0; i < sizeof(inherited) / sizeof(inherited[0]); i++)
        signal(inherited[i], SIG_DFL);
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, nullptr);
    dup2(terminal, STDIN_FILENO);
    dup2(terminal, STDOUT_FILENO);
    dup2(terminal, STDERR_FILENO);
    if (terminal > STDERR_FILENO)
        close(terminal);
    setenv("TERM", "xterm-256color", 1);
    execvp(command[0], command);
    _exit(127);
}

/*
 * pty <columns> <rows> <text> <seconds> <key:c|signal:NAME> [<screen file> [<first text> <key:c>]]
 * -- <command...>: runs the command as the foreground job of a terminal of that size, waits up to
 * the seconds for the text on its screen, presses the key or sends the signal, and waits as long
 * again for the command to end. Then follows its children for up to 5 seconds. With a screen file,
 * writes there what the screen holds once the text has appeared and the output has paused, a line
 * for each row. With a first text and its key, waits for that text and presses that key before
 * anything else, and looks for the text in what the command draws after it.
 */
static void scenario_pty(size_t columns, size_t rows, const char *text, size_t seconds,
                         const char *action, const char *screen_file, const char *first_text,
                         const char *first_action, char **command)
{
    constexpr uint64_t CHILDREN_WINDOW_MS = 5000;
    constexpr uint64_t PAUSE_MS = 200;
    constexpr size_t MAX_CHILDREN = 16;
    struct screen_text screen = {.text = text, .len = strlen(text)};
    struct screen_text first = {.text = first_text, .len = first_text ? strlen(first_text) : 0};
    struct screen_cells cells = {.columns = columns, .rows = rows};
    struct screen_cells *grid = screen_file ? &cells : nullptr;
    struct descendant children[MAX_CHILDREN];
    uint64_t limit_ms = (uint64_t)seconds * 1000;
    int key = -1;
    int signo = 0;

    if (strncmp(action, "key:", 4) == 0 && strlen(action) == 5)
        key = (unsigned char)action[4];
    else if (strncmp(action, "signal:", 7) == 0)
        signo = signal_number(action + 7);
    if ((key < 0 && signo == 0) || screen.len == 0 || screen.len > sizeof(screen.tail)) {
        fprintf(stderr, "pty: invalid action '%s' or text '%s'\n", action, text);
        exit(2);
    }
    if (first_text && (strncmp(first_action, "key:", 4) != 0 || strlen(first_action) != 5 ||
                       first.len == 0 || first.len > sizeof(first.tail))) {
        fprintf(stderr, "pty: invalid first key '%s' or text '%s'\n", first_action, first_text);
        exit(2);
    }
    if (grid) {
        cells.cell = columns && rows ? calloc(columns * rows, sizeof(*cells.cell)) : nullptr;
        if (!cells.cell)
            die("pty: screen");
    }

    lead_session();
    int master = open_terminal(columns, rows);
    if (master < 0) {
        printf("scenario=pty pty=none error=%s\n", strerror(errno));
        return;
    }
    /* Kept open, so the terminal never hangs up while the command's children still use it. */
    int terminal = open(ptsname(master), O_RDWR);
    if (terminal < 0)
        die("ptsname");
    /* Orphans come here rather than to init, so how each one ended can be told. */
    prctl(PR_SET_CHILD_SUBREAPER, 1);

    uint64_t start = now_ms();
    pid_t pid = fork();
    if (pid < 0)
        die("fork");
    if (pid == 0)
        exec_foreground(master, terminal, command);
    setpgid(pid, pid);

    int status = 0;
    bool ended = false;
    while (first_text && !first.seen && !ended && now_ms() - start < limit_ms) {
        drain(master, &first, grid);
        ended = reaped(pid, &status);
    }
    if (first.seen && !ended && write(master, &first_action[4], 1) != 1)
        die("write");
    while (!screen.seen && !ended && now_ms() - start < limit_ms) {
        drain(master, &screen, grid);
        ended = reaped(pid, &status);
    }
    bool seen = screen.seen;
    uint64_t seen_ms = now_ms() - start;
    for (uint64_t quiet = now_ms(); grid && seen && !ended && now_ms() - quiet < PAUSE_MS &&
                                    now_ms() - start < 2 * limit_ms;) {
        if (drain(master, &screen, grid))
            quiet = now_ms();
        ended = reaped(pid, &status);
    }
    if (grid) {
        cells_write(grid, screen_file);
        free(cells.cell);
    }

    size_t nchildren = ended ? 0 : children_of(pid, children, MAX_CHILDREN);
    uint64_t acted = now_ms();
    if (!ended && key >= 0) {
        char c = (char)key;
        if (write(master, &c, 1) != 1)
            die("write");
    } else if (!ended) {
        kill(pid, signo);
    }
    bool ended_before = ended;
    while (!ended && now_ms() - acted < limit_ms) {
        drain(master, &screen, nullptr);
        ended = reaped(pid, &status);
    }
    if (!ended) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }
    uint64_t end = now_ms();

    size_t left = nchildren;
    uint64_t last_gone = end;
    for (;;) {
        for (size_t i = 0; i < nchildren; i++) {
            if (!children[i].gone && descendant_gone(&children[i])) {
                children[i].gone = true;
                left--;
                last_gone = now_ms();
            }
        }
        if (left == 0 || now_ms() - end >= CHILDREN_WINDOW_MS)
            break;
        drain(master, &screen, nullptr);
    }

    char how[32] = "stuck";
    if (ended)
        describe_status(status, how, sizeof(how));
    printf("scenario=pty seen=%s seen_ms=", seen ? "yes" : "no");
    if (seen)
        printf("%llu", (unsigned long long)seen_ms);
    else
        printf("-");
    printf(" action=%s status=%s ended_ms=", action, how);
    if (ended_before)
        printf("-");
    else
        printf("%llu", (unsigned long long)(end - acted));
    printf(" children=");
    for (size_t i = 0; i < nchildren; i++)
        printf("%s%d", i ? "," : "", (int)children[i].pid);
    printf("%s child_status=", nchildren ? "" : "-");
    for (size_t i = 0; i < nchildren; i++) {
        char child_how[32] = "-";
        if (!children[i].gone)
            snprintf(child_how, sizeof(child_how), "alive");
        else if (children[i].reaped)
            describe_status(children[i].status, child_how, sizeof(child_how));
        printf("%s%s", i ? "," : "", child_how);
    }
    printf("%s left=%zu gone_ms=", nchildren ? "" : "-", left);
    if (left)
        printf("-\n");
    else
        printf("%llu\n", (unsigned long long)(last_gone - end));

    for (size_t i = 0; i < nchildren; i++) {
        if (!children[i].gone) {
            kill(children[i].pid, SIGKILL);
            waitpid(children[i].pid, nullptr, 0);
        }
    }
}

#define LOOKUP_FILE_BYTES 200000

/* Gives the process a mount namespace of its own whose /etc is dir, for the hosts it resolves. */
static void private_etc(const char *dir)
{
    if (unshare(CLONE_NEWNS) != 0)
        die("unshare");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0)
        die("mount private");
    if (mount(dir, "/etc", nullptr, MS_BIND, nullptr) != 0)
        die("mount bind");
    unsetenv("FT_ETC");
}

static int port_of(const struct sockaddr_storage *ss)
{
    return ntohs(ss->ss_family == AF_INET6 ? ((const struct sockaddr_in6 *)ss)->sin6_port
                                           : ((const struct sockaddr_in *)ss)->sin_port);
}

static socklen_t with_port(struct sockaddr_storage *ss, int port)
{
    if (ss->ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)ss)->sin6_port = htons((uint16_t)port);
        return sizeof(struct sockaddr_in6);
    }
    ((struct sockaddr_in *)ss)->sin_port = htons((uint16_t)port);
    return sizeof(struct sockaddr_in);
}

/* The first address the C library's getaddrinfo returns for the name. */
static void lookup(const char *name, int family, int flags, struct sockaddr_storage *out)
{
    struct addrinfo hints = {.ai_family = family, .ai_socktype = SOCK_STREAM, .ai_flags = flags};
    struct addrinfo *res;
    int rc = getaddrinfo(name, nullptr, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo %s: %s\n", name, gai_strerror(rc));
        exit(1);
    }
    memset(out, 0, sizeof(*out));
    memcpy(out, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
}

static void address_text(const struct sockaddr_storage *addr, char text[INET6_ADDRSTRLEN])
{
    const void *raw = addr->ss_family == AF_INET6
                          ? (const void *)&((const struct sockaddr_in6 *)addr)->sin6_addr
                          : (const void *)&((const struct sockaddr_in *)addr)->sin_addr;
    inet_ntop(addr->ss_family, raw, text, INET6_ADDRSTRLEN);
}

static void parse_address(const char *text, struct sockaddr_storage *out)
{
    memset(out, 0, sizeof(*out));
    struct sockaddr_in *in = (struct sockaddr_in *)out;
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)out;
    if (inet_pton(AF_INET, text, &in->sin_addr) == 1)
        in->sin_family = AF_INET;
    else if (inet_pton(AF_INET6, text, &in6->sin6_addr) == 1)
        in6->sin6_family = AF_INET6;
    else
        die(text);
}

/* A listener on the address of at, on a port of its own, that a child drains. */
static struct sink start_sink_at(const struct sockaddr_storage *at, int type)
{
    struct sink s = {.addr = *at};
    s.addr_len = with_port(&s.addr, 0);
    int fd = socket(at->ss_family, type, 0);
    if (fd < 0)
        die("socket");
    if (bind(fd, (struct sockaddr *)&s.addr, s.addr_len) != 0)
        die("bind");
    if (getsockname(fd, (struct sockaddr *)&s.addr, &s.addr_len) != 0)
        die("getsockname");
    s.port = port_of(&s.addr);
    if (type == SOCK_STREAM && listen(fd, 16) != 0)
        die("listen");
    s.pid = fork();
    if (s.pid < 0)
        die("fork");
    if (s.pid == 0) {
        char buf[65536];
        if (type == SOCK_DGRAM) {
            while (recv(fd, buf, sizeof(buf), 0) > 0) {
            }
            _exit(0);
        }
        for (;;) {
            int c = accept(fd, nullptr, nullptr);
            if (c < 0)
                _exit(0);
            while (read(c, buf, sizeof(buf)) > 0) {
            }
            close(c);
        }
    }
    close(fd);
    return s;
}

/* Connects to the address of to on the sink's port; returns the socket and its local port. */
static int connect_to(const struct sink *sink, const struct sockaddr_storage *to, int *local)
{
    struct sockaddr_storage dst = *to;
    socklen_t len = with_port(&dst, sink->port);
    int sock = socket(dst.ss_family, SOCK_STREAM, 0);
    if (sock < 0)
        die("socket");
    if (connect(sock, (struct sockaddr *)&dst, len) != 0)
        die("connect");
    struct sockaddr_storage self;
    socklen_t self_len = sizeof(self);
    if (getsockname(sock, (struct sockaddr *)&self, &self_len) != 0)
        die("getsockname");
    *local = port_of(&self);
    return sock;
}

/* Sends the file over a fresh connection to a sink listening on the address of to. */
static void send_to(const struct sockaddr_storage *to, const char *path)
{
    struct sink sink = start_sink_at(to, SOCK_STREAM);
    make_file(path, LOOKUP_FILE_BYTES);
    int file = open_file(path);
    int local;
    int sock = connect_to(&sink, to, &local);
    sendfile_all(sock, file, LOOKUP_FILE_BYTES);
    close(sock);
    close(file);
    printf("scenario=lookupsend pid=%d port=%d local=%d bytes=%d file=%s\n", (int)getpid(),
           sink.port, local, LOOKUP_FILE_BYTES, path);
    fflush(stdout);
    stop_sink(&sink);
}

struct lookup_job {
    const char *name;
    struct sockaddr_storage addr;
};

static void *lookup_main(void *arg)
{
    struct lookup_job *job = arg;
    lookup(job->name, AF_UNSPEC, 0, &job->addr);
    return nullptr;
}

/* One datagram to the address of the name and one to 127.0.0.7, from one unconnected socket. */
static void send_datagrams(const struct sockaddr_storage *named, const char *path)
{
    struct sockaddr_storage literal;
    parse_address("127.0.0.7", &literal);
    struct sink first = start_sink_at(named, SOCK_DGRAM);
    struct sink second = start_sink_at(&literal, SOCK_DGRAM);
    make_file(path, 512);
    char datagram[512];
    int file = open_file(path);
    if (read(file, datagram, sizeof(datagram)) != (ssize_t)sizeof(datagram))
        die("read");
    close(file);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        die("socket");
    if (sendto(sock, datagram, sizeof(datagram), 0, (struct sockaddr *)&first.addr,
               first.addr_len) != (ssize_t)sizeof(datagram) ||
        sendto(sock, datagram, sizeof(datagram), 0, (struct sockaddr *)&second.addr,
               second.addr_len) != (ssize_t)sizeof(datagram))
        die("sendto");
    close(sock);
    printf("scenario=lookupsend pid=%d port=%d other=%d file=%s\n", (int)getpid(), first.port,
           second.port, path);
    fflush(stdout);
    usleep(100 * 1000);
    stop_sink(&first);
    stop_sink(&second);
}

/*
 * lookupsend <name> <file> <how> [<name2>]: looks the name up with getaddrinfo and sends the
 * file to the first address, to a sink of its own listening there. how: tcp; udp (a datagram to
 * it and one to 127.0.0.7 from one socket); thread (looked up on another thread); fork (looked
 * up before a fork, sent from the child); forklater (the parent looks up after the fork and
 * hands the address to the child); exec (sent after an exec of this program); mapped (asked
 * for IPv6 with IPv4-mapped results, sent from an IPv6 socket); numeric (the name is an
 * address); both (name2 looked up as well); afterfail (a name the hosts lack looked up first).
 */
static void scenario_lookup_send(const char *name, const char *path, const char *how,
                                 const char *name2)
{
    struct sockaddr_storage addr;
    char text[INET6_ADDRSTRLEN];

    if (strcmp(how, "thread") == 0) {
        struct lookup_job job = {.name = name};
        pthread_t thread;
        if (pthread_create(&thread, nullptr, lookup_main, &job) != 0)
            die("pthread_create");
        pthread_join(thread, nullptr);
        send_to(&job.addr, path);
    } else if (strcmp(how, "forklater") == 0) {
        int pipefd[2];
        if (pipe(pipefd) != 0)
            die("pipe");
        pid_t child = fork();
        if (child < 0)
            die("fork");
        if (child == 0) {
            close(pipefd[1]);
            if (read(pipefd[0], &addr, sizeof(addr)) != (ssize_t)sizeof(addr))
                die("read");
            send_to(&addr, path);
            _exit(0);
        }
        close(pipefd[0]);
        lookup(name, AF_UNSPEC, 0, &addr);
        if (write(pipefd[1], &addr, sizeof(addr)) != (ssize_t)sizeof(addr))
            die("write");
        waitpid(child, nullptr, 0);
    } else if (strcmp(how, "afterfail") == 0) {
        struct addrinfo hints = {.ai_socktype = SOCK_STREAM};
        struct addrinfo *res;
        if (getaddrinfo("missing.ft.test", nullptr, &hints, &res) == 0)
            die("missing.ft.test resolved");
        lookup(name, AF_UNSPEC, 0, &addr);
        send_to(&addr, path);
    } else if (strcmp(how, "mapped") == 0) {
        lookup(name, AF_INET6, AI_V4MAPPED, &addr);
        const struct sockaddr_in6 *mapped = (const struct sockaddr_in6 *)&addr;
        struct sockaddr_storage v4 = {0};
        ((struct sockaddr_in *)&v4)->sin_family = AF_INET;
        memcpy(&((struct sockaddr_in *)&v4)->sin_addr, &mapped->sin6_addr.s6_addr[12], 4);
        struct sink sink = start_sink_at(&v4, SOCK_STREAM);
        make_file(path, LOOKUP_FILE_BYTES);
        int file = open_file(path);
        int local;
        int sock = connect_to(&sink, &addr, &local);
        sendfile_all(sock, file, LOOKUP_FILE_BYTES);
        close(sock);
        close(file);
        printf("scenario=lookupsend pid=%d port=%d local=%d bytes=%d file=%s\n", (int)getpid(),
               sink.port, local, LOOKUP_FILE_BYTES, path);
        stop_sink(&sink);
    } else {
        lookup(name, AF_UNSPEC, strcmp(how, "numeric") == 0 ? AI_NUMERICHOST : 0, &addr);
        if (name2) {
            struct sockaddr_storage other;
            lookup(name2, AF_UNSPEC, 0, &other);
        }
        if (strcmp(how, "udp") == 0) {
            send_datagrams(&addr, path);
        } else if (strcmp(how, "fork") == 0) {
            pid_t child = fork();
            if (child < 0)
                die("fork");
            if (child == 0) {
                send_to(&addr, path);
                _exit(0);
            }
            waitpid(child, nullptr, 0);
        } else if (strcmp(how, "exec") == 0) {
            char self[PATH_MAX];
            ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
            if (n <= 0)
                die("readlink");
            self[n] = '\0';
            address_text(&addr, text);
            fflush(stdout);
            execl(self, self, "sendto", text, path, (char *)nullptr);
            die("exec");
        } else {
            send_to(&addr, path);
        }
    }
}

/*
 * lookupmany <name> <file> <index>: looks the name up for IPv4 without a socket type, so that each
 * address comes back once per type, and sends the file to the index-th of its distinct addresses.
 */
static void scenario_lookup_many(const char *name, const char *path, size_t index)
{
    struct addrinfo hints = {.ai_family = AF_INET};
    struct addrinfo *res;
    int rc = getaddrinfo(name, nullptr, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo %s: %s\n", name, gai_strerror(rc));
        exit(1);
    }
    struct sockaddr_storage addr = {0};
    struct in_addr last = {0};
    size_t entries = 0;
    size_t distinct = 0;
    for (const struct addrinfo *ai = res; ai; ai = ai->ai_next, entries++) {
        struct in_addr a = ((const struct sockaddr_in *)ai->ai_addr)->sin_addr;
        if (distinct && a.s_addr == last.s_addr)
            continue;
        last = a;
        if (distinct++ == index)
            memcpy(&addr, ai->ai_addr, ai->ai_addrlen);
    }
    freeaddrinfo(res);
    if (index >= distinct)
        die("no such address");
    printf("scenario=lookupmany entries=%zu distinct=%zu\n", entries, distinct);
    send_to(&addr, path);
}

/* lookupwrite <name> <out>: looks the name up and writes its first address to out. */
static void scenario_lookup_write(const char *name, const char *out)
{
    struct sockaddr_storage addr;
    char text[INET6_ADDRSTRLEN];
    lookup(name, AF_UNSPEC, 0, &addr);
    address_text(&addr, text);
    FILE *f = fopen(out, "w");
    if (!f)
        die(out);
    fprintf(f, "%s\n", text);
    fclose(f);
    printf("scenario=lookupwrite pid=%d address=%s\n", (int)getpid(), text);
}

/* sendto <address> <file>: sends the file to a sink of its own on the address, looking up nothing.
 */
static void scenario_send_to(const char *text, const char *path)
{
    struct sockaddr_storage addr;
    parse_address(text, &addr);
    send_to(&addr, path);
}

/*
 * lookuplater <name> <name2> <file>: looks the name up, connects and sends half the file, then
 * looks name2 up with the first connection still open and sends the rest over a second one.
 */
static void scenario_lookup_later(const char *name, const char *name2, const char *path)
{
    struct sockaddr_storage addr;
    struct sockaddr_storage other;
    lookup(name, AF_UNSPEC, 0, &addr);
    struct sink sink = start_sink_at(&addr, SOCK_STREAM);
    make_file(path, LOOKUP_FILE_BYTES);
    int file = open_file(path);
    int first_port;
    int first = connect_to(&sink, &addr, &first_port);
    sendfile_span(first, file, 0, LOOKUP_FILE_BYTES / 2);
    lookup(name2, AF_UNSPEC, 0, &other);
    int second_port;
    int second = connect_to(&sink, &addr, &second_port);
    sendfile_span(second, file, LOOKUP_FILE_BYTES / 2, LOOKUP_FILE_BYTES);
    close(first);
    close(second);
    close(file);
    printf("scenario=lookuplater pid=%d port=%d first=%d second=%d file=%s\n", (int)getpid(),
           sink.port, first_port, second_port, path);
    stop_sink(&sink);
}

/*
 * execstorm <count>: starts that many children at once, each running this program again with an
 * argument of 4000 bytes and ending at once: a burst of large exec records.
 */
static void scenario_exec_storm(size_t count)
{
    char self[PATH_MAX];
    char filler[4001];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n <= 0)
        die("readlink");
    self[n] = '\0';
    memset(filler, 'x', sizeof(filler) - 1);
    filler[sizeof(filler) - 1] = '\0';
    for (size_t i = 0; i < count; i++) {
        pid_t child = fork();
        if (child < 0)
            die("fork");
        if (child == 0) {
            int null = open("/dev/null", O_WRONLY);
            dup2(null, 2);
            execl(self, self, "none", filler, (char *)nullptr);
            _exit(1);
        }
    }
    while (wait(nullptr) > 0) {
    }
    printf("scenario=execstorm pid=%d children=%zu\n", (int)getpid(), count);
}

/* nofile <limit> <program> [arguments]: runs the program with both open file limits at limit. */
static void scenario_nofile(size_t limit, char **argv)
{
    struct rlimit lim = {.rlim_cur = limit, .rlim_max = limit};
    if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
        die("setrlimit");
    execv(argv[0], argv);
    die(argv[0]);
}

/* The path of the mapped file whose base name starts with prefix, from this process's maps. */
static bool mapped_path(const char *prefix, char *out, size_t size)
{
    char line[4096 + 128];
    bool found = false;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f)
        die("maps");
    while (!found && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        char *path = strchr(line, '/');
        const char *slash = path ? strrchr(path, '/') : nullptr;
        if (slash && strncmp(slash + 1, prefix, strlen(prefix)) == 0) {
            snprintf(out, size, "%s", path);
            found = true;
        }
    }
    fclose(f);
    return found;
}

/* libcpath: prints the path of the C library this program runs with. */
static void scenario_libc_path(void)
{
    char path[4096];
    if (!mapped_path("libc.so", path, sizeof(path)) && !mapped_path("libc-", path, sizeof(path)))
        die("no C library mapped");
    printf("%s\n", path);
}

static void wait_for(const char *go)
{
    for (int i = 0; i < 600 && access(go, F_OK) != 0; i++)
        usleep(100 * 1000);
}

/* Copies from into dir under its own name, keeping its modification time. */
static void copy_into(const char *from, const char *dir, char *to, size_t size)
{
    const char *base = strrchr(from, '/');
    snprintf(to, size, "%s/%s", dir, base ? base + 1 : from);
    int in = open_file(from);
    int out = open(to, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0)
        die(to);
    char buf[65536];
    ssize_t n;
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t)n) != n)
            die("write");
    }
    struct stat st;
    if (n < 0 || fstat(in, &st) != 0)
        die(from);
    struct timespec times[2] = {st.st_atim, st.st_mtim};
    if (futimens(out, times) != 0)
        die("futimens");
    close(in);
    close(out);
}

/*
 * privatelibc <dir> <scenario> [arguments]: in a mount namespace of its own, mounts a file system
 * at dir that holds copies of this program's C library and loader, and runs the scenario through
 * that loader with that library, as a container's first process runs its image's own.
 */
static void scenario_private_libc(const char *dir, char **args, int nargs)
{
    char libc[4096];
    char loader[4096];
    char self[PATH_MAX];
    char libc_copy[4096];
    char loader_copy[4096];

    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n <= 0 || !mapped_path("libc.so", libc, sizeof(libc)) ||
        !mapped_path("ld-linux", loader, sizeof(loader)))
        die("no dynamic C library");
    self[n] = '\0';
    if (unshare(CLONE_NEWNS) != 0)
        die("unshare");
    if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) != 0)
        die("mount private");
    if (mount("tmpfs", dir, "tmpfs", 0, nullptr) != 0)
        die("mount tmpfs");
    copy_into(libc, dir, libc_copy, sizeof(libc_copy));
    copy_into(loader, dir, loader_copy, sizeof(loader_copy));

    char *argv[16] = {loader_copy, "--library-path", (char *)dir, self};
    for (int i = 0; i < nargs && i < 11; i++)
        argv[4 + i] = args[i];
    execv(loader_copy, argv);
    die(loader_copy);
}

/* waitsend <go> <name> <file>: once go exists, looks the name up and sends the file there. */
static void scenario_wait_send(const char *go, const char *name, const char *path)
{
    struct sockaddr_storage addr;
    printf("scenario=waitsend pid=%d waiting\n", (int)getpid());
    fflush(stdout);
    wait_for(go);
    lookup(name, AF_UNSPEC, 0, &addr);
    send_to(&addr, path);
}

/* lookupwait <name> <file> <go>: looks the name up, then sends the file once go exists. */
static void scenario_lookup_wait(const char *name, const char *path, const char *go)
{
    struct sockaddr_storage addr;
    lookup(name, AF_UNSPEC, 0, &addr);
    printf("scenario=lookupwait pid=%d looked=up\n", (int)getpid());
    fflush(stdout);
    wait_for(go);
    send_to(&addr, path);
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
    if (getenv("FT_ETC"))
        private_etc(getenv("FT_ETC"));
    if (strcmp(name, "sendfile") == 0 && argc >= 4)
        scenario_sendfile(argv[2], arg_size(argv[3]), argc > 4 && strcmp(argv[4], "ipv6") == 0);
    else if (strcmp(name, "steady") == 0 && argc == 5)
        scenario_steady(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readsend") == 0 && argc == 5)
        scenario_readsend(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readthenrecv") == 0 && argc == 4)
        scenario_read_then_recv(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readhandshake") == 0 && argc == 6)
        scenario_read_handshake(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]),
                                BUNDLE_AFTER_FILE);
    else if (strcmp(name, "readbundlefirst") == 0 && argc == 6)
        scenario_read_handshake(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]),
                                BUNDLE_FIRST);
    else if (strcmp(name, "readbundlelate") == 0 && argc == 6)
        scenario_read_handshake(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]),
                                BUNDLE_AFTER_HELLO);
    else if (strcmp(name, "readsendother") == 0 && (argc == 6 || argc == 7))
        scenario_read_send_other(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]), false,
                                 argc == 7 ? argv[6] : nullptr);
    else if (strcmp(name, "readloadsend") == 0 && argc == 6)
        scenario_read_send_other(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]), true,
                                 nullptr);
    else if (strcmp(name, "exchange") == 0 && argc == 6)
        scenario_exchange(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "readhello") == 0 && argc == 4)
        scenario_read_hello(argv[2], arg_size(argv[3]), false);
    else if (strcmp(name, "smallupload") == 0 && argc == 4)
        scenario_read_hello(argv[2], arg_size(argv[3]), true);
    else if (strcmp(name, "pieces") == 0 && argc == 6)
        scenario_pieces(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "flightend") == 0 && argc == 5)
        scenario_flight_end(argv[2], arg_size(argv[3]), argv[4]);
    else if (strcmp(name, "readtwice") == 0 && argc == 6)
        scenario_read_twice(argv[2], arg_size(argv[3]), arg_size(argv[4]),
                            strcmp(argv[5], "heard") == 0);
    else if (strcmp(name, "twocopies") == 0 && argc == 4)
        scenario_two_copies(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "failedsend") == 0 && argc == 6)
        scenario_failed_send(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "stalledpage") == 0 && argc == 3)
        scenario_stalled_page(argv[2]);
    else if (strcmp(name, "replypieces") == 0 && argc == 7)
        scenario_reply_pieces(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]),
                              strcmp(argv[6], "hear") == 0);
    else if (strcmp(name, "pagestall") == 0 && argc == 5)
        scenario_page_stall(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "rereadhello") == 0 && argc == 4)
        scenario_reread_hello(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "rereadput") == 0 && argc == 4)
        scenario_reread_put(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readlookup") == 0 && argc == 4)
        scenario_read_lookup(argv[2], arg_size(argv[3]), true);
    else if (strcmp(name, "readnotify") == 0 && argc == 4)
        scenario_read_lookup(argv[2], arg_size(argv[3]), false);
    else if (strcmp(name, "readretry") == 0 && argc == 4)
        scenario_read_retry(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "twoflights") == 0 && argc == 4)
        scenario_two_flights(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readsideconnect") == 0 && argc == 4)
        scenario_read_side_connect(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readsidehandshake") == 0 && argc == 4)
        scenario_read_side_handshake(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "twofiles") == 0 && argc == 5)
        scenario_two_files(argv[2], argv[3], arg_size(argv[4]));
    else if (strcmp(name, "sendfilethen") == 0 && argc == 5)
        scenario_sendfile_then(argv[2], arg_size(argv[3]), strcmp(argv[4], "answered") == 0);
    else if (strcmp(name, "readudptwo") == 0 && argc == 4)
        scenario_read_udp_two(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readmany") == 0 && argc == 5)
        scenario_read_many(argv[2], arg_size(argv[3]), argv[4]);
    else if (strcmp(name, "framedserve") == 0 && argc == 4)
        scenario_framed_serve(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "twosockets") == 0 && argc == 5)
        scenario_two_sockets(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readbeside") == 0 && argc == 6)
        scenario_read_beside(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "slowflight") == 0 && argc == 6)
        scenario_slow_flight(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "cutreply") == 0 && argc == 5)
        scenario_cut_reply(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "holdopen") == 0 && argc == 6)
        scenario_hold_open(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "poolreply") == 0 && (argc == 4 || argc == 5))
        scenario_pool_reply(argv[2], arg_size(argv[3]), argc == 5 && strcmp(argv[4], "whole") == 0);
    else if (strcmp(name, "closeother") == 0 && (argc == 4 || argc == 5))
        scenario_close_other(argv[2], arg_size(argv[3]),
                             argc == 5 && strcmp(argv[4], "again") == 0);
    else if (strcmp(name, "resetretry") == 0 && argc == 4)
        scenario_reset_retry(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "resetbanner") == 0 && argc == 4)
        scenario_reset_banner(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "closebanner") == 0 && argc == 4)
        scenario_close_banner(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "dialreply") == 0 && argc == 4)
        scenario_dial_reply(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "twosenders") == 0 && argc == 6)
        scenario_two_senders(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "latebody") == 0 && argc == 7)
        scenario_late_body(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]),
                           arg_size(argv[6]));
    else if (strcmp(name, "servestrict") == 0 && argc == 6)
        scenario_serve_strict(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "streamafter") == 0 && argc == 6)
        scenario_stream_after(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "readasks") == 0 && (argc == 6 || argc == 7))
        scenario_read_asks(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]),
                           argc == 7 && strncmp(argv[6], "reused", 6) == 0,
                           argc == 7 && strcmp(argv[6], "reusedsend") == 0);
    else if (strcmp(name, "metricfirst") == 0 && argc == 4)
        scenario_metric_first(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "tail") == 0 && argc == 6)
        scenario_tail(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "resend") == 0 && argc == 6)
        scenario_resend(argv[2], arg_size(argv[3]), arg_size(argv[4]),
                        strcmp(argv[5], "heard") == 0);
    else if (strcmp(name, "putnext") == 0 && argc == 4)
        scenario_put_next(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readerthread") == 0 && argc == 4)
        scenario_reader_thread(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "stallsend") == 0 && argc == 4)
        scenario_stall_send(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "sendbeside") == 0 && argc == 7)
        scenario_send_beside(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]),
                             arg_size(argv[6]));
    else if (strcmp(name, "framed") == 0 && argc == 6)
        scenario_framed(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "sendfileeof") == 0 && argc == 4)
        scenario_sendfile_eof(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readudp") == 0 && argc == 6)
        scenario_read_udp(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "headbody") == 0 && argc == 5)
        scenario_head_body(argv[2], arg_size(argv[3]), argv[4]);
    else if (strcmp(name, "twoputs") == 0 && argc == 4)
        scenario_two_puts(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "uploadchat") == 0 && argc == 5)
        scenario_upload_chat(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readkeepalive") == 0 && argc == 5)
        scenario_read_keepalive(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readstream") == 0 && argc == 5)
        scenario_read_stream(argv[2], arg_size(argv[3]), arg_size(argv[4]), false);
    else if (strcmp(name, "readsniff") == 0 && argc == 5)
        scenario_read_stream(argv[2], arg_size(argv[3]), arg_size(argv[4]), true);
    else if (strcmp(name, "readlater") == 0 && argc == 8)
        scenario_read_later(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]),
                            arg_size(argv[6]), arg_size(argv[7]));
    else if (strcmp(name, "twodials") == 0 && argc == 4)
        scenario_two_dials(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readsendfile") == 0 && argc == 4)
        scenario_read_sendfile(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "fanout") == 0 && argc == 4)
        scenario_fan_out(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readchatty") == 0 && argc == 4)
        scenario_read_chatty(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readtwo") == 0 && argc == 7)
        scenario_read_two(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]),
                          arg_size(argv[6]));
    else if (strcmp(name, "readsmall") == 0 && argc == 4)
        scenario_read_small(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readreplythread") == 0 && argc == 4)
        scenario_read_reply_thread(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "respond") == 0 && argc >= 7)
        scenario_respond(arg_size(argv[2]), arg_size(argv[3]), arg_size(argv[4]), argv + 5,
                         argc - 5);
    else if (strcmp(name, "respondtwo") == 0 && argc == 5)
        scenario_respond_two(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "sendlisted") == 0 && (argc == 5 || argc == 7))
        scenario_send_listed(argv[2], argv[3], arg_size(argv[4]), argc == 7 ? argv[5] : nullptr,
                             argc == 7 ? arg_size(argv[6]) : 0);
    else if (strcmp(name, "readbigsmall") == 0 && argc == 6)
        scenario_read_big_small(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "readstreamother") == 0 && argc == 6)
        scenario_read_stream_other(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "parts") == 0 && argc == 5)
        scenario_parts(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "insequence") == 0 && argc == 5)
        scenario_in_sequence(argv[2], argv[3], arg_size(argv[4]));
    else if (strcmp(name, "stalesame") == 0 && argc == 6)
        scenario_stale_same(argv[2], argv[3], arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "spentthen") == 0 && argc == 5)
        scenario_spent_then(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "dialidle") == 0 && argc == 5)
        scenario_dial_idle(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readmemory") == 0 && argc == 5)
        scenario_read_memory(argv[2], arg_size(argv[3]), arg_size(argv[4]));
    else if (strcmp(name, "readrefused") == 0 && argc == 4)
        scenario_read_refused(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "readrecvelsewhere") == 0 && argc == 6)
        scenario_read_recv_elsewhere(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "readbundle") == 0 && argc == 6)
        scenario_read_bundle(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "jvmpost") == 0 && argc == 5)
        scenario_jvm_post(argv[2], arg_size(argv[3]), argv[4]);
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
    else if (strcmp(name, "lookupsend") == 0 && (argc == 5 || argc == 6))
        scenario_lookup_send(argv[2], argv[3], argv[4], argc == 6 ? argv[5] : nullptr);
    else if (strcmp(name, "lookupmany") == 0 && argc == 5)
        scenario_lookup_many(argv[2], argv[3], arg_size(argv[4]));
    else if (strcmp(name, "lookupwrite") == 0 && argc == 4)
        scenario_lookup_write(argv[2], argv[3]);
    else if (strcmp(name, "sendto") == 0 && argc == 4)
        scenario_send_to(argv[2], argv[3]);
    else if (strcmp(name, "lookuplater") == 0 && argc == 5)
        scenario_lookup_later(argv[2], argv[3], argv[4]);
    else if (strcmp(name, "lookupwait") == 0 && argc == 5)
        scenario_lookup_wait(argv[2], argv[3], argv[4]);
    else if (strcmp(name, "execstorm") == 0 && argc == 3)
        scenario_exec_storm(arg_size(argv[2]));
    else if (strcmp(name, "nofile") == 0 && argc >= 4)
        scenario_nofile(arg_size(argv[2]), argv + 3);
    else if (strcmp(name, "libcpath") == 0 && argc == 2)
        scenario_libc_path();
    else if (strcmp(name, "waitsend") == 0 && argc == 5)
        scenario_wait_send(argv[2], argv[3], argv[4]);
    else if (strcmp(name, "privatelibc") == 0 && argc >= 4)
        scenario_private_libc(argv[2], argv + 3, argc - 3);
    else if (strcmp(name, "pty") == 0 && argc >= 9 && strcmp(argv[7], "--") == 0)
        scenario_pty(arg_size(argv[2]), arg_size(argv[3]), argv[4], arg_size(argv[5]), argv[6],
                     nullptr, nullptr, nullptr, argv + 8);
    else if (strcmp(name, "pty") == 0 && argc >= 10 && strcmp(argv[8], "--") == 0)
        scenario_pty(arg_size(argv[2]), arg_size(argv[3]), argv[4], arg_size(argv[5]), argv[6],
                     argv[7], nullptr, nullptr, argv + 9);
    else if (strcmp(name, "pty") == 0 && argc >= 12 && strcmp(argv[10], "--") == 0)
        scenario_pty(arg_size(argv[2]), arg_size(argv[3]), argv[4], arg_size(argv[5]), argv[6],
                     argv[7], argv[8], argv[9], argv + 11);
    else {
        fprintf(stderr, "usage: %s <scenario> <arguments>\n", argv[0]);
        return 2;
    }
    return 0;
}
