#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
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

enum sink_mode {
    SINK_DISCARD, /* reads and discards what each peer sends */
    SINK_GREET,   /* sends one line to each peer first */
    SINK_ANSWER,  /* answers each read with one line, as a server answers requests */
    SINK_STALL,   /* greets each peer and reads nothing for two seconds */
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
            if ((mode == SINK_GREET || mode == SINK_STALL) && write(c, "hello\n", 6) != 6)
                _exit(1);
            if (mode == SINK_STALL)
                sleep(2);
            while (read(c, buf, sizeof(buf)) > 0) {
                if (mode == SINK_ANSWER && write(c, "hello\n", 6) != 6)
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
 * resend <path> <bytes> <rounds>: over a connection that has heard from its peer and never hears
 * again, reads the file and sends it, round after round, as a status file is shipped.
 */
static void scenario_resend(const char *path, size_t size, size_t rounds)
{
    struct sink sink = start_sink(SOCK_STREAM, false, SINK_GREET);
    make_file(path, size);
    char *contents = malloc(size);
    if (!contents)
        die("malloc");
    int sock = connect_sink(&sink);
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
    else if (strcmp(name, "twosenders") == 0 && argc == 6)
        scenario_two_senders(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "latebody") == 0 && argc == 7)
        scenario_late_body(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]),
                           arg_size(argv[6]));
    else if (strcmp(name, "servestrict") == 0 && argc == 6)
        scenario_serve_strict(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "streamafter") == 0 && argc == 6)
        scenario_stream_after(argv[2], arg_size(argv[3]), argv[4], arg_size(argv[5]));
    else if (strcmp(name, "metricfirst") == 0 && argc == 4)
        scenario_metric_first(argv[2], arg_size(argv[3]));
    else if (strcmp(name, "tail") == 0 && argc == 6)
        scenario_tail(argv[2], arg_size(argv[3]), arg_size(argv[4]), arg_size(argv[5]));
    else if (strcmp(name, "resend") == 0 && argc == 5)
        scenario_resend(argv[2], arg_size(argv[3]), arg_size(argv[4]));
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
