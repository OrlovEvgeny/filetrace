#!/usr/bin/env python3
"""usage: scenarios.py <scenario> | --list

Each scenario plays a program whose system calls come in an exact order, then asks the agent
what it listed for this process, at once and 5 s later, and compares that with what really
left: every file a scenario sends must be listed with the bytes it sent, and nothing else.
The last line printed is RESULT: OK, RESULT: BUG, RESULT: INVALID or RESULT: SKIP."""
import faulthandler
import functools
import os
import socket
import struct
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import transfers  # noqa: E402

D = "/data/acceptance"
SINK = "/acceptance/sink.py"
BASE = 39200
K = 1024
REQ = b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
procs = []
SCENARIOS = {}


class Case:
    """notes: what the scenario did; expect: file name -> (least, most) bytes sent; check: more
    problems from the listed files; judge: replaces the comparison; invalid: why the scenario
    could not set itself up; skip: why the scenario does not apply on this machine; close: a
    connection left open, closed between two listings, of which those named in judged ("open",
    "closed") count"""

    def __init__(self, notes, expect=None, check=None, judge=None, invalid=None, close=None, judged=("open", "closed"), skip=None):
        self.notes = notes
        self.expect = expect or {}
        self.check = check
        self.judge = judge or own_files
        self.invalid = invalid
        self.close = close
        self.judged = judged
        self.skip = skip


def scenario(name):
    def register(fn):
        SCENARIOS[name] = fn
        return fn
    return register


def sink(port, *extra):
    procs.append(subprocess.Popen([sys.executable, SINK, str(port)] + list(extra), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    for _ in range(100):
        s = socket.socket()
        try:
            s.connect(("127.0.0.1", port))
            s.close()
            return
        except OSError:
            s.close()
            time.sleep(0.05)
    raise SystemExit("the sink on port %d did not start" % port)


def mk(name, size):
    path = "%s/%s" % (D, name)
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    return path


def readall(path, chunk=1 << 20):
    fd = os.open(path, os.O_RDONLY)
    out = []
    while True:
        b = os.read(fd, chunk)
        if not b:
            break
        out.append(b)
    os.close(fd)
    return b"".join(out)


def dial(port):
    """connect without a name lookup, so no resolver file is read"""
    s = socket.socket()
    s.connect(("127.0.0.1", port))
    return s


def reply(s):
    b = b""
    while b"\r\n\r\n" not in b:
        d = s.recv(4096)
        if not d:
            return
        b += d
    n = int(b.split(b"Content-Length: ")[1].split(b"\r\n")[0])
    while len(b) < b.index(b"\r\n\r\n") + 4 + n:
        b += s.recv(4096)


def exchange(s):
    s.sendall(REQ)
    reply(s)


def around(size, low=0.9, high=1.05):
    return (low * size, high * size)


def own_files(case, recs):
    """the files listed for this process against case.expect; anything else listed is false"""
    agg = {}
    for r in recs:
        path = (r.get("file") or {}).get("path") or ""
        if r["process"]["pid"] != os.getpid() or not path.startswith(D + "/") or os.path.basename(path) == "warmup":
            continue
        t, n = r["transfer"], r["network"]
        agg.setdefault(os.path.basename(path), []).append((t["method"], t["confidence"], t["bytes_sent"], n.get("remote_port"), n.get("protocol")))
    for name, v in sorted(agg.items()):
        print("  filetrace: %s %s" % (name, " + ".join("%s %s %d B -> :%s %s" % x for x in v)))
    if not agg:
        print("  filetrace: no file listed")
    problems = ["%s reported (%d B) but not sent" % (name, sum(x[2] for x in v)) for name, v in sorted(agg.items()) if name not in case.expect]
    for name, (lo, hi) in sorted(case.expect.items()):
        total = sum(x[2] for x in agg.get(name, []))
        if name not in agg:
            problems.append("%s sent but not reported" % name)
        elif not lo <= total <= hi:
            problems.append("%s reported with %d B, sent %.0f to %.0f B" % (name, total, lo, hi))
    if case.check:
        problems += case.check(agg)
    return problems


# One thread, reads and sends in an exact order -------------------------------------------------

def warm_up_orders():
    """modules, a connection with an exchange, a sendfile and a few reads, then 2.6 s for their state to expire"""
    sink(BASE, "--mode", "http")
    sink(BASE + 1, "--mode", "raw")
    tmp = mk("warmup", 70000)
    dummy = dial(BASE)
    exchange(dummy)
    readall(tmp)
    dsf = dial(BASE + 1)
    os.sendfile(dsf.fileno(), os.open(tmp, os.O_RDONLY), 0, 70000)
    readall("/etc/hosts")
    readall("/etc/localtime")
    files = {n: mk(n, s) for n, s in (("F", 300 * K), ("X", 20 * K), ("G", 500 * K), ("M", 1 << 20))}
    os.unlink(tmp)
    dummy.close()
    dsf.close()
    time.sleep(2.6)
    return files


def stale_reads(wait):
    f = warm_up_orders()
    old = dial(BASE)
    exchange(old)
    readall(f["F"])
    readall(f["X"])
    time.sleep(wait)
    old.sendall(os.urandom(3000))
    time.sleep(0.3)
    old.close()
    return Case("read F (300 KB) and X (20 KB), wait %s s, send 3000 B from memory on a connection used before the reads" % wait)


for _wait, _name in ((30, "30s"), (5, "5s"), (2.5, "2500ms")):
    SCENARIOS["stale-reads-then-memory-" + _name] = functools.partial(stale_reads, _wait)


@scenario("side-reads-then-small-file")
def side_reads_then_small_file():
    f = warm_up_orders()
    old = dial(BASE)
    exchange(old)
    readall(f["F"])
    xdata = readall(f["X"])
    readall("/etc/hosts")
    old.sendall(xdata)
    time.sleep(0.3)
    old.close()
    return Case("old connection; read F (300 KB, never sent), read X (20 KB), read /etc/hosts, send X", {"X": (18000, 21000)})


@scenario("unsent-file-then-memory-on-second-dial")
def unsent_file_then_memory_on_second_dial():
    f = warm_up_orders()
    readall(f["F"])
    c1 = dial(BASE + 1)
    c1.sendall(b"x" * 59 + b"\n")
    c2 = dial(BASE + 1)
    c2.sendall(os.urandom(100 * K))
    time.sleep(0.3)
    c1.close()
    c2.close()
    return Case("read F (300 KB), connect C1 and send 60 B, connect C2 and send 100 KB of unrelated memory")


@scenario("unsent-file-then-streamed-upload")
def unsent_file_then_streamed_upload():
    f = warm_up_orders()
    readall(f["F"])
    s = dial(BASE + 1)
    fd = os.open(f["G"], os.O_RDONLY)
    while True:
        b = os.read(fd, 32768)
        if not b:
            break
        s.sendall(b)
    time.sleep(0.3)
    s.close()
    return Case("read F (300 KB, never sent), connect, stream G (500 KB) in 32 KB reads and sends", {"G": (0.9 * 500 * K, 505 * K)})


@scenario("connect-read-send")
def connect_read_send():
    f = warm_up_orders()
    s = dial(BASE + 1)
    s.sendall(readall(f["X"]))
    time.sleep(0.3)
    s.close()
    return Case("connect, read X (20 KB), send it", {"X": (18000, 21000)})


@scenario("first-piece-read-before-connect-then-stream")
def first_piece_read_before_connect_then_stream():
    f = warm_up_orders()
    fd = os.open(f["M"], os.O_RDONLY)
    piece = os.read(fd, 65536)
    s = dial(BASE + 1)
    while piece:
        s.sendall(piece)
        piece = os.read(fd, 65536)
    time.sleep(0.3)
    s.close()
    return Case("read 64 KB of M (1 MB), connect, then send a piece and read the next until M is sent", {"M": around(1 << 20, high=1.02)})


@scenario("sniffed-head-then-stream")
def sniffed_head_then_stream():
    f = warm_up_orders()
    fd = os.open(f["M"], os.O_RDONLY)
    os.read(fd, 512)
    s = dial(BASE + 1)
    s.sendall(b"H" * 300)
    while True:
        piece = os.read(fd, 65536)
        if not piece:
            break
        s.sendall(piece)
    time.sleep(0.3)
    s.close()
    return Case("read 512 B of M (1 MB), connect, send a 300 B head, then read and send the rest in 64 KB pieces", {"M": around(1 << 20, high=1.02)})


@scenario("checksum-then-sendfile")
def checksum_then_sendfile():
    f = warm_up_orders()
    data = readall(f["F"])
    s = dial(BASE + 1)
    s.sendall(b"H" * 200)
    fd = os.open(f["F"], os.O_RDONLY)
    sent = 0
    while sent < len(data):
        sent += os.sendfile(s.fileno(), fd, sent, len(data) - sent)
    time.sleep(0.3)
    s.close()

    def once(agg):
        v = agg.get("F", [])
        return [] if len(v) == 1 and v[0][0] == "sendfile" else ["F listed as %s, sent once with sendfile" % ", ".join("%s/%s" % x[:2] for x in v)]
    return Case("read F (300 KB) whole for a checksum, connect, send a 200 B head, sendfile F", {"F": around(300 * K, high=1.02)}, once)


# Request and reply volumes, streams and parts ---------------------------------------------------

def warm_up_bursts(reply_at=False):
    sink(BASE, "--mode", "echo", "--echo-bytes", "6")
    sink(BASE + 1, "--mode", "raw")
    if reply_at:
        sink(BASE + 2, "--mode", "raw", "--reply-at", "3")
    dummy = dial(BASE)
    dummy.sendall(b"hello")
    dummy.recv(16)
    dummy.close()
    tmp = mk("warmup", 70000)
    readall(tmp)
    os.unlink(tmp)
    readall("/etc/hosts")
    time.sleep(2.6)


def chatty(fsize, req, count):
    warm_up_bursts()
    readall(mk("F", fsize))
    s = dial(BASE)
    msg = os.urandom(req)
    t0 = time.time()
    for _ in range(count):
        s.sendall(msg)
        got = b""
        while len(got) < 6:
            got += s.recv(16)
    elapsed = time.time() - t0
    s.close()
    return Case("read F (%d B, never sent); connect; %d x (send %d B from memory, receive 6 B) in %.2f s" % (fsize, count, req, elapsed))


for _fsize, _req, _count in ((65536, 500, 100), (307200, 500, 100), (2097152, 500, 100),
                             (65536, 3100, 100), (307200, 3100, 100), (2097152, 3100, 100),
                             (65536, 9216, 100), (307200, 9216, 100), (2097152, 9216, 100),
                             (65536, 20480, 100), (307200, 20480, 100), (2097152, 20480, 100),
                             (307200, 32768, 10), (307200, 49152, 7), (307200, 65536, 5),
                             (1048576, 16384, 64), (1048576, 32768, 32), (1048576, 65536, 16)):
    SCENARIOS["chatty-%d-%dx%d" % (_fsize, _req, _count)] = functools.partial(chatty, _fsize, _req, _count)


def small_file_after_pread(name):
    warm_up_bursts()
    big = mk("big", 10 << 20)
    small = mk(name, 20000)
    fd = os.open(big, os.O_RDONLY)
    os.pread(fd, 4096, 0)
    s = dial(BASE)
    s.sendall(b"r" * 200)
    s.recv(16)
    data = readall(small)
    s.sendall(b"H" * 200)
    s.sendall(data)
    s.recv(16)
    time.sleep(0.2)
    s.close()
    return Case("pread 4096 B of a 10 MB file, connect, one request and reply, read %s (20000 B), send it behind a 200 B head" % name, {name: (18000, 21000)})


for _name in ("small.json", "x.js", "x.so"):
    SCENARIOS["small-file-after-pread-" + _name] = functools.partial(small_file_after_pread, _name)


def one_way_stream(pause):
    warm_up_bursts()
    m = mk("M", 5 << 20)
    fd = os.open(m, os.O_RDONLY)
    piece = os.read(fd, 64 * K)
    s = dial(BASE + 1)
    n = 0
    while piece:
        s.sendall(piece)
        n += 1
        if pause and n == 40:
            time.sleep(pause)
        piece = os.read(fd, 64 * K)
    time.sleep(0.3)
    s.close()
    return Case("read the first 64 KB of M (5 MB), connect, send a piece and read the next; the peer never answers%s" % (", a %s s pause after 2.5 MB" % pause if pause else ""), {"M": around(5 << 20, high=1.02)})


SCENARIOS["one-way-stream"] = functools.partial(one_way_stream, 0)
SCENARIOS["one-way-stream-paused"] = functools.partial(one_way_stream, 3)


@scenario("parts-over-fresh-connections")
def parts_over_fresh_connections():
    warm_up_bursts()
    m = mk("M", 4 << 20)
    fd = os.open(m, os.O_RDONLY)
    for i in range(4):
        data = os.pread(fd, 1 << 20, i << 20)
        s = dial(BASE)
        s.sendall(data)
        s.recv(16)
        s.close()
        time.sleep(0.2)
    return Case("for each 1 MB part of M (4 MB): pread, connect, send, receive, close; 0.2 s apart", {"M": around(4 << 20, high=1.02)})


@scenario("same-size-files-over-fresh-connections")
def same_size_files_over_fresh_connections():
    warm_up_bursts()
    for i in range(4):
        mk("P%d" % i, 1 << 20)
    for i in range(4):
        data = readall("%s/P%d" % (D, i))
        s = dial(BASE)
        s.sendall(data)
        s.recv(16)
        s.close()
        time.sleep(0.2)
    return Case("four files of 1 MB each: read, connect, send, receive, close; 0.2 s apart", {"P%d" % i: around(1 << 20, high=1.02) for i in range(4)})


def stream_beside_side_connection(line):
    warm_up_bursts()
    f = mk("F", 2 << 20)
    fd = os.open(f, os.O_RDONLY)
    piece = os.read(fd, 64 * K)
    a = dial(BASE + 1)
    b = dial(BASE + 1)
    if line:
        b.sendall(b"x" * 59 + b"\n")
    while piece:
        a.sendall(piece)
        piece = os.read(fd, 64 * K)
    time.sleep(0.3)
    a.close()
    b.close()
    return Case("read the first 64 KB of F (2 MB), connect A, connect B (%s), stream F on A in 64 KB pieces" % ("a 60 B line on B" if line else "nothing sent on B"), {"F": around(2 << 20, high=1.02)})


SCENARIOS["stream-beside-idle-connection"] = functools.partial(stream_beside_side_connection, False)
SCENARIOS["stream-beside-connection-with-line"] = functools.partial(stream_beside_side_connection, True)


@scenario("late-send-on-dialed-connection")
def late_send_on_dialed_connection():
    warm_up_bursts()
    readall(mk("F", 200 * K))
    s = dial(BASE)
    time.sleep(60)
    s.sendall(os.urandom(205 * K))
    s.recv(16)
    s.close()
    return Case("read F (200 KB), connect, wait 60 s, send 205 KB of random memory, receive")


@scenario("slow-upload-with-reply-midway")
def slow_upload_with_reply_midway():
    warm_up_bursts(reply_at=True)
    data = readall(mk("F", 2 << 20))
    s = dial(BASE + 2)
    step = 128 * K
    for i in range(0, len(data), step):
        s.sendall(data[i:i + step])
        time.sleep(0.375)
    time.sleep(0.3)
    s.close()
    return Case("read F (2 MB) whole, connect, send it in 128 KB steps over about 6 s; the peer sends 4 B at second 3", {"F": around(2 << 20, high=1.02)})


# Servers, other sockets, other threads and cut replies ------------------------------------------

def warm_up_peers(greeter=True):
    sink(BASE, "--mode", "http")
    sink(BASE + 1, "--mode", "http")
    if greeter:
        sink(BASE + 2, "--mode", "raw", "--banner", "20")
    sink(BASE + 3, "--mode", "raw")
    d = socket.create_connection(("127.0.0.1", BASE))
    d.sendall(REQ)
    reply(d)
    d.close()
    mk("warmup", 70000)
    readall(D + "/warmup")
    os.unlink(D + "/warmup")
    readall("/etc/hosts")
    time.sleep(2.6)


def client_process(port, delay=0.3, send_after=b"x" * 50):
    """another process that connects to port, sends a request, reads the head of the answer and sends a little more"""
    code = ("import socket,time\ntime.sleep(%f)\ns=socket.create_connection(('127.0.0.1',%d))\n"
            "s.sendall(b'GET / HTTP/1.1\\r\\nHost: x\\r\\nContent-Length: 0\\r\\n\\r\\n')\nb=b''\n"
            "while b'\\r\\n\\r\\n' not in b: b+=s.recv(4096)\ntime.sleep(0.4)\ns.sendall(%r)\ntime.sleep(0.5)") % (delay, port, send_after)
    procs.append(subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))


def listener(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(4)
    return s


def recv_quietly(s, timeout):
    s.settimeout(timeout)
    try:
        s.recv(100)
    except Exception:
        pass


@scenario("server-pread-database-then-script")
def server_pread_database_then_script():
    warm_up_peers()
    db = mk("app.db", 5 << 20)
    js = mk("app.js", 20000)
    lsock = listener(BASE + 10)
    client_process(BASE + 10)
    c, _ = lsock.accept()
    c.recv(4096)
    fd = os.open(db, os.O_RDONLY)
    os.pread(fd, 4096, 100 * 4096)
    os.pread(fd, 4096, 900 * 4096)
    body = readall(js)
    c.sendall(b"H" * 300 + body)
    recv_quietly(c, 3)
    return Case("server thread: receive a request, pread 2 x 4096 B of app.db (5 MB), read app.js (20000 B), send a 300 B head and the file, receive", {"app.js": (18000, 21000)})


@scenario("old-connection-unsent-file-then-stream")
def old_connection_unsent_file_then_stream():
    warm_up_peers()
    man = mk("manifest.bin", 300000)
    jar = mk("app.jar", 420000)
    s = socket.create_connection(("127.0.0.1", BASE + 1))
    s.sendall(REQ)
    reply(s)
    readall(man)
    s.sendall(b"H" * 300)
    fd = os.open(jar, os.O_RDONLY)
    while True:
        b = os.read(fd, 16 * K)
        if not b:
            break
        s.sendall(b)
    recv_quietly(s, 1)
    s.close()
    return Case("old connection: read manifest.bin (300000 B, never sent), send 300 B, then read and send app.jar (420000 B) in 16 KB pieces, receive", {"app.jar": (0.9 * 420000, 425000)})


def server_page_after_metrics(udp):
    warm_up_peers()
    page = mk("page.html", 5000)
    lsock = listener(BASE + 10)
    client_process(BASE + 10)
    c, _ = lsock.accept()
    c.recv(4096)
    readall(page)
    if udp:
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.sendto(b"m" * 60, ("127.0.0.1", BASE + 20))
        u.close()
    else:
        t = socket.create_connection(("127.0.0.1", BASE + 1))
        t.sendall(b"m" * 59 + b"\n")
    with open(page, "rb") as f:
        body = f.read()
    c.sendall(b"H" * 200 + body)
    recv_quietly(c, 3)
    return Case("server: receive, read page.html (5000 B), a 60 B %s elsewhere, send a 200 B head and the file, receive" % ("UDP datagram" if udp else "line on another TCP connection"), {"page.html": (4500, 5300)})


SCENARIOS["server-page-after-metrics-datagram"] = functools.partial(server_page_after_metrics, True)
SCENARIOS["server-page-after-metrics-line"] = functools.partial(server_page_after_metrics, False)


@scenario("one-way-sender-resends-status")
def one_way_sender_resends_status():
    warm_up_peers()
    s = socket.create_connection(("127.0.0.1", BASE + 2))
    s.recv(64)
    st = mk("status.txt", 2000)
    fd = os.open(st, os.O_RDONLY)
    for _ in range(20):
        s.sendall(os.pread(fd, 2000, 0))
    time.sleep(0.3)
    s.close()
    return Case("one-way sender: a greeting once, then 20 x (read status.txt, 2000 B, from the start and send it); never receives again", {"status.txt": around(40000)})


@scenario("one-way-sender-tails-log")
def one_way_sender_tails_log():
    warm_up_peers()
    s = socket.create_connection(("127.0.0.1", BASE + 2))
    s.recv(64)
    log = mk("app.log", 10 * K)
    fd = os.open(log, os.O_RDONLY)
    os.lseek(fd, 10 * K, 0)
    for _ in range(20):
        with open(log, "ab") as f:
            f.write(os.urandom(500))
        s.sendall(os.read(fd, 4096))
    time.sleep(0.3)
    s.close()
    return Case("one-way sender: a greeting once, then 20 x (append 500 B to app.log, read the new 500 B, send them); never receives again", {"app.log": around(10000)})


def two_files_on_fresh_connection(a, b):
    warm_up_peers()
    fa = mk("a.json", a)
    fb = mk("b.json", b)
    s = socket.create_connection(("127.0.0.1", BASE + 2))
    s.recv(64)
    s.sendall(readall(fa))
    s.sendall(readall(fb))
    time.sleep(0.3)
    s.close()
    return Case("fresh connection, a greeting read once: read and send a.json (%d B), read and send b.json (%d B), close" % (a, b), {"a.json": around(a, high=1.1), "b.json": around(b, high=1.1)})


for _a, _b in ((2500, 2500), (3000, 3000), (5000, 6000)):
    SCENARIOS["two-files-on-fresh-connection-%d-%d" % (_a, _b)] = functools.partial(two_files_on_fresh_connection, _a, _b)


@scenario("one-read-two-sockets")
def one_read_two_sockets():
    warm_up_peers()
    job = mk("job.py", 20000)
    a = socket.create_connection(("127.0.0.1", BASE))
    a.sendall(REQ)
    reply(a)
    b = socket.create_connection(("127.0.0.1", BASE + 1))
    b.sendall(REQ)
    reply(b)
    data = readall(job)
    a.sendall(data)
    b.sendall(os.urandom(20500))
    time.sleep(0.3)
    a.close()
    b.close()

    def only_a(agg):
        ports = sorted(set(x[3] for x in agg.get("job.py", [])))
        return [] if ports in ([], [BASE]) else ["job.py listed to ports %s, sent only to %d" % (ports, BASE)]
    return Case("one read of job.py (20000 B); the file to socket A, 20500 B of other bytes to socket B, both heard before", {"job.py": (18000, 21000)}, only_a)


@scenario("token-read-other-thread-sends")
def token_read_other_thread_sends():
    warm_up_peers()
    tok = mk("api-token.txt", 2000)
    s = socket.create_connection(("127.0.0.1", BASE))
    s.sendall(REQ)
    reply(s)
    ready, done = threading.Event(), threading.Event()

    def thread_b():
        ready.wait()
        s.sendall(os.urandom(2100))
        done.set()
    t = threading.Thread(target=thread_b)
    t.start()
    readall(tok)
    s.sendall(os.urandom(150))
    ready.set()
    done.wait(3)
    s.sendall(REQ)
    reply(s)
    t.join()
    s.close()
    return Case("thread A reads api-token.txt (2000 B) and sends 150 B on a heard socket; thread B sends 2100 B of its own; then A receives")


@scenario("upload-read-before-connect-token-after")
def upload_read_before_connect_token_after():
    warm_up_peers()
    up = mk("upload.bin", 300000)
    tok = mk("token.txt", 20000)
    data = readall(up)
    s = socket.create_connection(("127.0.0.1", BASE + 3))
    readall(tok)
    s.sendall(data)
    time.sleep(0.3)
    s.close()
    return Case("read upload.bin (300000 B); connect; read token.txt (20000 B); one send of 300000 B; close", {"upload.bin": (0.9 * 300000, 305000)})


@scenario("config-then-memory-requests")
def config_then_memory_requests():
    warm_up_peers()
    readall(mk("client.conf", 3000))
    s = socket.create_connection(("127.0.0.1", BASE + 1))
    for _ in range(2):
        body = os.urandom(130000 - 60)
        s.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        reply(s)
    time.sleep(0.3)
    s.close()
    return Case("read client.conf (3000 B); connect; a 130000 B request from memory; reply; a second one; reply; close")


def small_file_behind_head(size, name):
    warm_up_peers()
    f = mk(name, size)
    s = socket.create_connection(("127.0.0.1", BASE + 3))
    s.sendall(b"H" * 1500)
    s.sendall(readall(f))
    time.sleep(0.3)
    s.close()
    return Case("connect; send a 1500 B head; read %s (%d B); send it; close" % (name, size), {name: (0.9 * size, size + 100)})


for _size in (2600, 2800, 2999):
    SCENARIOS["small-file-behind-head-%d" % _size] = functools.partial(small_file_behind_head, _size, "band.dat")
SCENARIOS["small-script-behind-head-2800"] = functools.partial(small_file_behind_head, 2800, "app.js")

CUT_CLIENT = """
import socket, sys, time
RQ = b"GET / HTTP/1.1\\r\\nHost: x\\r\\n\\r\\n"
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, %d)
s.connect(("127.0.0.1", %d))
s.sendall(RQ * %d)
got = b""
while len(got) < 200: got += s.recv(200 - len(got))
print("hello", flush=True)
for line in sys.stdin:
    n = int(line.split()[1]); t = 0; s.settimeout(0.3)
    while t < n:
        try: d = s.recv(min(512, n - t))
        except Exception: break
        if not d: break
        t += len(d)
    print("read", t, flush=True)
"""


def cut_reply(variant):
    """a reply cut short by a full socket buffer (non-blocking send), after a configuration read"""
    warm_up_peers()
    big = variant == "bigfile"
    cfg = mk("app.cfg", 2048 if variant == "six" else 60000 if big else 5000)
    rqlen = len(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    cut = variant != "full"
    rets = []
    for k in range(6 if variant == "six" else 1):
        lsock = listener(BASE + 10 + k)
        lsock.settimeout(10)
        cp = subprocess.Popen([sys.executable, "-c", CUT_CLIENT % (16384 if big else 4096, BASE + 10 + k, 2)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        procs.append(cp)
        c, _ = lsock.accept()
        c.recv(rqlen)
        if cut:
            c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16384 if big else 4096)
        c.sendall(b"H" * 200)
        cp.stdout.readline()
        if cut:
            c.setblocking(False)
            while True:
                try:
                    c.send(b"f" * 700)
                except BlockingIOError:
                    break
            cp.stdin.write("read %d\n" % (20000 if big else 2100))
            cp.stdin.flush()
            cp.stdout.readline()
            if big:
                c.setblocking(True)
                c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, struct.pack("ll", 0, 400000))
        t_free = time.time()
        c.recv(rqlen)
        data = readall(cfg)
        if variant in ("file", "bigfile"):
            asked = len(data)
            t_send = time.time()
            try:
                r = c.send(data)
            except (BlockingIOError, socket.timeout):
                r = -1
        else:
            asked = 3000 if variant == "six" else 4000
            t_send = time.time()
            try:
                r = c.send(b"R" * asked)
            except BlockingIOError:
                r = -1
        rets.append((asked, r, round((t_send - t_free) * 1000, 2)))
        c.setblocking(True)
        if variant == "six":
            c.close()
            lsock.close()
    print("  sends (asked, returned, ms after the client read):", rets)
    notes = "socket buffer full (non-blocking), the client frees part of it; app.cfg read, then a reply from %s asked and %s" % ("the file" if variant in ("file", "bigfile") else "memory", "cut short" if cut else "taken whole")
    if cut and not all(0 < r < a for a, r, _ in rets):
        return Case(notes, invalid="a send was not cut short")
    if big:
        return Case(notes, {"app.cfg": around(rets[0][1], high=1.1)})
    if variant == "file":
        return Case(notes, {"app.cfg": (1700, 2400)})
    return Case(notes)


for _variant, _name in (("mem", "cut-reply-from-memory"), ("full", "full-reply-from-memory"), ("file", "cut-reply-of-file"),
                        ("bigfile", "cut-reply-of-large-file"), ("six", "cut-replies-on-six-connections")):
    SCENARIOS[_name] = functools.partial(cut_reply, _variant)


# Uploads judged when their window ends: never-heard connections, other threads, slow readers ---

def peer(port, *args):
    procs.append(subprocess.Popen([sys.executable, "/acceptance/peer.py", str(port)] + list(args), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    time.sleep(0.4)


def head(total_len, body_len):
    """an HTTP request head of exactly total_len bytes announcing body_len bytes"""
    base = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % body_len
    h = base + b"X: " + b"p" * (total_len - len(base) - len(b"X: \r\n\r\n")) + b"\r\n\r\n"
    assert len(h) == total_len
    return h


def request(total):
    """a complete HTTP request of total bytes from memory"""
    bl = total - 60
    while True:
        h = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % bl
        if len(h) + bl == total:
            return h + os.urandom(bl)
        bl = total - len(h)


@scenario("upload-answered-then-next-request")
def upload_answered_then_next_request():
    warm_up_peers(greeter=False)
    f = mk("report.csv", 20000)
    s = socket.create_connection(("127.0.0.1", BASE + 1))
    data = readall(f)
    s.sendall(head(200, 20005))
    s.sendall(data)
    s.sendall(b"12345")
    reply(s)
    s.sendall(request(3000))
    reply(s)
    time.sleep(0.3)
    s.close()
    return Case("connect; read report.csv (20000 B); a 200 B head, the file in one send and a last 5 B; reply; the next request (3000 B) at once; reply; close", {"report.csv": around(20000)})


def upload_unanswered(size):
    warm_up_peers(greeter=False)
    f = mk("report.csv", size)
    s = socket.create_connection(("127.0.0.1", BASE + 3))
    data = readall(f)
    s.sendall(head(200, size))
    s.sendall(data)
    return Case("connect; read report.csv (%d B); a 200 B head and the file in one send; no reply and nothing more" % size, {"report.csv": around(size)}, close=s)


SCENARIOS["upload-unanswered-connection-open"] = functools.partial(upload_unanswered, 20000)
SCENARIOS["large-upload-unanswered-connection-open"] = functools.partial(upload_unanswered, 420000)


@scenario("status-resent-on-never-heard-connection")
def status_resent_on_never_heard_connection():
    warm_up_peers(greeter=False)
    st = mk("status.txt", 2048)
    s = socket.create_connection(("127.0.0.1", BASE + 3))
    fd = os.open(st, os.O_RDONLY)
    for _ in range(5):
        s.sendall(os.pread(fd, 2048, 0))
    return Case("connect; five rounds of reading status.txt (2048 B) and sending it; the peer never sends", {"status.txt": around(10240)}, close=s)


def files_on_never_heard_connection(files, pause):
    warm_up_peers(greeter=False)
    for name, size in files:
        mk(name, size)
    s = socket.create_connection(("127.0.0.1", BASE + 3))
    for i, (name, _) in enumerate(files):
        s.sendall(readall(D + "/" + name))
        if pause and i == 0:
            time.sleep(pause)
    time.sleep(0.3)
    s.close()
    return Case("a connection that never hears: %s%s, each read then sent" % (", ".join("%s (%d B)" % x for x in files), ", 5 s between the two" if pause else ""),
                {name: around(size) for name, size in files})


for _scn, _files, _pause in (("two-files-on-never-heard-connection", (("a.json", 5000), ("b.json", 5000)), 0),
                             ("three-files-on-never-heard-connection", (("x1.json", 3000), ("x2.json", 3000), ("x3.json", 3000)), 0),
                             ("two-php-files-on-never-heard-connection", (("a.php", 14000), ("b.php", 9000)), 0),
                             ("script-then-file-after-pause-on-never-heard-connection", (("worker.py", 14000), ("notes.txt", 20000)), 5)):
    SCENARIOS[_scn] = functools.partial(files_on_never_heard_connection, _files, _pause)


def writer_and_reader_threads(stream):
    warm_up_peers(greeter=False)
    if stream:
        name, size = "app.jar", 5 << 20
        peer(BASE + 10, "--notify-at", str(2 << 20))
    else:
        name, size = "page.html", 20000
        peer(BASE + 10, "--echo10")
    f = mk(name, size)
    s = socket.create_connection(("127.0.0.1", BASE + 10))
    stop = threading.Event()

    def reader():
        s.settimeout(0.5)
        while not stop.is_set():
            try:
                d = s.recv(64)
            except socket.timeout:
                continue
            except OSError:
                break
            if not d or stream:
                break
    t = threading.Thread(target=reader)
    t.start()
    data = readall(f)
    if stream:
        for i in range(0, len(data), 16384):
            s.sendall(data[i:i + 16384])
        notes = "thread W reads app.jar (5 MB) and sends it in 16 KB sends; thread R receives once, after about 2 MB"
    else:
        s.sendall(b"H" * 300)
        time.sleep(0.15)
        s.sendall(data[:16384])
        time.sleep(0.15)
        s.sendall(data[16384:])
        time.sleep(0.5)
        notes = "thread W reads page.html (20000 B) and sends 300 B, 16384 B and 3616 B 0.15 s apart; thread R receives 10 B after each"
    stop.set()
    t.join()
    s.close()
    return Case(notes, {name: around(size)})


SCENARIOS["writer-thread-page-reader-thread-echoes"] = functools.partial(writer_and_reader_threads, False)
SCENARIOS["writer-thread-stream-reader-thread-hears-once"] = functools.partial(writer_and_reader_threads, True)


def one_blocking_send(reader_thread):
    warm_up_peers(greeter=False)
    if reader_thread:
        name, size, buf = "page.html", 60000, 16384
        peer(BASE + 10, "--heard", "--rcvbuf", "16384", "--rate", "100000", "--notify-at", "20000")
    else:
        name, size, buf = "app.jar", 5 << 20, 65536
        peer(BASE + 10, "--heard", "--rcvbuf", "65536", "--rate", "300000")
    f = mk(name, size)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buf)
    s.connect(("127.0.0.1", BASE + 10))
    s.sendall(REQ)
    reply(s)
    stop = threading.Event()
    t = None
    if reader_thread:
        def reader():
            s.settimeout(0.5)
            while not stop.is_set():
                try:
                    if s.recv(64):
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break
        t = threading.Thread(target=reader)
        t.start()
    data = readall(f)
    t0 = time.time()
    s.sendall(data)
    took = time.time() - t0
    stop.set()
    if t:
        t.join()
    s.close()
    return Case("heard connection; read %s (%d B) whole; one blocking send of %.1f s to a slow reader%s" % (name, size, took, ", another thread receives after about 20000 B" if reader_thread else ""), {name: around(size)})


SCENARIOS["one-blocking-send-to-slow-reader"] = functools.partial(one_blocking_send, False)
SCENARIOS["one-blocking-send-reader-thread-hears"] = functools.partial(one_blocking_send, True)


@scenario("script-read-then-memory-requests")
def script_read_then_memory_requests():
    warm_up_peers(greeter=False)
    readall(mk("worker.py", 14000))
    s = socket.create_connection(("127.0.0.1", BASE + 1))
    s.sendall(request(5000))
    reply(s)
    s.sendall(request(200))
    reply(s)
    time.sleep(0.3)
    s.close()
    return Case("read worker.py (14000 B) whole; connect; 5000 B from memory; reply; 200 B; reply; close")


@scenario("config-read-after-connect-then-large-memory")
def config_read_after_connect_then_large_memory():
    warm_up_peers(greeter=False)
    mk("tiny.cfg", 3000)
    s = socket.create_connection(("127.0.0.1", BASE + 3))
    readall(D + "/tiny.cfg")
    s.sendall(os.urandom(130000))
    time.sleep(0.3)
    s.close()
    return Case("connect; read tiny.cfg (3000 B); send 130000 B from memory; close")


def token_read_then_unanswered_request(phase):
    warm_up_peers(greeter=False)
    mk("token.txt", 1500)
    s = socket.create_connection(("127.0.0.1", BASE + 3))
    readall(D + "/token.txt")
    s.sendall(os.urandom(1600))
    return Case("connect; read token.txt (1500 B); send a 1600 B request; the peer never answers; judged %s" % phase, close=s, judged=(phase,))


SCENARIOS["token-read-then-unanswered-request-while-open"] = functools.partial(token_read_then_unanswered_request, "open")
SCENARIOS["token-read-then-unanswered-request-at-close"] = functools.partial(token_read_then_unanswered_request, "closed")


# sendfile beside a memory body of the same size, and datagrams ----------------------------------

def sendfile_and_memory(size, order):
    sink(BASE, "--mode", "echo", "--echo-bytes", "6")
    a = mk("A", size)
    dummy = socket.create_connection(("127.0.0.1", BASE))
    dummy.sendall(b"x")
    dummy.recv(16)
    dummy.close()
    readall(mk("warmup", 70000))
    os.unlink(D + "/warmup")
    time.sleep(2.6)
    readall(a)
    s = socket.create_connection(("127.0.0.1", BASE))
    fd = os.open(a, os.O_RDONLY)

    def sendfile_all():
        sent = 0
        while sent < size:
            sent += os.sendfile(s.fileno(), fd, sent, size - sent)
    if order == "memory-first":
        s.sendall(os.urandom(size))
        s.recv(16)
        sendfile_all()
    elif order == "no-reply":
        sendfile_all()
        s.sendall(os.urandom(size))
    else:
        sendfile_all()
        s.recv(16)
        s.sendall(os.urandom(size))
    time.sleep(0.3)
    s.close()

    def once(agg):
        v = agg.get("A", [])
        return [] if len(v) == 1 and v[0][0] == "sendfile" else ["A listed as %s, sent once with sendfile" % (", ".join("%s/%s" % x[:2] for x in v) or "nothing")]
    what = {"memory-first": "%d B of memory, reply, sendfile A", "no-reply": "sendfile A, then %d B of memory without a reply between",
            "reply": "sendfile A, reply, %d B of memory"}[order] % size
    return Case("read A (%d B), connect, %s" % (size, what), {"A": around(size)}, once)


SCENARIOS["sendfile-reply-then-memory-64k"] = functools.partial(sendfile_and_memory, 64 * K, "reply")
SCENARIOS["sendfile-reply-then-memory-300k"] = functools.partial(sendfile_and_memory, 300 * K, "reply")
SCENARIOS["memory-reply-then-sendfile"] = functools.partial(sendfile_and_memory, 64 * K, "memory-first")
SCENARIOS["sendfile-then-memory-without-reply"] = functools.partial(sendfile_and_memory, 64 * K, "no-reply")


def datagrams(name, size, how):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", BASE))
    u.settimeout(0.1)
    stop = threading.Event()

    def drain():
        while not stop.is_set():
            try:
                u.recvfrom(65536)
            except Exception:
                pass
    threading.Thread(target=drain, daemon=True).start()
    path = mk(name, size)
    readall(mk("warmup", 70000))
    os.unlink(D + "/warmup")
    time.sleep(2.6)
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if how == "connected":
        c.connect(("127.0.0.1", BASE))
    data = readall(path)
    if how == "pieces":
        for i in range(0, len(data), 1400):
            c.sendto(data[i:i + 1400], ("127.0.0.1", BASE))
    elif how == "sendto":
        c.sendto(data, ("127.0.0.1", BASE))
    else:
        c.send(data)
    time.sleep(0.3)
    c.close()
    stop.set()
    what = {"connected": "a UDP socket connected before the read; one datagram", "sendto": "an unconnected UDP socket; one datagram",
            "pieces": "an unconnected UDP socket; datagrams of 1400 B"}[how]
    return Case("read %s (%d B) whole, send it on %s" % (name, size, what), {name: around(size)})


for _scn, _name, _size, _how in (("datagram-of-py-file", "payload.py", 4096, "connected"), ("datagram-of-passwd", "passwd", 2048, "connected"),
                                 ("datagram-of-js-file", "x.js", 4096, "connected"), ("datagram-of-php-file", "x.php", 4096, "connected"),
                                 ("unconnected-datagram-of-py-file", "payload.py", 4096, "sendto"), ("datagrams-of-large-file", "big.bin", 60 * K, "pieces"),
                                 ("datagrams-of-large-py-file", "big.py", 60 * K, "pieces"), ("datagram-of-ordinary-file", "x.bin", 4096, "connected")):
    SCENARIOS[_scn] = functools.partial(datagrams, _name, _size, _how)


# Bodies from memory of the size of a module the runtime read -----------------------------------

@scenario("module-sized-bodies")
def module_sized_bodies():
    sink(39961, "--mode", "http")
    url = "http://127.0.0.1:39961/up"
    runs = [
        ("python requests, 154582 B (typing .pyc)", ["python3", "-c", "import requests, os; requests.post('%s', data=os.urandom(154582))" % url]),
        ("python httpx, 154582 B", ["python3", "-c", "import httpx, os; httpx.post('%s', content=os.urandom(154582))" % url]),
        ("python requests, 85851 B (enum .pyc)", ["python3", "-c", "import requests, os; requests.post('%s', data=os.urandom(85851))" % url]),
        ("node http, 217747 B (acorn.js)", ["node", "-e", "const h=require('http'); const b=Buffer.alloc(217747, 120); const r=h.request('%s',{method:'POST',headers:{'Content-Length':b.length}},res=>res.resume()); r.end(b);" % url]),
        ("node fetch, 627423 B (undici-fetch.js)", ["node", "-e", "fetch('%s',{method:'POST',body:Buffer.alloc(627423,120)}).then(r=>r.text())" % url]),
        ("perl LWP, 326048 B (IO/Socket/SSL/PublicSuffix.pm)", ["perl", "-MLWP::UserAgent", "-e", "LWP::UserAgent->new->post('%s', Content => 'x' x 326048)" % url]),
    ]
    pids = []
    for label, cmd in runs:
        p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.wait()
        pids.append((label, p.pid))

    def none_listed(case, recs):
        problems = []
        for label, pid in pids:
            mine = [r for r in recs if r["process"]["pid"] == pid and (r.get("file") or {}).get("path")]
            print("  %s: %s" % (label, ", ".join("%s %d B" % (r["file"]["path"], r["transfer"]["bytes_sent"]) for r in mine) or "no file listed"))
            problems += ["%s: %s reported but not sent" % (label, r["file"]["path"]) for r in mine]
        return problems
    return Case("Python, Node.js and Perl clients post a body from memory the size of a module they read at start", judge=none_listed)


def main():
    if sys.argv[1:] == ["--list"]:
        print("\n".join(sorted(SCENARIOS)))
        return 0
    name = sys.argv[1]
    if name not in SCENARIOS:
        print("unknown scenario %s" % name, file=sys.stderr)
        return 2
    faulthandler.dump_traceback_later(240, exit=True)
    os.makedirs(D, exist_ok=True)
    try:
        case = SCENARIOS[name]()
        print("scenario %s: %s" % (name, case.notes))
        if case.skip:
            print("RESULT: SKIP (%s)" % case.skip)
            return 3
        if case.invalid:
            print("RESULT: INVALID (%s)" % case.invalid)
            return 2
        if case.close:
            problems = []
            for phase, title in (("open", "while the connection is open"), ("closed", "after it was closed")):
                if phase == "closed":
                    case.close.close()
                print("  %s%s:" % (title, "" if phase in case.judged else " (not judged)"))
                found = case.judge(case, transfers.both())
                if phase in case.judged:
                    problems += found
        else:
            problems = case.judge(case, transfers.both())
    finally:
        for p in procs:
            p.terminate()
    for p in problems:
        print("  problem:", p)
    print("RESULT: BUG" if problems else "RESULT: OK")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
