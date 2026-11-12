#!/bin/sh
# A 70000 B file with an ordinary, strict-listed or background-listed name is uploaded over plain
# TCP, read before the connect, after it, or on a connection that had a request answered.
# Every file is sent once. Background-listed names (.mo, .pyc) are never reported from a read
# and a send: that is a documented limit, not a failure.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
for e in bin php so pm pl class mo node py pyc js; do head -c 70000 /dev/urandom >$D/x.$e; done
start_agent
python3 $SINK 39811 --mode http >/dev/null 2>&1 &
S=$!
sleep 1
cat >/tmp/case.py <<'PY'
import os, socket, sys, time
path, order = sys.argv[1], sys.argv[2]
def readall(p):
    fd = os.open(p, os.O_RDONLY); out = b""
    while True:
        b = os.read(fd, 65536)
        if not b: break
        out += b
    os.close(fd); return out
def req(s):
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"); buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
    n = int(buf.split(b"Content-Length: ")[1].split(b"\r\n")[0])
    while len(buf) < buf.index(b"\r\n\r\n") + 4 + n: buf += s.recv(4096)
if order == "before":
    d = readall(path); s = socket.create_connection(("127.0.0.1", 39811)); s.sendall(d)
elif order == "after":
    s = socket.create_connection(("127.0.0.1", 39811)); d = readall(path); s.sendall(d)
else:
    s = socket.create_connection(("127.0.0.1", 39811)); req(s); d = readall(path); s.sendall(d)
time.sleep(0.3); s.close()
PY
: >/tmp/case.pids
for order in before after old; do
    for e in bin php so pm pl class mo node py pyc js; do
        python3 /tmp/case.py $D/x.$e $order &
        echo "$order $e $!" >>/tmp/case.pids
        wait $!
    done
done
fetch_transfers
python3 - <<'PY'
import json, sys
recs = json.load(open("/tmp/transfers.json"))
bug = 0
for l in open("/tmp/case.pids"):
    order, e, pid = l.split()
    mine = [r for r in recs if str(r["process"]["pid"]) == pid and (r.get("file") or {}).get("path")]
    got = sum(r["transfer"]["bytes_sent"] for r in mine if r["file"]["path"].endswith("/x." + e))
    other = ["%s:%d" % (r["file"]["path"], r["transfer"]["bytes_sent"]) for r in mine if not r["file"]["path"].endswith("/x." + e)]
    if 0.9 * 70000 <= got <= 1.05 * 70000:
        v = "ok"
    elif got == 0 and e in ("mo", "pyc"):
        v = "limit (background-listed name)"
    else:
        v = "FAILED"
    if other:
        v = "FAILED, also reported: " + ",".join(other)
    print("  %-6s x.%-5s reported %6d of 70000 B: %s" % (order, e, got, v))
    if v.startswith("FAILED"): bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S 2>/dev/null
stop_agent
exit $RC
