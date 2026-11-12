#!/bin/sh
# Small uploads on a kept-alive connection; each file is sent as many times as it is PUT.
#   a: curl -T f url1 -T f url2, a 3072 B file PUT twice on one connection. The first PUT of
#      several under 4 KB is a documented limit: one PUT of two reported is a limit.
#   b1: a request answered, the file read, a 1500 B head and the body, the next request at once
#      without reading an answer (pipelining, a documented limit).
#   b2: a request answered, the file read, a 1500 B signed head and the body as one PUT that is
#      answered, then one more request. A 1 KB file behind a head over 1 KB on a connection that
#      heard from its peer is a documented limit.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
for s in 1024 3072 4096 20000 61440; do head -c $s /dev/urandom >$D/f$s; done
start_agent
python3 $SINK 39891 --mode http >/dev/null 2>&1 &
S=$!
sleep 1
: >/tmp/case.pids
curl -sS -o /dev/null -T $D/f3072 http://127.0.0.1:39891/a -T $D/f3072 http://127.0.0.1:39891/b &
echo "a 3072 $!" >>/tmp/case.pids
wait $!
cat >/tmp/case.py <<'PY'
import os, socket, sys, time
path, mode = sys.argv[1], sys.argv[2]
s = socket.create_connection(("127.0.0.1", 39891))
def reply():
    b = b""
    while b"\r\n\r\n" not in b: b += s.recv(4096)
    n = int(b.split(b"Content-Length: ")[1].split(b"\r\n")[0])
    while len(b) < b.index(b"\r\n\r\n") + 4 + n: b += s.recv(4096)
req = b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
s.sendall(req); reply()
fd = os.open(path, os.O_RDONLY); d = b""
while True:
    c = os.read(fd, 65536)
    if not c: break
    d += c
if mode == "pipelined":
    s.sendall(b"H" * 1500); s.sendall(d)
    s.sendall(req); reply()
else:
    head = b"PUT /obj HTTP/1.1\r\nHost: x\r\nX-Sig: " + b"s" * 1400 + b"\r\nContent-Length: %d\r\n\r\n" % len(d)
    s.sendall(head); s.sendall(d); reply()
    s.sendall(req); reply()
time.sleep(0.3); s.close()
PY
python3 /tmp/case.py $D/f3072 pipelined &
echo "b1 3072 $!" >>/tmp/case.pids
wait $!
for s in 1024 3072 4096 20000 61440; do
    python3 /tmp/case.py $D/f$s answered &
    echo "b2 $s $!" >>/tmp/case.pids
    wait $!
done
fetch_transfers
python3 - <<'PY'
import json, sys
recs = json.load(open("/tmp/transfers.json"))
bug = 0
for l in open("/tmp/case.pids"):
    sc, size, pid = l.split()
    size = int(size)
    mine = [r for r in recs if str(r["process"]["pid"]) == pid and (r.get("file") or {}).get("path")]
    got = sum(r["transfer"]["bytes_sent"] for r in mine if r["file"]["path"].endswith("/f%d" % size))
    other = [r["file"]["path"] for r in mine if not r["file"]["path"].endswith("/f%d" % size)]
    sent = 2 * size if sc == "a" else size
    if 0.9 * sent <= got <= 1.05 * sent:
        v = "ok"
    elif sc == "a" and 0.9 * size <= got <= 1.05 * size:
        v = "limit (one PUT of two: the first small request of several)"
    elif sc == "b1" and got == 0:
        v = "limit (pipelined)"
    elif sc == "b2" and size == 1024 and got == 0:
        v = "limit (1 KB file behind a head over 1 KB on a heard connection)"
    else:
        v = "FAILED"
    if other:
        v = "FAILED, also reported: " + ",".join(other)
    what = {"a": "curl -T twice", "b1": "pipelined", "b2": "upload answered"}[sc]
    print("  %-16s %6d B file, %6d B sent: reported %6d B: %s" % (what, size, sent, got, v))
    if v.startswith("FAILED"): bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S 2>/dev/null
stop_agent
exit $RC
