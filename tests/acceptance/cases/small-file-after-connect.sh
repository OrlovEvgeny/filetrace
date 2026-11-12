#!/bin/sh
# A file of 1 to 60 KB read after the connect and sent whole over plain TCP, on a new connection
# and on one that had a request answered first. Each file is sent.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
for s in 1024 2048 4096 16384 32768 61440; do head -c $s /dev/urandom >$D/f$s.bin; done
start_agent
python3 $SINK 39861 --mode http >/dev/null 2>&1 &
S=$!
sleep 1
cat >/tmp/case.py <<'PY'
import os, socket, sys, time
path, shape = sys.argv[1], sys.argv[2]
def readall(p):
    fd = os.open(p, os.O_RDONLY); out = []
    while True:
        b = os.read(fd, 65536)
        if not b: break
        out.append(b)
    os.close(fd); return b"".join(out)
s = socket.create_connection(("127.0.0.1", 39861))
if shape == "old":
    s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"); buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
d = readall(path); s.sendall(d); time.sleep(0.3); s.close()
PY
: >/tmp/case.pids
for shape in after old; do
    for s in 1024 2048 4096 16384 32768 61440; do
        python3 /tmp/case.py $D/f$s.bin $shape &
        echo "$shape $s $!" >>/tmp/case.pids
        wait $!
    done
done
fetch_transfers
python3 - <<'PY'
import json, sys
recs = json.load(open("/tmp/transfers.json"))
bug = 0
for l in open("/tmp/case.pids"):
    shape, s, pid = l.split()
    mine = [r for r in recs if str(r["process"]["pid"]) == pid and (r.get("file") or {}).get("path")]
    got = sum(r["transfer"]["bytes_sent"] for r in mine if r["file"]["path"].endswith("/f%s.bin" % s))
    other = [r["file"]["path"] for r in mine if not r["file"]["path"].endswith("/f%s.bin" % s)]
    ok = 0.9 * int(s) <= got <= 1.05 * int(s) and not other
    print("  %-5s %6s B: reported %6d B%s %s" % (shape, s, got, ("; also reported: " + ",".join(other)) if other else "", "" if ok else "<-- FAILED"))
    if not ok: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S 2>/dev/null
stop_agent
exit $RC
