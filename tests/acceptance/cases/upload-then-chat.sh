#!/bin/sh
# A 300 KB file is read, a connection opened and the file PUT, the reply read, then 0, 5 or 30
# small request and reply exchanges follow on the same connection within 2 s. The file is sent
# once each time.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
head -c 307200 /dev/urandom >$D/A
start_agent
python3 $SINK 39881 --mode http >/dev/null 2>&1 &
S=$!
sleep 1
cat >/tmp/case.py <<'PY'
import os, socket, sys, time
n_chat = int(sys.argv[2])
fd = os.open(sys.argv[1], os.O_RDONLY); out = []
while True:
    b = os.read(fd, 65536)
    if not b: break
    out.append(b)
d = b"".join(out)
s = socket.create_connection(("127.0.0.1", 39881))
def reply():
    buf = b""
    while b"\r\n\r\n" not in buf: buf += s.recv(4096)
    n = int(buf.split(b"Content-Length: ")[1].split(b"\r\n")[0])
    while len(buf) < buf.index(b"\r\n\r\n") + 4 + n: buf += s.recv(4096)
s.sendall(b"PUT /up HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(d) + d); reply()
for i in range(n_chat):
    s.sendall(b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 300\r\n\r\n" + b"q" * 300); reply()
time.sleep(0.3); s.close()
PY
: >/tmp/case.pids
for n in 0 5 30; do
    python3 /tmp/case.py $D/A $n &
    echo "$n $!" >>/tmp/case.pids
    wait $!
done
fetch_transfers
python3 - <<'PY'
import json, sys
recs = json.load(open("/tmp/transfers.json"))
bug = 0
for l in open("/tmp/case.pids"):
    n, pid = l.split()
    mine = [r for r in recs if str(r["process"]["pid"]) == pid and (r.get("file") or {}).get("path")]
    got = sum(r["transfer"]["bytes_sent"] for r in mine if r["file"]["path"].endswith("/A"))
    other = [r["file"]["path"] for r in mine if not r["file"]["path"].endswith("/A")]
    ok = 0.9 * 307200 <= got <= 1.05 * 307200 and not other
    print("  upload then %2s exchanges: reported %6d of 307200 B%s %s" % (n, got, ("; also reported: " + ",".join(other)) if other else "", "" if ok else "<-- FAILED"))
    if not ok: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S 2>/dev/null
stop_agent
exit $RC
