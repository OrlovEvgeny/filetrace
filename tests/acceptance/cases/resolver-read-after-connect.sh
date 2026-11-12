#!/bin/sh
# A connection is opened, then a name lookup reads /etc/gai.conf and other resolver files, then a
# request of 1000 to 6000 B from memory goes on the first connection. No file is sent.
. /acceptance/lib.sh
start_agent
python3 $SINK 39831 --mode http >/dev/null 2>&1 &
S=$!
sleep 1
cat >/tmp/case.py <<'PY'
import socket, sys, time
size = int(sys.argv[1])
s = socket.create_connection(("127.0.0.1", 39831))
socket.getaddrinfo("localhost", 80)
body = b"q" * size
s.sendall(b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
buf = b""
while b"\r\n\r\n" not in buf: buf += s.recv(4096)
time.sleep(0.3); s.close()
PY
: >/tmp/case.pids
for n in 1000 2600 3000 4000 6000; do
    python3 /tmp/case.py $n &
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
    got = [(r["file"]["path"], r["transfer"]["bytes_sent"]) for r in recs if str(r["process"]["pid"]) == pid and (r.get("file") or {}).get("path")]
    print("  request %5s B: %s" % (n, ", ".join("%s %d B" % g for g in got) or "no file listed"))
    if got: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S 2>/dev/null
stop_agent
exit $RC
