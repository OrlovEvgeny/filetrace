#!/bin/sh
# Three identical 200 KB uploads (connect, read, send; one process each) starting 4 s after the
# agent did. Each is sent.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
for i in 1 2 3; do head -c 204800 /dev/urandom >$D/A$i; done
start_agent
python3 $SINK 39841 --mode raw >/dev/null 2>&1 &
S=$!
sleep 4
cat >/tmp/case.py <<'PY'
import os, socket, sys, time
s = socket.create_connection(("127.0.0.1", 39841))
fd = os.open(sys.argv[1], os.O_RDONLY); d = b""
while True:
    b = os.read(fd, 65536)
    if not b: break
    d += b
s.sendall(d); time.sleep(0.3); s.close()
PY
: >/tmp/case.pids
for i in 1 2 3; do
    python3 /tmp/case.py $D/A$i &
    echo "$i $!" >>/tmp/case.pids
    wait $!
done
fetch_transfers
python3 - <<'PY'
import json, sys
recs = json.load(open("/tmp/transfers.json"))
bug = 0
for l in open("/tmp/case.pids"):
    i, pid = l.split()
    mine = [r for r in recs if str(r["process"]["pid"]) == pid and (r.get("file") or {}).get("path")]
    got = sum(r["transfer"]["bytes_sent"] for r in mine if r["file"]["path"].endswith("/A" + i))
    other = [r["file"]["path"] for r in mine if not r["file"]["path"].endswith("/A" + i)]
    print("  upload %s: reported %d of 204800 B%s" % (i, got, ("; also reported: " + ",".join(other)) if other else ""))
    if not 0.9 * 204800 <= got <= 1.05 * 204800 or other: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S 2>/dev/null
stop_agent
exit $RC
