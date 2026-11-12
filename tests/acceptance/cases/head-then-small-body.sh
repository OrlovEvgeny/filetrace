#!/bin/sh
# An S3-style small upload over plain TCP: connect, read the file (3072, 20000 or 60000 B),
# send a 1500 B signed head and then the body. The file is sent once.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
for s in 3072 20000 60000; do head -c $s /dev/urandom >$D/f$s.bin; done
start_agent
python3 $SINK 39871 --mode raw >/dev/null 2>&1 &
S=$!
sleep 1
cat >/tmp/case.py <<'PY'
import os, socket, sys, time
s = socket.create_connection(("127.0.0.1", 39871))
fd = os.open(sys.argv[1], os.O_RDONLY); out = []
while True:
    b = os.read(fd, 65536)
    if not b: break
    out.append(b)
s.sendall(b"H" * 1500)
s.sendall(b"".join(out))
time.sleep(0.3); s.close()
PY
: >/tmp/case.pids
for s in 3072 20000 60000; do
    python3 /tmp/case.py $D/f$s.bin &
    echo "$s $!" >>/tmp/case.pids
    wait $!
done
fetch_transfers
python3 - <<'PY'
import json, sys
recs = json.load(open("/tmp/transfers.json"))
bug = 0
for l in open("/tmp/case.pids"):
    s, pid = l.split()
    mine = [r for r in recs if str(r["process"]["pid"]) == pid and (r.get("file") or {}).get("path")]
    got = sum(r["transfer"]["bytes_sent"] for r in mine if r["file"]["path"].endswith("/f%s.bin" % s))
    other = [r["file"]["path"] for r in mine if not r["file"]["path"].endswith("/f%s.bin" % s)]
    ok = 0.9 * int(s) <= got <= 1.05 * int(s) and not other
    print("  file %6s B: reported %6d B%s %s" % (s, got, ("; also reported: " + ",".join(other)) if other else "", "" if ok else "<-- FAILED"))
    if not ok: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S 2>/dev/null
stop_agent
exit $RC
