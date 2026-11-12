#!/bin/sh
# A program reads its 3000 B configuration, connects, then reads and sends a 70000 B file
# named x.php, and again with x.bin. The upload is sent each time; the configuration never is.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
head -c 3000 /dev/urandom >$D/config.ini
head -c 70000 /dev/urandom >$D/x.php
head -c 70000 /dev/urandom >$D/x.bin
start_agent
python3 $SINK 39821 --mode raw >/dev/null 2>&1 &
S=$!
sleep 1
cat >/tmp/case.py <<'PY'
import os, socket, sys, time
cfg, path = sys.argv[1], sys.argv[2]
def readall(p):
    fd = os.open(p, os.O_RDONLY); out = b""
    while True:
        b = os.read(fd, 65536)
        if not b: break
        out += b
    os.close(fd); return out
readall(cfg)
s = socket.create_connection(("127.0.0.1", 39821))
d = readall(path); s.sendall(d); time.sleep(0.3); s.close()
PY
: >/tmp/case.pids
for e in php bin; do
    python3 /tmp/case.py $D/config.ini $D/x.$e &
    echo "$e $!" >>/tmp/case.pids
    wait $!
done
fetch_transfers
python3 - <<'PY'
import json, sys
recs = json.load(open("/tmp/transfers.json"))
bug = 0
for l in open("/tmp/case.pids"):
    e, pid = l.split()
    mine = [r for r in recs if str(r["process"]["pid"]) == pid and ((r.get("file") or {}).get("path") or "").startswith("/data/acceptance/")]
    got = {}
    for r in mine:
        n = r["file"]["path"].split("/")[-1]
        got[n] = got.get(n, 0) + r["transfer"]["bytes_sent"]
    print("  x.%-4s: reported %s" % (e, got or "nothing"))
    if not 0.9 * 70000 <= got.get("x." + e, 0) <= 1.05 * 70000 or set(got) - {"x." + e}: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S 2>/dev/null
stop_agent
exit $RC
