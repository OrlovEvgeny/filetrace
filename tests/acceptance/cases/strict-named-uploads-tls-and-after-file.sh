#!/bin/sh
# Files named x.bin, x.php, x.js and x.so are uploaded in two shapes; each file is sent once.
#   a: a 1 MB file read after a TLS 1.3 connect and sent
#   b: a 2048 B file read after a 1500 B ordinary file, on plain TCP, and sent
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
for n in bin php js so; do
    head -c 1048576 /dev/urandom >$D/big.$n
    head -c 2048 /dev/urandom >$D/small.$n
done
head -c 1500 /dev/urandom >$D/first.cfg
start_agent
python3 $SINK 39893 --mode raw >/dev/null 2>&1 &
S1=$!
python3 $SINK 39894 --mode raw --tls 1.3 >/dev/null 2>&1 &
S2=$!
sleep 1
cat >/tmp/case.py <<'PY'
import os, socket, ssl, sys, time
import encodings.idna, stringprep
path, tr, first = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
def readall(p):
    fd = os.open(p, os.O_RDONLY); out = []
    while True:
        b = os.read(fd, 65536)
        if not b: break
        out.append(b)
    os.close(fd); return b"".join(out)
ctx = None
if tr == "tls13":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
time.sleep(0.05)
if first: readall("/data/acceptance/first.cfg")
s = socket.create_connection(("127.0.0.1", 39894 if ctx else 39893))
if ctx: s = ctx.wrap_socket(s, server_hostname="localhost")
d = readall(path); s.sendall(d); time.sleep(0.3); s.close()
PY
: >/tmp/case.pids
for n in bin php js so; do
    python3 /tmp/case.py $D/big.$n tls13 0 &
    echo "a big.$n 1048576 $!" >>/tmp/case.pids
    wait $!
    python3 /tmp/case.py $D/small.$n plain 1 &
    echo "b small.$n 2048 $!" >>/tmp/case.pids
    wait $!
done
fetch_transfers
python3 - <<'PY'
import json, sys
recs = json.load(open("/tmp/transfers.json"))
bug = 0
for l in open("/tmp/case.pids"):
    sc, fn, size, pid = l.split()
    mine = [r for r in recs if str(r["process"]["pid"]) == pid and (r.get("file") or {}).get("path")]
    got = sum(r["transfer"]["bytes_sent"] for r in mine if r["file"]["path"].endswith("/" + fn))
    other = [r["file"]["path"] for r in mine if not r["file"]["path"].endswith("/" + fn)]
    ok = 0.9 * int(size) <= got <= 1.05 * int(size) and not other
    what = "1 MB after a TLS 1.3 connect" if sc == "a" else "2 KB after a 1.5 KB ordinary file"
    print("  %-34s %-10s: reported %7d of %s B%s %s" % (what, fn, got, size, ("; also reported: " + ",".join(other)) if other else "", "" if ok else "<-- FAILED"))
    if not ok: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S1 $S2 2>/dev/null
stop_agent
exit $RC
