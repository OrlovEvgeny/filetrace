#!/bin/sh
# A Flask app sends app.js and app.bin of 2000 and 4000 B with send_file, once with its default
# reply head and once with the headers of a production app. Each file is sent twice.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
chmod 755 $D
python3 -c "
l = b'var a = 1; function f(x) { return x + 1; } // padding padding padding\n'
for n in (2000, 4000):
    for ext in ('js', 'bin'):
        open('$D/app%d.%s' % (n, ext), 'wb').write((l * 100)[:n])"
chmod 644 $D/*
start_agent
python3 /acceptance/flask_app.py >/dev/null 2>&1 &
FL=$!
sleep 2
for n in 2000 4000; do
    for ext in js bin; do
        curl -sS -o /dev/null "http://127.0.0.1:18301/file?f=$D/app$n.$ext"
        curl -sS -o /dev/null "http://127.0.0.1:18301/file?f=$D/app$n.$ext&hdr=1"
    done
done
fetch_transfers
python3 - $FL <<'PY'
import json, sys
recs = [r for r in json.load(open("/tmp/transfers.json")) if str(r["process"]["pid"]) == sys.argv[1] and (r.get("file") or {}).get("path")]
bug = 0
names = ["app%d.%s" % (n, ext) for n in (2000, 4000) for ext in ("js", "bin")]
for name in names:
    n = int(name[3:7])
    got = sum(r["transfer"]["bytes_sent"] for r in recs if r["file"]["path"].endswith("/" + name))
    ok = 0.9 * 2 * n <= got <= 1.05 * 2 * n
    print("  %s, two requests: reported %5d of %d B %s" % (name, got, 2 * n, "" if ok else "<-- FAILED"))
    if not ok: bug = 1
other = [r["file"]["path"] for r in recs if r["file"]["path"].split("/")[-1] not in names]
if other:
    print("  also reported: " + ", ".join(other)); bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $FL 2>/dev/null
stop_agent
exit $RC
