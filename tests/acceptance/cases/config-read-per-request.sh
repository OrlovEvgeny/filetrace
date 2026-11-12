#!/bin/sh
# A server reads its 4 KB configuration for every request and answers 413 B; eight requests
# on one keep-alive connection. The configuration is never sent.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
python3 -c "
l = b'# config line padding padding padding padding padding padding padding\n'
open('$D/app.cfg', 'wb').write((l * 100)[:4096])"
start_agent
python3 - $D/app.cfg >/dev/null 2>&1 <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
cfg = sys.argv[1]
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        with open(cfg, "rb") as f:
            f.read()
        body = b"ok " + b"x" * 297
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", 39501), H).serve_forever()
PY
SRV=$!
sleep 1
u=http://127.0.0.1:39501/
curl -sS $u $u $u $u $u $u $u $u >/dev/null
echo "scenario: 8 requests on one connection, each answered with 413 B after a read of app.cfg (4096 B); the file is never sent"
report $D "$SRV"
python3 - $D <<'PY'
import json, sys
bad = [r for r in json.load(open("/tmp/transfers.json")) if ((r.get("file") or {}).get("path") or "").startswith(sys.argv[1])]
print("RESULT: BUG" if bad else "RESULT: OK")
sys.exit(1 if bad else 0)
PY
RC=$?
kill $SRV 2>/dev/null
stop_agent
exit $RC
