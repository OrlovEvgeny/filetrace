#!/bin/sh
# nginx serves a 5 MB file over TLS, once with HTTP/2 and once with HTTP/1.1 (sendfile on).
# Each file left whole, once.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D /tmp/nginx-body /tmp/nginx-proxy /tmp/nginx-fcgi /tmp/nginx-uwsgi /tmp/nginx-scgi
head -c 5242880 /dev/urandom >$D/A.bin
head -c 5242880 /dev/urandom >$D/B.bin
chmod -R a+rX $D
start_agent
nginx -c /acceptance/nginx-tls.conf
sleep 1
curl -sS --http2 --cacert $TLS/ca.pem -o /dev/null -w "HTTP/2: %{http_version} %{size_download}\n" https://localhost:39711/A.bin
curl -sS --http1.1 --cacert $TLS/ca.pem -o /dev/null -w "HTTP/1.1: %{http_version} %{size_download}\n" https://localhost:39712/B.bin
fetch_transfers
python3 - $D <<'PY'
import json, sys
recs = [r for r in json.load(open("/tmp/transfers.json")) if ((r.get("file") or {}).get("path") or "").startswith(sys.argv[1])]
bug = 0
for r in recs:
    t = r["transfer"]
    print("  filetrace: %s by %s port %s %s %s sent=%d read=%d" % (r["file"]["path"], r["process"]["name"], r["network"].get("local_port"), t["method"], t["confidence"], t["bytes_sent"], t["bytes_read"]))
for name in ("A.bin", "B.bin"):
    mine = [r for r in recs if r["file"]["path"].endswith("/" + name)]
    got = sum(r["transfer"]["bytes_sent"] for r in mine)
    if not 0.9 * 5242880 <= got <= 1.05 * 5242880:
        print("  problem: %s listed with %d B in %d records" % (name, got, len(mine)))
        bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill "$(cat /run/acceptance-nginx.pid)" 2>/dev/null
stop_agent
exit $RC
