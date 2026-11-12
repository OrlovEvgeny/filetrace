#!/bin/sh
# Key, certificate and configuration files read while a TLS connection is made; none is sent.
#   a: curl with a client certificate and key   b: curl -K with a 3000 B config file
#   c: Python ssl with a private CA file read when the context is made
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
cp $TLS/ca.pem $TLS/client.pem $TLS/client.key $D/
python3 -c "
l = b'# curl config comment line, nothing to see here, padding padding padding\n'
open('$D/curlrc', 'wb').write((l * 50)[:3000])"
start_agent
python3 $SINK 39201 --tls 1.3 --clientcert >/dev/null 2>&1 &
S1=$!
python3 $SINK 39202 --tls 1.3 >/dev/null 2>&1 &
S2=$!
sleep 1
: >/tmp/case.pids
curl -sS -o /dev/null --cacert $D/ca.pem --cert $D/client.pem --key $D/client.key https://localhost:39201/ &
echo "a $!" >>/tmp/case.pids
wait $!
curl -sS -o /dev/null -K $D/curlrc --cacert /etc/ssl/certs/ca-certificates.crt -k https://localhost:39202/ &
echo "b $!" >>/tmp/case.pids
wait $!
python3 - $D/ca.pem >/dev/null <<'PY' &
import socket, ssl, sys, encodings.idna
ctx = ssl.create_default_context(cafile=sys.argv[1])
ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 39202)), server_hostname="localhost")
s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"); s.recv(4096)
PY
echo "c $!" >>/tmp/case.pids
wait $!
fetch_transfers
python3 - $D <<'PY'
import json, sys
d = sys.argv[1]
pids = {l.split()[1]: l.split()[0] for l in open("/tmp/case.pids")}
what = {"a": "curl --cert/--key", "b": "curl -K curlrc (3000 B)", "c": "python ssl, private CA file"}
bug = 0
for sc, desc in what.items():
    hits = [r for r in json.load(open("/tmp/transfers.json")) if pids.get(str(r["process"]["pid"])) == sc and ((r.get("file") or {}).get("path") or "").startswith(d)]
    for r in hits:
        print("  %s [%s]: REPORTED %s sent=%d read=%d %s" % (sc, desc, r["file"]["path"], r["transfer"]["bytes_sent"], r["transfer"]["bytes_read"], r["transfer"]["confidence"]))
    if not hits:
        print("  %s [%s]: nothing reported" % (sc, desc))
    bug |= bool(hits)
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S1 $S2 2>/dev/null
stop_agent
exit $RC
