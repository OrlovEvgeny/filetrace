#!/bin/sh
# A 200 KB upload over TLS 1.3 with a CA file, certificate or key read between the upload's
# read and the handshake. The upload is sent each time and nothing else is.
#   a: curl --cacert <private CA> --data-binary @A   b: Python, private CA read after the file
#   c: curl with a client certificate --data-binary @A   d: curl --cacert with a CA under /etc/ssl/certs
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
cp $TLS/ca.pem $TLS/client.pem $TLS/client.key $D/
cp $TLS/ca.pem /etc/ssl/certs/acceptance-ca.pem
head -c 204800 /dev/urandom >$D/A
start_agent
python3 $SINK 39301 --tls 1.3 >/dev/null 2>&1 &
S1=$!
python3 $SINK 39302 --tls 1.3 --clientcert >/dev/null 2>&1 &
S2=$!
sleep 1
: >/tmp/case.pids
curl -sS --max-time 10 -o /dev/null --cacert $D/ca.pem --data-binary @$D/A https://localhost:39301/up &
echo "a $!" >>/tmp/case.pids
wait $!
python3 - $D/A $D/ca.pem >/dev/null <<'PY' &
import socket, ssl, sys, encodings.idna
data = open(sys.argv[1], "rb").read()
ctx = ssl.create_default_context(cafile=sys.argv[2])
ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 39301)), server_hostname="localhost")
s.sendall(data)
PY
echo "b $!" >>/tmp/case.pids
wait $!
curl -sS --max-time 10 -o /dev/null --cacert $D/ca.pem --cert $D/client.pem --key $D/client.key --data-binary @$D/A https://localhost:39302/up &
echo "c $!" >>/tmp/case.pids
wait $!
curl -sS --max-time 10 -o /dev/null --cacert /etc/ssl/certs/acceptance-ca.pem --data-binary @$D/A https://localhost:39301/up &
echo "d $!" >>/tmp/case.pids
wait $!
fetch_transfers
python3 - $D <<'PY'
import json, sys
d = sys.argv[1]
pids = {l.split()[1]: l.split()[0] for l in open("/tmp/case.pids")}
what = {"a": "curl --cacert <private CA> -d @A", "b": "python, private CA read after A", "c": "curl, client certificate, -d @A", "d": "curl --cacert /etc/ssl/certs/.. -d @A"}
bug = 0
for sc, desc in what.items():
    recs = [r for r in json.load(open("/tmp/transfers.json")) if pids.get(str(r["process"]["pid"])) == sc and ((r.get("file") or {}).get("path") or "").startswith(d)]
    got = sum(r["transfer"]["bytes_sent"] for r in recs if r["file"]["path"].endswith("/A"))
    other = ["%s:%d" % (r["file"]["path"].split("/")[-1], r["transfer"]["bytes_sent"]) for r in recs if not r["file"]["path"].endswith("/A")]
    print("  %s [%s]: A reported %d of 204800 B%s" % (sc, desc, got, ("; also reported: " + ",".join(other)) if other else ""))
    if got < 0.9 * 204800 or got > 1.05 * 204800 or other: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S1 $S2 2>/dev/null
stop_agent
exit $RC
