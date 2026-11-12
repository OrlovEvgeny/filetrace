#!/bin/sh
# A 200 KB file read and uploaded by PHP and by other clients, over TLS and plain TCP.
# Every upload is sent.
#   a: PHP curl TLS 1.3   b: PHP stream tls:// TLS 1.3   c: PHP curl TLS 1.2   d: PHP curl plain
#   e: Python TLS 1.3   f: curl TLS 1.3
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
head -c 204800 /dev/urandom >$D/A
start_agent
python3 $SINK 39601 --mode http --tls 1.3 >/dev/null 2>&1 &
S1=$!
python3 $SINK 39602 --mode http --tls 1.2 >/dev/null 2>&1 &
S2=$!
python3 $SINK 39603 --mode http >/dev/null 2>&1 &
S3=$!
sleep 1
: >/tmp/case.pids
run() {
    sc=$1
    shift
    "$@" >/dev/null 2>&1 &
    echo "$sc $!" >>/tmp/case.pids
    wait $!
}
CURLPHP='$d=file_get_contents($argv[1]); $c=curl_init($argv[2]); curl_setopt($c,CURLOPT_POSTFIELDS,$d); curl_setopt($c,CURLOPT_SSL_VERIFYPEER,false); curl_setopt($c,CURLOPT_SSL_VERIFYHOST,0); curl_setopt($c,CURLOPT_RETURNTRANSFER,true); curl_exec($c);'
run a php -r "$CURLPHP" $D/A https://127.0.0.1:39601/up
run b php -r '$d=file_get_contents($argv[1]); $s=stream_socket_client("tls://127.0.0.1:39601",$e,$m,5,STREAM_CLIENT_CONNECT,stream_context_create(["ssl"=>["verify_peer"=>false,"verify_peer_name"=>false]])); fwrite($s,$d);' $D/A
run c php -r "$CURLPHP" $D/A https://127.0.0.1:39602/up
run d php -r "$CURLPHP" $D/A http://127.0.0.1:39603/up
run e python3 -c "
import ssl, socket, sys
d = open(sys.argv[1], 'rb').read()
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
c.wrap_socket(socket.create_connection(('127.0.0.1', 39601))).sendall(d)" $D/A
run f curl -sS -k -o /dev/null --data-binary @$D/A https://127.0.0.1:39601/up
fetch_transfers
python3 - <<'PY'
import json, sys
pids = {l.split()[1]: l.split()[0] for l in open("/tmp/case.pids")}
what = {"a": "php curl TLS 1.3", "b": "php stream tls:// TLS 1.3", "c": "php curl TLS 1.2", "d": "php curl plain", "e": "python TLS 1.3", "f": "curl TLS 1.3"}
bug = 0
for sc, desc in what.items():
    recs = [r for r in json.load(open("/tmp/transfers.json")) if pids.get(str(r["process"]["pid"])) == sc and (r.get("file") or {}).get("path")]
    got = sum(r["transfer"]["bytes_sent"] for r in recs if r["file"]["path"].endswith("/A"))
    other = ["%s:%d" % (r["file"]["path"], r["transfer"]["bytes_sent"]) for r in recs if not r["file"]["path"].endswith("/A")]
    print("  %s [%s]: A reported %d of 204800 B%s" % (sc, desc, got, ("; also reported: " + ",".join(other)) if other else ""))
    if got < 0.9 * 204800 or got > 1.05 * 204800 or other: bug = 1
print("RESULT: BUG" if bug else "RESULT: OK")
sys.exit(bug)
PY
RC=$?
kill $S1 $S2 $S3 2>/dev/null
stop_agent
exit $RC
