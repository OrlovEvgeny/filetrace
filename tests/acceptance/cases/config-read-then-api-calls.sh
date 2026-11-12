#!/bin/sh
# A client reads its 8 KB configuration, connects and makes four small API calls
# (460 B request, short reply) over plain TCP. The configuration is never sent.
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
head -c 8192 /dev/urandom >$D/config.bin
start_agent
python3 - 39101 <<'PY' &
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(5)
c, _ = s.accept()
buf = b""
while True:
    d = c.recv(65536)
    if not d: break
    buf += d
    while b"\r\n\r\n" in buf:
        i = buf.index(b"\r\n\r\n"); cl = int(buf[:i].split(b"Content-Length: ")[1].split(b"\r\n")[0])
        if len(buf) < i + 4 + cl: break
        buf = buf[i + 4 + cl:]
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
PY
SRV=$!
sleep 0.5
python3 - 39101 $D/config.bin >/tmp/case.client <<'PY' &
import socket, sys, os
port, path = int(sys.argv[1]), sys.argv[2]
open(path, "rb").read()
s = socket.create_connection(("127.0.0.1", port))
print(os.getpid(), flush=True)
for i in range(4):
    body = b"q" * 400
    s.sendall(b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    s.recv(4096)
PY
wait $!
echo "scenario: read config.bin (8192 B), connect, 4 x (460 B request, reply); the file was never sent"
report $D "$(cat /tmp/case.client)"
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
