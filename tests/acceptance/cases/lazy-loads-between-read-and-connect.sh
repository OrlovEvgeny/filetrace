#!/bin/sh
# A 200 KB file read, then modules or libraries loaded before the connection that uploads it.
# The upload is sent each time and nothing else is.
#   a: Perl LWP::UserAgent PUT   b: Perl IO::Socket::INET (reads /etc/protocols)
#   c: Perl, a .pm required between connect and send   d: Python C extensions imported in between
#   e: Python asyncio name lookup (its thread pool imports _queue.so)   f: Python .py modules imported in between
. /acceptance/lib.sh
D=/data/acceptance
mkdir -p $D
head -c 204800 /dev/urandom >$D/A
start_agent
python3 $SINK 39401 --mode http >/dev/null 2>&1 &
S1=$!
sleep 1
: >/tmp/case.pids
run() {
    sc=$1
    shift
    "$@" >/dev/null 2>&1 &
    echo "$sc $!" >>/tmp/case.pids
    wait $!
}
cat >/tmp/case.a.pl <<'PL'
use strict; use LWP::UserAgent;
open(my $f, '<:raw', $ARGV[0]) or die; local $/; my $data = <$f>; close $f;
LWP::UserAgent->new->put($ARGV[1], Content => $data);
PL
cat >/tmp/case.b.pl <<'PL'
use strict; use IO::Socket::INET;
open(my $f, '<:raw', $ARGV[0]) or die; local $/; my $data = <$f>; close $f;
my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$ARGV[1]") or die;
print $s $data; close $s;
PL
cat >/tmp/case.c.pl <<'PL'
use strict; use IO::Socket::INET;
open(my $f, '<:raw', $ARGV[0]) or die; local $/; my $data = <$f>; close $f;
my $s = IO::Socket::INET->new(PeerAddr => "127.0.0.1:$ARGV[1]") or die;
require IO::Compress::Zlib::Extra;
print $s $data; close $s;
PL
cat >/tmp/case.d.py <<'PY'
import sys, socket
data = open(sys.argv[1], "rb").read()
import _bz2, _lzma, _hashlib
s = socket.create_connection(("127.0.0.1", int(sys.argv[2])))
s.sendall(data); s.close()
PY
cat >/tmp/case.e.py <<'PY'
import sys, asyncio
async def main():
    data = open(sys.argv[1], "rb").read()
    await asyncio.get_running_loop().getaddrinfo("localhost", int(sys.argv[2]))
    r, w = await asyncio.open_connection("127.0.0.1", int(sys.argv[2]))
    w.write(data); await w.drain(); w.close()
asyncio.run(main())
PY
cat >/tmp/case.f.py <<'PY'
import sys, socket
data = open(sys.argv[1], "rb").read()
import textwrap, shlex, fnmatch, getopt, string
s = socket.create_connection(("127.0.0.1", int(sys.argv[2])))
s.sendall(data); s.close()
PY
run a perl /tmp/case.a.pl $D/A http://127.0.0.1:39401/up
run b perl /tmp/case.b.pl $D/A 39401
run c perl /tmp/case.c.pl $D/A 39401
run d python3 /tmp/case.d.py $D/A 39401
run e python3 /tmp/case.e.py $D/A 39401
run f python3 /tmp/case.f.py $D/A 39401
fetch_transfers
python3 - <<'PY'
import json, sys
pids = {l.split()[1]: l.split()[0] for l in open("/tmp/case.pids")}
what = {"a": "perl LWP PUT", "b": "perl IO::Socket::INET", "c": "perl, a .pm required in between", "d": "python C extensions in between", "e": "python asyncio name lookup", "f": "python .py modules in between"}
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
kill $S1 2>/dev/null
stop_agent
exit $RC
