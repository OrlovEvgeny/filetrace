#!/bin/sh
# usage: run.sh <directory with filetrace and filetrace-agent> <workload binary> [auto|trampoline|kprobe]
# Exits 77 when this machine cannot run the collector.

set -u

bin=$1
workload=$2
probes=${3:-auto}
work=$(mktemp -d /tmp/filetrace-it-XXXXXX)
data=$work/data
sock=$work/agent.sock
agent_pid=
failures=0
checks=0

mkdir -p "$data"

cleanup() {
    [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

ft() {
    "$bin/filetrace" --socket "$sock" "$@"
}

fail() {
    failures=$((failures + 1))
    echo "FAIL: $*"
}

# expect <description> <actual> <expected>
expect() {
    checks=$((checks + 1))
    if [ "$2" != "$3" ]; then
        fail "$1: got '$2', expected '$3'"
    fi
}

# expect_match <description> <text> <extended regex>
expect_match() {
    checks=$((checks + 1))
    if ! printf '%s\n' "$2" | grep -Eq -- "$3"; then
        fail "$1: '$2' does not match '$3'"
    fi
}

# Prints the named column of every data row of the CSV on standard input.
column() {
    awk -F, -v name="$1" '
        NR == 1 { for (i = 1; i <= NF; i++) if ($i == name) c = i; next }
        c { print $c }'
}

rows() {
    awk 'NR > 1' | wc -l | tr -d ' '
}

# Value of key=value in a workload report line.
field() {
    printf '%s\n' "$1" | tr ' ' '\n' | awk -F= -v key="$2" '$1 == key { print $2 }'
}

start_agent() {
    "$bin/filetrace-agent" --socket "$sock" --flush-interval 100ms --log-level warn \
        --probes "$probes" "$@" &
    agent_pid=$!
    i=0
    while [ ! -S "$sock" ] && [ $i -lt 100 ]; do
        kill -0 "$agent_pid" 2>/dev/null || return 1
        sleep 0.1
        i=$((i + 1))
    done
    [ -S "$sock" ]
}

stop_agent() {
    ft agent stop >/dev/null
    wait "$agent_pid"
    status=$?
    agent_pid=
    return $status
}

# Long enough for two counter flushes.
settle() {
    sleep 0.5
}

# A PHP-FPM pool "ft" on a Unix socket, whose scripts each upload the file they are given.
fpm=$(ls /usr/sbin/php-fpm* 2>/dev/null | head -1)
php_fpm_start() {
    mkdir -p "$work/php"
    cat >"$work/php/upload.php" <<'PHP'
<?php
$server = stream_socket_server('tcp://127.0.0.1:0');
$client = stream_socket_client('tcp://' . stream_socket_get_name($server, false));
$peer = stream_socket_accept($server);
$file = fopen($_SERVER['FT_FILE'], 'rb');
while (!feof($file)) {
    fwrite($client, fread($file, 8192));
    fread($peer, 8192);
}
PHP
    cp "$work/php/upload.php" "$work/php/other.php"
    cat >"$work/fpm.conf" <<CONF
[global]
error_log = $work/fpm.log
pid = $work/fpm.pid
[ft]
listen = $work/fpm.sock
pm = static
pm.max_children = 1
clear_env = no
CONF
    rm -f "$work/fpm.sock" "$work/fpm.pid"
    "$fpm" -R -y "$work/fpm.conf" || return 1
    i=0
    while [ ! -S "$work/fpm.sock" ] && [ $i -lt 50 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    settle
}

# php_request <script> <file>
php_request() {
    FT_FILE=$2 SCRIPT_FILENAME="$work/php/$1" SCRIPT_NAME="/$1" REQUEST_METHOD=GET \
        cgi-fcgi -bind -connect "$work/fpm.sock" >/dev/null
}

php_fpm_stop() {
    kill "$(cat "$work/fpm.pid")"
    while [ -e "$work/fpm.pid" ]; do sleep 0.1; done
}

"$bin/filetrace" doctor --probes "$probes" >"$work/doctor.txt" 2>&1
doctor=$?
if [ $doctor -eq 3 ] || [ $doctor -eq 5 ]; then
    cat "$work/doctor.txt"
    echo "SKIP: this machine cannot run the collector"
    exit 77
fi
expect "doctor exit code" "$doctor" 0

start_agent || { echo "FAIL: the agent did not start"; exit 1; }

expect "agent status exit code" "$(ft agent status >/dev/null; echo $?)" 0

# sendfile over IPv4: an exact attribution with exact byte counts.
report=$("$workload" sendfile "$data/report.csv" 5000000)
settle
csv=$(ft files --path "$data/report.csv" --format csv)
expect "sendfile rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "sendfile confidence" "$(printf '%s\n' "$csv" | column transfer.confidence)" exact
expect "sendfile method" "$(printf '%s\n' "$csv" | column transfer.method)" sendfile
expect "sendfile bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 5000000
expect "sendfile process" "$(printf '%s\n' "$csv" | column process.name)" ft_workload
expect "sendfile pid" "$(printf '%s\n' "$csv" | column process.pid)" "$(field "$report" pid)"
expect "sendfile remote port" "$(printf '%s\n' "$csv" | column network.remote_port)" \
    "$(field "$report" port)"
expect "sendfile remote address" "$(printf '%s\n' "$csv" | column network.remote_ip)" 127.0.0.1
expect "sendfile inode" "$(printf '%s\n' "$csv" | column file.inode)" \
    "$(stat -c %i "$data/report.csv")"
expect "sendfile device" "$(printf '%s\n' "$csv" | column file.device)" \
    "$(stat -c %d "$data/report.csv")"
expect "sendfile file size" "$(printf '%s\n' "$csv" | column file.size)" 5000000
expect "sendfile file owner" "$(printf '%s\n' "$csv" | column file.owner)" \
    "$(stat -c %U "$data/report.csv")"
expect_match "sendfile evidence" "$(printf '%s\n' "$csv" | column transfer.evidence)" \
    'direct_file_to_socket_transfer;.*socket_identity;remote_endpoint'
expect "sendfile incomplete" "$(printf '%s\n' "$csv" | column transfer.incomplete)" false
first_port=$(field "$report" port)
first_pid=$(field "$report" pid)

# Both ends of its connection, and its listener, are closed. Checked before any
# other scenario runs, because a later one can be given the same port.
csv=$(ft connections --port "$first_port" --state closed --format csv)
expect "closed connections" "$(printf '%s\n' "$csv" | rows)" 3
expect "no open connections" "$(ft connections --port "$first_port" --active --format csv | rows)" 0

# The same over IPv6.
report=$("$workload" sendfile "$data/v6.bin" 1000000 ipv6)
settle
csv=$(ft files --path "$data/v6.bin" --format csv)
expect "ipv6 bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 1000000
expect "ipv6 remote address" "$(printf '%s\n' "$csv" | column network.remote_ip)" ::1
expect "ipv6 confidence" "$(printf '%s\n' "$csv" | column transfer.confidence)" exact

# A read+send loop: inferred, never exact.
report=$("$workload" readsend "$data/upload.bin" 3000000 65536)
settle
csv=$(ft files --path "$data/upload.bin" --format csv)
expect "read+send rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "read+send confidence" "$(printf '%s\n' "$csv" | column transfer.confidence)" inferred
expect "read+send method" "$(printf '%s\n' "$csv" | column transfer.method)" read-write
expect "read+send bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 3000000
expect "read+send bytes read" "$(printf '%s\n' "$csv" | column transfer.bytes_read)" 3000000
expect_match "read+send evidence" "$(printf '%s\n' "$csv" | column transfer.evidence)" \
    'thread_read_then_send;repeated_read_then_send;byte_balance'
expect "read+send is not exact" \
    "$(ft files --path "$data/upload.bin" --confidence exact --format csv | rows)" 0

# A read followed by a receive and an unrelated send is not a transfer of the file.
"$workload" readthenrecv "$data/config.bin" 200000 >/dev/null
settle
expect "read, receive, then send" "$(ft files --path "$data/config.bin" --format csv | rows)" 0

# An upload over a fresh connection, as an HTTPS client makes it: the file is read whole,
# then a CA bundle, then the peers trade a hello each way before the file is sent. The
# receive ends what the bundle read could claim, so the upload is not pinned on it.
"$workload" readhandshake "$data/upload-tls.bin" 300000 "$data/ca-bundle.crt" 200000 >/dev/null
settle
expect "read before a handshake: CA bundle not reported" \
    "$(ft files --path "$data/ca-bundle.crt" --format csv | rows)" 0

# The same, with the hello received on a second connection: a receive on any socket ends
# what the read could claim.
"$workload" readrecvelsewhere "$data/upload-other.bin" 300000 "$data/ca-other.crt" 200000 \
    >/dev/null
settle
expect "receive on another connection: CA bundle not reported" \
    "$(ft files --path "$data/ca-other.crt" --format csv | rows)" 0

# Neither is sending a sliver of what was read.
"$workload" readlittle "$data/bundle.bin" 400000 >/dev/null
settle
expect "read much, send little" "$(ft files --path "$data/bundle.bin" --format csv | rows)" 0

# Descriptor numbers repeat across files; attribution must not.
"$workload" fdreuse "$data" 25 100000 >/dev/null
settle
csv=$(ft files --path "$data/reuse-*" --format csv)
expect "fd reuse rows" "$(printf '%s\n' "$csv" | rows)" 25
i=0
while [ $i -lt 25 ]; do
    one=$(ft files --path "$data/reuse-$i.bin" --format csv)
    expect "fd reuse file $i bytes" "$(printf '%s\n' "$one" | column transfer.bytes_sent)" \
        $((100000 + i * 4096))
    expect "fd reuse file $i confidence" \
        "$(printf '%s\n' "$one" | column transfer.confidence)" exact
    i=$((i + 1))
done

# A file renamed halfway through stays one file with all of its bytes.
"$workload" rename "$data/before.bin" "$data/after.bin" 2000000 >/dev/null
settle
csv=$(ft files --path "$data/before.bin" --format csv)
expect "rename rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "rename bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 2000000
expect "rename inode" "$(printf '%s\n' "$csv" | column file.inode)" \
    "$(stat -c %i "$data/after.bin")"

# A file sent after its last link is removed is reported as deleted.
"$workload" unlink "$data/gone.bin" 300000 >/dev/null
settle
csv=$(ft files --deleted --format csv)
expect "deleted rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "deleted path" "$(printf '%s\n' "$csv" | column file.path)" "$data/gone.bin"
expect "deleted flag" "$(printf '%s\n' "$csv" | column file.deleted)" true
expect "deleted bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 300000

# Datagrams to an unconnected socket's peer.
report=$("$workload" udp 50000)
settle
port=$(field "$report" port)
csv=$(ft flows --protocol udp --port "$port" --pid "$(field "$report" pid)" --format csv)
expect "udp flow rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "udp sent bytes" "$(printf '%s\n' "$csv" | column bytes_sent)" 50000
expect "udp remote port" "$(printf '%s\n' "$csv" | column remote_port)" "$port"
expect "udp send operations" "$(printf '%s\n' "$csv" | column send_operations)" 50
csv=$(ft transfers --confidence unknown --protocol udp --port "$port" --format csv)
expect "udp bytes have no file" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 50000
expect "udp transfer id" "$(ft transfers --confidence unknown --port "$port" --format quiet |
    grep -c '^tr_s')" 1

# Both directions of a half-closed exchange, byte for byte: a peek, a wait
# for the whole reply and the end of the stream add nothing.
report=$("$workload" duplex 300000 70000)
settle
expect "duplex server saw the request" "$(field "$report" status)" 0
port=$(field "$report" port)
csv=$(ft flows --port "$port" --pid "$(field "$report" pid)" --format csv)
expect "duplex client sent" "$(printf '%s\n' "$csv" | column bytes_sent)" 300000
expect "duplex client received" "$(printf '%s\n' "$csv" | column bytes_received)" 70000
csv=$(ft flows --port "$port" --pid "$(field "$report" server)" --format csv)
expect "duplex server received" "$(printf '%s\n' "$csv" | column bytes_received)" 300000
expect "duplex server sent" "$(printf '%s\n' "$csv" | column bytes_sent)" 70000

# Sends that the socket accepts only in part still add up to the file.
report=$("$workload" partialsend "$data/partial.bin" 3000000)
settle
expect_match "partial sends happened" "$(field "$report" calls)" '^[0-9]{3,}$'
csv=$(ft files --path "$data/partial.bin" --format csv)
expect "partial send rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "partial send bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 3000000
expect "partial send confidence" "$(printf '%s\n' "$csv" | column transfer.confidence)" inferred
csv=$(ft flows --port "$(field "$report" port)" --pid "$(field "$report" pid)" --format csv)
expect "partial send socket bytes" "$(printf '%s\n' "$csv" | column bytes_sent)" 3000000

report=$("$workload" partialsendfile "$data/partialsf.bin" 3000000)
settle
expect_match "partial sendfiles happened" "$(field "$report" calls)" '^[0-9]{2,}$'
csv=$(ft files --path "$data/partialsf.bin" --format csv)
expect "partial sendfile rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "partial sendfile bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 3000000
expect "partial sendfile confidence" "$(printf '%s\n' "$csv" | column transfer.confidence)" exact

# Processes, including the totals of their children.
report=$("$workload" child "$data/child.bin" 700000)
settle
parent=$(field "$report" parent)
child=$(field "$report" child)
csv=$(ft processes --pid "$child" --format csv)
expect "child outbound" "$(printf '%s\n' "$csv" | column bytes_sent)" 700000
netns=$(stat -Lc %i /proc/self/ns/net)
expect "child network namespace" "$(printf '%s\n' "$csv" | column network_namespace)" "$netns"
expect "namespace filter" "$(ft processes --pid "$child" --namespace "$netns" --format csv | rows)" 1
expect "child parent" "$(printf '%s\n' "$csv" | column ppid)" "$parent"
expect "child name" "$(printf '%s\n' "$csv" | column name)" ft_workload
expect "child status" "$(printf '%s\n' "$csv" | column status)" exited
expect "parent alone sent nothing" "$(ft processes --pid "$parent" --format csv | rows)" 0
csv=$(ft processes --pid "$parent" --include-children --format csv)
expect_match "parent with children" "$(printf '%s\n' "$csv" | column bytes_sent)" '^700000$'

expect_match "table header" "$(ft files --limit 1 | head -1)" \
    '^FILE +PROCESS +DESTINATION +BYTES +METHOD +CONFIDENCE$'
expect_match "json array" "$(ft files --limit 1 --format json | tr -d '\n')" \
    '^\[ *\{"event":"file_transfer","transfer_id":"tr_[0-9a-f]+".*"confidence":"(exact|inferred)".*\}\]$'
expect "jsonl lines" "$(ft files --path "$data/reuse-*" --format jsonl | wc -l | tr -d ' ')" 25
expect "quiet prints paths" "$(ft files --path "$data/report.csv" --format quiet)" \
    "$data/report.csv"
expect_match "top files" "$(ft top files --limit 1 | sed -n 3,4p | tr '\n' ' ')" \
    '^RANK +FILE +SENT +TRANSFERS +CONFIDENCE +1 +.*report\.csv +4\.77 MB +1 +EXACT'
expect_match "grouped flows" "$(ft flows --group-by protocol --format csv | head -1)" \
    '^protocol,bytes_sent,bytes_received,flows$'

# The event log holds the records that the totals above add up.
jsonl=$(ft events --type file_transfer --file "$data/report.csv" --jsonl)
expect_match "events: transfer record" "$jsonl" \
    '^\{"event":"file_transfer","timestamp":"[^"]+","sequence":[0-9]+,"process":\{"pid":[0-9]+,.*"name":"ft_workload"[^}]*\},"file":\{"path":"[^"]*/report\.csv",.*"size":5000000,.*"network":\{"protocol":"tcp",.*"remote_ip":"127\.0\.0\.1",.*"transfer":\{"method":"sendfile","bytes_sent":[0-9]+,"confidence":"exact"\}\}$'
expect "events: transfer bytes add up" "$(printf '%s\n' "$jsonl" |
    sed 's/.*"method":"sendfile","bytes_sent":\([0-9]*\).*/\1/' | awk '{ s += $1 } END { print s }')" \
    5000000
expect_match "events: text form" "$(ft events --type file_seen --file "$data/report.csv")" \
    'FILE_SEEN'
expect_match "events: text fields" \
    "$(ft events --type file_seen --file "$data/report.csv" | tr '\n' ' ')" \
    "file=$data/report.csv +inode=[0-9]+ +device=[0-9]+ +size=5000000"
expect "events: limit" "$(ft events --type network_send --limit 3 --jsonl | wc -l | tr -d ' ')" 3
expect_match "events: raw" "$(ft events --type socket_close --limit 1 --raw)" \
    '^seq=[0-9]+ time_ns=[0-9]+ type=socket_close pid=[0-9]+ .* text=$'
expect "events: unknown type exit code" "$(ft events --type file_open >/dev/null 2>&1; echo $?)" 2
expect_match "events: unknown type names the known ones" \
    "$(ft events --type file_open 2>&1)" 'file_transfer'

# inspect answers from the file, the process, the address, the socket and the flow.
out=$(ft inspect file "$data/report.csv" | tr '\n' ' ')
expect_match "inspect file: identity" "$out" \
    "Path: +$data/report.csv .*Inode: +$(stat -c %i "$data/report.csv") .*Size: +4\.77 MB"
expect_match "inspect file: history" "$out" \
    "TIME +PROCESS +PID +REMOTE +BYTES +METHOD +CONFIDENCE .* ft_workload +$first_pid +127\.0\.0\.1:$first_port"
expect_match "inspect file: totals" "$out" \
    'Total sent: +4\.77 MB +Destinations: +1 +Processes: +1 +Transfers: +1'
expect_match "inspect file: provenance" "$out" 'sendfile: +1 transfer +Exact: +1'
expect_match "inspect file: says where history starts" "$out" 'History starts at 20'
expect_match "inspect file: json" "$(ft inspect file "$data/report.csv" --json | tr -d '\n')" \
    '^\{"kind":"file","path":"[^"]+","totals":\{"bytes_sent":5000000,"transfers":1,"active_transfers":[01],"destinations":1,"processes":1\},"provenance":\{"methods":\{"sendfile":1,"read-write":0\},.*"transfers":\[ *\{"event":"file_transfer".*\],"observed_since":"[^"]+","events_lost":0\}$'
expect "inspect file: a pattern for several files" \
    "$(ft inspect file "$data/reuse-*" >/dev/null 2>&1; echo $?)" 2
expect_match "inspect file: nothing known" "$(ft inspect file "$data/absent.bin")" \
    '^No transfers of .* have been observed since'
out=$(ft inspect process "$first_pid" | tr '\n' ' ')
expect_match "inspect process" "$out" \
    "Name: +ft_workload +PID: +$first_pid .*Unique files: +1 .*TOP DESTINATIONS .*127\.0\.0\.1 .*FILES SENT .*report\.csv"
out=$(ft inspect ip 127.0.0.0/8 --limit 500 | tr '\n' ' ')
expect_match "inspect ip" "$out" 'NETWORK .*Remote: +127\.0\.0\.0/8 .*PROCESSES .*FILES SENT TO IT .*report\.csv'
expect_match "inspect ip: other networks" "$(ft inspect ip 203.0.113.0/24)" '^No traffic with'
flow=$(ft flows --pid "$first_pid" --port "$first_port" --format quiet)
out=$(ft inspect flow "$flow" | tr '\n' ' ')
expect_match "inspect flow" "$out" \
    "FLOW .*ID: +$flow .*Protocol: +TCP .*Remote: +127\.0\.0\.1:$first_port .*Sent: +4\.77 MB .*report\.csv"
socket_id=$(ft flows --pid "$first_pid" --port "$first_port" --format csv | column socket_id)
out=$(ft inspect socket "$socket_id" | tr '\n' ' ')
expect_match "inspect socket" "$out" \
    "SOCKET .*ID: +$socket_id .*State: +closed .*Process: +ft_workload \\(PID $first_pid\\) .*FLOWS .*report\.csv"
expect "inspect: unknown kind exit code" "$(ft inspect inode 5 >/dev/null 2>&1; echo $?)" 2
expect "inspect: missing subject exit code" "$(ft inspect file >/dev/null 2>&1; echo $?)" 2

# A transfer in progress has a rate, and watch shows it.
"$workload" steady "$data/steady.bin" 40000000 4 >"$work/steady.txt" &
steady_job=$!
sleep 2.2
steady_pid=$(field "$(cat "$work/steady.txt")" pid)
csv=$(ft files --path "$data/steady.bin" --active --format csv)
expect_match "steady transfer: rate near 10 MB/s" \
    "$(printf '%s\n' "$csv" | column transfer.bytes_per_second |
        awk '{ print ($1 > 6000000 && $1 < 14000000) ? "near" : "off: " $1 }')" '^near$'
expect_match "steady transfer: process rate" \
    "$(ft processes --pid "$steady_pid" --format csv | column bytes_sent_per_second |
        awk '{ print ($1 > 6000000 && $1 < 14000000) ? "near" : "off: " $1 }')" '^near$'
expect "steady transfer: sorted first by rate" \
    "$(ft files --sort rate --limit 1 --format quiet)" "$data/steady.bin"
out=$(timeout -s INT 1.2 "$bin/filetrace" --socket "$sock" watch --no-ui --interval 500ms)
expect_match "watch: header" "$out" '^FILETRACE  .* Linux [0-9]+\.[0-9]+  LIVE$'
expect_match "watch: counters" "$(printf '%s\n' "$out" | tr '\n' '|')" \
    '\|[0-9]+ +[0-9]+ +[0-9.]+ [KM]B/s\|Transfers +Processes +Outbound\|'
expect_match "watch: transfer row" "$out" \
    "^ft_workload $steady_pid +.*steady\.bin +127\.0\.0\.1 +sendfile +[0-9.]+ MB/s +EXACT$"
expect_match "watch: confidence line" "$out" 'EXACT: [1-9][0-9]* +[^ ]+ INFERRED: [0-9]+ +LOST: 0$'
out=$(timeout -s INT 1.2 "$bin/filetrace" --socket "$sock" watch --no-ui --interval 500ms \
    --remote 203.0.113.0/24)
expect_match "watch: a filter that matches nothing" "$out" 'No file transfers in progress'
wait "$steady_job"

# Host names replace addresses only where a reverse lookup finds one.
expect_match "resolve: destination by name" \
    "$(ft files --path "$data/report.csv" --resolve-hostnames | sed -n 2p)" \
    'report\.csv +ft_workload +localhost +4\.77 MB'
expect_match "resolve: json keeps the address" \
    "$(ft files --path "$data/report.csv" --resolve-hostnames --jsonl)" \
    '"remote_ip":"127\.0\.0\.1","remote_port":[0-9]+,"remote_host":"localhost"'
expect_match "resolve: off by default" "$(ft files --path "$data/report.csv" | sed -n 2p)" \
    'ft_workload +127\.0\.0\.1 +4\.77 MB'

# Following delivers what happens next and ends cleanly on a signal.
"$bin/filetrace" --socket "$sock" events --follow --type file_transfer,network_send --jsonl \
    >"$work/follow.jsonl" &
follow_pid=$!
sleep 0.5
"$workload" sendfile "$data/follow.bin" 700000 >/dev/null
settle
kill -TERM "$follow_pid"
wait "$follow_pid"
expect "events: follow exit code" "$?" 0
expect_match "events: follow saw the transfer" "$(cat "$work/follow.jsonl")" \
    '"event":"file_transfer".*follow\.bin'
expect "events: follow starts at the present" \
    "$(grep -c 'report\.csv' "$work/follow.jsonl")" 0

stats=$(ft stats --format json)
expect_match "stats status" "$stats" '"status":"healthy"'
expect_match "stats event log" "$stats" '"event_log_bytes":1048576,"event_log_events":[1-9]'
expect_match "stats backend" "$stats" \
    '"backend":"Linux eBPF \((trampolines|kprobes)\)","mode":"standard"'
if [ "$probes" != auto ]; then
    expect_match "stats probes" "$stats" "\"backend\":\"Linux eBPF \\($probes"
fi
expect_match "stats no loss" "$stats" '"dropped":0,'
expect_match "capabilities" "$(ft capabilities | grep '^Sendfile attribution')" 'FULL'

# Usage errors and an absent agent are distinguishable by exit code.
expect "invalid option exit code" "$(ft files --no-such-option >/dev/null 2>&1; echo $?)" 2
expect "invalid value exit code" "$(ft files --min-bytes lots >/dev/null 2>&1; echo $?)" 2
expect "no agent exit code" \
    "$("$bin/filetrace" --socket "$work/absent.sock" files >/dev/null 2>&1; echo $?)" 4

# An interpreter's transfers name the script it runs, found from its arguments and the
# directory it was started in. The scripts stay a second after sending: the agent reads
# /proc once it handles their traffic, and a process that is gone by then leaves nothing.
mkdir -p "$work/scripts"
cat >"$work/scripts/send.pl" <<'PERL'
use strict;
use warnings;
use IO::Socket::INET;

# usage: [TITLE=<title>] perl send.pl <file> [arguments]
# Sends the file to a sink of its own; with TITLE, from a forked worker that renames itself.
$| = 1;
my $path = $ARGV[0];
my $server = IO::Socket::INET->new(Listen => 1, LocalAddr => '127.0.0.1', LocalPort => 0)
    or die "listen: $!";
my $sink = fork() // die "fork: $!";
if ($sink == 0) {
    my $peer = $server->accept or exit 1;
    1 while sysread($peer, my $buf, 65536);
    exit 0;
}
my $worker = 0;
if (defined $ENV{TITLE}) {
    $worker = fork() // die "fork: $!";
    $0 = $ENV{TITLE} if $worker == 0;
}
if ($worker == 0) {
    my $client = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => $server->sockport)
        or die "connect: $!";
    open(my $in, '<', $path) or die "$path: $!";
    while (sysread($in, my $buf, 65536)) {
        syswrite($client, $buf) or die "send: $!";
    }
    close $client;
    print "pid=$$\n";
    sleep 1;
    exit 0 if defined $ENV{TITLE};
}
waitpid($worker, 0) if $worker;
waitpid($sink, 0);
PERL
if command -v perl >/dev/null 2>&1; then
    head -c 300000 /dev/urandom >"$data/perl-upload.bin"
    report=$(cd "$work/scripts" && perl -I lib -w send.pl "$data/perl-upload.bin" --token=s3cr3t)
    settle
    perl_pid=$(field "$report" pid)
    jsonl=$(ft files --path "$data/perl-upload.bin" --jsonl)
    expect_match "interpreter: command line" "$jsonl" \
        "\"command_line\":\"perl -I lib -w send\\.pl $data/perl-upload\\.bin --token=s3cr3t\""
    expect_match "interpreter: working directory" "$jsonl" "\"working_directory\":\"$work/scripts\""
    expect_match "interpreter: script" "$jsonl" "\"script\":\"$work/scripts/send\\.pl\""
    expect "interpreter: files by script" \
        "$(ft files --script "$work/scripts/*" --format quiet | grep -c 'perl-upload\.bin')" 1
    expect "interpreter: other programs left out" \
        "$(ft files --script "$work/scripts/*" --format quiet | grep -c 'report\.csv')" 0
    expect "interpreter: transfers by script" \
        "$(ft transfers --script '*/send.pl' --path "$data/perl-upload.bin" --format csv | rows)" 1
    expect "interpreter: another script" \
        "$(ft files --script 'pool:*' --path "$data/perl-upload.bin" --format csv | rows)" 0
    expect "interpreter: process script" \
        "$(ft processes --pid "$perl_pid" --format csv | column script)" "$work/scripts/send.pl"
    expect_match "interpreter: inspect process" "$(ft inspect process "$perl_pid" | tr '\n' ' ')" \
        "Command line: +perl -I lib -w send\\.pl .*Directory: +$work/scripts .*Script: +$work/scripts/send\\.pl"
    expect_match "interpreter: events" \
        "$(ft events --type file_transfer --script "$work/scripts/send.pl" --jsonl)" \
        "\"script\":\"$work/scripts/send\\.pl\"\\},\"file\":\\{\"path\":\"$data/perl-upload\\.bin\""
    expect_match "interpreter: script column" "$(ft files --path "$data/perl-upload.bin" | head -1)" \
        'CONFIDENCE +SCRIPT$'

    # A PHP-FPM worker names its pool in its title after it is forked.
    head -c 300000 /dev/urandom >"$data/pool-upload.bin"
    (cd "$work/scripts" && TITLE='php-fpm: pool site1' perl send.pl "$data/pool-upload.bin") >/dev/null
    settle
    csv=$(ft files --path "$data/pool-upload.bin" --format csv)
    expect "pool: script" "$(printf '%s\n' "$csv" | column process.script)" pool:site1
    expect "pool: command line" "$(printf '%s\n' "$csv" | column process.command_line)" \
        "php-fpm: pool site1"
    expect "pool: files by pool" \
        "$(ft files --script 'pool:site*' --format quiet | grep -c 'pool-upload\.bin')" 1

else
    echo "SKIP: perl is not installed; its interpreter checks did not run"
fi

if command -v python3 >/dev/null 2>&1; then
    cat >"$work/scripts/send.py" <<'PYTHON'
import os
import socket
import sys
import time

server = socket.create_server(("127.0.0.1", 0))
if os.fork() == 0:
    peer, _ = server.accept()
    while peer.recv(65536):
        pass
    os._exit(0)
client = socket.create_connection(server.getsockname())
with open(sys.argv[1], "rb", buffering=0) as f:
    while chunk := f.read(65536):
        client.sendall(chunk)
client.close()
time.sleep(1)
os.wait()
PYTHON
    head -c 300000 /dev/urandom >"$data/python-upload.bin"
    (cd "$work/scripts" && python3 -W ignore send.py "$data/python-upload.bin")
    settle
    csv=$(ft files --path "$data/python-upload.bin" --format csv)
    expect "python: script" "$(printf '%s\n' "$csv" | column process.script)" \
        "$work/scripts/send.py"
    expect_match "python: command line" "$(printf '%s\n' "$csv" | column process.command_line)" \
        '^python3(\.[0-9]+)? -W ignore send\.py '
else
    echo "SKIP: python3 is not installed; its interpreter checks did not run"
fi

# A PHP-FPM worker's transfers name the script of each request, not only the pool.
if [ -n "$fpm" ] && command -v cgi-fcgi >/dev/null 2>&1; then
    head -c 300000 /dev/urandom >"$data/php-upload.bin"
    head -c 200000 /dev/urandom >"$data/php-other.bin"
    php_fpm_start || { echo "FAIL: php-fpm did not start"; exit 1; }
    php_request upload.php "$data/php-upload.bin"
    php_request other.php "$data/php-other.bin"
    settle
    csv=$(ft files --path "$data/php-upload.bin" --format csv)
    expect "php: request script" "$(printf '%s\n' "$csv" | column process.script)" \
        "$work/php/upload.php"
    expect "php: request bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 300000
    expect "php: the worker's command line" \
        "$(printf '%s\n' "$csv" | column process.command_line)" "php-fpm: pool ft"
    expect "php: another request's script" \
        "$(ft files --path "$data/php-other.bin" --format csv | column process.script)" \
        "$work/php/other.php"
    expect "php: files by request script" \
        "$(ft files --script '*/other.php' --format quiet | grep -c 'php-other\.bin')" 1
    php_fpm_stop
else
    echo "SKIP: php-fpm or cgi-fcgi is not installed; the PHP request checks did not run"
fi

# A sender that exits right after sending is gone before /proc can be read; its command line
# and directory come with its exec.
(cd "$data" && "$workload" readsend "$data/short.bin" 300000 65536) >/dev/null
settle
csv=$(ft files --path "$data/short.bin" --format csv)
expect "short-lived: command line" "$(printf '%s\n' "$csv" | column process.command_line)" \
    "$workload readsend $data/short.bin 300000 65536"
expect "short-lived: working directory" \
    "$(printf '%s\n' "$csv" | column process.working_directory)" "$data"
if command -v python3 >/dev/null 2>&1; then
    cat >"$work/scripts/quick.py" <<'PYTHON'
import socket
import sys

server = socket.create_server(("127.0.0.1", 0))
client = socket.create_connection(server.getsockname())
peer, _ = server.accept()
with open(sys.argv[1], "rb", buffering=0) as f:
    while chunk := f.read(65536):
        client.sendall(chunk)
PYTHON
    head -c 300000 /dev/urandom >"$data/quick-upload.bin"
    (cd "$work/scripts" && python3 quick.py "$data/quick-upload.bin")
    settle
    expect "short-lived: script" \
        "$(ft files --path "$data/quick-upload.bin" --format csv | column process.script)" \
        "$work/scripts/quick.py"
fi

stop_agent
expect "agent exit code" "$?" 0
expect "socket removed" "$([ -e "$sock" ] && echo present || echo removed)" removed

start_agent --mode minimal || { echo "FAIL: the agent did not start in minimal mode"; exit 1; }

report=$("$workload" sendfile "$data/minimal.bin" 900000)
settle
expect "minimal: no file attribution" "$(ft files --format csv | rows)" 0
csv=$(ft flows --port "$(field "$report" port)" --pid "$(field "$report" pid)" --format csv)
expect "minimal: bytes still counted" "$(printf '%s\n' "$csv" | column bytes_sent)" 900000
expect_match "minimal: capability disabled" \
    "$(ft capabilities | grep '^Sendfile attribution')" 'DISABLED'
csv=$(ft transfers --port "$(field "$report" port)" --pid "$(field "$report" pid)" --format csv)
expect "minimal: bytes have no file" \
    "$(printf '%s\n' "$csv" | column transfer.confidence)" unknown

stop_agent
expect "minimal agent exit code" "$?" 0

# A hangup stops the agent as SIGTERM does: exit code 0 and the socket removed.
start_agent --mode minimal || { echo "FAIL: the agent did not start for the hangup"; exit 1; }
kill -HUP "$agent_pid"
wait "$agent_pid"
expect "agent exit code after SIGHUP" "$?" 0
agent_pid=
expect "socket removed after SIGHUP" "$([ -e "$sock" ] && echo present || echo removed)" removed

# A file named in no_minimum_paths is reported however small; another is not.
printf '[correlation]\nno_minimum_paths = ["%s/tiny-listed*"]\n' "$data" >"$work/no-minimum.toml"
start_agent --config "$work/no-minimum.toml" ||
    { echo "FAIL: the agent did not start with no_minimum_paths"; exit 1; }
"$workload" readsend "$data/tiny-listed.txt" 200 65536 >/dev/null
"$workload" readsend "$data/tiny-other.txt" 200 65536 >/dev/null
settle
csv=$(ft files --path "$data/tiny-listed.txt" --format csv)
expect "no minimum: listed file reported" "$(printf '%s\n' "$csv" | rows)" 1
expect "no minimum: listed file inferred" "$(printf '%s\n' "$csv" | column transfer.confidence)" \
    inferred
expect "no minimum: other file not reported" \
    "$(ft files --path "$data/tiny-other.txt" --format csv | rows)" 0
stop_agent
expect "no minimum agent exit code" "$?" 0

# Files in background_paths do not displace what a thread read before them, and count as sent
# only when all that was read of them went.
cat >"$work/background.toml" <<CONFIG
[correlation]
background_paths = ["$data/bg-*", "$data/ns-view/*", "/etc/passwd"]
no_minimum_paths = ["/etc/passwd"]
CONFIG
# The agent resolves the patterns to inodes when it starts, so the files exist by then.
: >"$data/bg-ca.crt"
: >"$data/bg-gai.conf"
: >"$data/bg-whole.bin"
mkdir -p "$data/ns-source" "$data/ns-view"
start_agent --config "$work/background.toml" ||
    { echo "FAIL: the agent did not start with background_paths"; exit 1; }
"$workload" readbundle "$data/up-bundle.bin" 300000 "$data/bg-ca.crt" 200000 >/dev/null
"$workload" readlittle "$data/bg-gai.conf" 4000 >/dev/null
"$workload" readsend "$data/bg-whole.bin" 4096 65536 >/dev/null
"$workload" upload /etc/passwd 65536 >/dev/null
settle
csv=$(ft files --path "$data/up-bundle.bin" --format csv)
expect "background: file read before the bundle reported" "$(printf '%s\n' "$csv" | rows)" 1
expect "background: file read before the bundle bytes" \
    "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 300000
expect "background: bundle not reported" "$(ft files --path "$data/bg-ca.crt" --format csv | rows)" 0
expect "background: part of a read not reported" \
    "$(ft files --path "$data/bg-gai.conf" --format csv | rows)" 0
csv=$(ft files --path "$data/bg-whole.bin" --format csv)
expect "background: whole read reported" "$(printf '%s\n' "$csv" | rows)" 1
expect "background: whole read bytes" "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" 4096
csv=$(ft files --path /etc/passwd --format csv)
expect "background: /etc/passwd upload reported" "$(printf '%s\n' "$csv" | rows)" 1
expect "background: /etc/passwd upload bytes" \
    "$(printf '%s\n' "$csv" | column transfer.bytes_sent)" "$(stat -L -c %s /etc/passwd)"

# A listed file made after the agent started is background once a read reports its path.
head -c 200000 /dev/zero >"$data/bg-late.crt"
"$workload" read "$data/bg-late.crt" >/dev/null
settle
"$workload" readbundle "$data/up-late.bin" 300000 "$data/bg-late.crt" 200000 >/dev/null
settle
expect "background: file read before a late bundle bytes" \
    "$(ft files --path "$data/up-late.bin" --format csv | column transfer.bytes_sent)" 300000
expect "background: late bundle not reported" \
    "$(ft files --path "$data/bg-late.crt" --format csv | rows)" 0

# So is one whose path matches only inside another mount namespace, as in a container.
head -c 200000 /dev/zero >"$data/ns-source/bundle.crt"
"$workload" nsread "$data/ns-source" "$data/ns-view" bundle.crt >/dev/null
settle
"$workload" readbundle "$data/up-ns.bin" 300000 "$data/ns-source/bundle.crt" 200000 >/dev/null
settle
expect "background: file read before a namespaced bundle bytes" \
    "$(ft files --path "$data/up-ns.bin" --format csv | column transfer.bytes_sent)" 300000
expect "background: namespaced bundle not reported" \
    "$(ft files --path "$data/ns-*" --format csv | rows)" 0
stop_agent
expect "background agent exit code" "$?" 0

# Without the PHP probes a worker's transfers name its pool.
if [ -n "$fpm" ] && command -v cgi-fcgi >/dev/null 2>&1; then
    printf '[process]\nphp_scripts = false\n' >"$work/no-php.toml"
    start_agent --config "$work/no-php.toml" ||
        { echo "FAIL: the agent did not start without PHP probes"; exit 1; }
    head -c 300000 /dev/urandom >"$data/php-unprobed.bin"
    php_fpm_start || { echo "FAIL: php-fpm did not start"; exit 1; }
    php_request upload.php "$data/php-unprobed.bin"
    settle
    expect "php off: the pool" \
        "$(ft files --path "$data/php-unprobed.bin" --format csv | column process.script)" pool:ft
    php_fpm_stop
    stop_agent
    expect "php off agent exit code" "$?" 0
fi

# Without arguments a command line keeps only the program; the script is still named.
if command -v perl >/dev/null 2>&1; then
    printf '[process]\narguments = false\n' >"$work/no-arguments.toml"
    start_agent --config "$work/no-arguments.toml" ||
        { echo "FAIL: the agent did not start without arguments"; exit 1; }
    (cd "$work/scripts" && perl send.pl "$data/perl-upload.bin" --token=s3cr3t) >/dev/null
    settle
    csv=$(ft files --path "$data/perl-upload.bin" --format csv)
    expect "no arguments: command line" "$(printf '%s\n' "$csv" | column process.command_line)" perl
    expect "no arguments: script" "$(printf '%s\n' "$csv" | column process.script)" \
        "$work/scripts/send.pl"
    expect "no arguments: the token stays out" \
        "$({ ft files --jsonl; ft processes --jsonl; ft events --jsonl; } | grep -c s3cr3t)" 0
    stop_agent
    expect "no arguments agent exit code" "$?" 0
else
    echo "SKIP: perl is not installed; the arguments checks did not run"
fi

# A configuration file decides what is collected and how the commands print.
cat >"$work/config.toml" <<CONFIG
[agent]
socket = "$sock"
flush_interval = "100ms"
log_level = "warn"
event_log_size = "256KB"

[network]
udp = false

[correlation]
confidence_threshold = "exact"

[storage]
enabled = true

[filters]
exclude_paths = ["$data/secret-*"]

[output]
format = "csv"
CONFIG
configured() {
    "$bin/filetrace" --config "$work/config.toml" "$@"
}
wait_for_socket() {
    i=0
    while [ ! -S "$sock" ] && [ $i -lt 100 ]; do
        sleep 0.1
        i=$((i + 1))
    done
}
out=$("$bin/filetrace" config validate "$work/config.toml" 2>&1)
expect "config: validate exit code" "$?" 0
expect_match "config: asks for what cannot be done" "$out" \
    'warning: \[storage\] enabled = true is ignored'
expect_match "config: show" "$(configured config show 2>/dev/null)" \
    '^event_log_size = "256KB"$'
printf '[agent]\nenabld = true\n' >"$work/broken.toml"
expect "config: broken file exit code" \
    "$("$bin/filetrace" config validate "$work/broken.toml" >/dev/null 2>&1; echo $?)" 6
expect_match "config: broken file message" \
    "$("$bin/filetrace" config validate "$work/broken.toml" 2>&1)" \
    "broken.toml:2: unknown setting 'enabld' in \\[agent\\]"
expect "config: commands refuse a broken file" \
    "$("$bin/filetrace" --config "$work/broken.toml" files >/dev/null 2>&1; echo $?)" 6
expect "config: the agent refuses a broken file" \
    "$("$bin/filetrace-agent" --config "$work/broken.toml" >/dev/null 2>&1; echo $?)" 6

"$bin/filetrace-agent" --config "$work/config.toml" --probes "$probes" 2>"$work/agent.err" &
agent_pid=$!
wait_for_socket
"$workload" sendfile "$data/secret-key.bin" 400000 >/dev/null
"$workload" sendfile "$data/public.bin" 400000 >/dev/null
"$workload" readsend "$data/inferred.bin" 3000000 65536 >/dev/null
report=$("$workload" udp 50000)
settle
expect_match "config: the agent warns" "$(cat "$work/agent.err")" \
    'storage\] enabled = true is ignored'
expect_match "config: default format" "$(configured files | head -1)" '^event,transfer_id,'
expect "config: excluded path" "$(configured files --path "$data/secret-key.bin" | rows)" 0
expect "config: other paths" "$(configured files --path "$data/public.bin" | rows)" 1
expect "config: confidence threshold" "$(configured files --path "$data/inferred.bin" | rows)" 0
expect "config: ignored protocol" \
    "$(configured flows --protocol udp --port "$(field "$report" port)" | rows)" 0
expect_match "config: event log size" "$(configured stats --json)" '"event_log_bytes":262144,'
configured agent stop >/dev/null
wait "$agent_pid"
expect "config: agent exit code" "$?" 0
agent_pid=

printf '[agent]\nsocket = "%s"\n[file]\ntrack_read = false\n' "$sock" >"$work/noread.toml"
"$bin/filetrace-agent" --config "$work/noread.toml" --probes "$probes" --log-level warn &
agent_pid=$!
wait_for_socket
expect_match "config: read probe off" "$(ft capabilities | grep '^Read+send correlation')" \
    'DISABLED +turned off in the configuration'
expect_match "config: sendfile probe on" "$(ft capabilities | grep '^Sendfile attribution')" \
    'FULL'
"$workload" readsend "$data/unread.bin" 3000000 65536 >/dev/null
"$workload" sendfile "$data/stillsent.bin" 300000 >/dev/null
settle
expect "config: no read-write attribution" \
    "$(ft files --path "$data/unread.bin" --format csv | rows)" 0
expect "config: sendfile still attributed" \
    "$(ft files --path "$data/stillsent.bin" --format csv | rows)" 1
stop_agent
expect "config: second agent exit code" "$?" 0

# Without an agent, watch collects for as long as it runs.
out=$(timeout -s INT 3 "$bin/filetrace" --socket "$work/absent.sock" watch --no-ui \
    --interval 500ms 2>"$work/watch.err")
expect_match "watch output" "$out" 'ACTIVE FILE TRANSFERS'
expect_match "watch output" "$out" '^PROCESSES$'
expect_match "watch notice" "$(cat "$work/watch.err")" 'monitoring in the foreground'

echo "$checks checks, $failures failed"
[ "$failures" -eq 0 ]
