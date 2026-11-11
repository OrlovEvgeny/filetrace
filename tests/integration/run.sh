#!/bin/sh
# usage: run.sh <directory with filetrace and filetraced> <workload binary> [auto|trampoline|kprobe]
# Exits 77 when this machine cannot run the collector.

set -u

bin=$1
workload=$2
probes=${3:-auto}
work=$(mktemp -d /tmp/filetrace-it-XXXXXX)
data=$work/data
sock=$work/daemon.sock
daemon_pid=
failures=0
checks=0

mkdir -p "$data"

cleanup() {
    [ -n "$daemon_pid" ] && kill "$daemon_pid" 2>/dev/null
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

start_daemon() {
    "$bin/filetraced" --socket "$sock" --flush-interval 100ms --log-level warn \
        --probes "$probes" "$@" &
    daemon_pid=$!
    i=0
    while [ ! -S "$sock" ] && [ $i -lt 100 ]; do
        kill -0 "$daemon_pid" 2>/dev/null || return 1
        sleep 0.1
        i=$((i + 1))
    done
    [ -S "$sock" ]
}

stop_daemon() {
    ft daemon stop >/dev/null
    wait "$daemon_pid"
    status=$?
    daemon_pid=
    return $status
}

# Long enough for two counter flushes.
settle() {
    sleep 0.5
}

"$bin/filetrace" doctor --probes "$probes" >"$work/doctor.txt" 2>&1
doctor=$?
if [ $doctor -eq 3 ] || [ $doctor -eq 5 ]; then
    cat "$work/doctor.txt"
    echo "SKIP: this machine cannot run the collector"
    exit 77
fi
expect "doctor exit code" "$doctor" 0

start_daemon || { echo "FAIL: the daemon did not start"; exit 1; }

expect "daemon status exit code" "$(ft daemon status >/dev/null; echo $?)" 0

# sendfile over IPv4: an exact attribution with exact byte counts.
report=$("$workload" sendfile "$data/report.csv" 5000000)
settle
csv=$(ft files --path "$data/report.csv" --format csv)
expect "sendfile rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "sendfile confidence" "$(printf '%s\n' "$csv" | column attribution.confidence)" exact
expect "sendfile method" "$(printf '%s\n' "$csv" | column transfer.method)" sendfile
expect "sendfile bytes" "$(printf '%s\n' "$csv" | column transfer.bytes)" 5000000
expect "sendfile process" "$(printf '%s\n' "$csv" | column process.name)" ft_workload
expect "sendfile pid" "$(printf '%s\n' "$csv" | column process.pid)" "$(field "$report" pid)"
expect "sendfile remote port" "$(printf '%s\n' "$csv" | column network.remote_port)" \
    "$(field "$report" port)"
expect "sendfile remote address" "$(printf '%s\n' "$csv" | column network.remote_address)" 127.0.0.1
expect "sendfile inode" "$(printf '%s\n' "$csv" | column file.inode)" \
    "$(stat -c %i "$data/report.csv")"
expect "sendfile device" "$(printf '%s\n' "$csv" | column file.device)" \
    "$(stat -c %d "$data/report.csv")"
expect_match "sendfile evidence" "$(printf '%s\n' "$csv" | column attribution.evidence)" \
    'direct_file_to_socket_transfer;.*socket_identity;remote_endpoint'
expect "sendfile incomplete" "$(printf '%s\n' "$csv" | column attribution.incomplete)" false
first_port=$(field "$report" port)

# The same over IPv6.
report=$("$workload" sendfile "$data/v6.bin" 1000000 ipv6)
settle
csv=$(ft files --path "$data/v6.bin" --format csv)
expect "ipv6 bytes" "$(printf '%s\n' "$csv" | column transfer.bytes)" 1000000
expect "ipv6 remote address" "$(printf '%s\n' "$csv" | column network.remote_address)" ::1
expect "ipv6 confidence" "$(printf '%s\n' "$csv" | column attribution.confidence)" exact

# A read+send loop: inferred, never exact.
report=$("$workload" readsend "$data/upload.bin" 3000000 65536)
settle
csv=$(ft files --path "$data/upload.bin" --format csv)
expect "read+send rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "read+send confidence" "$(printf '%s\n' "$csv" | column attribution.confidence)" inferred
expect "read+send method" "$(printf '%s\n' "$csv" | column transfer.method)" read_send
expect "read+send bytes" "$(printf '%s\n' "$csv" | column transfer.bytes)" 3000000
expect "read+send bytes read" "$(printf '%s\n' "$csv" | column transfer.bytes_read)" 3000000
expect_match "read+send evidence" "$(printf '%s\n' "$csv" | column attribution.evidence)" \
    'thread_read_then_send;repeated_read_then_send;byte_balance'
expect "read+send is not exact" \
    "$(ft files --path "$data/upload.bin" --confidence exact --format csv | rows)" 0

# A read followed by a receive and an unrelated send is not a transfer of the file.
"$workload" readthenrecv "$data/config.bin" 200000 >/dev/null
settle
expect "read, receive, then send" "$(ft files --path "$data/config.bin" --format csv | rows)" 0

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
    expect "fd reuse file $i bytes" "$(printf '%s\n' "$one" | column transfer.bytes)" \
        $((100000 + i * 4096))
    expect "fd reuse file $i confidence" \
        "$(printf '%s\n' "$one" | column attribution.confidence)" exact
    i=$((i + 1))
done

# A file renamed halfway through stays one file with all of its bytes.
"$workload" rename "$data/before.bin" "$data/after.bin" 2000000 >/dev/null
settle
csv=$(ft files --path "$data/before.bin" --format csv)
expect "rename rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "rename bytes" "$(printf '%s\n' "$csv" | column transfer.bytes)" 2000000
expect "rename inode" "$(printf '%s\n' "$csv" | column file.inode)" \
    "$(stat -c %i "$data/after.bin")"

# A file sent after its last link is removed is reported as deleted.
"$workload" unlink "$data/gone.bin" 300000 >/dev/null
settle
csv=$(ft files --deleted --format csv)
expect "deleted rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "deleted path" "$(printf '%s\n' "$csv" | column file.path)" "$data/gone.bin"
expect "deleted flag" "$(printf '%s\n' "$csv" | column file.deleted)" true
expect "deleted bytes" "$(printf '%s\n' "$csv" | column transfer.bytes)" 300000

# Datagrams to an unconnected socket's peer.
report=$("$workload" udp 50000)
settle
port=$(field "$report" port)
csv=$(ft flows --protocol udp --port "$port" --pid "$(field "$report" pid)" --format csv)
expect "udp flow rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "udp sent bytes" "$(printf '%s\n' "$csv" | column sent_bytes)" 50000
expect "udp remote port" "$(printf '%s\n' "$csv" | column remote_port)" "$port"
expect "udp send operations" "$(printf '%s\n' "$csv" | column send_operations)" 50
csv=$(ft transfers --confidence unknown --protocol udp --port "$port" --format csv)
expect "udp bytes have no file" "$(printf '%s\n' "$csv" | column transfer.bytes)" 50000
expect "udp transfer id" "$(ft transfers --confidence unknown --port "$port" --format quiet |
    grep -c '^tr_s')" 1

# Both directions of a half-closed exchange, byte for byte: a peek, a wait
# for the whole reply and the end of the stream add nothing.
report=$("$workload" duplex 300000 70000)
settle
expect "duplex server saw the request" "$(field "$report" status)" 0
port=$(field "$report" port)
csv=$(ft flows --port "$port" --pid "$(field "$report" pid)" --format csv)
expect "duplex client sent" "$(printf '%s\n' "$csv" | column sent_bytes)" 300000
expect "duplex client received" "$(printf '%s\n' "$csv" | column received_bytes)" 70000
csv=$(ft flows --port "$port" --pid "$(field "$report" server)" --format csv)
expect "duplex server received" "$(printf '%s\n' "$csv" | column received_bytes)" 300000
expect "duplex server sent" "$(printf '%s\n' "$csv" | column sent_bytes)" 70000

# Sends that the socket accepts only in part still add up to the file.
report=$("$workload" partialsend "$data/partial.bin" 3000000)
settle
expect_match "partial sends happened" "$(field "$report" calls)" '^[0-9]{3,}$'
csv=$(ft files --path "$data/partial.bin" --format csv)
expect "partial send rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "partial send bytes" "$(printf '%s\n' "$csv" | column transfer.bytes)" 3000000
expect "partial send confidence" "$(printf '%s\n' "$csv" | column attribution.confidence)" inferred
csv=$(ft flows --port "$(field "$report" port)" --pid "$(field "$report" pid)" --format csv)
expect "partial send socket bytes" "$(printf '%s\n' "$csv" | column sent_bytes)" 3000000

report=$("$workload" partialsendfile "$data/partialsf.bin" 3000000)
settle
expect_match "partial sendfiles happened" "$(field "$report" calls)" '^[0-9]{2,}$'
csv=$(ft files --path "$data/partialsf.bin" --format csv)
expect "partial sendfile rows" "$(printf '%s\n' "$csv" | rows)" 1
expect "partial sendfile bytes" "$(printf '%s\n' "$csv" | column transfer.bytes)" 3000000
expect "partial sendfile confidence" "$(printf '%s\n' "$csv" | column attribution.confidence)" exact

# Processes, including the totals of their children.
report=$("$workload" child "$data/child.bin" 700000)
settle
parent=$(field "$report" parent)
child=$(field "$report" child)
csv=$(ft processes --pid "$child" --format csv)
expect "child outbound" "$(printf '%s\n' "$csv" | column outbound_bytes)" 700000
expect "child parent" "$(printf '%s\n' "$csv" | column ppid)" "$parent"
expect "child name" "$(printf '%s\n' "$csv" | column name)" ft_workload
expect "child status" "$(printf '%s\n' "$csv" | column status)" exited
expect "parent alone sent nothing" "$(ft processes --pid "$parent" --format csv | rows)" 0
csv=$(ft processes --pid "$parent" --include-children --format csv)
expect_match "parent with children" "$(printf '%s\n' "$csv" | column outbound_bytes)" '^700000$'

# Both ends of the first scenario's connection, and its listener, are closed.
csv=$(ft connections --port "$first_port" --state closed --format csv)
expect "closed connections" "$(printf '%s\n' "$csv" | rows)" 3
expect "no open connections" "$(ft connections --port "$first_port" --active --format csv | rows)" 0

expect_match "table header" "$(ft files --limit 1 | head -1)" \
    '^FILE +PID +PROCESS +REMOTE +SENT +CONFIDENCE$'
expect_match "json array" "$(ft files --limit 1 --format json | tr -d '\n')" \
    '^\[ *\{"event":"transfer\.(progress|completed)","transfer_id":"tr_[0-9a-f]+".*"attribution":\{"confidence":"(exact|inferred)".*\}\]$'
expect "jsonl lines" "$(ft files --path "$data/reuse-*" --format jsonl | wc -l | tr -d ' ')" 25
expect "quiet prints paths" "$(ft files --path "$data/report.csv" --format quiet)" \
    "$data/report.csv"
expect_match "top files" "$(ft top files --limit 1 | sed -n 3,4p | tr '\n' ' ')" \
    '^RANK +FILE +SENT +TRANSFERS +CONFIDENCE +1 +.*report\.csv +4\.77 MB +1 +EXACT'
expect_match "grouped flows" "$(ft flows --group-by protocol --format csv | head -1)" \
    '^protocol,sent_bytes,received_bytes,flows$'

stats=$(ft stats --format json)
expect_match "stats status" "$stats" '"status":"healthy"'
expect_match "stats backend" "$stats" \
    '"backend":"Linux eBPF \((trampolines|kprobes)\)","mode":"standard"'
if [ "$probes" != auto ]; then
    expect_match "stats probes" "$stats" "\"backend\":\"Linux eBPF \\($probes"
fi
expect_match "stats no loss" "$stats" '"dropped":0,'
expect_match "capabilities" "$(ft capabilities | grep '^Sendfile attribution')" 'FULL'

# Usage errors and an absent daemon are distinguishable by exit code.
expect "invalid option exit code" "$(ft files --no-such-option >/dev/null 2>&1; echo $?)" 2
expect "invalid value exit code" "$(ft files --min-bytes lots >/dev/null 2>&1; echo $?)" 2
expect "no daemon exit code" \
    "$("$bin/filetrace" --socket "$work/absent.sock" files >/dev/null 2>&1; echo $?)" 4

stop_daemon
expect "daemon exit code" "$?" 0
expect "socket removed" "$([ -e "$sock" ] && echo present || echo removed)" removed

start_daemon --mode minimal || { echo "FAIL: the daemon did not start in minimal mode"; exit 1; }

report=$("$workload" sendfile "$data/minimal.bin" 900000)
settle
expect "minimal: no file attribution" "$(ft files --format csv | rows)" 0
csv=$(ft flows --port "$(field "$report" port)" --pid "$(field "$report" pid)" --format csv)
expect "minimal: bytes still counted" "$(printf '%s\n' "$csv" | column sent_bytes)" 900000
expect_match "minimal: capability disabled" \
    "$(ft capabilities | grep '^Sendfile attribution')" 'DISABLED'
csv=$(ft transfers --port "$(field "$report" port)" --pid "$(field "$report" pid)" --format csv)
expect "minimal: bytes have no file" \
    "$(printf '%s\n' "$csv" | column attribution.confidence)" unknown

stop_daemon
expect "minimal daemon exit code" "$?" 0

# Without a daemon, watch collects for as long as it runs.
out=$(timeout -s INT 3 "$bin/filetrace" --socket "$work/absent.sock" watch --no-ui \
    --interval 500ms 2>"$work/watch.err")
expect_match "watch output" "$out" 'TOP OUTBOUND PROCESSES'
expect_match "watch output" "$out" 'ACTIVE FILE TRANSFERS'
expect_match "watch notice" "$(cat "$work/watch.err")" 'monitoring in the foreground'

echo "$checks checks, $failures failed"
[ "$failures" -eq 0 ]
