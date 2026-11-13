#!/bin/sh
# usage: sim_test.sh <ft_sim_agent> <filetrace>
# Runs the simulated agent and checks what the commands see: transfers of both methods and both
# confidences, workers under their master, the output of top and of watch without their screens,
# and a stop that exits 0 and removes the socket.
set -eu

# absolute <path>: the path from the root, for the commands run in the temporary directory.
absolute()
{
    case $1 in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$(pwd)" "$1" ;;
    esac
}

agent=$(absolute "$1")
cli=$(absolute "$2")
work=$(mktemp -d)
pid=
trap '[ -z "$pid" ] || kill "$pid" 2>/dev/null; rm -rf "$work"' EXIT

# A temporary directory can be too long for a socket path, so the socket is named relative to it.
cd "$work"

checks=0
failures=0

# ok <name> <command...>: the command succeeds.
ok()
{
    name=$1
    shift
    checks=$((checks + 1))
    if ! "$@"; then
        printf 'FAIL %s\n' "$name" >&2
        failures=$((failures + 1))
    fi
}

# query <file> <arguments>: output of the command, whose exit code 9 only says events were lost.
query()
{
    out=$1
    shift
    code=0
    "$cli" --socket sim.sock "$@" >"$out" 2>/dev/null || code=$?
    [ "$code" -eq 0 ] || [ "$code" -eq 9 ]
}

# exits <code> <command...>: the command ends with that exit code.
exits()
{
    want=$1
    shift
    got=0
    "$@" >/dev/null 2>&1 || got=$?
    [ "$got" -eq "$want" ]
}

# json_valid <file>: the file holds one JSON document.
json_valid()
{
    python3 -I -m json.tool "$1" >/dev/null
}

# has_array <file> <member>: the document's member is an array.
has_array()
{
    python3 -I -c 'import json, sys; sys.exit(not isinstance(json.load(open(sys.argv[1]))[sys.argv[2]], list))' "$1" "$2"
}

# stream_two_lines: the first two documents of the stream, read by a reader that then goes away.
stream_two_lines()
{
    ("$cli" --socket sim.sock top --json --delay 500ms 2>/dev/null; echo $? >stream.status) |
        head -n 2 >stream.ndjson
}

# watch_frame <file>: the first frame of watch, which is stopped once the frame is whole.
watch_frame()
{
    "$cli" --socket sim.sock watch --no-ui --limit 100 >"$1" 2>/dev/null &
    watcher=$!
    waited=0
    while ! grep -q 'LOST: ' "$1" && [ "$waited" -lt 50 ]; do
        sleep 0.1
        waited=$((waited + 1))
    done
    kill "$watcher" 2>/dev/null || true
    wait "$watcher" 2>/dev/null || true
    grep -q 'LOST: ' "$1"
}

# A history of the stream makes the transfers and the processes known as soon as it serves.
"$agent" --socket sim.sock --seed 1 --history 20s 2>agent.log &
pid=$!

waited=0
while [ ! -S sim.sock ] && [ "$waited" -lt 50 ]; do
    sleep 0.1
    waited=$((waited + 1))
done
ok "the agent serves its socket" test -S sim.sock

ok "transfers are listed" query transfers.json transfers --active --format json
ok "processes are listed" query processes.json processes --format json
ok "stats are listed" query stats.txt stats

ok "sendfile transfers are present" grep -q '"method":"sendfile"' transfers.json
ok "read-write transfers are present" grep -q '"method":"read-write"' transfers.json
ok "exact transfers are present" grep -q '"confidence":"exact"' transfers.json
ok "inferred transfers are present" grep -q '"confidence":"inferred"' transfers.json
ok "nginx workers have the master as parent" grep -q '"ppid":2210,"name":"nginx"' processes.json
ok "the master is listed" grep -q '"pid":2210,"ppid":1,"name":"nginx"' processes.json
ok "the backend is the simulation" grep -q '^sim, standard mode' stats.txt
ok "transfers are active" grep -Eq '^Active transfers: +[1-9]' stats.txt
ok "names are kept" grep -Eq '^Names: +[1-9][0-9]* of 4,096' stats.txt
ok "lookups are kept" grep -Eq '^Name lookups: +[1-9][0-9]* of 16,384' stats.txt
ok "libraries are probed" grep -Eq '^Name libraries: +9 of 256' stats.txt

ok "connections are listed" query connections.txt connections --limit 4000
ok "connections have a column of names" grep -Eq '^PID +PROCESS +PROTOCOL +LOCAL +REMOTE +NAME +STATE' connections.txt
ok "a looked-up name is shown" grep -Eq ' 10\.0\.7\.3[12]:873 +mirror-[12]\.internal ' connections.txt
ok "several looked-up names are counted" grep -q ' ch-replica-2\.internal (+1) ' connections.txt
ok "a server name through a proxy says so" grep -q ' registry\.ml\.example\.com via proxy\.corp\.internal ' connections.txt
ok "an accepted connection has no name" grep -Eq ' nginx +TCP +[^ ]+:443 +[^ ]+ +- ' connections.txt
ok "files are listed by a name" query named.jsonl files --remote '*.s3.example.com' --jsonl
ok "the name filter leaves what has the name" grep -q '"remote_name":"pg-backups.s3.example.com","remote_name_source":"lookup+tls","resolved_names":\["pg-backups.s3.example.com"\],"resolved_name_count":1' named.jsonl
ok "the name filter leaves nothing else" test "$(grep -vc '"remote_name":"pg-backups.s3.example.com"' named.jsonl)" -eq 0
ok "an unknown name lists nothing" query unnamed.txt files --remote none.example.com --format quiet
ok "nothing is listed for it" test ! -s unnamed.txt
ok "events are listed by a name" query events.txt events --type socket_connect --remote 'mirror-*' --limit 1
ok "an event names its remote end" grep -Eq '^  remote_name=mirror-[12]\.internal$' events.txt
ok "an event says where the name is from" grep -q '^  remote_name_source=lookup$' events.txt
ok "raw events are listed" query events.raw events --type socket_connect --remote 'mirror-*' --limit 1 --raw
ok "a raw event names its remote end" grep -Eq ' remote_port=873 remote_name=mirror-[12]\.internal bytes=' events.raw
ok "raw events without a name are listed" query bare.raw events --type network_send --process nginx --limit 1 --raw
ok "a raw event without a name keeps the field" grep -Eq ' remote_port=[0-9]+ remote_name=- bytes=' bare.raw
ok "events are listed as JSON" query events.jsonl events --type socket_connect --remote 'mirror-*' --limit 1 --jsonl
ok "a JSON event names its remote end" grep -Eq '"remote_port":873,"remote_name":"mirror-[12]\.internal","remote_name_source":"lookup"\}' events.jsonl

socket=$("$cli" --socket sim.sock connections --remote 'registry.*' --format quiet 2>/dev/null | head -n 1)
ok "a socket is inspected" query socket.txt inspect socket "$socket"
ok "the socket has its name" grep -Eq '^Name: +registry\.ml\.example\.com via proxy\.corp\.internal$' socket.txt
ok "the socket says where the name is from" grep -Eq '^Name from: +TLS server name$' socket.txt
ok "the socket lists what was looked up" grep -Eq '^Resolved names: +proxy\.corp\.internal$' socket.txt
ok "its flows have a column of names" grep -Eq '^FLOW +PID +PROCESS +REMOTE +NAME +SENT' socket.txt
ok "its files have a column of names" grep -Eq '^FILE +PROCESS +REMOTE +NAME +BYTES' socket.txt
flow=$("$cli" --socket sim.sock flows --remote clickhouse.internal --format quiet 2>/dev/null | head -n 1)
ok "a flow is inspected" query flow.txt inspect flow "$flow"
ok "the flow has its names" grep -Eq '^Name: +ch-replica-2\.internal \(\+1\)$' flow.txt
ok "the flow lists them" grep -Eq '^Resolved names: +ch-replica-2\.internal, clickhouse\.internal$' flow.txt
flow=$("$cli" --socket sim.sock flows --process nginx --format quiet 2>/dev/null | head -n 1)
ok "a flow nobody named is inspected" query bare.txt inspect flow "$flow"
ok "it has no line of names" exits 1 grep -Eq '^(Name|Name from|Resolved names):' bare.txt
ok "its files have no column of names" exits 1 grep -q ' NAME ' bare.txt

ok "flows are grouped by remote" query by-remote.txt flows --group-by remote
ok "the groups have a column of names" grep -Eq '^REMOTE +NAME +SENT +RECEIVED +FLOWS$' by-remote.txt
ok "a group counts the other names" grep -Eq '^10\.0\.6\.14 +ch-replica-2\.internal \(\+1\) ' by-remote.txt
ok "a group says a name through a proxy" grep -Eq '^10\.0\.8\.40 +registry\.ml\.example\.com via proxy\.corp\.internal ' by-remote.txt
ok "a group nobody named has none" grep -Eq '^10\.0\.5\.22 +- ' by-remote.txt
ok "flows are grouped by remote as JSON" query by-remote.json flows --group-by remote --json
ok "a group lists its names" grep -q '"remote_ip":"10.0.6.14",.*,"remote_names":\["ch-replica-2.internal","clickhouse.internal"\]}' by-remote.json
ok "a group nobody named lists none" grep -q '"remote_ip":"10.0.5.22",[^}]*"flows":1}' by-remote.json
ok "flows are grouped by remote as CSV" query by-remote.csv flows --group-by remote --format csv
ok "the CSV joins the names" grep -Eq '^10\.0\.6\.14,[0-9]+,[0-9]+,1,ch-replica-2\.internal;clickhouse\.internal$' by-remote.csv
ok "unnamed groups are grouped by remote" query bare-remote.txt flows --group-by remote --process nginx
ok "they have no column of names" grep -Eq '^REMOTE +SENT +RECEIVED +FLOWS$' bare-remote.txt
ok "unnamed groups are grouped by remote as CSV" query bare-remote.csv flows --group-by remote --process nginx --format csv
ok "their CSV header still ends in the names" test "$(head -n 1 bare-remote.csv)" = remote_ip,bytes_sent,bytes_received,flows,remote_names
ok "top ranks the destinations" query destinations.txt top destinations --limit 100
ok "the destinations have a column of names" grep -Eq '^RANK +REMOTE +NAME +SENT +RECEIVED +FLOWS$' destinations.txt
ok "a destination counts the other names" grep -Eq '^[0-9]+ +10\.0\.6\.14 +ch-replica-2\.internal \(\+1\) ' destinations.txt
ok "a destination says a name through a proxy" grep -Eq '^[0-9]+ +10\.0\.8\.40 +registry\.ml\.example\.com via proxy\.corp\.internal ' destinations.txt

ok "top prints a snapshot" query top.txt top --once
ok "the snapshot has its header" grep -q 'DESTINATION' top.txt
ok "the snapshot has rows" grep -q 'nginx' top.txt
for mode in transfers processes destinations files; do
    ok "top lists the $mode as JSON" query "top-$mode.json" top --mode "$mode" --once --json
    ok "the $mode JSON is valid" json_valid "top-$mode.json"
    ok "the $mode JSON has its rows" has_array "top-$mode.json" "$mode"
done
ok "top lists the ranking as JSON" query top-leaders.json top --leaders --window 1h --once --json
ok "the ranking JSON is valid" json_valid top-leaders.json
ok "the ranking JSON has its files" has_array top-leaders.json files
ok "top reads a ranking as a table" query top-leaders.txt top --leaders --once
ok "the ranking table says what it covers" grep -q '^Window 1h, ' top-leaders.txt
ok "top streams one document per line" stream_two_lines
ok "the stream ends with exit 0 when its reader has gone" test "$(cat stream.status)" -eq 0
ok "the stream has the lines that were read" test "$(wc -l <stream.ndjson)" -eq 2
head -n 1 stream.ndjson >stream-first.json
ok "a line of the stream is a document" json_valid stream-first.json
ok "top refuses a filter that does not parse" exits 2 "$cli" --socket sim.sock top --once --filter rate:abc
ok "top refuses a sort its mode lacks" exits 2 "$cli" --socket sim.sock top --mode files --sort age --once

ok "watch prints a frame" watch_frame watch.txt
ok "watch shows a name in place of an address" grep -Eq '^rclone [0-9]+ +/srv/backups/pg/[^ ]+ +pg-backups\.s3\.example\.com +read-write ' watch.txt
ok "watch leaves the address of a named end out" exits 1 grep -q '52\.219\.170\.52' watch.txt
ok "watch shows the address of an end nobody named" grep -Eq '^java [0-9]+ +/var/lib/kafka/[^ ]+ +10\.0\.5\.2[23] +sendfile ' watch.txt

kill -TERM "$pid"
status=0
wait "$pid" || status=$?
pid=
ok "the agent exits 0 when stopped" test "$status" -eq 0
ok "the agent removes its socket" test ! -e sim.sock

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
