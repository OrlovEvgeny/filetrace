#!/bin/sh
# usage: sim_test.sh <ft_sim_agent> <filetrace>
# Runs the simulated agent and checks what the commands see: transfers of both methods and both
# confidences, workers under their master, the output of top without its screen, and a stop that
# exits 0 and removes the socket.
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

kill -TERM "$pid"
status=0
wait "$pid" || status=$?
pid=
ok "the agent exits 0 when stopped" test "$status" -eq 0
ok "the agent removes its socket" test ! -e sim.sock

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
