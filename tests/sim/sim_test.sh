#!/bin/sh
# usage: sim_test.sh <ft_sim_agent> <filetrace>
# Runs the simulated agent and checks what the commands see: transfers of both methods and both
# confidences, workers under their master, and a stop that exits 0 and removes the socket.
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

kill -TERM "$pid"
status=0
wait "$pid" || status=$?
pid=
ok "the agent exits 0 when stopped" test "$status" -eq 0
ok "the agent removes its socket" test ! -e sim.sock

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
