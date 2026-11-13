#!/bin/sh
# usage: arguments_test.sh <filetrace>
# Checks how the commands refuse arguments they do not take: an unknown one,
# and an option another command takes. Both are refused before the agent is
# asked, so no agent is needed.
set -eu

cli=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

checks=0
failures=0

# says <name> <exit code> <expected first line or ""> <arguments>
says()
{
    name=$1
    expected_code=$2
    expected=$3
    shift 3
    checks=$((checks + 1))
    code=0
    "$cli" --socket "$work/none.sock" "$@" >"$work/out" 2>&1 || code=$?
    first=$(head -n 1 "$work/out")
    if [ "$code" -ne "$expected_code" ] || { [ -n "$expected" ] && [ "$first" != "$expected" ]; }; then
        printf 'FAIL %s\n  expected exit %s and: %s\n  got exit %s and: %s\n' "$name" \
            "$expected_code" "$expected" "$code" "$first" >&2
        failures=$((failures + 1))
    fi
}

says "files refuses an unknown option" 2 \
    "filetrace: unknown argument '--no-such-option' for 'files'" files --no-such-option
says "transfers refuses an unknown option" 2 \
    "filetrace: unknown argument '--no-such-option' for 'transfers'" transfers --no-such-option
says "top processes names --protocol" 2 \
    "filetrace: --protocol does not apply to 'top processes'" top processes --protocol tcp
says "processes names --remote" 2 "filetrace: --remote does not apply to 'processes'" \
    processes --remote 192.0.2.1
says "processes names the flag --completed" 2 \
    "filetrace: --completed does not apply to 'processes'" processes --completed
says "events names --state with a value" 2 "filetrace: --state does not apply to 'events'" \
    events --state=closed
says "watch names --json, an output option it lacks" 2 \
    "filetrace: --json does not apply to 'watch'" watch --json
says "connections names --script" 2 "filetrace: --script does not apply to 'connections'" \
    connections --script '/srv/*'
says "top names --since as a report option" 2 \
    "filetrace: --since applies to a report: filetrace top processes --since ..." top --since 1h
says "top refuses an unknown mode" 2 \
    "filetrace: invalid value 'cpu' for --mode (expected transfers, processes, destinations, files or leaders)" \
    top --mode cpu
says "top refuses an unknown sort key" 2 \
    "filetrace: invalid value 'speed' for --sort (expected rate, bytes, progress, age, pid, user, proc, script, file, size, dest, method or conf)" \
    top --sort speed
says "top refuses an unknown group" 2 \
    "filetrace: invalid value 'asn' for --group (expected none, process, script, dest, dir, subnet or name)" \
    top --group asn
says "top refuses a delay below 500ms" 2 \
    "filetrace: invalid value '100ms' for --delay (expected a duration from 500ms to 10s)" \
    top --delay 100ms
says "top refuses an unknown window" 2 \
    "filetrace: invalid value '2h' for --window (expected 1m, 5m, 15m, 1h, 24h or 7d)" \
    top --leaders --window 2h
says "top refuses a limit of 0" 2 \
    "filetrace: invalid value '0' for --limit (expected a number from 1 to 1000)" \
    top --leaders --limit 0
says "a remote that is neither an address nor a name is refused" 2 \
    "filetrace: invalid value 'x y' for --remote (expected an IP address, a CIDR network or a host name; '*' wildcards in a name)" \
    files --remote 'x y'
says "half an address is not taken for a name" 2 \
    "filetrace: invalid value '10.0.0' for --remote (expected an IP address, a CIDR network or a host name; '*' wildcards in a name)" \
    files --remote 10.0.0
says "an address with a wildcard is not taken for a name" 2 \
    "filetrace: invalid value '10.0.*' for --remote (expected an IP address, a CIDR network or a host name; '*' wildcards in a name)" \
    connections --remote '10.0.*'
says "top takes a name for --remote" 2 \
    "filetrace: --window does not apply to the transfers mode (use --leaders)" \
    top --remote example.org --window 5m
says "top refuses a remote that is neither an address nor a name" 2 \
    "filetrace: invalid value 'x y' for --remote (expected an IP address, a CIDR network or a host name; '*' wildcards in a name)" \
    top --remote 'x y'
says "top takes half an address for no name either" 2 \
    "filetrace: invalid value '10.0.0' for --remote (expected an IP address, a CIDR network or a host name; '*' wildcards in a name)" \
    top --remote 10.0.0
says "top asks for leaders with --window" 2 \
    "filetrace: --window does not apply to the transfers mode (use --leaders)" top --window 5m
says "top asks for processes with --tree" 2 \
    "filetrace: --tree does not apply to the files mode (use --mode processes)" \
    top --mode files --tree
says "top refuses --leaders with another mode" 2 \
    "filetrace: --leaders conflicts with --mode files" top --leaders --mode files
says "top points --sort at --by in leaders" 2 \
    "filetrace: --sort does not apply to the leaders mode (use --by)" top --leaders --sort rate
# An option the command reads itself still reaches the agent, which is not running.
says "events reads --limit itself" 4 "" events --limit 3
says "top files takes --protocol" 4 "" top files --protocol tcp
says "top files takes --limit" 4 "" top files --limit 1
says "files takes --script" 4 "" files --script 'pool:*'
says "processes takes --script" 4 "" processes --script=/srv/app/export.py
says "events takes --script" 4 "" events --script 'module:*'
# Without an agent, top collects by itself where the kernel allows it.
if [ "$(uname -s)" = Darwin ]; then
    says "top says what to do on macOS" 5 \
        "Nothing can be collected on macOS: filetrace reads the Linux kernel. Run it on a Linux host, kernel 6.1 or later." \
        top --once
fi

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
