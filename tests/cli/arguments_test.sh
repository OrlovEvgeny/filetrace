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
# An option the command reads itself still reaches the agent, which is not running.
says "events reads --limit itself" 4 "" events --limit 3
says "top files takes --protocol" 4 "" top files --protocol tcp
says "files takes --script" 4 "" files --script 'pool:*'
says "processes takes --script" 4 "" processes --script=/srv/app/export.py
says "events takes --script" 4 "" events --script 'module:*'

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
