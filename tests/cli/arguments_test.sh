#!/bin/sh
# usage: arguments_test.sh <filetrace>
# Checks how the commands refuse arguments they do not take. They are refused
# before the agent is asked, so no agent is needed.
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
printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
