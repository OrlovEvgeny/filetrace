#!/bin/sh
# usage: fallback_test.sh <filetrace>
# Checks how capabilities names the reason it checked the machine itself.
set -eu

cli=$1
# Root connects to any socket, so the refused case cannot be made.
[ "$(id -u)" -ne 0 ] || exit 77
command -v python3 >/dev/null 2>&1 || exit 77

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

checks=0
failures=0

# source_of <socket>: the line that names where the capabilities came from.
source_of()
{
    "$cli" --socket "$1" capabilities 2>/dev/null | grep '^Reported by' || true
}

check()
{
    checks=$((checks + 1))
    if [ "$2" != "$3" ]; then
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3" >&2
        failures=$((failures + 1))
    fi
}

python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$work/agent.sock"

check "no socket" "Reported by a check of this machine (no agent is running)." \
    "$(source_of "$work/missing.sock")"
check "nobody listening" "Reported by a check of this machine (no agent is running)." \
    "$(source_of "$work/agent.sock")"
chmod 000 "$work/agent.sock"
check "socket not accessible" \
    "Reported by a check of this machine (the agent's socket is not accessible)." \
    "$(source_of "$work/agent.sock")"

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
