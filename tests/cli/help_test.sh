#!/bin/sh
# usage: help_test.sh <filetrace> <filetrace-agent>
# Checks that the help texts name the options, defaults and exit codes the
# commands have.
set -eu

cli=$1
agent=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

checks=0
failures=0

# has <name> <file> <text>: the file contains the text on one line.
has()
{
    checks=$((checks + 1))
    if ! grep -qF -- "$3" "$2"; then
        printf 'FAIL %s\n  missing: %s\n' "$1" "$3" >&2
        failures=$((failures + 1))
    fi
}

# before <name> <file> <first> <second>: the first text appears on an earlier line.
before()
{
    checks=$((checks + 1))
    first=$(grep -nF -- "$3" "$2" | head -n 1 | cut -d: -f1)
    second=$(grep -nF -- "$4" "$2" | head -n 1 | cut -d: -f1)
    if [ -z "$first" ] || [ -z "$second" ] || [ "$first" -ge "$second" ]; then
        printf 'FAIL %s\n  "%s" (line %s) is not before "%s" (line %s)\n' \
            "$1" "$3" "${first:-none}" "$4" "${second:-none}" >&2
        failures=$((failures + 1))
    fi
}

for command in files top watch agent doctor stats events; do
    "$cli" help "$command" >"$work/$command"
done
"$agent" --help >"$work/filetrace-agent"

has "--name is named as an alias" "$work/files" "alias: --name)"
has "exit code 6 is listed" "$work/files" "6  invalid configuration file"
has "top says where --protocol applies" "$work/top" \
    "--protocol applies to files, destinations and connections, not to"
has "top says what quiet prints" "$work/top" \
    "processes. --format quiet prints one process ID, file path, remote"
has "watch says where --confidence applies" "$work/watch" \
    "--confidence to the files view; --min-bytes to the files and processes"
has "agent run lists --event-log-size" "$work/agent" "--event-log-size <size>"
has "doctor lists --format" "$work/doctor" "[--format table|json]"
has "stats says --interval implies --watch" "$work/stats" \
    "Repeat at this interval (default: 1s); implies"
has "filetrace-agent lists exit code 8" "$work/filetrace-agent" \
    "8 the metrics page cannot listen"

note="Byte counts cover a record's whole observed lifetime"
before "top lists --limit with the other options" "$work/top" "--limit <n>" "$note"
before "events lists --limit with the other options" "$work/events" "--limit <n>" "$note"

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
