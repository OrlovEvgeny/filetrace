#!/bin/sh
# usage: compare.sh <run directory> <run directory>
# Prints the settings of two runs, of run.sh or of tools/dev/vm/acceptance.sh, and every
# scenario whose verdict differs between them. Exits 1 when one does.
set -eu

for dir in "$1" "$2"; do
    echo "$dir:"
    sed 's/^/  /' "$dir/settings"
done
if [ "$(grep '^window ' "$1/settings")" != "$(grep '^window ' "$2/settings")" ]; then
    echo "the runs used different correlation windows: a difference can come from that"
fi

# Prints "<scenario>.<probes> <verdict>" for a run: OK, BUG, SKIP or ERROR, with the failed runs
# out of those made when there was more than one.
summary() {
    for v in "$1"/*.verdict; do
        [ -e "$v" ] || continue
        printf '%s %s\n' "$(basename "$v" .verdict)" "$(cat "$v")"
    done | awk '{
        key = $1
        sub(/\.[0-9]+$/, "", key)
        runs[key]++
        if ($2 == "BUG") bugs[key]++
        else if ($2 == "SKIP") skipped[key]++
        else if ($2 != "OK") broken[key]++
    } END {
        for (key in runs) {
            v = broken[key] ? "ERROR" : bugs[key] ? "BUG" : skipped[key] ? "SKIP" : "OK"
            if (runs[key] > 1) v = v " " (bugs[key] + 0) "/" runs[key]
            print key, v
        }
    }' | sort
}

summary "$1" >"${TMPDIR:-/tmp}/compare.$$.a"
summary "$2" >"${TMPDIR:-/tmp}/compare.$$.b"
trap 'rm -f "${TMPDIR:-/tmp}/compare.$$".*' EXIT

awk '
    FNR == NR { a[$1] = substr($0, length($1) + 2); next }
    { b[$1] = substr($0, length($1) + 2) }
    END {
        for (k in a) keys[k] = 1
        for (k in b) keys[k] = 1
        for (k in keys) {
            n++
            va = (k in a) ? a[k] : "not run"
            vb = (k in b) ? b[k] : "not run"
            if (va == vb) continue
            d++
            probes = k
            sub(/.*\./, "", probes)
            name = substr(k, 1, length(k) - length(probes) - 1)
            printf "%-54s %-6s %-9s %s\n", name, probes, va, vb
        }
        printf "%d scenario runs compared, %d differ\n", n, d
        exit (d > 0)
    }' "${TMPDIR:-/tmp}/compare.$$.a" "${TMPDIR:-/tmp}/compare.$$.b"
