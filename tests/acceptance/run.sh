#!/bin/sh
# usage: run.sh [-j jobs] [-n runs] [-w window] <directory with filetrace and filetrace-agent> [scenario or finding...]
#        run.sh [-n runs] --list [scenario or finding...]
# Runs the scenarios of expected.txt, or those named, each in a privileged container of its
# own on both probe sets, as many times as its row or -n asks, and compares the verdicts
# with the expected ones; -w sets the agent's correlation window. --list prints each
# selected scenario with its number of runs. Exits 77 when Docker is not available and 1 on
# any deviation.
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
image=${FILETRACE_ACCEPTANCE_IMAGE:-filetrace-acceptance}
prefix=${FILETRACE_ACCEPTANCE_PREFIX:-filetrace-acceptance}
probe_sets=${FILETRACE_ACCEPTANCE_PROBES:-auto kprobe}

# --one <binaries> <output directory> <scenario> <probes> <run>: one run, its log and its verdict.
if [ "${1:-}" = --one ]; then
    bin=$2 out=$3 name=$4 probes=$5 run=$6
    log=$out/$name.$probes.$run.log
    # In a PID namespace of its own the agent runs in a limited mode.
    docker run --rm --name "$prefix-$name-$probes-$run-$$" --privileged --pid=host --init \
        -e FILETRACE_ACCEPTANCE_WINDOW -v "$here:/acceptance:ro" -v "$bin:/ft/bin:ro" "$image" \
        timeout -k 10 300 sh /acceptance/scenario.sh "$name" "$probes" >"$log" 2>&1 || true
    verdict=$(sed -n 's/^RESULT: \([A-Z]*\).*/\1/p' "$log" | tail -n 1)
    echo "${verdict:-ERROR}" >"$out/$name.$probes.$run.verdict"
    echo "$name $probes run $run: ${verdict:-ERROR}"
    exit 0
fi

jobs=1
min_runs=1
list=
FILETRACE_ACCEPTANCE_WINDOW=${FILETRACE_ACCEPTANCE_WINDOW:-}
while [ $# -gt 0 ]; do
    case $1 in
        -j)
            jobs=$2
            shift 2
            ;;
        -n)
            min_runs=$2
            shift 2
            ;;
        -w)
            FILETRACE_ACCEPTANCE_WINDOW=$2
            shift 2
            ;;
        --list)
            list=1
            shift
            ;;
        *) break ;;
    esac
done
export FILETRACE_ACCEPTANCE_WINDOW
expected=$here/expected.txt

# Prints "scenario runs" for the rows of expected.txt whose name or finding is among the arguments, or all.
selected() {
    grep -v '^#' "$expected" | while read -r name finding _ _ _ _ runs _; do
        [ -n "$name" ] || continue
        [ "$runs" -ge "$min_runs" ] || runs=$min_runs
        if [ $# -eq 0 ]; then
            echo "$name $runs"
            continue
        fi
        for s in "$@"; do
            if [ "$s" = "$name" ] || [ "$s" = "$finding" ]; then
                echo "$name $runs"
                break
            fi
        done
    done
}

if [ -n "$list" ]; then
    selected "$@"
    exit 0
fi
if [ $# -lt 1 ]; then
    sed -n '2,3s/^# //p' "$0" >&2
    exit 2
fi
bin=$(CDPATH='' cd -- "$1" && pwd)
shift
for b in filetrace filetrace-agent; do
    if [ ! -x "$bin/$b" ]; then
        echo "no $b in $bin" >&2
        exit 2
    fi
done
if ! docker info >/dev/null 2>&1; then
    echo "Docker is not available" >&2
    exit 77
fi

docker build -q -t "$image" "$here" >/dev/null
out=${FILETRACE_ACCEPTANCE_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/filetrace-acceptance-XXXXXX")}
mkdir -p "$out"
# The containers mount this copy, so the checkout can change while they run.
rm -rf "$out/suite"
cp -R "$here" "$out/suite"
expected=$out/suite/expected.txt
printf 'binaries %s\nversion %s\nwhere containers\nwindow %s\n' "$bin" \
    "$(head -n 1 "$bin/VERSION" 2>/dev/null || echo unknown)" "${FILETRACE_ACCEPTANCE_WINDOW:-default}" >"$out/settings"

plan=$out/plan
: >"$plan"
selected "$@" | while read -r name runs; do
    for probes in $probe_sets; do
        i=1
        while [ "$i" -le "$runs" ]; do
            echo "$name $probes $i" >>"$plan"
            i=$((i + 1))
        done
    done
done
if [ ! -s "$plan" ]; then
    echo "no scenario matches: $*" >&2
    exit 2
fi

echo "logs in $out"
if [ -n "$FILETRACE_ACCEPTANCE_WINDOW" ]; then
    echo "agent correlation window: $FILETRACE_ACCEPTANCE_WINDOW"
fi
xargs -P "$jobs" -L 1 sh "$out/suite/run.sh" --one "$bin" "$out" <"$plan"

: >"$out/statuses"
echo
awk '{ print $1, $2 }' "$plan" | uniq | while read -r name probes; do
    read -r _ finding auto kprobe release_auto release_kprobe _ reason <<EOF
$(awk -v n="$name" '$1 == n' "$expected")
EOF
    if [ "$probes" = kprobe ]; then
        want=$kprobe release=$release_kprobe
    else
        want=$auto release=$release_auto
    fi
    runs=0 bugs=0 broken=0
    for v in "$out/$name.$probes".*.verdict; do
        runs=$((runs + 1))
        case $(cat "$v") in
            OK) ;;
            BUG) bugs=$((bugs + 1)) ;;
            *) broken=$((broken + 1)) ;;
        esac
    done
    if [ "$broken" -gt 0 ]; then
        verdict=ERROR
    elif [ "$bugs" -gt 0 ]; then
        verdict=BUG
    else
        verdict=OK
    fi
    [ "$runs" -eq 1 ] || verdict="$verdict $bugs/$runs"
    case $release in
        OK | -) on_release="" ;;
        BUG) on_release=", as on the release" ;;
        *) on_release=", release failed $release" ;;
    esac
    if [ "$broken" -gt 0 ]; then
        status=failed outcome="FAILED, $broken of $runs runs gave no verdict"
    elif [ "$bugs" -eq 0 ]; then
        status=ok outcome=ok
        [ "$want" = LIMIT ] && outcome="ok, the limit was not met"
    elif [ "$release" = OK ]; then
        status=worse outcome="FAILED, worse than the release"
    elif [ "$want" = LIMIT ]; then
        status=limit outcome="limit$on_release: $reason"
    else
        status=failed outcome="FAILED$on_release"
    fi
    printf '%-54s %-7s %-6s %-9s %-6s %s\n' "$name" "$finding" "$probes" "$verdict" "$want" "$outcome"
    echo "$status" >>"$out/statuses"
done

checked=$(wc -l <"$out/statuses" | tr -d ' ')
worse=$(grep -c '^worse$' "$out/statuses" || true)
failed=$(($(grep -c '^failed$' "$out/statuses" || true) + worse))
limits=$(grep -c '^limit$' "$out/statuses" || true)
echo
echo "$checked checks: $failed failed ($worse worse than the release), $limits at a documented limit; logs in $out"
[ "$failed" -eq 0 ]
