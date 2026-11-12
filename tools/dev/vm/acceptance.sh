#!/bin/sh
# usage: acceptance.sh [-n runs] [-p] <kernel version prefix> <output directory> [scenario or finding...]
# Runs the acceptance scenarios inside VMs booted on that kernel, with the acceptance image's
# filesystem as their root, and writes each run's log and verdict as tests/acceptance/run.sh
# does, for tests/acceptance/compare.sh against a container run of the same commit.
# -p keeps the scenarios of scenarios.py only. The agent's correlation window is
# FILETRACE_ACCEPTANCE_WINDOW, 10s by default: emulated CPUs miss the 2 s default by timing.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../../.." && pwd)
image=${FILETRACE_ACCEPTANCE_IMAGE:-filetrace-acceptance}
window=${FILETRACE_ACCEPTANCE_WINDOW:-10s}
build=build/vm-acceptance
# Scenario runs per boot: boot.sh stops a VM after 30 minutes.
per_boot=${FILETRACE_ACCEPTANCE_PER_BOOT:-12}

runs=1
python_only=
while [ $# -gt 0 ]; do
    case $1 in
        -n)
            runs=$2
            shift 2
            ;;
        -p)
            python_only=1
            shift
            ;;
        *) break ;;
    esac
done
if [ $# -lt 2 ]; then
    sed -n '2,7s/^# //p' "$0" >&2
    exit 2
fi
kernel=$1
mkdir -p "$2" "$root/$build"
out=$(CDPATH='' cd -- "$2" && pwd)
shift 2

sh "$root/tests/acceptance/run.sh" -n "$runs" --list "$@" | while read -r name n; do
    if [ -z "$python_only" ] || [ ! -f "$root/tests/acceptance/cases/$name.sh" ]; then
        echo "$name:$n"
    fi
done >"$out/plan"
if [ ! -s "$out/plan" ]; then
    echo "no scenario matches: $*" >&2
    exit 2
fi

docker build -q -t "$image" "$root/tests/acceptance" >/dev/null
container=$(docker create "$image")
docker export "$container" >"$root/$build/rootfs.tar"
docker rm "$container" >/dev/null
printf 'binaries %s\nversion %s\nwhere vm %s\nwindow %s\n' "$root/$build" \
    "$(git -C "$root" describe --always --dirty)" "$kernel" "$window" >"$out/settings"

# Each line of chunks holds the scenarios of one boot, two probe sets per run.
awk -v max="$per_boot" '{
    n = substr($0, index($0, ":") + 1) * 2
    if (line != "" && w + n > max) { print line; line = ""; w = 0 }
    line = line " " $0
    w += n
} END { if (line != "") print line }' "$out/plan" >"$out/chunks"

echo "logs in $out"
echo "agent correlation window: $window"
boot=0
while read -r chunk; do
    boot=$((boot + 1))
    FILETRACE_VM_BUILD=$build "$root/tools/dev/vm.sh" "$kernel" \
        "FILETRACE_ACCEPTANCE_WINDOW=$window sh /acceptance/guest.sh 'auto kprobe' $chunk" \
        </dev/null >"$out/console.$boot.log" 2>&1 || true
    awk -v out="$out" '
        /^FT_ACCEPTANCE_BEGIN / { file = out "/" $2 "." $3 "." $4 ".log"; printf "" >file; next }
        /^FT_ACCEPTANCE_END / { close(file); file = ""; next }
        file != "" { print >file }' "$out/console.$boot.log"
done <"$out/chunks"

tr ' ' '\n' <"$out/chunks" | grep : | while read -r item; do
    name=${item%:*}
    for probes in auto kprobe; do
        i=1
        while [ "$i" -le "${item##*:}" ]; do
            log=$out/$name.$probes.$i.log
            verdict=$(sed -n 's/^RESULT: \([A-Z]*\).*/\1/p' "$log" 2>/dev/null | tail -n 1)
            echo "${verdict:-ERROR}" >"$out/$name.$probes.$i.verdict"
            echo "$name $probes run $i: ${verdict:-ERROR}"
            i=$((i + 1))
        done
    done
done
