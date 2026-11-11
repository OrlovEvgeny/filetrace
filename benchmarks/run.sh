#!/bin/sh
# usage: run.sh <directory with filetrace and filetraced> <syscalls benchmark binary> [probes]
# Needs the same privileges as the daemon. Build with CMAKE_BUILD_TYPE=Release.

set -eu

bin=$1
bench=$2
probes=${3:-auto}
work=$(mktemp -d /tmp/filetrace-bench-XXXXXX)
sock=$work/daemon.sock
daemon=
trap '[ -n "$daemon" ] && kill "$daemon" 2>/dev/null; wait 2>/dev/null; rm -rf "$work"' EXIT

ft() {
    "$bin/filetrace" --socket "$sock" "$@"
}

json_number() {
    printf '%s' "$1" | sed -n "s/.*\"$2\":\\([0-9.]*\\).*/\\1/p"
}

run_mode() {
    mode=$1
    if [ "$mode" != off ]; then
        "$bin/filetraced" --socket "$sock" --mode "$mode" --probes "$probes" --log-level error &
        daemon=$!
        while [ ! -S "$sock" ]; do
            sleep 0.1
        done
    fi

    "$bench" "$work/data.bin" >"$work/$mode.txt"

    if [ "$mode" != off ]; then
        stats=$(ft stats --format json)
        printf '%s' "$stats" | sed -n 's/.*"backend":"\([^"]*\)".*/\1/p' >"$work/backend.txt"
        echo "rss_bytes $(json_number "$stats" memory_bytes)" >>"$work/$mode.txt"
        echo "dropped $(json_number "$stats" dropped)" >>"$work/$mode.txt"

        # CPU use is sampled once the workload is over.
        sleep 5
        stats=$(ft stats --format json)
        echo "idle_cpu_percent $(json_number "$stats" cpu_percent)" >>"$work/$mode.txt"
        ft daemon stop >/dev/null
        wait "$daemon"
        daemon=
    fi
}

value() {
    awk -v key="$2" '$1 == key { print $2 }' "$work/$1.txt"
}

for mode in off minimal standard; do
    run_mode "$mode"
done

echo "kernel:  $(uname -sr) $(uname -m), $(nproc) CPUs"
echo "backend: $(cat "$work/backend.txt")"
echo
printf '%-18s %10s %18s %18s\n' "ns per call" "no agent" "minimal" "standard"
for test in send_1k pread_4k read_send_16k sendfile_64k; do
    base=$(value off $test)
    printf '%-18s %10s' "$test" "$base"
    for mode in minimal standard; do
        ns=$(value $mode $test)
        printf ' %9s (%+4d%%)' "$ns" $(((ns - base) * 100 / base))
    done
    echo
done
echo
printf '%-18s %10s %18s %18s\n' "agent" "" "minimal" "standard"
printf '%-18s %10s %15s MB %15s MB\n' "resident memory" "" \
    "$(($(value minimal rss_bytes) / 1048576))" "$(($(value standard rss_bytes) / 1048576))"
printf '%-18s %10s %17s%% %17s%%\n' "idle CPU" "" \
    "$(value minimal idle_cpu_percent)" "$(value standard idle_cpu_percent)"
printf '%-18s %10s %18s %18s\n' "events lost" "" \
    "$(value minimal dropped)" "$(value standard dropped)"
