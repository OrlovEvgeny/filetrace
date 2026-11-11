#!/bin/sh
# Run inside the development container: tools/dev/linux.sh tools/dev/demo.sh
set -eu

build=/src/build/demo
sock=/tmp/filetrace-demo.sock
data=/var/tmp/filetrace-demo

cmake -S /src -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$build" >/dev/null

ft() {
    "$build/filetrace" --socket "$sock" "$@"
}

say() {
    printf '\n\033[1m== %s\033[0m\n' "$*"
}

say "filetrace doctor: can this kernel be monitored?"
"$build/filetrace" doctor

"$build/filetrace-agent" --socket "$sock" --log-level warn &
agent=$!
trap 'kill $agent 2>/dev/null; wait $agent 2>/dev/null; rm -rf "$data"' EXIT
while [ ! -S "$sock" ]; do
    sleep 0.1
done

mkdir -p "$data"
say "generating traffic: sendfile(2), a read+send loop, UDP datagrams"
"$build/tests/ft_workload" sendfile "$data/video.mp4" 50000000
"$build/tests/ft_workload" sendfile "$data/backup.tar.gz" 8000000 ipv6
"$build/tests/ft_workload" readsend "$data/customers.csv" 12000000 65536
"$build/tests/ft_workload" readthenrecv "$data/ca-bundle.crt" 200000
"$build/tests/ft_workload" udp 50000
"$build/tests/ft_workload" steady "$data/stream.bin" 40000000 5 >"$data/steady.txt" &
steady=$!
sleep 2

say "filetrace watch --no-ui: one snapshot of what is being sent right now"
timeout -s INT 0.8 "$build/filetrace" --socket "$sock" watch --no-ui --limit 5 || true

say "filetrace files: which files went to the network, and how sure is that?"
ft files

say "filetrace files --remote 127.0.0.0/8 --confidence exact: from an address to its files"
ft files --remote 127.0.0.0/8 --confidence exact

say "filetrace inspect file: from a file to who sent it, and where"
ft inspect file "$data/video.mp4"

pid=$(tr ' ' '\n' <"$data/steady.txt" | sed -n 's/^pid=//p')
say "filetrace inspect process $pid: from a process to what it is sending"
ft inspect process "$pid"

say "filetrace processes"
ft processes --limit 6

say "filetrace connections"
ft connections --limit 6

say "filetrace events: the records behind the totals"
ft events --type file_seen,file_transfer --limit 3

say "filetrace files --json (one record)"
ft files --path "$data/video.mp4" --json

say "filetrace stats: the agent's own cost"
ft stats

wait "$steady"
say "done"
echo "ca-bundle.crt was read but never reported: the process heard from its peer"
echo "before sending unrelated data, so nothing ties that file to the send."
