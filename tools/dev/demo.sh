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

"$build/filetraced" --socket "$sock" --log-level warn &
daemon=$!
trap 'kill $daemon 2>/dev/null; wait $daemon 2>/dev/null; rm -rf "$data"' EXIT
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
sleep 1

say "filetrace files: which files went to the network, and how sure is that?"
ft files

say "filetrace transfers: the same, plus sent bytes that no file explains"
ft transfers --limit 8

say "filetrace processes"
ft processes --limit 8

say "filetrace connections"
ft connections --limit 8

say "filetrace files --format json (one record)"
ft files --path "$data/video.mp4" --format json

say "filetrace stats: the collector's own cost"
ft stats

say "done"
echo "ca-bundle.crt was read but never reported: the process heard from its peer"
echo "before sending unrelated data, so nothing ties that file to the send."
