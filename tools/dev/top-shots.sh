#!/bin/sh
# usage: top-shots.sh [<output directory> [<build directory>]]
# Saves every screen of filetrace top as text, HTML and PNG, drawn from the
# simulated agent in a terminal of 174 by 44, so that a change to the screen
# can be looked at. The files go to a directory under the system's temporary
# one unless another is named; the build directory defaults to the dev preset's.
# Needs python3 (3.9 or later); the PNG files also need Chrome or Chromium.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
temporary=${TMPDIR:-/tmp}
out=${1:-${temporary%/}/filetrace-top-shots}
build=${2:-$root/build/dev-$(uname -s)}

for binary in filetrace tests/ft_sim_agent; do
    if [ ! -x "$build/$binary" ]; then
        echo "top-shots.sh: $build/$binary is missing; build the tree first" >&2
        exit 1
    fi
done

# A Unix socket path is short, so the socket gets a directory of its own.
work=$(mktemp -d)
sock=$work/agent.sock
"$build/tests/ft_sim_agent" --socket "$sock" --history 2h --log-level warn &
agent=$!
trap 'kill $agent 2>/dev/null; wait $agent 2>/dev/null; rm -rf "$work"' EXIT

tries=0
while [ ! -S "$sock" ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 300 ] || ! kill -0 "$agent" 2>/dev/null; then
        echo "top-shots.sh: the simulated agent did not start" >&2
        exit 1
    fi
    sleep 0.1
done

mkdir -p "$out"
python3 "$root/tools/dev/tuishot.py" --title "filetrace top" \
    --text "$out/top.txt" --png "$out/top.png" --steps "
        sleep:4
        shot:transfers
        key:2, sleep:1.5, key:t, sleep:1, key:down, key:down, key:F8, sleep:1
        shot:processes
        key:esc, key:3, sleep:1.5, key:F8, sleep:1
        shot:destinations
        key:esc, key:1, sleep:1, key:F4, text:dest:public, key:enter, key:F6, sleep:1
        shot:filter
        key:esc, key:F4, key:ctrl-u, key:enter, key:4, sleep:1.5, key:F8, sleep:1
        shot:files
        key:esc, key:L, sleep:3
        shot:leaders
        key:F1, sleep:1
        shot:help
    " -- "$build/filetrace" --socket "$sock" top

echo "$out"
