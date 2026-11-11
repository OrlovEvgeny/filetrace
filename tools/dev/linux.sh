#!/bin/sh
# Sharing the host PID namespace keeps kernel-reported PIDs equal to those under /proc.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
image=${FILETRACE_DEV_IMAGE:-filetrace-dev}

if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker build -t "$image" "$root/tools/dev"
fi

tty=
if [ -t 0 ] && [ -t 1 ]; then
    tty=-t
fi

exec docker run --rm -i $tty \
    --privileged \
    --pid=host \
    -v "$root:/src" \
    -w /src \
    "$image" "$@"
