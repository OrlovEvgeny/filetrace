#!/bin/sh
# usage: vm.sh <kernel version prefix> <command...>
# Kernels: 6.1 (Debian 12) and 6.12 (Debian 13), for arm64 hosts only.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
build=${FILETRACE_VM_BUILD:-build/vm}
kernel=$1
shift

if ! docker image inspect filetrace-vm >/dev/null 2>&1; then
    docker build -t filetrace-vm "$root/tools/dev/vm"
fi

"$root/tools/dev/linux.sh" sh -c "cmake -S /src -B /src/$build -G Ninja -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build /src/$build >/dev/null"

exec docker run --rm -i -v "$root:/src:ro" filetrace-vm /src/tools/dev/vm/boot.sh "$kernel" "/src/$build" "$@"
