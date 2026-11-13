#!/bin/sh
# usage: vm.sh [--arch x86_64] <kernel version prefix> <command...>
# Kernels: 6.1 (Debian 12) and 6.12 (Debian 13), for arm64 hosts only.
# With --arch x86_64, on arm64 and amd64 hosts: 6.12.13 and 6.12.15, Debian's builds without and
# with the fix for CVE-2025-21834, running the static amd64 binaries that tools/dist builds.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)

if [ "${1:-}" = --arch ]; then
    if [ "${2:-}" != x86_64 ]; then
        echo "vm.sh: unsupported architecture: ${2:-}" >&2
        exit 2
    fi
    shift 2
    build=build/vm-x86_64
    kernel=$1
    shift

    if ! docker image inspect filetrace-vm-x86_64 >/dev/null 2>&1; then
        docker build --platform linux/amd64 -t filetrace-vm-x86_64 "$root/tools/dev/vm/x86_64"
    fi
    if ! docker image inspect filetrace-vm-x86_64-qemu >/dev/null 2>&1; then
        docker build -t filetrace-vm-x86_64-qemu "$root/tools/dev/vm/x86_64/qemu"
    fi

    mkdir -p "$root/$build"
    if ! DOCKER_DEFAULT_PLATFORM=linux/amd64 FILETRACE_DIST_IMAGE=filetrace-vm-dist-amd64 \
        "$root/tools/dist/build.sh" </dev/null >"$root/$build/dist.log" 2>&1; then
        cat "$root/$build/dist.log" >&2
        exit 1
    fi
    docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" -v "$root:/src:ro" \
        -v "$root/$build:/out" filetrace-vm-x86_64 \
        /src/tools/dev/vm/x86_64/root.sh "$kernel" /src/dist/stage/linux-amd64/bin /out "$@"

    kvm=
    if [ "$(uname -m)" = x86_64 ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        kvm=--device=/dev/kvm
    fi
    exec docker run --rm -i $kvm -v "$root:/src:ro" filetrace-vm-x86_64-qemu \
        /src/tools/dev/vm/boot.sh --arch x86_64 "/src/$build"
fi

build=${FILETRACE_VM_BUILD:-build/vm}
kernel=$1
shift

if ! docker image inspect filetrace-vm >/dev/null 2>&1; then
    docker build -t filetrace-vm "$root/tools/dev/vm"
fi

"$root/tools/dev/linux.sh" sh -c "cmake -S /src -B /src/$build -G Ninja -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build /src/$build >/dev/null"

exec docker run --rm -i -v "$root:/src:ro" filetrace-vm /src/tools/dev/vm/boot.sh "$kernel" "/src/$build" "$@"
