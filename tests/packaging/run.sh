#!/bin/sh
# usage: run.sh [<case>...]
# Installs the packages found in dist/ in containers and checks the result.
# Cases: deb rpm apk sysv unprivileged (default: all of them). The Docker host
# has to allow privileged containers and run a kernel with BTF.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"

[ $# -gt 0 ] || set -- deb rpm apk sysv unprivileged

case $(docker info --format '{{.Architecture}}') in
aarch64 | arm64)
    deb_arch=arm64
    rpm_arch=aarch64
    ;;
x86_64 | amd64)
    deb_arch=amd64
    rpm_arch=x86_64
    ;;
*)
    echo "run.sh: unsupported Docker host architecture" >&2
    exit 1
    ;;
esac

version=
for package in dist/filetrace_*_"$deb_arch".deb; do
    [ -f "$package" ] || continue
    if [ -n "$version" ]; then
        echo "run.sh: dist/ holds more than one deb for $deb_arch" >&2
        exit 1
    fi
    version=${package#dist/filetrace_}
    version=${version%_"$deb_arch".deb}
done
if [ -z "$version" ]; then
    echo "run.sh: dist/ holds no deb for $deb_arch; run tools/dist/package.sh first" >&2
    exit 1
fi

# The packages under test go in new/; old/ holds the same binaries under a
# lower version, to upgrade from.
work=dist/test
rm -rf "$work"
mkdir -p "$work/new" "$work/old" "$work/tarball"
cp dist/filetrace_*_"$deb_arch".deb dist/filetrace-*."$rpm_arch".rpm \
    dist/filetrace_*_"$rpm_arch".apk "$work/new/"
tar -xzf "dist/filetrace-$version-linux-$deb_arch.tar.gz" -C "$work/tarball" --strip-components=1
FILETRACE_VERSION=0.0.0.1 tools/dist/package.sh "$work/older" >/dev/null
cp "$work"/older/filetrace_*_"$deb_arch".deb "$work"/older/filetrace-*."$rpm_arch".rpm \
    "$work"/older/filetrace_*_"$rpm_arch".apk "$work/old/"

containers=
cleanup()
{
    # shellcheck disable=SC2086
    [ -z "$containers" ] || docker rm -f $containers >/dev/null 2>&1 || true
}
trap cleanup EXIT

# start <name> <docker run arguments...>
# Without systemd, --init gives the container a first process that reaps the
# daemons the service scripts leave behind.
start()
{
    container=filetrace-test-$1
    shift
    docker rm -f "$container" >/dev/null 2>&1 || true
    docker run -d --name "$container" \
        -v "$root:/src:ro" -v "$root/$work:/pkg:ro" "$@" >/dev/null
    containers="$containers $container"
}

# boot <name> <image>: a container with systemd as its init.
boot()
{
    docker build -q -t "filetrace-test-$2" -f "tests/packaging/images/$2.Dockerfile" \
        tests/packaging/images >/dev/null
    start "$1" --privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw "filetrace-test-$2"
    tries=60
    while [ "$tries" -gt 0 ]; do
        state=$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)
        case $state in
        running | degraded) return 0 ;;
        esac
        sleep 1
        tries=$((tries - 1))
    done
    echo "run.sh: systemd did not come up in $container" >&2
    return 1
}

run_case()
{
    docker exec -e FT_VERSION="$version" "$container" sh "/src/tests/packaging/cases/$1.sh"
}

failed=
for name in "$@"; do
    printf '== %s\n' "$name"
    code=0
    case $name in
    deb)
        boot deb debian-systemd && run_case deb || code=$?
        ;;
    rpm)
        boot rpm rocky-systemd && run_case rpm || code=$?
        ;;
    apk)
        docker build -q -t filetrace-test-alpine-openrc \
            -f tests/packaging/images/alpine-openrc.Dockerfile tests/packaging/images >/dev/null
        start apk --privileged --init filetrace-test-alpine-openrc && run_case apk || code=$?
        ;;
    sysv)
        start sysv --privileged --init debian:13 sleep infinity && run_case sysv || code=$?
        ;;
    unprivileged)
        start unprivileged --user 65534:65534 --cap-drop ALL \
            -v "$root/$work/tarball:/opt:ro" debian:13 sleep infinity &&
            run_case unprivileged || code=$?
        ;;
    *)
        echo "run.sh: unknown case: $name" >&2
        code=2
        ;;
    esac
    [ "$code" -eq 0 ] || failed="$failed $name"
done

if [ -n "$failed" ]; then
    echo "run.sh: failed:$failed" >&2
    exit 1
fi
