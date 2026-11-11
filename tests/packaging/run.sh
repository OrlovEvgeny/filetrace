#!/bin/sh
# usage: run.sh [<case>...]
# Installs the packages found in dist/ in containers and checks the result.
# Cases: deb rpm apk sysv unprivileged install-systemd install-openrc repo-apt
# repo-rpm repo-apk (default: all of them). The Docker host has to allow
# privileged containers and run a kernel with BTF.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"

[ $# -gt 0 ] || set -- deb rpm apk sysv unprivileged install-systemd install-openrc \
    repo-apt repo-rpm repo-apk

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
    dist/filetrace_*_"$rpm_arch".apk dist/install.sh "$work/new/"
tar -xzf "dist/filetrace-$version-linux-$deb_arch.tar.gz" -C "$work/tarball" --strip-components=1
FILETRACE_VERSION=0.0.0.1 tools/dist/package.sh "$work/older" >/dev/null
cp "$work"/older/filetrace_*_"$deb_arch".deb "$work"/older/filetrace-*."$rpm_arch".rpm \
    "$work"/older/filetrace_*_"$rpm_arch".apk "$work/old/"

# Both versions and a candidate published the way a release is: signed with
# throwaway keys, laid out as release assets, indexed into a download site,
# and uploaded to a directory that stands in for the bucket.
checksums()
{
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$@"
    else
        shasum -a 256 "$@"
    fi
}
tools/release/keys.sh "$work/keys" >/dev/null
export FILETRACE_GPG_KEY_FILE="$work/keys/gpg.key"
export FILETRACE_APK_KEY_FILE="$work/keys/filetrace.rsa"
for published in "$version-stable" 0.0.0.1-stable 0.0.0.2-prestable; do
    FILETRACE_VERSION=${published%-*} tools/dist/package.sh "$work/signed-$published" >/dev/null
    release=$work/releases/v$published
    mkdir -p "$release"
    find "$work/signed-$published" -maxdepth 1 -type f -exec cp {} "$release/" \;
    (cd "$release" && checksums ./*.tar.gz ./*.deb ./*.rpm ./*.apk | sed 's|  \./|  |' >SHA256SUMS)
done
tools/release/site.sh "$work/releases" "$work/site"
# rclone check compares the files of both sides; a bucket has no empty directories.
if ! {
    FILETRACE_SITE_REMOTE="$root/$work/bucket" tools/release/deploy.sh "$work/site" &&
        rclone check "$work/site" "$root/$work/bucket"
} 2>"$work/deploy.log"; then
    cat "$work/deploy.log" >&2
    echo "run.sh: the bucket does not hold the site" >&2
    exit 1
fi

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

# image <name>: builds tests/packaging/images/<name>.Dockerfile.
image()
{
    docker build -q -t "filetrace-test-$1" -f "tests/packaging/images/$1.Dockerfile" \
        tests/packaging/images >/dev/null
}

# boot <name> <image>: a container with systemd as its init.
boot()
{
    image "$2"
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
        image alpine-openrc &&
            start apk --privileged --init filetrace-test-alpine-openrc &&
            run_case apk || code=$?
        ;;
    sysv)
        image debian &&
            start sysv --privileged --init filetrace-test-debian &&
            run_case sysv || code=$?
        ;;
    install-systemd)
        boot install-systemd debian-systemd && run_case install-systemd || code=$?
        ;;
    install-openrc)
        image alpine-openrc &&
            start install-openrc --privileged --init filetrace-test-alpine-openrc &&
            run_case install-openrc || code=$?
        ;;
    repo-apt)
        boot repo-apt debian-systemd && run_case repo-apt || code=$?
        ;;
    repo-rpm)
        boot repo-rpm rocky-systemd && run_case repo-rpm || code=$?
        ;;
    repo-apk)
        image alpine-openrc &&
            start repo-apk --privileged --init filetrace-test-alpine-openrc &&
            run_case repo-apk || code=$?
        ;;
    unprivileged)
        image debian &&
            start unprivileged --user 65534:65534 --cap-drop ALL \
                -v "$root/$work/tarball:/opt:ro" filetrace-test-debian &&
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
