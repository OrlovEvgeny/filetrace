#!/bin/sh
# usage: darwin.sh
# Builds the macOS binaries for this machine's architecture with the
# third-party libraries linked in, and stages them in dist/stage/darwin-<arch>.
# FILETRACE_VERSION and FILETRACE_COMMIT override what git reports.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"

version=${FILETRACE_VERSION:-$(tools/release/version.sh current)}
commit=${FILETRACE_COMMIT:-$(git rev-parse --short=12 HEAD)}

case $(uname -m) in
arm64) arch=arm64 ;;
x86_64) arch=amd64 ;;
*)
    echo "darwin.sh: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

build=build/dist-darwin-$arch
stage=dist/stage/darwin-$arch

cmake --preset dist -B "$build" -DFILETRACE_VERSION="$version" -DFILETRACE_COMMIT="$commit"
cmake --build "$build"
ctest --test-dir "$build" --output-on-failure

rm -rf "$stage"
mkdir -p "$stage/bin"
for name in filetrace filetrace-agent; do
    if otool -L "$build/$name" | tail -n +2 | grep -v '/usr/lib/libSystem'; then
        echo "darwin.sh: $name loads a library a clean system does not have" >&2
        exit 1
    fi
    cp "$build/$name" "$stage/bin/$name"
    strip -x "$stage/bin/$name"
done

reported=$("$stage/bin/filetrace" version | head -n 1)
if [ "$reported" != "Filetrace $version" ]; then
    echo "darwin.sh: built '$reported', expected 'Filetrace $version'" >&2
    exit 1
fi

# The libraries linked into the binaries, for the third-party notices.
{
    for module in libprotobuf-c libnghttp2; do
        printf '%s %s\n' "$module" "$(pkg-config --modversion "$module")"
    done
    printf 'termbox2 %s\n' "$(sed -n 's/^#define TB_VERSION_STR "\(.*\)"$/\1/p' third_party/termbox2/termbox2.h)"
} >"$stage/third-party.txt"

ls -l "$stage/bin"
