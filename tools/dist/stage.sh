#!/bin/sh
# usage: stage.sh <version> <commit>
# Runs inside the image built from tools/dist/Dockerfile.
set -eu

version=$1
commit=$2

case $(uname -m) in
x86_64) arch=amd64 ;;
aarch64) arch=arm64 ;;
*)
    echo "stage.sh: unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

build=build/dist-linux-$arch
stage=dist/stage/linux-$arch

# Alpine ships some static libraries as GCC LTO bytecode, which only the GCC
# driver can turn into code at link time.
cmake --preset dist -B "$build" \
    -DFILETRACE_VERSION="$version" \
    -DFILETRACE_COMMIT="$commit" \
    -DCMAKE_C_LINK_EXECUTABLE='gcc <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>'
cmake --build "$build"
ctest --test-dir "$build" --output-on-failure -R '^unit$'

rm -rf "$stage"
mkdir -p "$stage/bin" "$stage/debug"
for name in filetrace filetrace-agent; do
    if llvm-readelf --program-headers --dynamic-table "$build/$name" | grep -Eq 'INTERP|NEEDED'; then
        echo "stage.sh: $name is not fully static" >&2
        exit 1
    fi
    llvm-objcopy --only-keep-debug "$build/$name" "$stage/debug/$name.debug"
    llvm-objcopy --strip-all --add-gnu-debuglink="$stage/debug/$name.debug" \
        "$build/$name" "$stage/bin/$name"
done

reported=$("$stage/bin/filetrace" version | head -n 1)
if [ "$reported" != "Filetrace $version" ]; then
    echo "stage.sh: built '$reported', expected 'Filetrace $version'" >&2
    exit 1
fi

# The libraries linked into the binaries, for the third-party notices.
{
    printf 'musl %s\n' "$(apk info --installed --verbose musl | sed 's/^musl-//;s/-r[0-9]*$//')"
    for module in libbpf libelf zlib libzstd libprotobuf-c libnghttp2; do
        printf '%s %s\n' "$module" "$(pkg-config --modversion "$module")"
    done
} >"$stage/third-party.txt"

ls -l "$stage/bin"
