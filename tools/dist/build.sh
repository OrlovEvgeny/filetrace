#!/bin/sh
# usage: build.sh
# Builds fully static Linux binaries for this machine's architecture and stages
# them in dist/stage/linux-<arch>. FILETRACE_VERSION and FILETRACE_COMMIT
# override what git reports.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
image=${FILETRACE_DIST_IMAGE:-filetrace-dist}

docker build -q -t "$image" "$root/tools/dist" >/dev/null

version=${FILETRACE_VERSION:-$(cd "$root" && tools/release/version.sh current)}
commit=${FILETRACE_COMMIT:-$(git -C "$root" rev-parse --short=12 HEAD)}

exec docker run --rm -i \
    --user "$(id -u):$(id -g)" \
    -v "$root:/src" \
    -w /src \
    "$image" tools/dist/stage.sh "$version" "$commit"
