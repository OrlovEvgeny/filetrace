#!/bin/sh
# usage: site.sh <releases directory> <site directory>
# Builds the download site from <releases directory>/<tag>/<release assets>:
# the files of every release under dist/<tag>/ and, from the stable and lts
# releases, signed apt, yum and apk repositories, the installer of the newest
# one, the public keys, and the files install.sh reads to find a version.
# FILETRACE_GPG_KEY_FILE and FILETRACE_APK_KEY_FILE name the private keys.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
[ $# -eq 2 ] || {
    echo "usage: site.sh <releases directory> <site directory>" >&2
    exit 2
}
: "${FILETRACE_GPG_KEY_FILE:?names the OpenPGP private key}"
: "${FILETRACE_APK_KEY_FILE:?names the RSA private key}"

releases=$(CDPATH='' cd -- "$1" && pwd)
rm -rf "$2"
mkdir -p "$2/dist"
site=$(CDPATH='' cd -- "$2" && pwd)
gpg_key=$(CDPATH='' cd -- "$(dirname -- "$FILETRACE_GPG_KEY_FILE")" && pwd)/$(basename -- "$FILETRACE_GPG_KEY_FILE")
apk_key=$(CDPATH='' cd -- "$(dirname -- "$FILETRACE_APK_KEY_FILE")" && pwd)/$(basename -- "$FILETRACE_APK_KEY_FILE")

# newest <channel>...: the tag, without its v, of the highest version in these channels.
newest()
{
    for channel in "$@"; do
        for release in "$releases"/v*-"$channel"; do
            [ -d "$release" ] || continue
            tag=${release##*/}
            printf '%s\n' "${tag#v}"
        done
    done | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | tail -n 1
}

for release in "$releases"/v*; do
    [ -d "$release" ] || continue
    cp -R "$release" "$site/dist/"
done
if [ -z "$(ls "$site/dist")" ]; then
    echo "site.sh: no release under $releases" >&2
    exit 1
fi
install -m 0644 "$root/packaging/site/index.html" "$site/index.html"

latest=$(newest stable lts)
# Candidates alone give nothing to index and no version to install by channel.
[ -n "$latest" ] || exit 0

mkdir "$site/channels" "$site/versions"
for release in "$releases"/v*-stable "$releases"/v*-lts; do
    [ -d "$release" ] || continue
    tag=${release##*/}
    version=${tag#v}
    printf '%s\n' "$tag" >"$site/versions/${version%-*}"
done
printf '%s\n' "${latest%-*}" >"$site/channels/stable"
latest_lts=$(newest lts)
[ -z "$latest_lts" ] || printf '%s\n' "${latest_lts%-*}" >"$site/channels/lts"

run()
{
    image=$1
    shift
    docker build -q -t "filetrace-site-$image" -f "$root/tools/release/site/$image.Dockerfile" \
        "$root/tools/release/site" >/dev/null
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
        -v "$root:/src:ro" -v "$releases:/releases:ro" -v "$site:/site" "$@"
}
run debian -v "$gpg_key:/keys/gpg.key:ro" filetrace-site-debian \
    sh /src/tools/release/site/apt-rpm.sh
run alpine -v "$apk_key:/keys/filetrace.rsa:ro" filetrace-site-alpine \
    sh /src/tools/release/site/apk.sh

install -m 0755 "$releases/v$latest/install.sh" "$site/install.sh"
