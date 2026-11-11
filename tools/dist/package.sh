#!/bin/sh
# usage: package.sh [<output directory>]
# Turns every tree under dist/stage into release archives in dist/, or in the
# directory given: a tarball per platform, plus deb, rpm and apk packages for
# Linux. FILETRACE_VERSION overrides the version git reports.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$root"

version=${FILETRACE_VERSION:-$(tools/release/version.sh current)}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
export SOURCE_DATE_EPOCH

stages=$root/dist/stage
dist=$root/dist
if [ $# -gt 0 ]; then
    mkdir -p "$1"
    dist=$(CDPATH='' cd -- "$1" && pwd)
fi
packaging=$root/packaging

# apk accepts digits, dots and a fixed set of suffixes: 26.11.1.80+5.gabc1234
# becomes 26.11.1.80_git5.
apk_version()
{
    case $1 in
    *+[0-9]*) printf '%s_git%s\n' "${1%%+*}" "$(printf '%s\n' "${1#*+}" | sed 's/[^0-9].*//')" ;;
    *) printf '%s\n' "${1%%+*}" ;;
    esac
}

# notices <third-party.txt> <output>
notices()
{
    {
        cat <<TEXT
The Filetrace binaries include the software listed below.

The source code of Filetrace and the scripts that build these binaries are at
https://github.com/OrlovEvgeny/filetrace, so the binaries can be rebuilt
against a modified copy of any of these libraries.
TEXT
        while read -r module module_version; do
            entry=$(grep "^$module|" "$packaging/licenses/components") || {
                echo "package.sh: no license recorded for $module" >&2
                exit 1
            }
            printf '\n%s\n%s %s\nLicense: %s\n%s\n%s\n\n' \
                '================================================================================' \
                "$(printf '%s\n' "$entry" | cut -d'|' -f2)" "$module_version" \
                "$(printf '%s\n' "$entry" | cut -d'|' -f3)" \
                "$(printf '%s\n' "$entry" | cut -d'|' -f4)" \
                '================================================================================'
            for text in $(printf '%s\n' "$entry" | cut -d'|' -f5); do
                cat "$packaging/licenses/$text"
                echo
            done
        done <"$1"
    } >"$2"
}

# archive <parent directory> <entry> <output.tar.gz>
archive()
{
    if tar --version 2>/dev/null | grep -q 'GNU tar'; then
        tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
            -C "$1" -cf "$3.tar" "$2"
    else
        tar --no-xattrs --no-mac-metadata --uid 0 --gid 0 --numeric-owner \
            -C "$1" -cf "$3.tar" "$2"
    fi
    gzip -n -9 <"$3.tar" >"$3"
    rm "$3.tar"
}

# script <name> <format> [<event>]: a maintainer script made of the shared
# library and the body for <name>.
script()
{
    {
        printf '#!/bin/sh\nset -e\nft_format=%s\n' "$2"
        [ -z "${3:-}" ] || printf 'ft_event=%s\n' "$3"
        cat "$packaging/scripts/lib.sh" "$packaging/scripts/$1.sh"
    }
}

docs()
{
    mkdir -p "$1"
    cp README.md LICENSE "$1/"
    notices "$stage/third-party.txt" "$1/THIRD_PARTY_LICENSES"
}

package_linux()
{
    arch=$1
    name=filetrace-$version-linux-$arch
    work=$dist/work/linux-$arch

    tree=$work/$name
    mkdir -p "$tree/bin" "$tree/etc/filetrace" "$tree/share/filetrace"
    cp "$stage/bin/filetrace" "$stage/bin/filetrace-agent" "$tree/bin/"
    cp "$packaging/config/config.toml" "$tree/etc/filetrace/"
    for part in systemd openrc sysv logrotate; do
        cp -R "$packaging/$part" "$tree/share/filetrace/"
    done
    docs "$tree/share/doc/filetrace"
    archive "$work" "$name" "$dist/$name.tar.gz"

    mkdir -p "$work/$name-debug"
    cp "$stage/debug/"*.debug "$work/$name-debug/"
    archive "$work" "$name-debug" "$dist/$name-debug.tar.gz"

    packaged=$work/root
    mkdir -p "$packaged/usr/bin" "$packaged/etc/filetrace" "$packaged/systemd" \
        "$packaged/sysv" "$packaged/openrc" "$packaged/logrotate" "$work/scripts"
    cp "$stage/bin/filetrace" "$stage/bin/filetrace-agent" "$packaged/usr/bin/"
    cp "$packaging/config/config.toml" "$packaged/etc/filetrace/"
    docs "$packaged/usr/share/doc/filetrace"
    sed 's|@bindir@|/usr/bin|g' "$packaging/systemd/filetrace-agent.service.in" \
        >"$packaged/systemd/filetrace-agent.service"
    sed 's|@bindir@|/usr/bin|g' "$packaging/sysv/filetrace-agent.in" \
        >"$packaged/sysv/filetrace-agent"
    sed 's|@bindir@|/usr/bin|g' "$packaging/openrc/filetrace-agent.in" \
        >"$packaged/openrc/filetrace-agent"
    cp "$packaging/openrc/filetrace-agent.confd" "$packaged/openrc/"
    cp "$packaging/logrotate/filetrace-agent" "$packaged/logrotate/"

    for format in deb rpm; do
        for hook in postinstall preremove postremove; do
            script "$hook" "$format" >"$work/scripts/$hook.$format"
        done
    done
    script postinstall apk install >"$work/scripts/postinstall.apk"
    script postinstall apk upgrade >"$work/scripts/postupgrade.apk"
    script preremove apk >"$work/scripts/preremove.apk"

    for format in deb rpm apk; do
        package_version=$version
        [ "$format" != apk ] || package_version=$(apk_version "$version")
        (cd "$work" && FT_ARCH=$arch FT_PACKAGE_VERSION=$package_version \
            nfpm package --config "$packaging/nfpm.yaml" --packager "$format" --target "$dist/")
    done
}

package_darwin()
{
    name=filetrace-$version-darwin-$1
    work=$dist/work/darwin-$1
    mkdir -p "$work/$name/bin"
    cp "$stage/bin/filetrace" "$stage/bin/filetrace-agent" "$work/$name/bin/"
    docs "$work/$name/share/doc/filetrace"
    archive "$work" "$name" "$dist/$name.tar.gz"
}

rm -rf "$dist/work"
rm -f "$dist"/*.tar.gz "$dist"/*.deb "$dist"/*.rpm "$dist"/*.apk

found=0
for stage in "$stages"/*; do
    [ -d "$stage" ] || continue
    found=1
    platform=$(basename "$stage")
    case $platform in
    linux-*) package_linux "${platform#linux-}" ;;
    darwin-*) package_darwin "${platform#darwin-}" ;;
    *)
        echo "package.sh: unknown platform: $platform" >&2
        exit 1
        ;;
    esac
done
if [ "$found" -eq 0 ]; then
    echo "package.sh: nothing is staged under dist/stage; run tools/dist/build.sh first" >&2
    exit 1
fi

find "$dist" -maxdepth 1 -type f | sort
