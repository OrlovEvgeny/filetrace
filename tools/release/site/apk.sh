#!/bin/sh
# Builds the apk repositories of the site. Runs in the image of
# alpine.Dockerfile with the releases at /releases, the site at /site and the
# RSA private key at /keys/filetrace.rsa; apk looks a signature up by that name.
set -eu

mkdir -p /site/apk
openssl rsa -in /keys/filetrace.rsa -pubout -out /site/apk/filetrace.rsa.pub 2>/dev/null

channels=stable
for release in /releases/v*-lts; do
    [ ! -d "$release" ] || channels='stable lts'
done

for channel in $channels; do
    for arch in x86_64 aarch64; do
        target=/site/apk/$channel/$arch
        mkdir -p "$target"
        for package in /releases/*/filetrace_*_"$arch".apk; do
            [ -f "$package" ] || continue
            case $channel:$package in
            stable:* | lts:/releases/v*-lts/*) ;;
            *) continue ;;
            esac
            # apk fetches a package by the name and version its index records.
            version=$(tar -xzOf "$package" .PKGINFO 2>/dev/null | sed -n 's/^pkgver = //p')
            cp "$package" "$target/filetrace-$version.apk"
        done
        set -- "$target"/*.apk
        [ -f "$1" ] || continue
        apk index --allow-untrusted --quiet --rewrite-arch "$arch" \
            --output "$target/APKINDEX.tar.gz" "$@"
        abuild-sign -q -k /keys/filetrace.rsa "$target/APKINDEX.tar.gz"
    done
done
