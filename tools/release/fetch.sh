#!/bin/sh
# usage: fetch.sh <directory>
# Downloads the packages and the installer of every published release into
# <directory>/<tag>/, the layout site.sh reads. Candidates are left out.
# Needs gh, signed in to the repository.
set -eu

[ $# -eq 1 ] || {
    echo "usage: fetch.sh <directory>" >&2
    exit 2
}

gh release list --exclude-drafts --exclude-pre-releases --limit 1000 \
    --json tagName --jq '.[].tagName' |
    while read -r tag; do
        case $tag in
        v*-stable | v*-lts) ;;
        *) continue ;;
        esac
        mkdir -p "$1/$tag"
        gh release download "$tag" --dir "$1/$tag" --clobber \
            --pattern '*.deb' --pattern '*.rpm' --pattern '*.apk' --pattern install.sh
    done
