#!/bin/sh
# usage: notes.sh [<tag> <previous tag or ""> <commit>]
# Prints the notes of the release that tags <commit> as <tag>, from the commits
# after <previous tag>. Without arguments, prints what a release cut now would
# say.
set -eu

cd "$(dirname -- "$0")/../.."

if [ $# -eq 0 ]; then
    exec git-cliff --unreleased --strip all
fi

tag=$1
previous=$2
commit=$3

if [ -z "$previous" ]; then
    exec git-cliff --tag "$tag" --strip all "$commit"
fi
git-cliff --tag "$tag" --strip all "$previous..$commit"
printf '\n[Every change](https://github.com/OrlovEvgeny/filetrace/compare/%s...%s)\n' \
    "$previous" "$tag"
