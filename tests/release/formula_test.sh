#!/bin/sh
# usage: formula_test.sh <formula.sh>
set -eu

script=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

checks=0
failures=0

check()
{
    checks=$((checks + 1))
    if [ "$2" != "$3" ]; then
        printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3" >&2
        failures=$((failures + 1))
    fi
}

# has <what> <file> <line>: <file> holds <line> exactly once.
has()
{
    check "$1" 1 "$(grep -cxF -- "$3" "$2" || true)"
}

refused()
{
    what=$1
    shift
    checks=$((checks + 1))
    if sh "$script" "$@" >/dev/null 2>&1; then
        printf 'FAIL %s\n  expected a refusal of: %s\n' "$what" "$*" >&2
        failures=$((failures + 1))
    fi
}

sums=$work/SHA256SUMS
serial=1000
for platform in darwin-arm64 darwin-amd64 linux-arm64 linux-amd64; do
    serial=$((serial + 1))
    printf '%s%060d  filetrace-26.11.2.3-%s.tar.gz\n' "$serial" 0 "$platform"
done >"$sums"
printf '%064d  filetrace-26.11.2.3-linux-amd64.deb\n' 0 >>"$sums"

sh "$script" 26.11.2.3 v26.11.2.3-lts "$sums" >"$work/filetrace.rb"
sh "$script" --line 26.11.2.3 v26.11.2.3-lts "$sums" >"$work/filetrace@26.11.rb"
FILETRACE_RELEASE_URL=file:///srv/dist sh "$script" 26.11.2.3 v26.11.2.3-lts "$sums" >"$work/local.rb"

has 'class of the formula' "$work/filetrace.rb" 'class Filetrace < Formula'
has 'version' "$work/filetrace.rb" '  version "26.11.2.3"'
has 'url of an archive' "$work/filetrace.rb" \
    '      url "https://filetrace.eorlov.org/dist/v26.11.2.3-lts/filetrace-26.11.2.3-linux-arm64.tar.gz"'
check 'one url per archive' 4 "$(grep -c '^      url "' "$work/filetrace.rb")"
check 'one checksum per archive' 4 "$(grep -c '^      sha256 "[0-9a-f]\{64\}"$' "$work/filetrace.rb")"
check 'the formula is linked' 0 "$(grep -c keg_only "$work/filetrace.rb" || true)"

has 'class of the line formula' "$work/filetrace@26.11.rb" 'class FiletraceAT2611 < Formula'
has 'the line formula is keg-only' "$work/filetrace@26.11.rb" '  keg_only :versioned_formula'
check 'the line formula differs only in class and keg' \
    "$(sed 1d "$work/filetrace.rb")" "$(sed -e 1d -e '/keg_only/,/^$/d' "$work/filetrace@26.11.rb")"

has 'url under another base' "$work/local.rb" \
    '      url "file:///srv/dist/v26.11.2.3-lts/filetrace-26.11.2.3-darwin-arm64.tar.gz"'

if command -v ruby >/dev/null 2>&1; then
    for formula in "$work/filetrace.rb" "$work/filetrace@26.11.rb"; do
        check "ruby parses $(basename "$formula")" 0 "$(ruby -c "$formula" >/dev/null 2>&1 && echo 0 || echo 1)"
    done
fi

grep -v darwin-amd64 "$sums" >"$work/partial"
refused 'an archive without a checksum' 26.11.2.3 v26.11.2.3-lts "$work/partial"
refused 'missing arguments' --line 26.11.2.3 v26.11.2.3-lts

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
