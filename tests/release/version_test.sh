#!/bin/sh
# usage: version_test.sh <version.sh>
set -eu

command -v git >/dev/null 2>&1 || exit 77

script=$1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid

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

# Numbered subjects keep commits on different branches from sharing a hash.
serial=0

commits()
{
    count=$1
    while [ "$count" -gt 0 ]; do
        serial=$((serial + 1))
        git commit -q --allow-empty -m "chore: commit $serial"
        count=$((count - 1))
    done
}

release()
{
    git tag -a -m "$1" "$1" "${2:-HEAD}"
}

current()
{
    sh "$script" current "$@"
}

# next_field <field> <arguments of next...>
next_field()
{
    wanted=$1
    shift
    sh "$script" next "$@" | sed -n "s/^$wanted=//p"
}

short()
{
    git rev-parse --short=7 HEAD
}

git init -q -b master "$work/repo"
cd "$work/repo"

commits 3
check 'no release yet' "0.0.0.3+g$(short)" "$(current)"
refused 'a patch before any release' next patch
check 'first release, tag' v26.11.1.3-stable "$(next_field tag new --date 2026-11)"
check 'first release, version' 26.11.1.3 "$(next_field version new --date 2026-11)"
check 'first release, line' 26.11 "$(next_field line new --date 2026-11)"
check 'first release, previous' '' "$(next_field previous new --date 2026-11)"
check 'first release, latest' true "$(next_field latest new --date 2026-11)"
check 'first release, prerelease' false "$(next_field prerelease new --date 2026-11)"
check 'first release, commit' "$(git rev-parse HEAD)" "$(next_field commit new --date 2026-11)"

release v26.11.1.3-stable
git branch 26.11
check 'at a release' 26.11.1.3 "$(current)"
refused 'a release without commits' next patch
refused 'a second line in one month' next new --date 2026-11

commits 2
check 'after a release' "26.11.1.3+2.g$(short)" "$(current)"
check 'an explicit revision' 26.11.1.3 "$(current v26.11.1.3-stable)"

git switch -q 26.11
commits 2
check 'patch, tag' v26.11.2.2-stable "$(next_field tag patch)"
check 'patch, previous' v26.11.1.3-stable "$(next_field previous patch)"
check 'patch of the newest line, latest' true "$(next_field latest patch)"
release v26.11.2.2-stable

git switch -q master
check 'a patch does not reach master' "26.11.1.3+2.g$(short)" "$(current)"
check 'next line, tag' v26.12.1.2-stable "$(next_field tag new --date 2026-12)"
check 'next line, previous' v26.11.1.3-stable "$(next_field previous new --date 2026-12)"
check 'next line, latest' true "$(next_field latest new --date 2026-12)"
release v26.12.1.2-stable

git switch -q 26.11
commits 1
check 'patch of an older line, tag' v26.11.3.1-stable "$(next_field tag patch)"
check 'patch of an older line, latest' false "$(next_field latest patch)"
refused 'a patch that skips a release of its line' next patch --ref v26.11.1.3-stable

git switch -q master
commits 4
check 'candidate, tag' v27.1.1.4-prestable \
    "$(next_field tag new --channel prestable --date 2027-01)"
check 'candidate, prerelease' true \
    "$(next_field prerelease new --channel prestable --date 2027-01)"
check 'candidate, latest' false "$(next_field latest new --channel prestable --date 2027-01)"
release v27.1.1.4-prestable
check 'at a candidate' 27.1.1.4 "$(current)"
check 'release of the candidate commit' v27.1.1.4-stable "$(next_field tag new --date 2027-01)"

commits 1
check 'a candidate is not a base' "26.12.1.2+5.g$(short)" "$(current)"
check 'release after a candidate' v27.1.1.5-stable "$(next_field tag new --date 2027-01)"
release v27.1.1.5-stable
check 'a release wins over a candidate' 27.1.1.5 "$(current)"

commits 2
check 'lts line, tag' v27.3.1.2-lts "$(next_field tag new --channel lts --date 2027-03)"
release v27.3.1.2-lts
git switch -q -c 27.3
commits 1
check 'lts patch, tag' v27.3.2.1-lts "$(next_field tag patch)"
check 'lts patch, channel' lts "$(next_field channel patch)"
check 'lts candidate, tag' v27.3.2.1-prestable "$(next_field tag patch --channel prestable)"
refused 'a stable patch of an lts line' next patch --channel stable

printf 'one\n' >tracked
git add tracked
git commit -q -m 'chore: add a file'
printf 'two\n' >tracked
check 'modified tree' "27.3.1.2+2.g$(short).dirty" "$(current)"
git checkout -q tracked

refused 'an unknown revision' current no-such-revision
refused 'an unknown channel' next new --channel nightly
refused 'a malformed date' next new --date 2027-3
refused 'a date for a patch' next patch --date 2027-03
refused 'an unknown command' bump

printf '%d checks, %d failed\n' "$checks" "$failures"
[ "$failures" -eq 0 ]
