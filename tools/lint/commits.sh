#!/bin/sh
# usage: commits.sh [<revision range>]
# The range defaults to $FILETRACE_COMMIT_RANGE, then to what master lacks.
set -eu

range=${1:-${FILETRACE_COMMIT_RANGE:-origin/master..HEAD}}
types='feat|fix|chore|refactor|docs|test|perf'
failed=0

for commit in $(git rev-list --no-merges "$range"); do
    subject=$(git log -1 --format=%s "$commit")
    reason=
    if ! printf '%s\n' "$subject" | grep -Eq "^($types)!?: [a-z0-9]"; then
        reason="must read '<type>: <subject>' with a lowercase subject and one of: $types"
    elif [ "${#subject}" -gt 72 ]; then
        reason='is longer than 72 characters'
    elif printf '%s\n' "$subject" | grep -q '\.$'; then
        reason='ends with a period'
    fi
    if [ -n "$reason" ]; then
        printf '%s %s\n    %s\n' "$(git rev-parse --short "$commit")" "$subject" "$reason" >&2
        failed=1
    fi
done

exit "$failed"
