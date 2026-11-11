#!/bin/sh
# usage: config.sh <filetrace> <config.toml>
# The packaged configuration must be valid as shipped, state the built-in
# default of every setting it lists, and list every setting this build honors.
set -eu

cli=$1
template=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Settings the build accepts but cannot act on, or that cannot be turned off.
cat >"$work/omitted" <<'LIST'
correlation.track_fd_lifecycle
correlation.track_io_uring
correlation.track_process_lifecycle
file.track_mmap
file.track_open
file.track_splice
network.tc_egress
storage.enabled
storage.path
storage.retention
LIST

# keys <file>: one "section.key" per setting.
keys()
{
    awk '
        /^\[/ { section = substr($0, 2, length($0) - 2) }
        /^[a-z_0-9]+ = / { print section "." $1 }
    ' "$1" | sort
}

"$cli" config validate "$template" >/dev/null

sed -E 's/^# ([a-z_0-9]+ = )/\1/' "$template" >"$work/explicit.toml"
"$cli" config validate "$work/explicit.toml" >/dev/null

FILETRACE_CONFIG=$work/absent.toml "$cli" config show | grep -v '^#' >"$work/defaults"
FILETRACE_CONFIG=$work/explicit.toml "$cli" config show | grep -v '^#' >"$work/shown"
if ! diff "$work/defaults" "$work/shown"; then
    echo "config.sh: $template states a value that is not the built-in default" >&2
    exit 1
fi

keys "$work/defaults" >"$work/all"
keys "$work/explicit.toml" >"$work/listed"
sort "$work/listed" "$work/omitted" >"$work/accounted"
if ! diff "$work/all" "$work/accounted"; then
    echo "config.sh: $template and the settings of this build differ" >&2
    exit 1
fi
