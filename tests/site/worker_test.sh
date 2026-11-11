#!/bin/sh
# usage: worker_test.sh
# Runs the tests of the Worker that serves filetrace.eorlov.org.
set -eu

command -v node >/dev/null 2>&1 || exit 77
exec node --test "$(dirname -- "$0")/worker_test.mjs"
