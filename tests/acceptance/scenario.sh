#!/bin/sh
# usage: scenario.sh <scenario> auto|kprobe
# Runs one scenario inside the acceptance container; its last line is RESULT: OK or RESULT: BUG.
set -u

here=$(dirname "$0")
name=$1
PROBES=$2
export PROBES

if [ -f "$here/cases/$name.sh" ]; then
    exec sh "$here/cases/$name.sh"
fi

. "$here/lib.sh"
start_agent
python3 -u "$here/scenarios.py" "$name"
status=$?
stop_agent
exit $status
