#!/bin/sh
# usage: guest.sh <probe sets> <scenario:runs...>
# Runs scenarios one after another on this machine, as inside a kernel VM where no container
# separates them: each in a session of its own that is ended with it, from a clean /data, /tmp
# and /run, between the lines the host splits the output by.
set -u

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
sets=$1
shift

for item in "$@"; do
    name=${item%:*}
    runs=${item##*:}
    for probes in $sets; do
        i=1
        while [ "$i" -le "$runs" ]; do
            rm -rf /data/acceptance /run/filetrace /tmp/case.* /tmp/transfers*.json /tmp/agent.log
            echo "FT_ACCEPTANCE_BEGIN $name $probes $i"
            # --foreground keeps the scenario's processes in this session, which is killed whole.
            setsid timeout --foreground -k 10 300 sh "$here/scenario.sh" "$name" "$probes" </dev/null 2>&1 &
            session=$!
            wait "$session"
            kill -KILL -- "-$session" 2>/dev/null
            echo "FT_ACCEPTANCE_END $name $probes $i"
            i=$((i + 1))
        done
    done
done
