# shellcheck shell=sh disable=SC2034
# Sourced by the cases: the agent's start and stop, and what Filetrace listed.
# PROBES is auto or kprobe; the binaries under test are in /ft/bin.

FT=/ft/bin
SINK=/acceptance/sink.py
TLS=/opt/ft-acceptance/tls
PROBES=${PROBES:?PROBES must be auto or kprobe}

start_agent() {
    mkdir -p /run/filetrace
    set -- --probes "$PROBES"
    if [ -n "${FILETRACE_ACCEPTANCE_WINDOW:-}" ]; then
        printf '[correlation]\nwindow = "%s"\n' "$FILETRACE_ACCEPTANCE_WINDOW" >/tmp/acceptance-agent.toml
        set -- "$@" --config /tmp/acceptance-agent.toml
        echo "agent correlation window: $FILETRACE_ACCEPTANCE_WINDOW"
    fi
    "$FT/filetrace-agent" "$@" >/tmp/agent.log 2>&1 &
    AGENT=$!
    i=0
    while [ ! -S /run/filetrace/agent.sock ] && [ $i -lt 100 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    sleep 0.7
}

stop_agent() {
    kill "$AGENT" 2>/dev/null
    wait "$AGENT" 2>/dev/null
}

# Writes to /tmp/transfers.json every record listed at once or 5 s later.
fetch_transfers() {
    python3 /acceptance/transfers.py >/tmp/transfers.json
}

# report <directory> <pids>: prints every transfer listed for a file under <directory> or for <pids>.
report() {
    fetch_transfers
    python3 - "$1" "$2" <<'PY'
import json, sys
d, pids = sys.argv[1], set(int(x) for x in sys.argv[2].split() if x)
n = 0
for r in json.load(open("/tmp/transfers.json")):
    f = r.get("file") or {}
    if r["process"]["pid"] in pids or (f.get("path") or "").startswith(d):
        t = r["transfer"]; net = r["network"]
        print("  filetrace: pid=%d %s %s -> %s:%s %s %s sent=%d read=%d" % (r["process"]["pid"], r["process"]["name"], f.get("path"), net.get("remote_ip"), net.get("remote_port"), t["method"], t["confidence"], t["bytes_sent"], t["bytes_read"]))
        n += 1
if n == 0:
    print("  filetrace: no transfer listed")
PY
}
