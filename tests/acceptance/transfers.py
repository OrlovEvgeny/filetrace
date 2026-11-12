#!/usr/bin/env python3
"""Asks the agent for its transfers at once and again 5 s later, when a window that aged
has reported, and prints every record either answer held as one JSON list (the later copy
of a record wins). Files of the scenario only one answer held are named on standard error."""
import json
import subprocess
import sys
import time

FT = "/ft/bin/filetrace"
DATA = "/data/acceptance/"
LATE = 5


def query():
    for _ in range(5):
        out = subprocess.run([FT, "transfers", "--json"], capture_output=True, text=True)
        if out.stdout.strip():
            return json.loads(out.stdout)
        time.sleep(1)
    print("filetrace transfers gave no answer: %s" % out.stderr.strip(), file=sys.stderr)
    return []


def key(r):
    if "transfer_id" in r:
        return r["transfer_id"]
    f, n, t = r.get("file") or {}, r.get("network") or {}, r["transfer"]
    return (r["process"]["pid"], f.get("path"), n.get("socket_id"), n.get("remote_port"), t["method"])


def both():
    now = query()
    time.sleep(LATE)
    late = query()
    merged = {key(r): r for r in now}
    merged.update((key(r), r) for r in late)
    early, later = {key(r) for r in now}, {key(r) for r in late}
    for tid in sorted(early ^ later, key=str):
        r = merged[tid]
        if ((r.get("file") or {}).get("path") or "").startswith(DATA):
            print("  only %s: pid %d %s %d B" % ("at once" if tid in early else "%d s later" % LATE, r["process"]["pid"], r["file"]["path"], r["transfer"]["bytes_sent"]), file=sys.stderr)
    return list(merged.values())


if __name__ == "__main__":
    json.dump(both(), sys.stdout)
