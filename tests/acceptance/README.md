# Acceptance scenarios

Programs that read and send files in exact orders, each judged against what really left the
machine: every file sent must be listed with the bytes it sent, and nothing else may be. They
load the agent's eBPF programs, so they run in privileged containers and are not part of
`mise run ci`.

```sh
mise run test:acceptance <dir>                    # every scenario on auto and kprobe
tests/acceptance/run.sh <dir> F017 one-way-stream # the rows of a finding, or scenarios by name
tests/acceptance/run.sh -n 4 <dir> F031           # at least four runs of each
tests/acceptance/run.sh -j 3 <dir>                # three containers at once
tests/acceptance/run.sh -w 10s <dir>              # the agent's correlation window set to 10 s
```

`<dir>` holds `filetrace` and `filetrace-agent` built for Linux on this machine's
architecture. The image is built from the `Dockerfile` here; `FILETRACE_ACCEPTANCE_IMAGE`,
`FILETRACE_ACCEPTANCE_PREFIX` (container names), `FILETRACE_ACCEPTANCE_PROBES` and
`FILETRACE_ACCEPTANCE_OUT` (logs and verdicts) change the defaults.

Each container runs with `--privileged --pid=host`: the agent needs both. All containers share
the kernel with whatever else runs on it, so a scenario only looks at its own processes and
at files under `/data/acceptance`. Load changes timing; parallel runs make flaky rows flakier.

`run.sh` copies this directory into the output directory and the containers mount that copy,
so the checkout can be edited or rebased while a run goes on.

## expected.txt

One row per scenario: its finding, the expected verdict on each probe set, what release
26.11.7.4 showed, how many runs it needs and, for a `LIMIT`, the documented limit or residue
that explains the deviation. `OK` is derived from what the scenario sent, never from what a
build did. A row fails when its verdict differs from the expected one, and is reported as worse
than the release when the release passed it.

## Adding a scenario

Write `cases/<name>.sh`, which sources `lib.sh` and ends with `RESULT: OK` or `RESULT: BUG`, or
register a function in `scenarios.py` that returns a `Case` naming every file it sent; then
add its row to `expected.txt`.
