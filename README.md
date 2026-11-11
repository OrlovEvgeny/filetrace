# Filetrace

Filetrace shows which files a machine sends over the network, which process
sends them, and where they go. It observes the operating system itself, so no
application has to be changed, and it says how sure each answer is.

```text
$ sudo filetrace files
FILE                    PROCESS  DESTINATION   BYTES    METHOD      CONFIDENCE
/var/www/video.mp4      nginx    198.51.100.4  1.20 GB  sendfile    EXACT
/data/export/users.csv  python   192.0.2.10    85.2 MB  read-write  INFERRED
```

The questions it answers run in both directions:

| From | To | Command |
|---|---|---|
| a file | who sends it, and to whom | `filetrace inspect file /data/report.pdf` |
| an address | the files sent to it | `filetrace files --remote 203.0.113.25` |
| a process | what it is sending now | `filetrace inspect process 1245` |
| the network | the processes behind the traffic | `filetrace processes` |

## Platform support

| Platform | Collection | Status |
|---|---|---|
| Linux 6.1 or later | eBPF through libbpf and CO-RE | Tested on Linux 6.1, 6.12 and 7.0, arm64 |
| macOS | none | The CLI builds and reports diagnostics; collection needs an Endpoint Security system extension |
| FreeBSD | none | Collection needs a DTrace backend |

Kernel functions are traced through BPF trampolines (fentry/fexit) where the
kernel can attach them and through kprobes where it cannot, as on arm64 before
6.4. `filetrace doctor` loads and attaches every probe on the machine it runs
on and reports which of the two is in use and what the kernel accepted. Other
kernels and x86-64 are expected to work through CO-RE but are untested.

## Try it

On any machine with Docker, including macOS:

```sh
tools/dev/linux.sh tools/dev/demo.sh
```

This builds the project in a Linux container, starts the agent, sends files
with `sendfile(2)`, with a read+send loop and over UDP, and walks through the
commands below. The container sees the kernel it runs on: under Docker Desktop
that is the Docker VM, not the macOS host.

For the live view, in two terminals:

```sh
tools/dev/linux.sh build/demo/filetrace watch
tools/dev/linux.sh build/demo/tests/ft_workload steady /tmp/big.bin 200000000 20
```

## Build

Linux needs Clang 19 or later (C23 and `#embed`), CMake 3.25, libbpf 1.3 and
`llvm-strip`. `tools/dev/Dockerfile` lists the Debian packages.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo build/filetrace doctor
```

`-DFILETRACE_SANITIZE=ON` builds with AddressSanitizer and
UndefinedBehaviorSanitizer.

## Two programs

`filetrace-agent` loads the probes, keeps what they report in bounded memory
and answers queries on a local socket. `filetrace` is the command-line
interface: it asks the agent and prints. Only the agent needs privileges to
load BPF programs; the socket accepts root and the agent's own user.

```sh
sudo filetrace-agent &       # or: sudo filetrace agent run
sudo filetrace watch
```

Without a running agent, `filetrace watch` and `filetrace events --follow`
collect in the foreground for as long as they run.

## Commands

```text
filetrace [--socket <path>] [--config <path>] <command> [options]
```

`filetrace` alone reports whether the agent is running and lists the commands.

| Command | Shows |
|---|---|
| `watch` | Live view: file transfers in progress, with process, destination, method and rate; keys switch to processes and connections |
| `files` | Files associated with network transfers |
| `processes` | Outbound rate, files sent and open connections per process |
| `connections` | Open and recently closed sockets, by their local and remote ends |
| `flows` | Bytes per process, socket and remote endpoint |
| `inspect` | Everything known about one `file`, `process`, `socket`, `flow` or `ip` |
| `events` | The agent's records in order: process, socket, network and transfer events |
| `stats` | The agent's own events, losses, CPU and memory |
| `doctor` | Whether this machine can be monitored: kernel, every probe, features, pipeline |
| `config` | The configuration in effect; validates a file |
| `version` | Version, build and platform |

Also: `top` (highest-volume processes, files, destinations or connections),
`transfers` (transfer records including sent bytes no file accounts for),
`capabilities` (each feature as FULL, PARTIAL, UNAVAILABLE or DISABLED, with
the reason) and `agent run|status|stop`.

`filetrace help <command>` lists a command's options, examples and exit codes.

### Common filters

`--pid`, `--process`, `--user`, `--cgroup`, `--namespace`, `--file` (also
`--path`, with `*` wildcards), `--path-regex`, `--remote` and `--local` (an
address or a CIDR network), `--port`, `--protocol`, `--method`,
`--confidence`, `--min-bytes`, `--min-size`, `--since`, `--until`, `--active`,
`--completed`, `--sort`, `--limit`. Each command accepts the ones that apply
to what it lists. `--resolve-hostnames` shows remote addresses by name where a
reverse DNS lookup finds one.

### Output

Every listing prints as `table`, `json`, `jsonl`, `csv` or `quiet`
(`--format`, or `--json` and `--jsonl`). Machine-readable formats carry exact
byte counts and RFC 3339 timestamps, and use one schema for a transfer whether
it comes from `files` or from `events`. A record of the demo above, wrapped
for reading:

```json
{
  "event": "file_transfer",
  "transfer_id": "tr_4",
  "timestamp": "2026-11-11T12:00:04.561Z",
  "host": "c52a23e07bc3",
  "platform": "linux",
  "process": {"pid": 7672, "ppid": 7529, "name": "ft_workload",
              "executable": "/src/build/demo/tests/ft_workload"},
  "file": {"path": "/var/tmp/filetrace-demo/video.mp4", "inode": 366815, "device": 63,
           "size": 50000000, "owner": "root", "filesystem": "overlay", "deleted": false},
  "network": {"protocol": "tcp", "socket_id": 421,
              "local_ip": "127.0.0.1", "local_port": 45190,
              "remote_ip": "127.0.0.1", "remote_port": 48175},
  "transfer": {"method": "sendfile", "bytes_sent": 50000000, "bytes_per_second": 0,
               "operations": 1, "started": "2026-11-11T12:00:04.561Z", "duration_ms": 0,
               "state": "active", "confidence": "exact",
               "evidence": ["direct_file_to_socket_transfer", "file_identity",
                            "socket_identity", "remote_endpoint"],
               "incomplete": false}
}
```

`file.size`, `transfer.bytes_read` and `transfer.bytes_sent` are three
different numbers: the size of the file when it was first seen, what a thread
read from it, and what the socket accepted. In `files` a record covers a
transfer's whole lifetime; in `events` it covers one collection interval.

Sockets, flows and transfers have stable IDs (`SOCKET`, `FLOW` and `ID`
columns, `socket_id`, `flow_id` and `transfer_id` fields) that `inspect`
takes.

Exit code 9 means the answer may be incomplete: events were lost inside the
queried time range. Lost events are also counted in `watch`, `stats` and
`doctor`.

### watch

```text
FILETRACE  web-01 · Linux 6.8  LIVE

4             13            6.67 MB/s
Transfers     Processes     Outbound

ACTIVE FILE TRANSFERS
PROCESS      FILE                         DESTINATION    METHOD           RATE  CONFIDENCE
nginx 1245   /var/www/stream.bin          203.0.113.25   sendfile    6.67 MB/s  EXACT
nginx 1245   /var/www/video.mp4           198.51.100.10  sendfile        0 B/s  EXACT
python 892   /data/export/customers.csv   203.0.113.50   read-write      0 B/s  INFERRED

● EXACT: 2   ● INFERRED: 1   LOST: 0
[F] Files  [P] Processes  [N] Network  [Space] Pause  [?] Help  [Q] Quit
```

`--no-ui` appends a snapshot per interval instead, which is also what happens
when the output is not a terminal.

### inspect

```text
$ filetrace inspect file /var/www/video.mp4
FILE
────────────────────────────────────
Path:             /var/www/video.mp4
Device:           253:0
Inode:            366815
Size:             47.7 MB
Owner:            www-data
Deleted:          no

TRANSFER HISTORY
────────────────────────────────────
TIME                 PROCESS  PID   REMOTE               BYTES    METHOD    CONFIDENCE
2026-11-11 12:00:04  nginx    1245  198.51.100.10:48175  47.7 MB  sendfile  EXACT

TOTALS
────────────────────────────────────
Total sent:       47.7 MB
Destinations:     1
Processes:        1
Transfers:        1
Active transfers: 1

PROVENANCE
────────────────────────────────────
sendfile:         1 transfer
Exact:            1

History starts at 2026-11-11 12:00:04, when the agent started.
Nothing earlier is kept.
```

`inspect process <pid>` adds what the system knows about a running process
(cgroup, open files) to what the agent observed (connections, rates, top
destinations, files sent). `inspect ip <address|cidr>` lists the processes
that talk to an address and the files sent to it.

### events

```text
$ filetrace events --type file_transfer --since 5m
12:00:06.737 FILE_TRANSFER
  pid=1245
  process=nginx
  file=/var/www/stream.bin
  inode=366820
  socket=434
  remote=203.0.113.25:39063
  bytes=2000000
  method=sendfile
  confidence=exact
```

Event types: `process_exec`, `process_fork`, `process_exit`,
`socket_connect`, `socket_listen`, `socket_established`, `socket_close`,
`file_seen`, `network_send`, `network_receive`, `file_transfer`,
`event_loss`. Byte counts are gathered in the kernel and collected several
times a second, so a network or transfer event carries the bytes of one such
interval, not of one system call; file opens and single system calls are not
recorded. `--follow` prints events as they happen. Past events come from a log
of bounded size (1 MB by default) that holds the most recent ones.

## Confidence

| Level | Meaning |
|---|---|
| EXACT | The kernel moved the file's data to the socket in one operation (`sendfile`) |
| INFERRED | A thread read the file and then sent on the socket (`read-write`); the payload cannot be proven to come only from that file |
| UNKNOWN | Bytes were sent and no file could be associated with them |

STRONG is defined for provenance followed through intermediate operations; no
probe produces it. A level is never raised by a filter or an output format,
and every record lists the evidence behind it.

Byte counts are what the local socket accepted. They are not the number of
bytes on the wire and not what the remote end acknowledged.

## Configuration

The agent reads `/etc/filetrace/config.toml` if it exists (`--config` or
`$FILETRACE_CONFIG` name another file); its command-line options override the
file. `filetrace config show` prints every setting with the value in effect,
and is a way to write a first file:

```toml
[agent]
enabled = true
mode = "standard"            # "minimal": processes, sockets and byte counts only
probes = "auto"              # or "trampoline", "kprobe"
socket = "/run/filetrace/agent.sock"
ring_buffer_size = "4MB"     # kernel-to-agent event queue
event_batch_size = 512       # counters read from the kernel per call
flush_interval = "250ms"
event_log_size = "1MB"       # 0 keeps no events
log_level = "info"

[network]
tcp = true
udp = true
ipv4 = true
ipv6 = true

[file]
track_read = true            # read-write attribution
track_sendfile = true        # sendfile attribution

[correlation]
enabled = true
window = "2s"                # longest read-to-send gap that still associates
confidence_threshold = "inferred"   # "exact" reports sendfile only
inferred_min_bytes = "1KB"
inferred_min_percent = 5

[limits]                     # entries per table; the least recently used go first
processes = 4096
sockets = 16384
flows = 16384
files = 16384
transfers = 16384
kernel_counters = 16384
kernel_files = 16384

[output]
format = "table"             # default format of the listing commands
timestamps = true

[filters]
exclude_processes = ["systemd"]
exclude_paths = ["/proc/*", "/sys/*"]
```

The file also accepts `[network] tc_egress`, `[file] track_open`,
`track_mmap` and `track_splice`, `[correlation] track_fd_lifecycle` and
`track_io_uring`, and a `[storage]` section. This build cannot do what they
ask: setting one to `true` is reported as a warning by `filetrace config
validate` and by the agent when it starts, and is otherwise ignored. An
unknown setting or a value of the wrong kind is an error (exit code 6).

## How it works

BPF programs attach to tracepoints and kernel functions:

| Probe | Records |
|---|---|
| `sched_process_exec`, `_fork`, `_exit` | Process identity and lifetime |
| `inet_sock_set_state` | TCP connect, listen, establish and close |
| `inet_sendmsg`, `inet_recvmsg` and the IPv6 pair | Bytes per socket, process and remote endpoint |
| `do_splice_direct` | `sendfile`: file and socket in the same kernel operation |
| `vfs_read` | Which regular file each thread read last, and how much |
| `__destroy_inode` | The end of a deleted file, after which its inode number can name another |

The probes see the kernel's own file and socket objects, so nothing is keyed
on file descriptor numbers and descriptor reuse cannot misattribute a
transfer. A file is identified by device and inode; its path, size and owner
are read from the kernel when the file is first seen and are only labels. A
file that is given the inode number of a deleted one is a separate file with
its own path.

High-frequency data never becomes one event per call. Byte counts accumulate
in a kernel hash map keyed by socket, process and file; the agent swaps that
map for an empty one every 250 ms and reads the idle one, so no update is
lost. Process and socket lifecycle events travel through a ring buffer. Rates
are bytes per second over the last one to two seconds.

A read+send association is recorded when a thread sends within the correlation
window (2 s) after reading a regular file, with no receive in between, and
only up to the number of bytes it read. It is reported once it covers at least
1 KB and 5% of what was read from the file.

All state is in memory and bounded: every table has a fixed capacity and
forgets its least recently updated entry, and the event log keeps separate
shares for transfers, network and process events so that a flood of one kind
does not push out the others. History starts when the agent starts, and every
report that depends on it says so.

### Without BPF trampolines

The table above needs the return value of each traced function. Where the
kernel cannot attach trampolines, the usual substitute is a return probe, and
it does not hold up here: a return probe keeps one of a small pool of
instances for as long as the call blocks (as many as there are CPUs on a
kernel without full preemption), so a few threads waiting in `recv` are
enough for every other return to go unseen.

The kprobe set therefore probes function entries only and reads the results
from counters the kernel keeps anyway:

| Probe | Records |
|---|---|
| `tcp_sendmsg`, `tcp_cleanup_rbuf` | TCP bytes, as the advance of the socket's send and receive sequence numbers |
| `inet_sock_set_state` | Connection start, and the last bytes before the FIN, which takes a sequence number itself |
| `ip_send_skb`, `ip6_send_skb`, `skb_consume_udp` | UDP datagrams, each with its length and its peer |
| `do_splice_direct` | `sendfile`: the file, capped by what is left of it, claims the bytes the socket takes next |
| `vfs_read` | Which file each thread reads; the size comes from the task's I/O accounting |
| `inet_sock_destruct`, `__destroy_inode` | The end of a socket and of a deleted file |

Sequence numbers cannot miss a call: whatever was sent since the socket was
last looked at is the difference. `--probes kprobe` selects this set on any
kernel.

## Limits

- With the kprobe set: the bytes of the last send on a connection are counted
  when the socket is next used or closed; kernel TLS sockets count encrypted
  bytes; raw and ICMP sockets are not counted; file reads need a kernel built
  with `CONFIG_TASK_XACCT`.
- A file read by one thread and sent by another, or passed through a pipe, is
  not associated with the send.
- Files read with `readv`, io_uring or through a memory mapping are not seen
  as read. Bytes sent through io_uring are still counted per socket.
  `--method splice`, `mmap` and `io_uring` are accepted and refused with exit
  code 5 rather than answered with an empty list.
- With the kprobe set, what a thread reads with `readv` between a file read
  and a send is counted as read from that file.
- A file read entirely before a fresh TLS connection is opened is not
  associated: the handshake's receive ends the association.
- An inferred association can be wrong when a thread reads one file and then
  sends unrelated data of similar size without receiving in between.
- `--since` and `--until` select records by when they were active; byte counts
  cover each record's whole observed lifetime.
- Inside a container on overlayfs, device and inode are those of the overlay
  mount. On btrfs, files in different subvolumes can share an inode number.
- An accepted connection has no owning process until that process sends or
  receives on it.

Not included in this build: persistent history, Prometheus and OpenTelemetry
exporters, packet-level counters, TLS attribution, and the `record`, `replay`,
`monitor` and `integrations` commands.

## Tests

```sh
ctest --test-dir build --output-on-failure
```

`unit` covers formatting, the bounded tables and the event log, the
correlation state and its filters, the configuration file, the IPC round trip
with a scripted backend including a live event stream, and every output
format; it runs on Linux and macOS. `integration-auto` and
`integration-kprobe` need root and a supporting kernel, and are skipped
otherwise. They start the agent with the probe set the kernel prefers and with
the kprobe set, generate real transfers (sendfile over IPv4 and IPv6,
read+send, UDP, descriptor reuse across 25 files, rename and unlink during a
transfer, a half-closed exchange with peeked and awaited replies, sends and
sendfiles accepted only in part, a transfer at a steady rate) and assert on
exact byte counts, rates, confidence levels and the output of every command,
with and without a configuration file.

From macOS, `tools/dev/linux.sh <command>` runs a command in the Linux
container with the source tree mounted at `/src`. To test against another
kernel, `tools/dev/vm.sh <version> <command>` boots it under QEMU inside a
container, with the build as its root filesystem:

```sh
tools/dev/vm.sh 6.1 'sh /ft/tests/integration/run.sh /ft/bin /ft/bin/ft_workload'
```

Debian's 6.1 and 6.12 arm64 kernels are included; the first has no BPF
trampolines and exercises the kprobe set as shipped.

## Overhead

`benchmarks/run.sh` times the traced system calls with and without the agent.
One run of each probe set on Linux 7.0.14, arm64, 12 CPUs, inside the Docker
Desktop VM, in nanoseconds per call:

| Trampolines | no agent | minimal | standard |
|---|---:|---:|---:|
| `send`, 1 KB over loopback TCP | 1448 | 1571 | 1580 |
| `pread`, 4 KB from the page cache | 242 | 241 | 304 |
| `pread` + `send`, 16 KB | 2547 | 2670 | 2786 |
| `sendfile`, 64 KB | 2592 | 2446 | 2333 |

| Kprobes | no agent | minimal | standard |
|---|---:|---:|---:|
| `send`, 1 KB over loopback TCP | 1491 | 1594 | 1549 |
| `pread`, 4 KB from the page cache | 240 | 241 | 384 |
| `pread` + `send`, 16 KB | 2552 | 2744 | 2981 |
| `sendfile`, 64 KB | 2900 | 2367 | 2263 |

| Agent | minimal | standard |
|---|---:|---:|
| Resident memory | 5 MB | 11 MB |
| CPU with no workload | 0.10% | 0.10% |
| Events lost | 0 | 0 |

These are measurements of one machine, with run-to-run noise of several
percent (the `sendfile` rows differ by less than that); they are not
guarantees. The CPU figure is the mean of twenty one-second samples that
ranged from 0.05% to 0.19%, in a VM whose own services keep sending. The kprobe figures come from forcing that set on a kernel that
does not need it; kprobes on the kernels that do may cost more. In addition
to the agent's memory, the kernel holds the BPF maps: roughly 10 MB at the
default sizes, and about 8 MB more for the kprobe set's socket table.

## Layout

```text
backends/        collection backends; linux/ holds the BPF probes and loader
core/            data model, bounded tables, event log, correlation state, queries, IPC
agent/           filetrace-agent: event loop, local query socket, configuration file
cmd/             filetrace: commands and output views
exporters/, ui/  JSON and CSV writers, tables, terminal, live view
tests/           unit tests and kernel integration tests
benchmarks/      system call overhead benchmark
tools/dev/       Linux development container, demo, and QEMU harness for other kernels
```
