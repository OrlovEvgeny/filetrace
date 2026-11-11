# Filetrace

Filetrace shows which files a machine sends over the network, which process
sends them, and where they go. It observes the operating system itself, so no
application has to be changed, and it says how sure each answer is.

```text
$ sudo filetrace files
FILE                        PID   PROCESS  REMOTE              SENT     CONFIDENCE
/var/www/video.mp4          1842  nginx    198.51.100.4:443    1.20 GB  EXACT
/data/export/customers.csv  3821  python   192.0.2.10:443      85.2 MB  INFERRED
```

## Platform support

| Platform | Collection | Status |
|---|---|---|
| Linux 6.1 or later | eBPF through libbpf and CO-RE | Run and tested on Linux 7.0, arm64 |
| macOS | none | The CLI builds and reports diagnostics; collection needs an Endpoint Security system extension |
| FreeBSD | none | Collection needs a DTrace backend |

The probes rely on BPF trampolines (fentry/fexit), which arm64 kernels provide
from 6.4. They have been exercised on one kernel only; other kernels in range
are expected to work through CO-RE but are untested. `filetrace doctor` loads
and attaches every probe on the machine it runs on and reports what the kernel
accepted.

## Try it

On any machine with Docker, including macOS:

```sh
tools/dev/linux.sh tools/dev/demo.sh
```

This builds the project in a Linux container, starts the daemon, sends files
with `sendfile(2)`, with a read+send loop and over UDP, and prints what
Filetrace observed. The container sees the kernel it runs on: under Docker
Desktop that is the Docker VM, not the macOS host.

For the live dashboard, in two terminals:

```sh
tools/dev/linux.sh build/demo/filetrace watch
tools/dev/linux.sh build/demo/tests/ft_workload sendfile /tmp/big.bin 200000000
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

## Usage

```sh
sudo filetraced &            # collect in the background
sudo filetrace watch         # live overview
sudo filetrace files         # files sent, with confidence
```

Without a running daemon, `filetrace watch` collects in the foreground for as
long as it runs.

| Command | Shows |
|---|---|
| `watch` | Live totals, top senders and file transfers in progress |
| `files` | Files associated with network transfers |
| `transfers` | The same, plus sent bytes that no file accounts for |
| `processes` | Bytes sent and received per process |
| `connections` | Open and recently closed sockets |
| `flows` | Bytes per process, socket and remote endpoint |
| `top` | Highest-volume processes, files, destinations or connections |
| `stats` | The collector's own events, losses, CPU and memory |
| `doctor` | Whether this machine can be monitored, probe by probe |
| `capabilities` | Each feature as FULL, PARTIAL, UNAVAILABLE or DISABLED, with the reason |
| `daemon` | `run`, `status`, `stop` |

Query commands share their filters (`--pid`, `--process`, `--path`,
`--remote`, `--protocol`, `--since`, `--confidence`, `--min-bytes`, ...) and
print as `table`, `json`, `jsonl`, `csv` or `quiet`. `filetrace help <command>`
lists the options, examples and exit codes of each.

Exit code 9 means the answer may be incomplete: events were lost inside the
queried time range.

## Confidence

| Level | Meaning |
|---|---|
| EXACT | The kernel moved the file's data to the socket in one operation (`sendfile`) |
| INFERRED | A thread read the file and then sent on the socket; the payload cannot be proven to come only from that file |
| UNKNOWN | Bytes were sent and no file could be associated with them |

STRONG is defined for provenance followed through intermediate operations; no
probe produces it. A level is never raised by a filter or an output format,
and every record lists the evidence behind it (`--format json`).

`SENT` counts bytes the local socket accepted. It is not the number of bytes
on the wire and not what the remote end acknowledged.

## How it works

Ten BPF programs attach to tracepoints and kernel functions:

| Probe | Records |
|---|---|
| `sched_process_exec`, `_fork`, `_exit` | Process identity and lifetime |
| `inet_sock_set_state` | TCP connect, listen, establish and close |
| `inet_sendmsg`, `inet_recvmsg` and the IPv6 pair | Bytes per socket, process and remote endpoint |
| `do_splice_direct` | `sendfile`: file and socket in the same kernel operation |
| `vfs_read` | Which regular file each thread read last, and how much |

The probes see the kernel's own file and socket objects, so nothing is keyed
on file descriptor numbers and descriptor reuse cannot misattribute a
transfer. A file is identified by device, inode and generation; its path is
read from the kernel when the file is first seen and is only a label.

High-frequency data never becomes one event per call. Byte counts accumulate
in a kernel hash map keyed by socket, process and file; the daemon swaps that
map for an empty one every 250 ms and reads the idle one, so no update is
lost. Process and socket lifecycle events travel through a ring buffer.

A read+send association is recorded when a thread sends within the correlation
window (2 s) after reading a regular file, with no receive in between, and
only up to the number of bytes it read. It is reported once it covers at least
1 KB and 5% of what was read from the file.

All state is in memory and bounded: every table has a fixed capacity and
forgets its least recently updated entry. History starts when the daemon
starts.

## Limits

- A file read by one thread and sent by another, or passed through a pipe, is
  not associated with the send.
- Files read with `readv`, io_uring or through a memory mapping are not seen
  as read. Bytes sent through io_uring are still counted per socket.
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

Not included in this build: a configuration file, persistent history,
Prometheus and OpenTelemetry exporters, the `inspect`, `events`, `record`,
`replay`, `monitor`, `config` and `integrations` commands, kprobe fallbacks
for kernels without BPF trampolines, and packet-level counters.

## Tests

```sh
ctest --test-dir build --output-on-failure
```

`unit` covers formatting, the bounded tables, the correlation state, the IPC
round trip with a scripted backend, and every output format; it runs on Linux
and macOS. `integration` needs root and a supporting kernel, and is skipped
otherwise: it starts the daemon, generates real transfers (sendfile over IPv4
and IPv6, read+send, UDP, descriptor reuse across 25 files, rename and unlink
during a transfer) and asserts on exact byte counts and confidence levels.

From macOS, `tools/dev/linux.sh <command>` runs a command in the Linux
container with the source tree mounted at `/src`.

## Overhead

`benchmarks/run.sh` times the traced system calls with and without the daemon.
One run on Linux 7.0.14, arm64, 12 CPUs, inside the Docker Desktop VM:

| ns per call | no agent | minimal | standard |
|---|---:|---:|---:|
| `send`, 1 KB over loopback TCP | 1420 | 1570 | 1564 |
| `pread`, 4 KB from the page cache | 241 | 241 | 307 |
| `pread` + `send`, 16 KB | 2554 | 2650 | 2842 |
| `sendfile`, 64 KB | 2613 | 2622 | 2517 |

| Daemon | minimal | standard |
|---|---:|---:|
| Resident memory | 5 MB | 11 MB |
| CPU with no workload | 0.08% | 0.08% |
| Events lost | 0 | 0 |

These are measurements of one machine, with run-to-run noise of several
percent; they are not guarantees. In addition to the daemon's memory, the
kernel holds the BPF maps: roughly 10 MB at the default sizes.

## Layout

```text
backends/        collection backends; linux/ holds the BPF probes and loader
core/            data model, bounded tables, correlation state, queries, IPC
daemon/          filetraced: event loop and local query socket
cmd/             filetrace: commands and output views
exporters/, ui/  JSON and CSV writers, tables, terminal, live dashboard
tests/           unit tests and kernel integration tests
benchmarks/      system call overhead benchmark
tools/dev/       Linux development container and demo
```
