# Mapped send diagnostics

This standalone experiment counts buffers that point into file mappings at send
entry. It does not generate Filetrace events, establish a transfer, measure
accepted bytes, or change the production probes.

`run` loads one probe, filters to the PID of its child, executes a command, waits
for it, prints counters, and detaches. The two attachments are
`fentry/inet_sendmsg` and `kprobe/tcp_sendmsg`. The smoke test uses IPv4 TCP.

Run from the repository root on Linux with BTF, BPF privileges, Clang, libbpf
headers, libelf, a C compiler, and Python 3:

```sh
mkdir -p build/mapped-probe
clang -target bpf -D__TARGET_ARCH_arm64 -O2 -g -I. \
  -I/usr/include/aarch64-linux-gnu \
  -c tools/diagnostics/mapped-send/probe.bpf.c \
  -o build/mapped-probe/probe.bpf.o
cc -Wall -Wextra -Werror tools/diagnostics/mapped-send/run.c \
  -lbpf -lelf -lz -o build/mapped-probe/run
python3 tools/diagnostics/mapped-send/smoke.py --php
```

On amd64, use `__TARGET_ARCH_x86` and the `x86_64-linux-gnu` include directory.
Omit `--php` if PHP CLI is unavailable. Inside Docker, use `--pid=host` so the
child PID agrees with the BPF TGID; the smoke test also needs BPF privileges.

Verified on Linux 7.0.14-linuxkit arm64 with PHP 8.4.27 CLI, November 12, 2026:

| Workload | Both attachments |
|---|---|
| One read-only shared file mapping, 4096 bytes | One mapped buffer, 4096 observed bytes |
| Heap copy of that mapping | Anonymous buffer |
| Header plus mapping in a two-element iovec | Rejected as multi-vector |
| Changed private COW mapping | Rejected as unsafe mapping |
| Writable anonymous shared mapping | Rejected as unsafe mapping |
| PHP `readfile` / `fpassthru`, direct socket stdout, 65536 bytes | 65536 mapped bytes each |
| Same PHP functions inside `ob_start` / `ob_end_flush` | Anonymous buffer, zero mapped bytes |

Linux 6.1 and 6.12 have been inspected in source only; this is not a claim of
verifier or runtime compatibility on those kernels. No throughput benchmark has
been run.

The callback requires a regular file, a range entirely inside one VMA,
`VM_MAYSHARE`, and neither `VM_WRITE` nor `VM_MAYWRITE`. Linux clears `VM_SHARED`
for a shared mapping opened through an O_RDONLY descriptor; `VM_MAYSHARE` is the
relevant flag. Private mappings remain ambiguous even after removing write
permission because they may contain changed COW pages.

The iterator enum values and old `iov` versus new `__iov` field use CO-RE
relocations. Only UBUF and single-element IOVEC are considered. A helper failure
or unsupported buffer is counted and skipped. The probe reads metadata, not
payload contents, and keeps no VMA or file pointer after the callback.

Before production use, entry snapshots need to be reconciled with actual return
bytes, partial writes, EAGAIN, retries, sendfile/splice, file offsets and EOF,
socket/process lifetimes, mapping races, and bounded vector walks. A mapping
observation alone does not justify an `exact` transfer. Output buffering, TLS,
compression, or a proxy can remove the association before the network syscall.
