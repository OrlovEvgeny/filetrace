# Filetrace

Filetrace shows which files a machine sends over the network, which process
sends them, and where they go. It reads this from the kernel with eBPF, so no
application has to be changed.

![filetrace top switching between the transfers in progress, their destinations by name and by address, the process tree, the destinations, the files and the ranking of the files sent most, then filtering the transfers to public destinations](.github/assets/filetrace-top.gif)

`sudo filetrace top` is the live view above, recorded on simulated traffic:
the transfers in progress, the same traffic by process, destination and file,
and the files sent most over a window of time. The other commands print
lists:

```text
$ sudo filetrace files
FILE                PROCESS  DESTINATION     BYTES  METHOD      CONFIDENCE  SCRIPT
/var/www/video.mp4  nginx    198.51.100.4  1.20 GB  sendfile    EXACT       -
/data/users.csv     python3  192.0.2.10    85.2 MB  read-write  INFERRED    /srv/shop/export.py
/data/invoice.pdf   php-fpm  203.0.113.25  2.10 MB  read-write  INFERRED    /srv/blog/index.php
```

Start from a file to see who sends it and to whom, or from an address or a
process to see the files sent to it or by it. Every answer says how sure it
is: `EXACT` means the kernel moved the file to the socket itself (`sendfile`),
and `INFERRED` means a thread read the file and then sent on the socket.

For an interpreter, `SCRIPT` names the program it runs: the script of a
Python, PHP, Node.js, Ruby, Perl, Lua or shell process, and for PHP-FPM and
mod_php the script of the request that sent the file. Each process is also
recorded with its command line and working directory.

Next to an address Filetrace shows the name the process itself used for it:
the name it looked up, the server name its TLS client asked for, or
`target via proxy` where it reached the target through a proxy. No packet is
parsed and nothing is looked up again: the name is read where the program
asks for it, and `--remote` takes a name or a pattern of one wherever it takes
an address. `top` and `watch` show the name in place of the address; the key
`a`, or `--addresses` for a snapshot, shows the address.

```text
$ sudo filetrace connections --remote '*.example*'
PID  PROCESS  PROTOCOL  LOCAL              REMOTE             NAME                                          STATE      SENT  RECEIVED  SOCKET
203  curl     TCP       10.20.0.5:35184    198.51.100.31:80   mirror.example.net                            CLOSED  3.00 MB     173 B    4101
202  curl     TCP       10.20.0.5:44656    192.0.2.44:443     api.payments.example                          CLOSED  1.75 KB   8.31 KB       3
170  python3  TCP       203.0.113.8:55665  198.51.100.20:443  artifacts.example.org                         CLOSED  1.75 KB   8.31 KB    8193
198  curl     TCP       10.20.0.5:39006    203.0.113.8:3128   artifacts.example.org via proxy.corp.example  CLOSED  1.88 KB   8.35 KB    4099
195  curl     TCP       10.20.0.5:50568    198.51.100.20:443  registry.example.com                          CLOSED  1.75 KB   8.31 KB    4097
194  wget     TCP       10.20.0.5:42069    198.51.100.31:80   mirror.example.net                            CLOSED    142 B     173 B       1
```

The third row is the proxy's own connection to the target of the fourth. A
name needs a program that looks names up through the C library or speaks TLS
through OpenSSL or GnuTLS: Go's own resolver and TLS, c-ares, Java, rustls,
static binaries and TLS over a memory buffer, as in Node.js and Python's
asyncio, get none or only the looked-up one. [Known
limitations](https://filetrace.eorlov.org/reference/limitations#destination-names)
has the list.

The agent can also publish what it sees as Prometheus metrics, over OTLP to
an OpenTelemetry collector, and through a gRPC API.

Collection needs Linux 6.1 or later, on x86-64 or arm64. On macOS the command
installs and reports diagnostics, and collects nothing.

The documentation is at <https://filetrace.eorlov.org>.

## Try it without installing

On a Linux machine with kernel 6.1 or later, download the release archive and
run the live view. Nothing is installed and no service is started: `top`
collects by itself for as long as it runs.

```sh
v=$(curl -fsSL https://filetrace.eorlov.org/channels/stable) a=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl -fsSL "https://filetrace.eorlov.org/dist/v$v-stable/filetrace-$v-linux-$a.tar.gz" | tar xz
sudo "./filetrace-$v-linux-$a/bin/filetrace" top
```

Run this way, it shows activity from the moment it starts; the installed agent
below keeps the history between runs and feeds the exporters.

Where `filetrace-agent` is already running, `top` shows what that agent
collects, and when the agent is from an older release that speaks another
protocol, `top` reports "The agent speaks a different protocol version".
Upgrade the installed package to the archive's version, or stop the service
(`sudo systemctl stop filetrace-agent`) and start `top` again to have it
collect by itself.

## Install

```sh
curl -fsSL https://filetrace.eorlov.org/install.sh | sudo sh
```

On Linux the installer sets up the apt, dnf, yum, zypper or apk repository
that fits the system and installs the `filetrace` package, so upgrades arrive
with the system's own. Without one of those package managers it unpacks the
release archive under `/usr/local`. It then starts `filetrace-agent`, the
service that collects; `filetrace` is the command that queries it. Append
`-s -- --help` to `sh` for the options: a version, the `lts` channel,
`--no-start`, `--uninstall`.

Homebrew, on macOS 15 or later and on Linux, installs the two programs
without a service:

```sh
brew install orlovevgeny/filetrace/filetrace
```

For anything else, a [release](https://github.com/OrlovEvgeny/filetrace/releases)
has the archives.

To check that the machine can be monitored:

```sh
sudo filetrace doctor
```

## Examples

The agent runs as root, so the commands that query it need `sudo`.

```sh
sudo filetrace top                             # live screen: transfers, processes, destinations, files
sudo filetrace top --leaders --window 24h      # the files sent most over the last day
sudo filetrace watch                           # live view of the transfers in progress
sudo filetrace files                           # files sent over the network
sudo filetrace files --remote 203.0.113.25     # files sent to one address
sudo filetrace files --script '/srv/shop/*'    # files sent by the scripts under one directory
sudo filetrace inspect file /data/report.pdf   # who sent a file, and to whom
sudo filetrace inspect process 1245            # what a process is sending
sudo filetrace processes                       # outbound rate and files sent per process
sudo filetrace events --type file_transfer --since 5m   # transfers of the last five minutes
sudo filetrace files --json                    # the same list as JSON
```

`filetrace help <command>` lists a command's options.
