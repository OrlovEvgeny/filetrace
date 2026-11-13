#!/bin/sh
# usage: run.sh <directory with filetrace, filetrace-agent and ft_refuse_uretprobe> <unfixed|fixed>
# Runs as root in the x86_64 guest of tools/dev/vm.sh on a kernel without (unfixed) or with
# (fixed) the fix for CVE-2025-21834, without which a return probe kills a process whose seccomp
# filter refuses the uretprobe system call. The agent must attach no return probe on the unfixed
# kernel and its PHP and lookup probes on the fixed one; PHP and curl under such a filter must
# live on both; on the unfixed kernel [process] force_return_probes must get curl killed.

set -u

bin=$1
kernel=$2
case $kernel in
unfixed | fixed) ;;
*)
    sed -n '2p' "$0" >&2
    exit 2
    ;;
esac

# The verdict on return probes is the kernel's own.
unset FILETRACE_TEST_RETURN_PROBES

refuse=$bin/ft_refuse_uretprobe
php=/usr/bin/php
curl=/usr/bin/curl
work=$(mktemp -d /tmp/filetrace-returns-XXXXXX)
www=$work/www
sock=$work/agent.sock
size=1048576
agent_pid=
servers=
failures=0
checks=0

cleanup() {
    [ -n "$agent_pid" ] && kill "$agent_pid" 2>/dev/null
    for pid in $servers; do
        kill "$pid" 2>/dev/null
    done
    wait 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT

ft() {
    "$bin/filetrace" --socket "$sock" "$@"
}

fail() {
    failures=$((failures + 1))
    echo "FAIL: $*"
}

# expect <description> <actual> <expected>
expect() {
    checks=$((checks + 1))
    if [ "$2" != "$3" ]; then
        fail "$1: got '$2', expected '$3'"
    fi
}

# expect_match <description> <text> <extended regex>
expect_match() {
    checks=$((checks + 1))
    if ! printf '%s\n' "$2" | grep -Eq -- "$3"; then
        fail "$1: '$2' does not match '$3'"
    fi
}

# expect_no_match <description> <text> <extended regex>
expect_no_match() {
    checks=$((checks + 1))
    if printf '%s\n' "$2" | grep -Eq -- "$3"; then
        fail "$1: '$(printf '%s\n' "$2" | grep -E -- "$3")' matches '$3'"
    fi
}

# within <seconds> <command...>: whether the command succeeds within that many seconds
within() {
    n=$1
    shift
    until "$@"; do
        [ "$n" -gt 0 ] || return 1
        sleep 1
        n=$((n - 1))
    done
}

listening() {
    grep -Eq ": [0-9A-F]{8}:$(printf '%04X' "$1") [0-9A-F]{8}:0000 0A " /proc/net/tcp
}

alive() {
    state=$(sed -n 's/^[0-9]* (.*) \([A-Z]\) .*/\1/p' "/proc/$1/stat" 2>/dev/null)
    [ -n "$state" ] && [ "$state" != Z ]
}

# logged <log name> <text>
logged() {
    grep -q -- "$2" "$work/$1.log"
}

# start_agent <log name> [<agent option>...]
start_agent() {
    log=$1
    shift
    rm -f "$sock"
    "$bin/filetrace-agent" --socket "$sock" --log-level info "$@" >"$work/$log.log" 2>&1 &
    agent_pid=$!
    i=0
    while [ ! -S "$sock" ] && [ $i -lt 120 ] && kill -0 "$agent_pid" 2>/dev/null; do
        sleep 1
        i=$((i + 1))
    done
    if [ ! -S "$sock" ]; then
        fail "the agent did not start"
        finish
    fi
}

# stop_agent <log name>
stop_agent() {
    ft agent stop >/dev/null
    wait "$agent_pid"
    expect "$1: exit status" "$?" 0
    agent_pid=
}

# Children of the agent, other processes of the filetrace binaries and zombies, one per line.
leftovers() {
    for stat in /proc/[0-9]*/stat; do
        line=$(cat "$stat" 2>/dev/null) || continue
        pid=${line%% *}
        rest=${line##*) }
        state=${rest%% *}
        rest=${rest#* }
        parent=${rest%% *}
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        if [ "$parent" = "$agent_pid" ] || [ "$state" = Z ] ||
            { [ "$pid" != "$agent_pid" ] && [ "${exe#"$bin"/filetrace}" != "$exe" ]; }; then
            echo "$pid $state $parent $exe"
        fi
    done
}

# What a killed test process of the agent or doctor would leave.
expect_nothing_left() {
    expect "$1: processes left" "$(leftovers)" ""
    expect "$1: core files" "$(ls "$work/cores")" ""
    expect "$1: segfaults in the kernel log" "$(dmesg | grep segfault)" ""
}

# expect_alive_under <filter> <pid of PHP under it> <its port>
expect_alive_under() {
    expect "PHP under $1: bytes answered" \
        "$(wget -q -O - "http://127.0.0.1:$3/download.php" | wc -c | tr -d ' ')" $size
    sleep 2
    alive "$2" && state=alive || state=dead
    expect "PHP under $1: after a request" "$state" alive

    "$refuse" "$1" "$curl" -sS -o /dev/null "http://$1.returns.test:8080/download.php"
    expect "curl under $1: exit status" "$?" 0
}

# expect_listed <filter> <pid of PHP under it> <address of the name curl looked up under it>
expect_listed() {
    script=$(printf '%s\n' "$files" | grep "\"pid\":$2," | grep "\"path\":\"$www/data.bin\"" |
        sed -n 's/.*"script":"\([^"]*\)".*/\1/p' | head -1)
    expect "files: script of PHP under $1" "$script" "$www/download.php"

    connection=$(printf '%s\n' "$connections" | grep "\"remote_ip\":\"$3\",\"remote_port\":8080,")
    expect "connections: name curl looked up under $1" \
        "$(printf '%s\n' "$connection" | sed -n 's/.*"remote_name":"\([^"]*\)".*/\1/p')" \
        "$1.returns.test"
    expect "connections: source of the name curl looked up under $1" \
        "$(printf '%s\n' "$connection" | sed -n 's/.*"remote_name_source":"\([^"]*\)".*/\1/p')" \
        lookup
}

finish() {
    if [ "$failures" -gt 0 ]; then
        for log in "$work"/*.log; do
            echo "--- $log"
            cat "$log"
        done
    fi
    echo "$checks checks, $failures failed"
    [ "$failures" -eq 0 ]
    exit
}

echo "$("$bin/filetrace" version | head -1) on kernel $(uname -r), checked as $kernel"
cd "$work" || exit 1
# Not POSIX, but busybox ash, the guest's shell, has it.
# shellcheck disable=SC3045
ulimit -c unlimited
mkdir -p "$work/cores"
echo "$work/cores/core.%e.%p" >/proc/sys/kernel/core_pattern
ip addr add 192.0.2.11/32 dev lo
ip addr add 192.0.2.12/32 dev lo
printf '192.0.2.11 eperm.returns.test\n192.0.2.12 enosys.returns.test\n' >>/etc/hosts

mkdir -p "$www"
dd if=/dev/urandom of="$www/data.bin" bs=1024 count=$((size / 1024)) 2>/dev/null
cat >"$www/download.php" <<'PHP'
<?php
// fread and echo in turn: readfile() maps the file, which leaves no transfer to see.
$file = fopen(__DIR__ . '/data.bin', 'rb');
while (!feof($file)) {
    echo fread($file, 65536);
    flush();
}
PHP

# Started before the agent, which probes PHP and the C library once a process maps them.
"$php" -S 0.0.0.0:8080 -t "$www" >"$work/php.log" 2>&1 &
servers="$servers $!"
"$refuse" eperm "$php" -S 0.0.0.0:8081 -t "$www" >"$work/php-eperm.log" 2>&1 &
php_eperm=$!
"$refuse" enosys "$php" -S 0.0.0.0:8082 -t "$www" >"$work/php-enosys.log" 2>&1 &
php_enosys=$!
servers="$servers $php_eperm $php_enosys"
for port in 8080 8081 8082; do
    within 120 listening $port || fail "nothing listens on port $port"
done

start_agent agent
if [ "$kernel" = unfixed ]; then
    expect_match "agent: return probes" "$(cat "$work/agent.log")" \
        'return probes kill processes under seccomp on this kernel.*not attached'
else
    within 60 logged agent 'probing PHP requests'
    within 60 logged agent 'probing name lookups'
    expect_no_match "agent: return probes" "$(cat "$work/agent.log")" 'return probes kill'
    expect_match "agent: PHP probed" "$(cat "$work/agent.log")" 'probing PHP requests'
    expect_match "agent: lookups probed" "$(cat "$work/agent.log")" 'probing name lookups'
fi
expect_nothing_left "agent started"

ft doctor >"$work/doctor.log" 2>&1
expect "doctor: exit status" "$?" 0
row=$(grep '^Return probes:' "$work/doctor.log")
if [ "$kernel" = unfixed ]; then
    expect_match "doctor: return probes" "$row" \
        '^Return probes: +LIMITED \(.*only with \[process\] force_return_probes\)$'
else
    expect_match "doctor: return probes" "$row" '^Return probes: +AVAILABLE '
fi
expect_nothing_left "doctor ran"

capabilities=$(ft capabilities --json | tr '{' '\n')
for feature in destination_names php_request_scripts; do
    status=$(printf '%s\n' "$capabilities" | grep "\"feature\":\"$feature\"" |
        sed -n 's/.*"status":"\([A-Z]*\)".*/\1/p')
    if [ "$kernel" = unfixed ]; then
        expect "capabilities: $feature" "$status" UNAVAILABLE
    else
        expect_match "capabilities: $feature" "$status" '^(FULL|PARTIAL)$'
    fi
done

expect_alive_under eperm "$php_eperm" 8081
expect_alive_under enosys "$php_enosys" 8082
expect_nothing_left "clients ran"

if [ "$kernel" = unfixed ]; then
    expect_no_match "agent: probes attached" "$(cat "$work/agent.log")" 'probing '
else
    # A listing in the second a client exits can miss its last flush.
    sleep 3
    files=$(ft files --json)
    connections=$(ft connections --since 10m --json)
    expect_listed eperm "$php_eperm" 192.0.2.11
    expect_listed enosys "$php_enosys" 192.0.2.12
fi
stop_agent agent

if [ "$kernel" = unfixed ]; then
    printf '[process]\nforce_return_probes = true\n' >"$work/force.toml"
    start_agent forced --config "$work/force.toml"
    within 60 logged forced 'probing name lookups'
    expect_match "forced agent: return probes" "$(cat "$work/forced.log")" \
        'force_return_probes attaches the PHP, lookup and TLS probes all the same'
    expect_match "forced agent: lookups probed" "$(cat "$work/forced.log")" 'probing name lookups'
    before=$(dmesg | grep -c segfault)
    killed=0
    for filter in eperm enosys; do
        "$refuse" $filter "$curl" -sS -o /dev/null "http://$filter.returns.test:8080/download.php"
        status=$?
        expect "forced: curl under $filter: exit status" "$status" 139
        [ "$status" -eq 139 ] && killed=$((killed + 1))
    done
    expect "forced: segfaults the kernel logged" "$(($(dmesg | grep -c segfault) - before))" 2
    if [ "$killed" -eq 0 ]; then
        fail "nothing died under [process] force_return_probes: this kernel lets return probes" \
            "through seccomp, so the checks above prove nothing"
    fi
    stop_agent forced
fi

finish
