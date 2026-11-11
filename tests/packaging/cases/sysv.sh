#!/bin/sh
# Runs in a Debian container without systemd, where policy-rc.d forbids
# starting services.
set -eu
. /src/tests/packaging/assert.sh

script=/etc/init.d/filetrace-agent
export DEBIAN_FRONTEND=noninteractive

dpkg -i /pkg/new/*.deb
expect_file $script
expect_file /etc/rc2.d/S01filetrace-agent
expect_stopped
expect_exit 3 $script status

expect_exit 0 $script start
expect_running 'after start'
expect_exit 0 $script status
expect_exit 0 $script start
first=$(agent_pid)

expect_exit 0 $script restart
expect_running 'after restart'
checks=$((checks + 1))
[ "$(agent_pid)" != "$first" ] || fail 'restart kept the same process'

expect_exit 0 $script stop
expect_stopped
expect_exit 3 $script status
expect_exit 0 $script stop
expect_exit 2 $script reload

printf '[no_such_section]\n' >>/etc/filetrace/config.toml
expect_exit 6 $script start
expect_exit 3 $script status

dpkg -P filetrace
expect_no_file $script
expect_no_file /etc/rc2.d/S01filetrace-agent

summary sysv
