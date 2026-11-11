#!/bin/sh
# Runs in an RPM-based container booted with systemd.
set -eu
. /src/tests/packaging/assert.sh

unit=filetrace-agent

rpm -i /pkg/old/*.rpm
for path in /usr/bin/filetrace /usr/bin/filetrace-agent /etc/filetrace/config.toml \
    /usr/lib/systemd/system/$unit.service /usr/share/doc/filetrace/LICENSE; do
    expect_file "$path"
done
expect_no_file /etc/init.d/$unit
expect_exit 0 filetrace config validate
# The distribution's preset decides; without one of ours the service stays off.
expect_eq 'enablement after install' disabled "$(systemctl is-enabled $unit || true)"
expect_stopped

systemctl enable --now $unit
expect_running 'after enabling'
first=$(agent_pid)

printf '\n# kept across upgrades\n' >>/etc/filetrace/config.toml
rpm -U /pkg/new/*.rpm
expect_running 'after upgrade'
checks=$((checks + 1))
[ "$(agent_pid)" != "$first" ] || fail 'the upgrade did not restart the agent'
expect_exit 0 grep -q 'kept across upgrades' /etc/filetrace/config.toml
expect_eq 'enablement kept by an upgrade' enabled "$(systemctl is-enabled $unit)"
expect_version

rpm -e filetrace
expect_no_file /usr/bin/filetrace
expect_no_file /usr/lib/systemd/system/$unit.service
expect_eq 'the unit state after removal' inactive "$(systemctl is-active $unit || true)"
expect_file /etc/filetrace/config.toml.rpmsave

summary rpm
