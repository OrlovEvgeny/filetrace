#!/bin/sh
# Runs in a Debian container booted with systemd.
set -eu
. /src/tests/packaging/assert.sh

unit=filetrace-agent
export DEBIAN_FRONTEND=noninteractive

dpkg -i /pkg/old/*.deb
for path in /usr/bin/filetrace /usr/bin/filetrace-agent /etc/filetrace/config.toml \
    /usr/lib/systemd/system/$unit.service /etc/init.d/$unit /etc/logrotate.d/$unit \
    /usr/share/doc/filetrace/LICENSE /usr/share/doc/filetrace/THIRD_PARTY_LICENSES; do
    expect_file "$path"
done
expect_exit 0 filetrace config validate
expect_eq 'enablement after install' enabled "$(systemctl is-enabled $unit)"
expect_running 'after install'
expect_eq 'the unit state after install' active "$(systemctl is-active $unit)"
expect_exit 0 filetrace capabilities
first=$(agent_pid)

printf '\n# kept across upgrades\n' >>/etc/filetrace/config.toml
dpkg -i /pkg/new/*.deb
expect_running 'after upgrade'
checks=$((checks + 1))
[ "$(agent_pid)" != "$first" ] || fail 'the upgrade did not restart the agent'
expect_exit 0 grep -q 'kept across upgrades' /etc/filetrace/config.toml
expect_version
checks=$((checks + 1))
filetrace stats --format json | grep -q "\"version\": *\"$FT_VERSION\"" ||
    fail 'the running agent does not report the upgraded version'

# A file the new version rejects must not take a working agent down. The
# command refuses such a file too, so systemd is asked for the process.
second=$(systemctl show --property MainPID --value $unit)
cp /etc/filetrace/config.toml /tmp/config.toml
printf '[no_such_section]\n' >>/etc/filetrace/config.toml
dpkg -i /pkg/new/*.deb
expect_eq 'the agent after an upgrade with a broken file' "$second" \
    "$(systemctl show --property MainPID --value $unit)"
expect_eq 'the unit state after an upgrade with a broken file' active "$(systemctl is-active $unit)"
cp /tmp/config.toml /etc/filetrace/config.toml

systemctl disable --now $unit
dpkg -i /pkg/new/*.deb
expect_eq 'enablement kept by an upgrade' disabled "$(systemctl is-enabled $unit || true)"
expect_stopped
systemctl enable --now $unit
expect_running 'after enabling again'

dpkg -r filetrace
expect_eq 'the unit state after removal' inactive "$(systemctl is-active $unit || true)"
expect_no_file /usr/bin/filetrace
expect_no_file /usr/lib/systemd/system/$unit.service
expect_file /etc/filetrace/config.toml

dpkg -P filetrace
expect_no_file /etc/filetrace
expect_no_file /etc/init.d/$unit

summary deb
