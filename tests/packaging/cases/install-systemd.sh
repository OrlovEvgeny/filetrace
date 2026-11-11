#!/bin/sh
# Runs in a Debian container booted with systemd; install.sh unpacks the
# release archive because the test publishes no package repository.
set -eu
. /src/tests/packaging/assert.sh

unit=filetrace-agent
installer=/pkg/new/install.sh
export FILETRACE_REPO_URL=file:///pkg/site
export FILETRACE_RELEASE_URL=file:///pkg/releases

expect_exit 0 sh $installer --dry-run
expect_no_file /usr/local/bin/filetrace
expect_exit 1 sh $installer --method package
expect_exit 1 sh $installer --version 0.0.0.0
expect_exit 1 sh $installer --no-such-option

sh $installer
for path in /usr/local/bin/filetrace /usr/local/bin/filetrace-agent \
    /etc/filetrace/config.toml /etc/systemd/system/$unit.service \
    /usr/local/share/doc/filetrace/LICENSE; do
    expect_file "$path"
done
expect_exit 0 grep -q '^ExecStart=/usr/local/bin/filetrace-agent$' /etc/systemd/system/$unit.service
expect_eq 'enablement after install' enabled "$(systemctl is-enabled $unit)"
expect_running 'after install'
expect_version
first=$(agent_pid)

printf '\n# kept across upgrades\n' >>/etc/filetrace/config.toml
sh $installer
expect_running 'after installing again'
checks=$((checks + 1))
[ "$(agent_pid)" != "$first" ] || fail 'installing again did not restart the agent'
expect_exit 0 grep -q 'kept across upgrades' /etc/filetrace/config.toml

sh $installer --uninstall
expect_no_file /usr/local/bin/filetrace
expect_no_file /etc/systemd/system/$unit.service
expect_eq 'the unit state after removal' inactive "$(systemctl is-active $unit || true)"
expect_file /etc/filetrace/config.toml

sh $installer --no-start
expect_file /usr/local/bin/filetrace
expect_eq 'enablement with --no-start' disabled "$(systemctl is-enabled $unit || true)"
expect_stopped
sh $installer --uninstall

# An archive that does not match the published checksum is not installed.
mkdir -p /tmp/releases
cp -R /pkg/releases/. /tmp/releases/
sed -i 's/^[0-9a-f]\{8\}/00000000/' /tmp/releases/*/SHA256SUMS
expect_exit 1 env FILETRACE_RELEASE_URL=file:///tmp/releases sh $installer
expect_no_file /usr/local/bin/filetrace

summary install-systemd
