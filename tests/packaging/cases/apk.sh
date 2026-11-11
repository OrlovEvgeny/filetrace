#!/bin/sh
# Runs in an Alpine container with OpenRC installed and marked as started.
set -eu
. /src/tests/packaging/assert.sh

service=filetrace-agent
mkdir -p /run/openrc
touch /run/openrc/softlevel

apk add --allow-untrusted --no-network /pkg/old/*.apk
for path in /usr/bin/filetrace /usr/bin/filetrace-agent /etc/filetrace/config.toml \
    /etc/init.d/$service /etc/conf.d/$service /usr/share/doc/filetrace/LICENSE; do
    expect_file "$path"
done
expect_exit 0 filetrace config validate
expect_stopped

rc-update add $service default
rc-service $service start
expect_running 'after starting'
expect_exit 0 rc-service $service status
first=$(agent_pid)

printf '\n# kept across upgrades\n' >>/etc/filetrace/config.toml
apk add --allow-untrusted --no-network /pkg/new/*.apk
expect_running 'after upgrade'
checks=$((checks + 1))
[ "$(agent_pid)" != "$first" ] || fail 'the upgrade did not restart the agent'
expect_exit 0 grep -q 'kept across upgrades' /etc/filetrace/config.toml
expect_version

apk del --no-network filetrace
expect_no_file /usr/bin/filetrace
expect_no_file /etc/init.d/$service
checks=$((checks + 1))
! rc-update show default | grep -q $service || fail 'the service is still in the default runlevel'

summary apk
