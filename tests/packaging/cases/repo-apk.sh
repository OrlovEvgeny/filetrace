#!/bin/sh
# Runs in an Alpine container with OpenRC marked as started; install.sh sets up
# the apk repository of the test site and installs from it.
set -eu
. /src/tests/packaging/assert.sh

service=filetrace-agent
installer=/pkg/new/install.sh
export FILETRACE_REPO_URL=file:///pkg/site
export FILETRACE_RELEASE_URL=file:///pkg/releases
mkdir -p /run/openrc
touch /run/openrc/softlevel

installed()
{
    apk list --installed filetrace 2>/dev/null | sed -n 's/^filetrace-\([^ ]*\) .*/\1/p'
}

sh $installer --version 0.0.0.1
expect_file /etc/apk/keys/filetrace.rsa.pub
expect_exit 0 grep -qxF file:///pkg/site/apk/stable /etc/apk/repositories
expect_eq 'the version asked for' 0.0.0.1 "$(installed)"
checks=$((checks + 1))
rc-update show default | grep -q $service || fail 'the service is not in the default runlevel'
expect_running 'after install'
first=$(agent_pid)

sh $installer
checks=$((checks + 1))
[ "$(installed)" != 0.0.0.1 ] || fail 'the newest version was not installed'
expect_running 'after upgrade'
checks=$((checks + 1))
[ "$(agent_pid)" != "$first" ] || fail 'the upgrade did not restart the agent'
expect_version

sh $installer --uninstall
expect_eq 'the package after removal' '' "$(installed)"
expect_no_file /etc/apk/keys/filetrace.rsa.pub
checks=$((checks + 1))
! grep -q /pkg/site /etc/apk/repositories || fail 'the repository is still configured'

summary repo-apk
