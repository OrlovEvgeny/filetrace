#!/bin/sh
# Runs in a Debian container booted with systemd; install.sh sets up the apt
# repository of the test site and installs from it.
set -eu
. /src/tests/packaging/assert.sh

unit=filetrace-agent
installer=/pkg/new/install.sh
export FILETRACE_REPO_URL=file:///pkg/site
export FILETRACE_RELEASE_URL=file:///pkg/releases

# Empty unless the package is fully installed; a removed package keeps its
# configuration and its version in dpkg's records.
installed()
{
    dpkg-query -W -f '${db:Status-Abbrev} ${Version}' filetrace 2>/dev/null |
        sed -n 's/^ii  *//p'
}

sh $installer --version 0.0.0.1
expect_file /etc/apt/sources.list.d/filetrace.sources
expect_eq 'the version asked for' 0.0.0.1 "$(installed)"
expect_eq 'enablement after install' enabled "$(systemctl is-enabled $unit)"
expect_running 'after install'
first=$(agent_pid)

sh $installer
expect_eq 'the newest version' "$FT_VERSION" "$(installed)"
expect_running 'after upgrade'
checks=$((checks + 1))
[ "$(agent_pid)" != "$first" ] || fail 'the upgrade did not restart the agent'
expect_version

# apt alone keeps the host current from here on.
expect_exit 0 apt-get install -y --only-upgrade filetrace

sh $installer --uninstall
expect_eq 'the package after removal' '' "$(installed)"
expect_no_file /etc/apt/sources.list.d/filetrace.sources
expect_no_file /etc/apt/keyrings/filetrace.asc

sh $installer --no-start
expect_eq 'the newest version again' "$FT_VERSION" "$(installed)"

# A repository signed by another key is refused.
sh $installer --uninstall
mkdir /tmp/site
cp -R /pkg/site/. /tmp/site/
sed -i 's/Filetrace/Tampered/' /tmp/site/apt/dists/stable/InRelease
expect_exit 100 env FILETRACE_REPO_URL=file:///tmp/site sh $installer
expect_eq 'the package after a refused install' '' "$(installed)"

summary repo-apt
