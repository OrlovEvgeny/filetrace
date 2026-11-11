#!/bin/sh
# Runs in a Debian container booted with systemd; install.sh sets up the apt
# repository of the test site and installs from it.
set -eu
. /src/tests/packaging/assert.sh

unit=filetrace-agent
installer=/pkg/new/install.sh
export FILETRACE_REPO_URL=file:///pkg/bucket

# Empty unless the package is fully installed; a removed package keeps its
# configuration and its version in dpkg's records.
installed()
{
    dpkg-query -W -f '${db:Status-Abbrev} ${Version}' filetrace 2>/dev/null |
        sed -n 's/^ii  *//p'
}

# A channel without a release is refused before apt is given its repository,
# also when a published version is asked for.
expect_exit 1 sh $installer --channel lts
expect_exit 1 sh $installer --channel lts --version 0.0.0.1
expect_no_file /etc/apt/sources.list.d/filetrace.sources
expect_no_file /etc/apt/keyrings/filetrace.asc

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

# A candidate can be downloaded, but no repository offers it.
expect_file /pkg/bucket/dist/v0.0.0.2-prestable/SHA256SUMS
expect_exit 100 apt-get install -y filetrace=0.0.0.2

sh $installer --uninstall
expect_eq 'the package after removal' '' "$(installed)"
expect_no_file /etc/apt/sources.list.d/filetrace.sources
expect_no_file /etc/apt/keyrings/filetrace.asc

sh $installer --no-start
expect_eq 'the newest version again' "$FT_VERSION" "$(installed)"

# apt asks for an index by its checksum, so the named copies are not needed.
sh $installer --uninstall
mkdir /tmp/hashed
cp -R /pkg/bucket/. /tmp/hashed/
rm /tmp/hashed/apt/dists/stable/main/binary-*/Packages*
# Nor does a mirror of the repository need the files the archive method reads.
rm -r /tmp/hashed/channels /tmp/hashed/versions /tmp/hashed/dist
expect_exit 0 env FILETRACE_REPO_URL=file:///tmp/hashed sh $installer --no-start
expect_eq 'the version installed by checksum alone' "$FT_VERSION" "$(installed)"

# A repository signed by another key is refused. apt has no lists of this
# address yet; with older ones it would warn and install from those.
sh $installer --uninstall
mkdir /tmp/site
cp -R /pkg/bucket/. /tmp/site/
sed -i 's/Filetrace/Tampered/' /tmp/site/apt/dists/stable/InRelease
expect_exit 100 env FILETRACE_REPO_URL=file:///tmp/site sh $installer
expect_eq 'the package after a refused install' '' "$(installed)"

summary repo-apt
