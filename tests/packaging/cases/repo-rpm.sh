#!/bin/sh
# Runs in an RPM-based container booted with systemd; install.sh sets up the
# yum repository of the test site and installs from it.
set -eu
. /src/tests/packaging/assert.sh

unit=filetrace-agent
installer=/pkg/new/install.sh
export FILETRACE_REPO_URL=file:///pkg/site
export FILETRACE_RELEASE_URL=file:///pkg/releases

installed()
{
    rpm -q --qf '%{VERSION}' filetrace 2>/dev/null || true
}

sh $installer --version 0.0.0.1
expect_file /etc/yum.repos.d/filetrace.repo
expect_eq 'the version asked for' 0.0.0.1 "$(installed)"
# The package leaves the service off; the installer turns it on.
expect_eq 'enablement after install' enabled "$(systemctl is-enabled $unit)"
expect_running 'after install'
first=$(agent_pid)

sh $installer
expect_eq 'the newest version' "$FT_VERSION" "$(installed)"
expect_running 'after upgrade'
checks=$((checks + 1))
[ "$(agent_pid)" != "$first" ] || fail 'the upgrade did not restart the agent'
expect_version
expect_exit 0 rpm -K "$(rpm -q filetrace --qf '/pkg/releases/v%{VERSION}-stable/filetrace-%{VERSION}-%{RELEASE}.%{ARCH}.rpm')"

sh $installer --uninstall
expect_exit 1 rpm -q filetrace
expect_no_file /etc/yum.repos.d/filetrace.repo

summary repo-rpm
