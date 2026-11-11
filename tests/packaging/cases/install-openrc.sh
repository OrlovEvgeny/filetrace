#!/bin/sh
# Runs in an Alpine container with OpenRC marked as started; install.sh is told
# to unpack the release archive instead of using the package repository.
set -eu
. /src/tests/packaging/assert.sh

service=filetrace-agent
installer=/pkg/new/install.sh
method='--method tarball'
export FILETRACE_REPO_URL=file:///pkg/bucket
mkdir -p /run/openrc
touch /run/openrc/softlevel

sh $installer $method
for path in /usr/local/bin/filetrace /usr/local/bin/filetrace-agent \
    /etc/filetrace/config.toml /etc/init.d/$service /etc/conf.d/$service; do
    expect_file "$path"
done
expect_exit 0 grep -q '^command=/usr/local/bin/filetrace-agent$' /etc/init.d/$service
checks=$((checks + 1))
rc-update show default | grep -q $service || fail 'the service is not in the default runlevel'
expect_running 'after install'
expect_version

sh $installer --uninstall
expect_no_file /usr/local/bin/filetrace
expect_no_file /etc/init.d/$service
checks=$((checks + 1))
! rc-update show default | grep -q $service || fail 'the service is still in the default runlevel'
expect_file /etc/filetrace/config.toml

summary install-openrc
