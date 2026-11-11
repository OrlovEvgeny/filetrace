#!/bin/sh
# Runs as an ordinary user without capabilities, on the unpacked tarball at /opt.
set -eu
. /src/tests/packaging/assert.sh

PATH=/opt/bin:$PATH

expect_version
expect_exit 0 filetrace --help
expect_exit 0 filetrace config validate
expect_exit 0 filetrace config validate /opt/etc/filetrace/config.toml
expect_exit 2 filetrace no-such-command
expect_exit 4 filetrace agent status
expect_exit 4 filetrace files
expect_exit 3 filetrace doctor
expect_exit 0 filetrace-agent --help
expect_exit 2 filetrace-agent --no-such-option
expect_exit 6 filetrace-agent --config /nonexistent
expect_exit 3 filetrace-agent

sh /src/tests/packaging/config.sh /opt/bin/filetrace /opt/etc/filetrace/config.toml

summary unprivileged
