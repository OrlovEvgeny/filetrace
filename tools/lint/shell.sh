#!/bin/sh
# usage: shell.sh
# Lints the shell scripts, the service script templates and the maintainer
# scripts as packages assemble them.
set -eu

cd "$(dirname -- "$0")/../.."

# The maintainer script bodies are fragments that only run behind lib.sh.
git ls-files -z '*.sh' \
    ':!packaging/scripts/postinstall.sh' \
    ':!packaging/scripts/preremove.sh' \
    ':!packaging/scripts/postremove.sh' |
    xargs -0 shellcheck --severity=warning

shellcheck --severity=warning --shell=sh packaging/sysv/*.in packaging/openrc/*.in

for hook in postinstall preremove postremove; do
    {
        printf '#!/bin/sh\nset -e\nft_format=deb\n'
        cat packaging/scripts/lib.sh "packaging/scripts/$hook.sh"
    } | shellcheck --severity=warning -
done

sed -e '/^# @lib@$/{' -e 'r packaging/scripts/lib.sh' -e 'd' -e '}' packaging/install.sh.in |
    shellcheck --severity=warning --shell=sh -
