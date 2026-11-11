#!/bin/sh
# usage: keys.sh <directory>
# Creates the signing keys of the package repositories in <directory>:
#   gpg.key         OpenPGP key for the apt and yum repositories and the rpm packages
#   filetrace.rsa   RSA key for the apk repository and packages
# Neither has a passphrase, so the directory has to stay private.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
[ $# -eq 1 ] || {
    echo "usage: keys.sh <directory>" >&2
    exit 2
}
mkdir -p "$1"
out=$(CDPATH='' cd -- "$1" && pwd)
if [ -e "$out/gpg.key" ] || [ -e "$out/filetrace.rsa" ]; then
    echo "keys.sh: $out already holds keys" >&2
    exit 1
fi

docker build -q -t filetrace-site-debian -f "$root/tools/release/site/debian.Dockerfile" \
    "$root/tools/release/site" >/dev/null
docker run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$out:/out" \
    filetrace-site-debian sh -eu <<'SCRIPT'
umask 077
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
    --quick-generate-key 'Filetrace releases' rsa4096 sign never
gpg --batch --armor --export-secret-keys >/out/gpg.key
openssl genrsa -out /out/filetrace.rsa 4096 2>/dev/null
SCRIPT
ls -l "$out"
