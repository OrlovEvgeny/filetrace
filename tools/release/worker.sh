#!/bin/sh
# usage: worker.sh
# Deploys the Cloudflare Worker that serves https://filetrace.eorlov.org:
# the download site from the R2 bucket and the documentation from Mintlify.
# R2_BUCKET_NAME names the bucket. Wrangler needs a login (npx wrangler login)
# or CLOUDFLARE_API_TOKEN with permission to edit Workers and the zone.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
: "${R2_BUCKET_NAME:?names the bucket of the download site}"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sed -e "s|@worker@|$root/packaging/site/worker.js|" -e "s|@bucket@|$R2_BUCKET_NAME|" \
    "$root/packaging/site/wrangler.toml.in" >"$work/wrangler.toml"
cd "$work"
npx --yes wrangler@4 deploy --config "$work/wrangler.toml"
