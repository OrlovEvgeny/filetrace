#!/bin/sh
# usage: deploy.sh <site directory>
# Uploads the site that site.sh built to the R2 bucket that serves
# https://filetrace.eorlov.org. What never changes under its name goes first
# and the indexes that refer to it after, so a client finds every file an
# index names, whichever index it holds. Nothing is deleted.
# R2_ACCOUNT_ID, R2_BUCKET_NAME, R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY name
# the bucket and an API token that may write its objects.
# FILETRACE_SITE_REMOTE names another rclone destination to upload to instead.
set -eu

[ $# -eq 1 ] || {
    echo "usage: deploy.sh <site directory>" >&2
    exit 2
}
site=$(CDPATH='' cd -- "$1" && pwd)

remote=${FILETRACE_SITE_REMOTE:-}
if [ -z "$remote" ]; then
    : "${R2_ACCOUNT_ID:?names the Cloudflare account}"
    : "${R2_BUCKET_NAME:?names the bucket}"
    : "${R2_ACCESS_KEY_ID:?names the API token}"
    : "${R2_SECRET_ACCESS_KEY:?holds the secret of the API token}"
    export RCLONE_CONFIG=/dev/null
    export RCLONE_S3_PROVIDER=Cloudflare
    export RCLONE_S3_ENDPOINT="https://$R2_ACCOUNT_ID.r2.cloudflarestorage.com"
    export RCLONE_S3_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID"
    export RCLONE_S3_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
    # A token scoped to the objects of one bucket may not ask whether the bucket exists.
    export RCLONE_S3_NO_CHECK_BUCKET=true
    remote=:s3:$R2_BUCKET_NAME
fi

# Release files, packages, and the indexes named after their own checksum.
fixed='/dist/**
*.deb
*.rpm
*.apk
/apt/dists/**/by-hash/**
/rpm/**/repodata/*-*'

# What a browser should show instead of saving.
text='/install.sh
/gpg.key
/apk/filetrace.rsa.pub
/channels/*
/versions/*'

# only <patterns>: the rclone filter that admits nothing else.
only()
{
    printf '%s\n' "$1" | sed 's/^/+ /'
    echo '- *'
}

# upload <cache-control> <rclone argument>...: copies what the filter on stdin admits.
upload()
{
    cache=$1
    shift
    rclone copy "$site" "$remote" --checksum --filter-from - --verbose --stats 0 \
        --header-upload "Cache-Control: $cache" "$@"
}

# A file of a published release that differs from the bucket's is an error, not an update.
only "$fixed" | upload 'public, max-age=31536000, immutable' --immutable
printf '%s\n' "$fixed" "$text" | sed 's/^/- /' | upload no-cache
only "$text" | upload no-cache --header-upload 'Content-Type: text/plain; charset=utf-8'
