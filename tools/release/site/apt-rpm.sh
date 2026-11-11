#!/bin/sh
# Builds the apt and yum repositories of the site. Runs in the image of
# debian.Dockerfile with the releases at /releases, the site at /site and the
# OpenPGP private key at /keys/gpg.key.
set -eu

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
gpg --batch --quiet --import /keys/gpg.key
key=$(gpg --batch --list-secret-keys --with-colons | awk -F: '$1 == "fpr" { print $10; exit }')
gpg --batch --armor --export "$key" >/site/gpg.key

sign()
{
    gpg --batch --yes --local-user "$key" --armor --detach-sign --output "$2" "$1"
}

# The lts channel offers the releases of lts lines; stable offers every release.
lts_versions=
for release in /releases/v*-lts; do
    [ -d "$release" ] || continue
    version=${release##*/v}
    lts_versions="$lts_versions ${version%-lts}"
done
channels=stable
[ -z "$lts_versions" ] || channels='stable lts'

# in_channel <channel> <package path>
in_channel()
{
    case $1:$2 in
    stable:* | lts:/releases/v*-lts/*) return 0 ;;
    esac
    return 1
}

pool=pool/main/f/filetrace
mkdir -p "/site/apt/$pool"
cp /releases/*/filetrace_*.deb "/site/apt/$pool/"
cd /site/apt
for channel in $channels; do
    for arch in amd64 arm64; do
        index=dists/$channel/main/binary-$arch
        mkdir -p "$index"
        apt-ftparchive --arch "$arch" packages pool >"$index/Packages"
        if [ "$channel" = lts ]; then
            awk -v RS= -v ORS='\n\n' -v wanted="$lts_versions" '
                BEGIN { count = split(wanted, list, " "); for (i = 1; i <= count; i++) keep[list[i]] }
                match($0, /(^|\n)Version: [^\n]+/) {
                    version = substr($0, RSTART, RLENGTH)
                    sub(/^\n?Version: /, "", version)
                    if (version in keep) print
                }
            ' "$index/Packages" >"$index/Packages.kept"
            mv "$index/Packages.kept" "$index/Packages"
        fi
        gzip -9nk "$index/Packages"
        # Fetched by checksum, a replaced index stays for the clients still reading it.
        mkdir -p "$index/by-hash/SHA256"
        for file in "$index/Packages" "$index/Packages.gz"; do
            cp "$file" "$index/by-hash/SHA256/$(sha256sum "$file" | cut -d' ' -f1)"
        done
    done
    apt-ftparchive \
        -o APT::FTPArchive::Release::Origin=Filetrace \
        -o APT::FTPArchive::Release::Label=Filetrace \
        -o APT::FTPArchive::Release::Suite="$channel" \
        -o APT::FTPArchive::Release::Codename="$channel" \
        -o APT::FTPArchive::Release::Architectures='amd64 arm64' \
        -o APT::FTPArchive::Release::Components=main \
        -o APT::FTPArchive::Release::Acquire-By-Hash=yes \
        -o APT::FTPArchive::Release::MD5=false \
        -o APT::FTPArchive::Release::SHA1=false \
        -o APT::FTPArchive::Release::SHA512=false \
        release "dists/$channel" >Release
    mv Release "dists/$channel/Release"
    gpg --batch --yes --local-user "$key" --clearsign \
        --output "dists/$channel/InRelease" "dists/$channel/Release"
    sign "dists/$channel/Release" "dists/$channel/Release.gpg"
done

for channel in $channels; do
    for arch in x86_64 aarch64; do
        target=/site/rpm/$channel/$arch
        mkdir -p "$target"
        for package in /releases/*/filetrace-*."$arch".rpm; do
            [ -f "$package" ] || continue
            in_channel "$channel" "$package" || continue
            cp "$package" "$target/"
            # createrepo_c records this time, and a new one would rename the index.
            touch -d "@$(rpm -qp --qf '%{BUILDTIME}' "$package" 2>/dev/null)" "$target/${package##*/}"
        done
        # gzip is the one compression every yum, dnf and zypper reads.
        createrepo_c --quiet --general-compress-type gz "$target"
        sign "$target/repodata/repomd.xml" "$target/repodata/repomd.xml.asc"
    done
done
