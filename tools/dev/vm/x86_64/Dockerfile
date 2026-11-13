# The amd64 userland of the x86_64 guests and their kernels: Debian's 6.12.13, without the fix for
# CVE-2025-21834, and 6.12.15, with it.

# On the build host's own architecture: an emulated curl crashes in TLS.
FROM --platform=$BUILDPLATFORM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 AS kernels

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/kernels /tmp/debs && cd /tmp/debs \
 && curl -fsSL -o linux-image-6.12.13-amd64.deb \
        https://snapshot.debian.org/file/fff1cff30ac1f83bf0411f7fd5319c9d26684e96 \
 && curl -fsSL -o linux-image-6.12.15-amd64.deb \
        https://snapshot.debian.org/file/098fde5095a14444b7ea53f8cf415254611affa1 \
 && printf '%s  %s\n' \
        484fffd29cba8343619217406ac2fc86af2285f1d6a3ecd16982dbf444f03421 linux-image-6.12.13-amd64.deb \
        a938720b42fb18ce2221f9e8f92622faeb3683d06ed42fe4df08c63fb1e307c8 linux-image-6.12.15-amd64.deb \
    | sha256sum -c - \
 && for deb in *.deb; do \
        dpkg-deb --fsys-tarfile "$deb" | tar -x --wildcards './boot/vmlinuz-*' './boot/config-*'; \
    done \
 && mv boot/vmlinuz-* boot/config-* /opt/kernels/ \
 && cd / && rm -rf /tmp/debs

FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        busybox-static \
        cpio \
        curl \
        gcc \
        libc6-dev \
        php-cli \
 && rm -rf /var/lib/apt/lists/*

COPY --from=kernels /opt/kernels /opt/kernels
