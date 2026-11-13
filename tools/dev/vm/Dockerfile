FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        busybox-static \
        ca-certificates \
        cpio \
        gnutls-bin \
        openssl \
        libbpf1 \
        libfcgi-bin \
        libnghttp2-14 \
        libprotobuf-c1 \
        php-fpm \
        qemu-system-arm \
 && echo "deb http://deb.debian.org/debian bookworm main" > /etc/apt/sources.list.d/bookworm.list \
 && apt-get update \
 && mkdir -p /opt/kernels /tmp/debs && cd /tmp/debs \
 && for suite in bookworm trixie; do \
        version=$(apt-cache madison linux-image-arm64 | awk -v s="$suite/main" '$0 ~ s { print $3; exit }'); \
        package=$(apt-cache depends "linux-image-arm64=$version" | awk '/Depends: linux-image-/ { print $2; exit }'); \
        apt-get download "$package"; \
    done \
 && for deb in *.deb; do \
        dpkg-deb --fsys-tarfile "$deb" | tar -x --wildcards './boot/vmlinuz-*' './boot/config-*'; \
    done \
 && mv boot/vmlinuz-* boot/config-* /opt/kernels/ \
 && rm -rf /tmp/debs /var/lib/apt/lists/*
