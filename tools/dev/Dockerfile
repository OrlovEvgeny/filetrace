FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        bpftool \
        ca-certificates \
        clang \
        cmake \
        git \
        gnutls-bin \
        openssl \
        iproute2 \
        libbpf-dev \
        libclang-rt-dev \
        libelf-dev \
        libnghttp2-dev \
        libprotobuf-c-dev \
        linux-libc-dev \
        libfcgi-bin \
        llvm \
        ninja-build \
        php-cli \
        php-fpm \
        pkgconf \
        procps \
        python3 \
        zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# The mounted tree belongs to the host user, which git refuses to read otherwise.
RUN git config --system --add safe.directory /src

WORKDIR /src
