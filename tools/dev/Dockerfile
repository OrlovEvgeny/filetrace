FROM debian:trixie-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        bpftool \
        ca-certificates \
        clang \
        cmake \
        git \
        iproute2 \
        libbpf-dev \
        libclang-rt-dev \
        libelf-dev \
        libnghttp2-dev \
        libprotobuf-c-dev \
        linux-libc-dev \
        llvm \
        ninja-build \
        pkgconf \
        procps \
        zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# The mounted tree belongs to the host user, which git refuses to read otherwise.
RUN git config --system --add safe.directory /src

WORKDIR /src
