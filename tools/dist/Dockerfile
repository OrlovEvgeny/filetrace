FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache \
        binutils \
        clang \
        cmake \
        elfutils-dev \
        gcc \
        libbpf-dev \
        linux-headers \
        llvm \
        musl-dev \
        nghttp2-dev \
        nghttp2-static \
        pkgconf \
        protobuf-c-dev \
        samurai \
        zlib-dev \
        zlib-static \
        zstd-dev \
        zstd-static

WORKDIR /src
