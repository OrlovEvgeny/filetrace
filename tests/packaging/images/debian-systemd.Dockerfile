FROM debian:13@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6

# policy-rc.d keeps services from starting while an image is built; a booted
# system has none.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl procps systemd systemd-sysv \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/sbin/policy-rc.d

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
