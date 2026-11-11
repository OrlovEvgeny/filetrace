FROM debian:13

# policy-rc.d keeps services from starting while an image is built; a booted
# system has none.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl procps systemd systemd-sysv \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/sbin/policy-rc.d

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
