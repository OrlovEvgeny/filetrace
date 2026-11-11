FROM rockylinux/rockylinux:9

RUN dnf -y install procps-ng systemd \
 && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
