FROM rockylinux/rockylinux:9@sha256:8101994123cf3d0a8fee517bee7f39e555c7d92bd2d9eb3303cc988a0eeed00f

RUN dnf -y install procps-ng systemd \
 && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
