FROM rockylinux/rockylinux:9@sha256:bb5755f96bec05ff26165e779ec843d7167544be9e50770508f307019a6d05c4

RUN dnf -y install procps-ng systemd \
 && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
