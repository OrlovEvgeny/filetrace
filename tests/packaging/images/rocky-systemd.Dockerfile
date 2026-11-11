FROM rockylinux/rockylinux:10@sha256:827d37bc128288ccf160ee318bb3cb92d591164cb217e92f8bc61e3982ae1834

RUN dnf -y install procps-ng systemd \
 && dnf clean all

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
