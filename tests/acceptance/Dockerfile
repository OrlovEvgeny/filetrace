FROM debian:stable-slim@sha256:9e3624ad785d0d322f0c69194c2c0ebba7bc5fda3e2c6523ac095b4f08a12ba7
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl openssl nginx php-cli php-curl \
      python3 python3-flask python3-requests python3-httpx \
      perl libwww-perl libio-socket-ssl-perl liblwp-protocol-https-perl \
      nodejs \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* /usr/share/doc /usr/share/man \
      /usr/share/locale/*/LC_MESSAGES/*.mo
COPY certs.sh /usr/local/bin/ft-acceptance-certs
RUN sh /usr/local/bin/ft-acceptance-certs /opt/ft-acceptance/tls
