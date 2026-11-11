FROM alpine:3.24

RUN apk add --no-cache curl openrc

CMD ["sleep", "infinity"]
