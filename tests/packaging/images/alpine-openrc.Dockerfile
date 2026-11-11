FROM alpine:3.24

RUN apk add --no-cache openrc

CMD ["sleep", "infinity"]
