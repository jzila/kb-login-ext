FROM alpine:3.3
MAINTAINER John Zila <john@jzila.com>

EXPOSE 6379

RUN apk add --update redis && \
    sed -i 's/daemonize yes/daemonize no/g' /etc/redis.conf && \
    sed -i 's/# bind 0.0.0.0/bind 0.0.0.0/g' /etc/redis.conf && \
    rm -rf /var/cache/apk/*

ENTRYPOINT ["redis-server", "/etc/redis.conf"]

CMD []
