FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        memcached \
        sasl2-bin \
        libsasl2-2 \
        libsasl2-modules \
        ca-certificates \
        procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/sasl2

COPY memcached.conf /etc/sasl2/memcached.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 11211

ENTRYPOINT ["/entrypoint.sh"]
