FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends snmpd \
    && rm -rf /var/lib/apt/lists/*

COPY snmpd.conf /etc/snmp/snmpd.conf

EXPOSE 161/udp

CMD ["snmpd", "-f", "-Lo", "-C", "-c", "/etc/snmp/snmpd.conf"]
