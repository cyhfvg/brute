#!/bin/sh
set -eu

USER_NAME="${MEMCACHED_USER:-admin}"
USER_PASS="${MEMCACHED_PASS:-memcached_pass}"
SASLDB="/etc/sasl2/memcached-sasldb2"

rm -f "$SASLDB"
printf '%s' "$USER_PASS" | saslpasswd2 -p -c -a memcached -f "$SASLDB" "$USER_NAME"
chmod 644 "$SASLDB"

exec memcached -u memcache -S -m 64 -p 11211 -l 0.0.0.0
