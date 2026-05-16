#!/bin/sh

set -e

for i in $(seq 1 50); do
    username="test${i}"
    password="Pass@123${i}"

    adduser -D -s /bin/bash "${username}"

    echo "${username}:${password}" | chpasswd
done
# 创建常见弱口令用户
for username in \
    admin \
    test \
    ubuntu \
    oracle \
    mysql \
    tomcat
do
    adduser -D -s /bin/bash "${username}"

    echo "${username}:${username}" | chpasswd
done

echo "[+] users initialized"
