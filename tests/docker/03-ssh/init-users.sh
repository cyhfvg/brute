#!/bin/sh

echo "[*] Initializing SSH users..."

create_user() {
    USERNAME="$1"
    PASSWORD="$2"

    if ! id "$USERNAME" >/dev/null 2>&1; then
        adduser -D -s /bin/sh "$USERNAME"
        echo "[+] User created: $USERNAME"
    else
        echo "[*] User exists: $USERNAME"
    fi

    echo "${USERNAME}:${PASSWORD}" | chpasswd
}

create_user "admin" "admin123"
create_user "query" "query_query"
create_user "test" "testpass1"

echo "root:toor" | chpasswd

echo "[+] SSH user initialization done."
