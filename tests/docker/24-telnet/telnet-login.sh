#!/bin/sh
printf 'login: '
read user
printf 'Password: '
read pass
user=$(printf '%s' "$user" | tr -d '\r')
pass=$(printf '%s' "$pass" | tr -d '\r')
printf '\n'
if [ "$user" = "admin" ] && [ "$pass" = "telnet_pass" ]; then
  export PS1='# '
  exec /bin/sh
fi
echo 'Login incorrect'
exit 1
