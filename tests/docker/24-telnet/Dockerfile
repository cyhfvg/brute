FROM alpine:3.20
RUN apk add --no-cache busybox-extras
COPY telnet-login.sh /usr/local/bin/telnet-login
RUN chmod +x /usr/local/bin/telnet-login
EXPOSE 23
CMD ["telnetd", "-F", "-p", "23", "-l", "/usr/local/bin/telnet-login"]
