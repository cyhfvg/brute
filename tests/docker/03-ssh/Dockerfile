FROM alpine:3.22

RUN apk add --no-cache \
    openssh \
    shadow \
    bash

# Enable password login
RUN sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#PermitRootLogin yes/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    echo 'AllowUsers root admin query test' >> /etc/ssh/sshd_config && \
    echo 'MaxAuthTries 99999' >> /etc/ssh/sshd_config && \
    echo 'MaxStartups 100:100:200' >> /etc/ssh/sshd_config && \
    echo 'PerSourcePenalties no' >> /etc/ssh/sshd_config && \
    echo 'LoginGraceTime 100m' >> /etc/ssh/sshd_config && \
    echo 'PubkeyAuthentication no' >> /etc/ssh/sshd_config

# SSH host keys
RUN ssh-keygen -A

EXPOSE 22
