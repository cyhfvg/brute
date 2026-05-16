FROM alpine:latest

RUN apk add --no-cache \
    openssh \
    bash \
    shadow

# 创建 sshd 运行目录
RUN mkdir -p /var/run/sshd

# 设置 root 密码
RUN echo 'root:root123456' | chpasswd

# 拷贝 sshd 配置
COPY sshd_config /etc/ssh/sshd_config

# 拷贝用户初始化脚本
COPY init-users.sh /init-users.sh

RUN chmod +x /init-users.sh

# 初始化用户
RUN /init-users.sh

# 生成 host key
RUN ssh-keygen -A

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
