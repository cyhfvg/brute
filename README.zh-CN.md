# brute

`brute` 是一个使用 Rust 编写的多协议口令爆破与登录验证命令行工具，适用于授权安全测试、实验环境验证和内部口令审计。

英文主文档见：[README.md](README.md)。

## 项目侧重点

`brute` 面向实战环境中的轻量部署：

- 静态编译单文件发布。
- 运行时不依赖 OpenSSL/libssh2/native-tls 动态库。
- 对离线环境友好。
- 类 NetExec 的协议优先命令结构。
- 清晰终端输出，成功凭据高亮显示。
- 本地 SQLite 凭据数据库，支持 workspace 隔离。
- MCP stdio 服务, 供大模型验证账户、密码喷洒, 以及查询已保存凭据。


目标工作流是：构建一次，复制单个二进制到授权测试环境，无需额外安装共享库即可运行。

## 致谢

感谢 [NetExec](https://github.com/Pennyw0rth/NetExec) 对协议化 CLI 风格和可读输出格式的启发。`brute` 也参考了 Hydra、Medusa 在 HTTP/Tomcat 认证测试场景中的常见使用方式。

本项目使用 AI 工具 Codex 辅助编码实现。

## 支持协议

已实现模块：

- `ssh`
- `ftp`
- `mysql`
- `postgresql`
- `redis`
- `oracle`
- `tomcat-manager`，别名 `tomcat`
- `smb`（无 `-x`；可选 `--shares` 枚举 share/Access）
- `rdp`（仅登录/爆破，无 `-x`）
- `winrm`
- `vnc`（仅登录/爆破，无 `-x`）
- `http`（HTTP Basic Auth 登录/爆破；`--path`，默认 `/`；`--protocol {http,https}`，默认 `http`；HTTPS 默认跳过证书校验；无 `-x`）
- `zookeeper`（别名 `zk`；登录/爆破/未授权；`-x` zkCli 风格命令；默认端口 `2181`）
- `memcached`（别名 `memcache`；登录/爆破/未授权；`-x` stats/get/set；默认端口 `11211`）
- `mongodb`（别名 `mongo`；登录/爆破/未授权；`-x` ping/listDatabases；默认端口 `27017`）
- `elasticsearch`（别名 `es`；登录/爆破/未授权 HTTP Basic；`-x` `_cat` 路径；默认端口 `9200`）
- `docker`（别名 `docker-api`；未授权 Docker Engine API；`-x` `/info` `/containers/json`；默认端口 `2375`）
- `snmp`（SNMPv2c community；`-x` OID GET；默认端口 `161/udp`）
- `activemq`（别名 `amq`；STOMP CONNECT；`-x` SEND；默认端口 `61613`）
- `rabbitmq`（别名 `amqp`；AMQP 0-9-1；`-x` queue.declare；默认端口 `5672`）
- `rsync`（daemon 模块 AUTHREQD；`--module`；默认端口 `873`）
- `mssql`（别名 `sqlserver`；TDS 登录；`-x` SQL；默认端口 `1433`）
- `kafka`（SASL/PLAIN；`-x` metadata；默认端口 `9092`）
- `kibana`（HTTP 登录；`-x` status API；默认端口 `5601`）
- `nfs`（NFSv3 ONC RPC AUTH_NULL/AUTH_UNIX；`-x` dump；默认端口 `2049`）
- `telnet`（IAC + login/password；`-x` shell 命令；默认端口 `23`）
- `ldap`（simple bind；`-x` whoami/search；默认端口 `389`）
- `grafana`（HTTP 登录；`-x` org API；默认端口 `3000`）
- `prometheus`（别名 `prom`；HTTP Basic；`-x` query/metrics；默认端口 `9090`）
- `jenkins`（HTTP Basic；`-x` whoami/api；默认端口 `8080`）
- `couchdb`（别名 `couch`；HTTP Basic；`-x` dbs；默认端口 `5984`）
- `clickhouse`（别名 `ch`；HTTP SQL；`-x` version；默认端口 `8123`）
- `neo4j`（HTTP Cypher；`-x` ping；默认端口 `7474`）
- `etcd`（v3 HTTP；`-x` version；默认端口 `2379`）
- `influxdb`（别名 `influx`；InfluxQL HTTP；`-x` dbs；默认端口 `8086`）
- `solr`（admin HTTP；`-x` cores；默认端口 `8983`）
- `minio`（console HTTP；`-x` buckets；默认端口 `9001`）
- `nacos`（HTTP；`-x` namespaces；默认端口 `8848`）
- `nexus`（REST HTTP；`-x` repos；默认端口 `8081`）
- `jboss`（别名 `wildfly`；management Digest；`-x` version；默认端口 `9990`）
- `druid`（SQL HTTP；`-x` status；默认端口 `8888`）
- `spark`（master UI；`-x` json；默认端口 `8080`）
- `hadoop`（别名 `hdfs`；NameNode HTTP；`-x` jmx；默认端口 `9870`）
- `kubelet`（HTTPS；token 放 `-p`；`-x` pods；默认端口 `10250`）
- `gitlab`（HTTP；`-x` user；默认端口 `80`）

当前协议待办见：[docs/TODO.md](docs/TODO.md)。

## 安装与构建

### 直接下载 Release

从 [GitHub Releases](https://github.com/cyhfvg/brute/releases) 下载预编译二进制，赋予执行权限后即可使用：

```bash
# 示例: Linux x86_64 musl 静态二进制
chmod +x brute
./brute --help
```

如有 musl / 静态构建产物，优先使用，可避免依赖系统动态库。

### 从源码构建

开发构建：

```bash
cargo build
```

release 构建：

```bash
cargo build --release
```

Linux musl 静态 release：

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

产物路径：

```text
target/x86_64-unknown-linux-musl/release/brute
```

检查静态链接：

```bash
ldd target/x86_64-unknown-linux-musl/release/brute
```

预期结果：

```text
statically linked
```

## 快速开始

基本格式：

```bash
brute <protocol> <target|target_file>... (-u <username|user_file>... -p <password|pass_file>... | --id <credential_id>) [options]
```

示例：

```bash
brute ssh 192.168.10.5 -u root admin -p 123456 password --port 22
brute ssh 192.168.10.5 -u admin -p 123456 -x 'id'
brute ssh targets.txt -u users.txt -p pass.txt --threads 32
brute ftp 192.168.10.5 -u users.txt -p pass.txt -x 'PWD'
brute mysql db.internal -u root -p weakpass --port 3306 -x 'show databases;'
brute postgresql 192.168.10.5 -u pg_users.txt -p pg_pass.txt -x 'select version();'
brute oracle db.internal -u system -p oracle --service-name ORCLPDB1 -x 'select * from dual'
brute oracle db.internal -u users.txt -p pass.txt --service-name services.txt
brute redis 192.168.10.5 -u '' -p redis_pass.txt -x 'INFO server'
brute tomcat 192.168.10.5 -u user.txt -p passwd.txt --port 8080 --path /manager/html
brute tomcat 10.10.50.24/29 -u admin -p admin123
brute http 192.168.10.5 -u admin -p 123456 --path /
brute http 192.168.10.5 -u users.txt -p pass.txt --port 8080 --path /manager/html --threads 16
brute http 192.168.10.5 -u admin -p secret --protocol https --port 8443 --path /
brute smb 192.168.10.5 -u users.txt -p pass.txt --port 445
brute smb 192.168.10.5 -u admin -p 'P@ssw0rd' --shares
brute rdp 192.168.10.5 -u users.txt -p pass.txt --port 3389
brute vnc 192.168.10.5 -u '' -p 'secret' --port 5900
brute vnc 192.168.10.5 -u users.txt -p pass.txt --port 5901 --threads 16
brute winrm 192.168.10.5 -u users.txt -p pass.txt --port 5985
brute winrm 192.168.10.5 -u admin -p 'P@ssw0rd' -x 'whoami'
brute winrm 192.168.10.5 -u admin -p 'P@ssw0rd' --shell-type powershell -x 'whoami'
brute winrm 192.168.10.5 -u admin -p 'P@ssw0rd' --shell-type cmd -x @script.bat
brute winrm 192.168.10.5 -u admin -p 'P@ssw0rd' --shell-type powershell -x @script.ps1
brute zookeeper 192.168.5.10 -u zkadmin -p '7ojb*tkzxKnsD]8Akgef'
brute zookeeper 192.168.5.10 -u '' -p ''
brute zookeeper 192.168.5.10 -u user.txt -p pass.txt --continue-on-success
brute zookeeper 192.168.5.10 -u zkadmin -p 'zkadmin_pass' -x 'ls /'
brute memcached 192.168.5.10 -u admin -p 'memcached_pass'
brute memcached 192.168.5.10 -u '' -p ''
brute memcached 192.168.5.10 -u user.txt -p pass.txt --continue-on-success
brute memcached 192.168.5.10 -u admin -p 'memcached_pass' -x 'stats'
brute mongodb 192.168.5.10 -u admin -p 'mongodb_pass'
brute mongodb 192.168.5.10 -u '' -p ''
brute mongodb 192.168.5.10 -u user.txt -p pass.txt --continue-on-success
brute mongodb 192.168.5.10 -u admin -p 'mongodb_pass' -x 'listDatabases'
brute elasticsearch 192.168.5.10 -u elastic -p 'elastic_pass'
brute elasticsearch 192.168.5.10 -u '' -p ''
brute elasticsearch 192.168.5.10 -u elastic -p 'elastic_pass' -x 'indices'
brute docker 192.168.5.10 -u '' -p ''
brute docker 192.168.5.10 -u '' -p '' -x 'containers'
brute snmp 192.168.5.10 -u '' -p secret
brute snmp 192.168.5.10 -u '' -p secret -x sysName
brute activemq 192.168.5.10 -u admin -p admin
brute activemq 192.168.5.10 -u admin -p admin -x 'hello'
brute rabbitmq 192.168.5.10 -u admin -p 'rabbit_pass'
brute rabbitmq 192.168.5.10 -u admin -p 'rabbit_pass' -x brute
brute rsync 192.168.5.10 -u admin -p secret --module files
brute mssql 192.168.5.10 -u sa -p 'Your_password1'
brute mssql 192.168.5.10 -u sa -p 'Your_password1' -x 'SELECT @@VERSION'
brute kafka 192.168.5.10 -u admin -p kafka_pass
brute kafka 192.168.5.10 -u admin -p kafka_pass -x metadata
brute kibana 192.168.5.10 -u elastic -p elastic_pass
brute kibana 192.168.5.10 -u elastic -p elastic_pass -x status
brute nfs 192.168.5.10 -u '' -p ''
brute nfs 192.168.5.10 -u 0 -p '' -x dump
brute telnet 192.168.5.10 -u admin -p telnet_pass
brute telnet 192.168.5.10 -u '' -p ''
brute telnet 192.168.5.10 -u admin -p telnet_pass -x id
brute ldap 192.168.5.10 -u 'cn=admin,dc=example,dc=org' -p ldap_pass
brute ldap 192.168.5.10 -u '' -p ''
brute ldap 192.168.5.10 -u 'cn=admin,dc=example,dc=org' -p ldap_pass -x whoami
brute grafana 192.168.5.10 -u admin -p grafana_pass
brute grafana 192.168.5.10 -u '' -p ''
brute grafana 192.168.5.10 -u admin -p grafana_pass -x org
brute prometheus 192.168.5.10 -u admin -p prometheus_pass
brute prometheus 192.168.5.10 -u '' -p ''
brute prometheus 192.168.5.10 -u admin -p prometheus_pass -x query
brute jenkins 192.168.5.10 -u admin -p jenkins_pass
brute jenkins 192.168.5.10 -u '' -p ''
brute jenkins 192.168.5.10 -u admin -p jenkins_pass -x whoami
brute couchdb 192.168.5.10 -u admin -p couch_pass
brute couchdb 192.168.5.10 -u '' -p ''
brute couchdb 192.168.5.10 -u admin -p couch_pass -x dbs
brute clickhouse 192.168.5.10 -u admin -p click_pass
brute clickhouse 192.168.5.10 -u '' -p ''
brute clickhouse 192.168.5.10 -u admin -p click_pass -x version
brute neo4j 192.168.5.10 -u neo4j -p neo4j_pass
brute neo4j 192.168.5.10 -u '' -p ''
brute neo4j 192.168.5.10 -u neo4j -p neo4j_pass -x ping
brute etcd 192.168.5.10 -u root -p etcd_pass
brute etcd 192.168.5.10 -u '' -p ''
brute etcd 192.168.5.10 -u root -p etcd_pass -x version
brute influxdb 192.168.5.10 -u admin -p influx_pass
brute influxdb 192.168.5.10 -u '' -p ''
brute influxdb 192.168.5.10 -u admin -p influx_pass -x dbs
brute solr 192.168.5.10 -u solr -p solr_pass
brute solr 192.168.5.10 -u '' -p ''
brute solr 192.168.5.10 -u solr -p solr_pass -x cores
brute minio 192.168.5.10 -u minioadmin -p minio_pass
brute minio 192.168.5.10 -u '' -p ''
brute minio 192.168.5.10 -u minioadmin -p minio_pass -x buckets
brute nacos 192.168.5.10 -u nacos -p nacos
brute nacos 192.168.5.10 -u '' -p ''
brute nacos 192.168.5.10 -u nacos -p nacos -x namespaces
brute nexus 192.168.5.10 -u admin -p nexus_pass
brute nexus 192.168.5.10 -u '' -p ''
brute nexus 192.168.5.10 -u admin -p nexus_pass -x repos
brute jboss 192.168.5.10 -u admin -p jboss_pass
brute jboss 192.168.5.10 -u '' -p ''
brute jboss 192.168.5.10 -u admin -p jboss_pass -x version
brute druid 192.168.5.10 -u admin -p druid_pass
brute druid 192.168.5.10 -u '' -p ''
brute druid 192.168.5.10 -u admin -p druid_pass -x status
brute spark 192.168.5.10 -u spark -p spark_pass
brute spark 192.168.5.10 -u '' -p ''
brute spark 192.168.5.10 -u spark -p spark_pass -x json
brute hadoop 192.168.5.10 -u hdfs -p hadoop_pass
brute hadoop 192.168.5.10 -u '' -p ''
brute hadoop 192.168.5.10 -u hdfs -p hadoop_pass -x jmx
brute kubelet 192.168.5.10 -u '' -p k8s-token
brute kubelet 192.168.5.10 -u '' -p ''
brute kubelet 192.168.5.10 -u '' -p k8s-token -x pods
brute gitlab 192.168.5.10 -u root -p Gl7ab-Rx9p2q
brute gitlab 192.168.5.10 -u '' -p ''
brute gitlab 192.168.5.10 -u root -p Gl7ab-Rx9p2q -x user
```

## 顶级参数

以下参数与 `--version` 同级，必须写在协议子命令**之前**：

- `--proxy <PROXY_URL>`: 支持 `http` 与 `socks5`。URL 形式：`protocol://[username[:password]@]host:port`。示例：`brute --proxy socks5://user:pass@127.0.0.1:1080 ssh 10.0.0.1 -u admin -p pass`、`brute --proxy http://127.0.0.1:8080 http 10.0.0.1 -u admin -p pass`。
- `--no-color`: 关闭彩色输出。

## MCP 服务

`brute mcp` 在同一静态单文件中启动 stdio [Model Context Protocol](https://modelcontextprotocol.io/) 服务。协议走标准输入/输出上的 JSON-RPC, 不能与彩色 CLI 输出混用。

```bash
brute mcp
```

宿主配置示例:

```json
{
  "mcpServers": {
    "brute": {
      "command": "/path/to/brute",
      "args": ["mcp"]
    }
  }
}
```

提供给大模型的工具:

- `verify_account`: 用一组用户名/密码或已保存凭据 id 验证单个目标。
- `spray_passwords`: 对一个或多个目标做用户名/密码列表或字典喷洒。
- `list_credentials`: 查询已经验证并写入 `~/.config/brute/brute.db` 的凭据。
- `list_workspaces`: 列出本地 workspace 和当前 workspace。
- `list_protocols`: 列出支持的协议和默认端口。

MCP 验证成功后的凭据会写入所选 workspace, 行为与 CLI 一致。仅允许对授权目标使用。

更完整的自然语言提问与对应 tool JSON 见 [docs/MCP.example.md](docs/MCP.example.md).



## 常用参数

- `TARGET`: 目标 IPv4 地址、IPv4 CIDR、主机名、FQDN，或包含上述内容的文件（每行一个）。IPv4 CIDR 会展开为前缀内全部地址，含网络地址与广播地址（`192.168.50.24/29` -> `192.168.50.24`..`192.168.50.31`）。单个 CIDR 最多展开 65536 个地址（`/16`）。不支持 IPv6。可传入多个。
- `-u, --username <USERNAME...>`: 用户名或用户名文件；空用户名使用 `-u ''`。
- `-p, --password <PASSWORD...>`: 密码或密码文件；空密码使用 `-p ''`。
- `--id <ID>`: 从当前 workspace 读取已保存凭据；与 `-u/-p` 互斥。
- `--port <PORT>`: 覆盖协议默认端口。
- `--threads <N>`: 同时进行的登录尝试数上限（跨目标与凭据的全局并发），默认 `16`，最小值为 `1`。
- `--retries <N>`: 传输层临时错误重试次数，默认 `3`。
- `--timeout-ms <MS>`: 单次尝试超时，默认 `5000`，最小值为 `1`。
- `--continue-on-success`: 命中成功凭据后仍继续尝试该目标剩余凭据。

`-u/-p` 与 `--id` 二选一：普通爆破使用 `-u/-p`，复用保存凭据使用 `--id`。

## 命令执行

以下模块支持登录成功后执行命令：

- `ssh`: 远程 shell 命令，例如 `-x 'id'`
- `ftp`: FTP 控制命令，例如 `-x 'PWD'`
- `mysql`: SQL 查询，例如 `-x 'show databases;'`
- `postgresql`: SQL 查询，例如 `-x 'select version();'`
- `oracle`: SQL 查询，例如 `-x 'select * from dual'`
- `redis`: Redis 命令，例如 `-x 'INFO server'`
- `winrm`: 通过 `--shell-type powershell`（`-x` 省略时默认）或 `cmd` 执行远程命令；
  使用`-x @path`加载本地脚本
- `zookeeper`: zkCli 风格命令，例如 `-x 'ls /'`
- `memcached`: ASCII/binary 命令，例如 `-x 'stats'`
- `mongodb`: admin 命令，例如 `-x 'listDatabases'`
- `elasticsearch`: HTTP GET 路径，例如 `-x 'indices'`
- `docker`: Engine API GET 路径，例如 `-x 'containers'`
- `snmp`: SNMPv2c GET，例如 `-x 'sysName'`
- `mssql`: SQL 查询，例如 `-x 'SELECT @@VERSION'`
- `activemq`: 向 `/queue/brute` STOMP SEND，例如 `-x 'hello'`
- `rabbitmq`: queue.declare，例如 `-x 'brute'`
- `kafka`: Metadata 请求，例如 `-x 'metadata'`
- `kibana`: status API，例如 `-x 'status'`
- `nfs`: 尝试 MOUNT DUMP，例如 `-x 'dump'`
- `telnet`: 远程 shell 命令，例如 `-x 'id'`
- `ldap`: whoami 或 LDAP search，例如 `-x 'whoami'`
- `grafana`: org API，例如 `-x 'org'`
- `prometheus`: PromQL 查询，例如 `-x 'query'`
- `jenkins`: Jenkins API，例如 `-x 'whoami'`
- `couchdb`: `_all_dbs`，例如 `-x 'dbs'`
- `clickhouse`: SQL 查询，例如 `-x 'version'`
- `neo4j`: Cypher，例如 `-x 'ping'`
- `etcd`: version/range API，例如 `-x 'version'`
- `influxdb`: InfluxQL，例如 `-x 'dbs'`
- `solr`: Solr admin API，例如 `-x 'cores'`
- `minio`: MinIO console API，例如 `-x 'buckets'`
- `nacos`: Nacos API，例如 `-x 'namespaces'`
- `nexus`: Nexus REST API，例如 `-x 'repos'`
- `jboss`: WildFly management，例如 `-x 'version'`
- `druid`: Druid SQL，例如 `-x 'status'`
- `spark`: Spark master UI，例如 `-x 'json'`
- `hadoop`: Hadoop NameNode，例如 `-x 'jmx'`
- `kubelet`: kubelet HTTPS，例如 `-x 'pods'`
- `gitlab`: GitLab API，例如 `-x 'user'`

示例：

```bash
brute ssh 192.168.10.5 -u admin -p 123456 -x 'id'
brute winrm 192.168.10.5 -u admin -p 123456 --shell-type powershell -x 'whoami'
```

认证已成功但认证后命令执行失败时，工具会单独输出命令错误，并仍将已验证凭据保存到当前 workspace。

## WinRM

针对 WinRM HTTP（默认端口 `5985`）的登录与字典爆破

```bash
brute winrm 192.168.10.5 -u admin -p 'P@ssw0rd'
brute winrm 192.168.10.5 -u users.txt -p pass.txt --port 5985 --threads 16
brute winrm 192.168.10.5 -u admin -p 'P@ssw0rd' -x 'whoami'
brute winrm 192.168.10.5 -u admin -p 'P@ssw0rd' --shell-type powershell -x @script.ps1
```

用户名支持 `DOMAIN\user` 或 `user@domain`。连接/协议错误会在错误行输出非空原因。HTTPS（5986）、Kerberos、CredSSP 与 NTLM hash 登录尚未实现。

## SMB

可选登录后枚举 shares：

```bash
brute smb 192.168.10.5 -u admin -p 'P@ssw0rd' --shares
```

启用 `--shares` 时，认证成功后会输出 share 名称与 Access（`READ`；磁盘 share 在非侵入写探测成功时为 `READ,WRITE`）。share 枚举失败单独报告，不会丢弃已验证凭据。

用户名支持 `DOMAIN\user` 或 `user@domain` 形式。

## RDP

仅登录与字典爆破（无 `-x` / `--execute`）：

```bash
brute rdp 192.168.10.5 -u admin -p 'P@ssw0rd'
brute rdp 192.168.10.5 -u users.txt -p pass.txt --port 3389 --threads 16
```

使用纯 Rust `rdp-rs` 完成 NLA/CredSSP（NTLM）。OpenSSL 通过 `vendored` 静态编入，release 单文件不依赖系统 `libssl`。用户名支持 `DOMAIN\user` 或 `user@domain`。

## VNC

仅登录与字典爆破（无 `-x` / `--execute`）：

```bash
brute vnc 192.168.10.5 -u '' -p 'secret'
brute vnc 192.168.10.5 -u users.txt -p pass.txt --port 5900 --threads 16
```

经典 RFB 路径使用 VNC Authentication（security type 2，DES challenge-response；密码有效长度 8 字节）。

## ZooKeeper

登录、字典爆破、允许未授权（`-u '' -p ''`）以及认证后 zkCli 风格命令（默认端口 `2181`）：

```bash
brute zookeeper 192.168.5.10 -u zkadmin -p 'zkadmin_pass'
brute zookeeper 192.168.5.10 -u '' -p ''
brute zookeeper 192.168.5.10 -u user.txt -p pass.txt --continue-on-success
brute zookeeper 192.168.5.10 -u zkadmin -p 'zkadmin_pass' -x 'ls /'
```

空凭据会探测未授权 `getChildren("/")`，集群允许匿名读取时记为未授权访问。非空凭据使用 SASL DIGEST-MD5（JAAS `DigestLoginModule`）。`-x` 支持 `ls`、`get`、`stat`、`create`、`set`、`delete`、`deleteall`、`mkdir`。命令失败不会丢掉已验证登录。别名：`zk`。

## Memcached

登录、字典爆破、允许未授权（`-u '' -p ''`）以及认证后命令（默认端口 `11211`）：

```bash
brute memcached 192.168.5.10 -u admin -p 'memcached_pass'
brute memcached 192.168.5.10 -u '' -p ''
brute memcached 192.168.5.10 -u user.txt -p pass.txt --continue-on-success
brute memcached 192.168.5.10 -u admin -p 'memcached_pass' -x 'stats'
```

空凭据会探测未授权二进制 `STAT`，守护进程允许匿名命令时记为未授权访问。非空凭据使用二进制协议 SASL PLAIN。`-x` 支持 `stats`/`version`/`get`/`set`/`delete`/`flush_all`。命令失败不会丢掉已验证登录。别名：`memcache`。

## MongoDB

登录、字典爆破、允许未授权（`-u '' -p ''`）以及认证后命令（默认端口 `27017`）：

```bash
brute mongodb 192.168.5.10 -u admin -p 'mongodb_pass'
brute mongodb 192.168.5.10 -u '' -p ''
brute mongodb 192.168.5.10 -u user.txt -p pass.txt --continue-on-success
brute mongodb 192.168.5.10 -u admin -p 'mongodb_pass' -x 'listDatabases'
```

空凭据会探测未授权 `admin.listDatabases`，部署允许匿名命令时记为未授权访问。非空凭据对 `authSource=admin` 做 SCRAM 认证。`-x` 接受 JSON 文档或简写 `ping`/`listDatabases`/`serverStatus`/`buildInfo`。命令失败不会丢掉已验证登录。别名：`mongo`。

## Elasticsearch

登录、字典爆破、允许未授权（`-u '' -p ''`）以及认证后 HTTP API GET（默认端口 `9200`）：

```bash
brute elasticsearch 192.168.5.10 -u elastic -p 'elastic_pass'
brute elasticsearch 192.168.5.10 -u '' -p ''
brute elasticsearch 192.168.5.10 -u elastic -p 'elastic_pass' -x 'indices'
```

空凭据对 `GET /` 不带 Authorization，2xx 记为未授权访问。非空凭据使用 HTTP Basic Auth。`-x` 为 GET 路径（`indices`、`health`、`nodes` 或任意绝对路径）。命令失败不会丢掉已验证登录。别名：`es`。



## Docker API

未授权 Docker Engine API（`-u '' -p ''`）以及可选 HTTP Basic Auth（默认端口 `2375`）：

```bash
brute docker 192.168.5.10 -u '' -p ''
brute docker 192.168.5.10 -u admin -p 'docker_pass'
brute docker 192.168.5.10 -u '' -p '' -x 'containers'
```

空凭据对 `GET /version` 不带 Authorization，2xx 记为未授权访问。非空凭据使用 HTTP Basic Auth（反向代理场景）。`-x` 为 GET 路径（`info`、`containers`、`images`、`version` 或任意绝对路径）。命令失败不会丢掉已验证登录。别名：`docker-api`。


## SNMP

SNMPv2c community 喷洒（默认端口 `161/udp`）。密码即 community；空凭据探测 `public`。

```bash
brute snmp 192.168.5.10 -u '' -p secret
brute snmp 192.168.5.10 -u '' -p communities.txt --continue-on-success
brute snmp 192.168.5.10 -u '' -p secret -x sysName
```

用 `sysDescr.0` GET 校验 community。`-x` 接受点分 OID 或简写 `sysDescr`/`sysName`/`sysUptime`。无 TCP `--proxy`（UDP）。命令失败不会丢掉已验证 community。


## ActiveMQ

STOMP CONNECT 登录与字典爆破（默认端口 `61613`）：

```bash
brute activemq 192.168.5.10 -u admin -p admin
brute activemq 192.168.5.10 -u '' -p ''
brute activemq 192.168.5.10 -u admin -p admin -x 'hello'
```

空凭据探测匿名 CONNECT。非空凭据发送 STOMP `login`/`passcode`。`-x` 把正文 SEND 到 `/queue/brute`。命令失败不会丢掉已验证登录。别名：`amq`。


## RabbitMQ

AMQP 0-9-1 登录与字典爆破（默认端口 `5672`）：

```bash
brute rabbitmq 192.168.5.10 -u admin -p 'rabbit_pass'
brute rabbitmq 192.168.5.10 -u '' -p ''
brute rabbitmq 192.168.5.10 -u admin -p 'rabbit_pass' -x brute
```

空凭据探测 `guest`/`guest`。非空凭据使用 SASL PLAIN。`-x` 声明指定队列（默认 `brute`）。命令失败不会丢掉已验证登录。别名：`amqp`。

## rsync

rsync daemon 模块登录与字典爆破（默认端口 `873`）：

```bash
brute rsync 192.168.5.10 -u admin -p secret
brute rsync 192.168.5.10 -u '' -p '' --module files
brute rsync 192.168.5.10 -u admin -p secret --module files
```

`--module` 选择 daemon 模块（默认 `files`）。空凭据仅在模块不要求密码时成功。AUTHREQD 使用 MD5(password || challenge)。不提供 `-x`/`--execute`。



## MSSQL

SQL Server TDS 登录与字典爆破（默认端口 `1433`）：

```bash
brute mssql 192.168.5.10 -u sa -p 'Your_password1'
brute mssql 192.168.5.10 -u sa -p 'Your_password1' -x 'SELECT @@VERSION'
```

通过 `tiberius` 做 SQL 认证。`-x` 执行 SQL 并最多预览 10 行。命令失败不会丢掉已验证登录。别名：`sqlserver`。


## Kafka

Kafka SASL/PLAIN 登录与字典爆破（默认端口 `9092`）：

```bash
brute kafka 192.168.5.10 -u admin -p kafka_pass
brute kafka 192.168.5.10 -u admin -p kafka_pass -x metadata
```

使用 Kafka `SaslHandshake` + `SaslAuthenticate` 与 PLAIN（`\0user\0pass`）。`-x` 发起 Metadata 请求。命令失败不会丢掉已验证登录。


## Kibana

Kibana 登录与字典爆破（默认端口 `5601`）：

```bash
brute kibana 192.168.5.10 -u elastic -p elastic_pass
brute kibana 192.168.5.10 -u '' -p ''
brute kibana 192.168.5.10 -u elastic -p elastic_pass -x status
```

空凭据探测无会话的 `GET /api/status`。非空凭据 POST `/internal/security/login`。`-x` 使用登录 cookie GET Kibana API 路径（默认 `/api/status`）。命令失败不会丢掉已验证登录。


## NFS

NFSv3 ONC RPC 探测（默认端口 `2049`）：

```bash
brute nfs 192.168.5.10 -u '' -p ''
brute nfs 192.168.5.10 -u 0 -p '' -x dump
```

空凭据使用 AUTH_NULL。非空用户名在可解析时作为 UNIX uid（否则 uid 0）。NFS 没有密码。`-x` 在同一 TCP 会话尝试 MOUNT DUMP。

## Telnet

Telnet 登录与字典喷洒（默认端口 `23`）：

```bash
brute telnet 192.168.5.10 -u admin -p telnet_pass
brute telnet 192.168.5.10 -u '' -p ''
brute telnet 192.168.5.10 -u admin -p telnet_pass -x id
```

空凭据探测对端是否在没有登录提示的情况下进入 shell。非空凭据在拒绝 Telnet 选项后应答 `login:` / `Password:`。`-x` 在同一会话执行 shell 命令。命令失败不会丢掉已验证登录。

## LDAP

LDAP simple bind 与字典喷洒（默认端口 `389`）：

```bash
brute ldap 192.168.5.10 -u 'cn=admin,dc=example,dc=org' -p ldap_pass
brute ldap 192.168.5.10 -u '' -p ''
brute ldap 192.168.5.10 -u 'cn=admin,dc=example,dc=org' -p ldap_pass -x whoami
```

`-u` 是 bind DN。空凭据探测匿名 bind 并读取 Root DSE。`-x` 执行 `whoami`、`rootdse`、LDAP filter 或 DN 搜索。命令失败不会丢掉已验证登录。

## Grafana

Grafana 登录与字典喷洒（默认端口 `3000`）：

```bash
brute grafana 192.168.5.10 -u admin -p grafana_pass
brute grafana 192.168.5.10 -u '' -p ''
brute grafana 192.168.5.10 -u admin -p grafana_pass -x org
```

空凭据探测无会话的 `GET /api/org`。非空凭据 POST `/login`。`-x` 使用登录 cookie GET Grafana API 路径（默认 `/api/org`）。命令失败不会丢掉已验证登录。

## Prometheus

Prometheus HTTP Basic 登录与字典喷洒（默认端口 `9090`）：

```bash
brute prometheus 192.168.5.10 -u admin -p prometheus_pass
brute prometheus 192.168.5.10 -u '' -p ''
brute prometheus 192.168.5.10 -u admin -p prometheus_pass -x query
```

空凭据探测不带 Authorization 的 `GET /api/v1/status/buildinfo`。非空凭据走 HTTP Basic Auth。`-x` GET `query`/`targets`/`metrics` 或调用方路径。命令失败不会丢掉已验证登录。

## Jenkins

Jenkins HTTP Basic 登录与字典喷洒（默认端口 `8080`）：

```bash
brute jenkins 192.168.5.10 -u admin -p jenkins_pass
brute jenkins 192.168.5.10 -u '' -p ''
brute jenkins 192.168.5.10 -u admin -p jenkins_pass -x whoami
```

空凭据探测不带 Authorization 的 `GET /api/json`。非空凭据走 HTTP Basic Auth。`401`/`403` 为认证失败。`-x` GET `whoami`/`queue`/`computers` 或调用方路径。命令失败不会丢掉已验证登录。

## CouchDB

CouchDB HTTP Basic 登录与字典喷洒（默认端口 `5984`）：

```bash
brute couchdb 192.168.5.10 -u admin -p couch_pass
brute couchdb 192.168.5.10 -u '' -p ''
brute couchdb 192.168.5.10 -u admin -p couch_pass -x dbs
```

空凭据探测不带 Authorization 的 `GET /`。非空凭据走 HTTP Basic Auth。`-x` GET `_all_dbs`/`_up` 或调用方路径。命令失败不会丢掉已验证登录。

## ClickHouse

ClickHouse HTTP 登录与字典喷洒（默认端口 `8123`）：

```bash
brute clickhouse 192.168.5.10 -u admin -p click_pass
brute clickhouse 192.168.5.10 -u '' -p ''
brute clickhouse 192.168.5.10 -u admin -p click_pass -x version
```

空凭据探测不带 Authorization 的 `SELECT 1`。非空凭据走 HTTP Basic Auth。`-x` 执行 SQL（`version`/`databases` 或查询）。命令失败不会丢掉已验证登录。

## Neo4j

Neo4j HTTP Cypher 登录与字典喷洒（默认端口 `7474`）：

```bash
brute neo4j 192.168.5.10 -u neo4j -p neo4j_pass
brute neo4j 192.168.5.10 -u '' -p ''
brute neo4j 192.168.5.10 -u neo4j -p neo4j_pass -x ping
```

空凭据探测不带 Authorization 的 `RETURN 1`。非空凭据以 HTTP Basic Auth POST `/db/neo4j/tx/commit`。`-x` 执行 Cypher（`ping`/`labels` 或语句）。命令失败不会丢掉已验证登录。

## etcd

etcd v3 HTTP 登录与字典喷洒（默认端口 `2379`）：

```bash
brute etcd 192.168.5.10 -u root -p etcd_pass
brute etcd 192.168.5.10 -u '' -p ''
brute etcd 192.168.5.10 -u root -p etcd_pass -x version
```

空凭据探测无 token 的 `POST /v3/kv/range`。非空凭据 POST `/v3/auth/authenticate`。`-x` GET `/version` 或 POST `/v3/kv/range`。命令失败不会丢掉已验证登录。

## InfluxDB

InfluxDB 1.x HTTP Basic 登录与字典喷洒（默认端口 `8086`）：

```bash
brute influxdb 192.168.5.10 -u admin -p influx_pass
brute influxdb 192.168.5.10 -u '' -p ''
brute influxdb 192.168.5.10 -u admin -p influx_pass -x dbs
```

空凭据探测不带 Authorization 的 `SHOW DATABASES`。非空凭据走 HTTP Basic Auth。`-x` 执行 InfluxQL（`dbs`/`users` 或查询）。命令失败不会丢掉已验证登录。

## Solr

Solr HTTP 登录与字典喷洒（默认端口 `8983`）：

```bash
brute solr 192.168.5.10 -u solr -p solr_pass
brute solr 192.168.5.10 -u '' -p ''
brute solr 192.168.5.10 -u solr -p solr_pass -x cores
```

空凭据探测不带 Authorization 的 `GET /solr/admin/info/system`。非空凭据走 HTTP Basic Auth。`-x` GET cores/system（或路径）。命令失败不会丢掉已验证登录。

## MinIO

MinIO console 登录与字典喷洒（默认端口 `9001`）：

```bash
brute minio 192.168.5.10 -u minioadmin -p minio_pass
brute minio 192.168.5.10 -u '' -p ''
brute minio 192.168.5.10 -u minioadmin -p minio_pass -x buckets
```

空凭据对 `/api/v1/login` POST 空 accessKey/secretKey。非空凭据走同一登录接口。`-x` GET buckets/info（或路径）。命令失败不会丢掉已验证登录。

## Nacos

Nacos HTTP 登录与字典喷洒（默认端口 `8848`）：

```bash
brute nacos 192.168.5.10 -u nacos -p nacos
brute nacos 192.168.5.10 -u '' -p ''
brute nacos 192.168.5.10 -u nacos -p nacos -x namespaces
```

空凭据探测无 token 的配置列表。非空凭据 POST `/nacos/v1/auth/login`。`-x` GET namespaces/configs（或路径）。命令失败不会丢掉已验证登录。

## Nexus

Nexus Repository Manager REST 登录与字典喷洒（默认端口 `8081`）：

```bash
brute nexus 192.168.5.10 -u admin -p nexus_pass
brute nexus 192.168.5.10 -u '' -p ''
brute nexus 192.168.5.10 -u admin -p nexus_pass -x repos
```

登录走 HTTP Basic 的 `GET /service/rest/v1/security/users`。关闭匿名时空凭据失败。`-x` GET repos/status（或路径）。命令失败不会丢掉已验证登录。

## JBoss / WildFly

WildFly HTTP management Digest 登录与字典喷洒（默认端口 `9990`）：

```bash
brute jboss 192.168.5.10 -u admin -p jboss_pass
brute jboss 192.168.5.10 -u '' -p ''
brute jboss 192.168.5.10 -u admin -p jboss_pass -x version
```

空凭据探测不带 Authorization 的 `GET /management`。非空凭据走 HTTP Digest。`-x` POST management（`version`/`state` 或 JSON）。命令失败不会丢掉已验证登录。

## Druid

Druid SQL HTTP 登录与字典喷洒（默认端口 `8888`）：

```bash
brute druid 192.168.5.10 -u admin -p druid_pass
brute druid 192.168.5.10 -u '' -p ''
brute druid 192.168.5.10 -u admin -p druid_pass -x status
```

空凭据探测不带 Authorization 的 `POST /druid/v2/sql`。非空凭据走 HTTP Basic Auth。`-x` GET status 或 POST SQL。命令失败不会丢掉已验证登录。

## Spark

Spark master UI 登录与字典喷洒（默认端口 `8080`）：

```bash
brute spark 192.168.5.10 -u spark -p spark_pass
brute spark 192.168.5.10 -u '' -p ''
brute spark 192.168.5.10 -u spark -p spark_pass -x json
```

空凭据探测不带 Authorization 的 `GET /json/`。非空凭据走 HTTP Basic Auth。`-x` GET json/env（或路径）。命令失败不会丢掉已验证登录。

## Hadoop

Hadoop NameNode HTTP 登录与字典喷洒（默认端口 `9870`）：

```bash
brute hadoop 192.168.5.10 -u hdfs -p hadoop_pass
brute hadoop 192.168.5.10 -u '' -p ''
brute hadoop 192.168.5.10 -u hdfs -p hadoop_pass -x jmx
```

空凭据探测不带 Authorization 的 `GET /jmx`。非空凭据走 HTTP Basic Auth。`-x` GET jmx/webhdfs（或路径）。命令失败不会丢掉已验证登录。

## Kubelet

Kubelet HTTPS 登录与字典喷洒（默认端口 `10250`）：

```bash
brute kubelet 192.168.5.10 -u '' -p k8s-token
brute kubelet 192.168.5.10 -u '' -p ''
brute kubelet 192.168.5.10 -u '' -p k8s-token -x pods
```

空凭据探测不带 Authorization 的 `GET /runningpods/`。非空 `-p` 作为 `Authorization: Bearer` 发送。HTTP 401 为认证失败；403 与 2xx 为凭据命中。`-x` GET pods/healthz（或路径）。跳过 TLS 证书校验。命令失败不会丢掉已验证登录。

## GitLab

GitLab HTTP 登录与字典喷洒（默认端口 `80`）：

```bash
brute gitlab 192.168.5.10 -u root -p Gl7ab-Rx9p2q
brute gitlab 192.168.5.10 -u '' -p ''
brute gitlab 192.168.5.10 -u root -p Gl7ab-Rx9p2q -x user
```

空凭据探测不带 token 的 `GET /api/v4/user`。非空凭据 POST `/oauth/token` 走 password grant。`-x` 带 Bearer 请求 user/projects。命令失败不会丢掉已验证登录。





















## Oracle

`oracle` 必须且只能选择一种数据库标识模式；`TARGET` 应为主机名/IP，默认端口为 `1521`，可用 `--port` 覆盖。

- `--service-name <SERVICE_NAME...>` 使用 Oracle Easy Connect：`//host:port/service_name`。支持多个 Service Name 和/或字典文件（规则与 `-u`/`-p` 相同）。
- `--sid <SID...>` 使用完整的 Oracle Net 连接描述符。支持多个 SID 和/或字典文件；与 `--service-name` 互斥。

提供 Service Name 或 SID 时，会按笛卡尔积展开全部组合：

```text
service-name × username × password
# 或
sid × username × password
```

这覆盖三者都是文件，或其中任意两维是文件/多值的情况。控制台输出格式为 `SERVICE/user:pass` 或 `sid:SID/user:pass`。账号级跳过键包含数据库标识，因此同一用户名仍可在其他 service/SID 上继续尝试。目标级“首次成功即停”默认行为不变；枚举多个标识或账号时请加 `--continue-on-success`。

```bash
brute oracle cloud.home.lab -u APPUSER -p PASSWORD --service-name XE -x 'select * from dual'
brute oracle cloud.home.lab -u users.txt -p pass.txt --service-name services.txt --port 11521 --continue-on-success
brute oracle cloud.home.lab -u users.txt -p pass.txt --sid sids.txt --port 11521 --continue-on-success
brute oracle db.internal -u system -p oracle --sid ORCL -x 'select * from dual'
```

`-x` 会在认证成功后执行 SQL 查询，并以 `列名=值` 形式最多预览 10 行结果。执行前会移除 SQL 尾部空白和一个或多个客户端分号。查询同样受 `--timeout-ms` 约束；查询失败或超时会单独报告，不会丢弃已验证的凭据。

Oracle 模块使用纯 Rust 的 `oracle-rs` Thin 驱动，构建和运行时均不需要 Oracle Client、OCI、ODPI-C 或 Oracle 动态链接库。仓库使用 `cyhfvg/oracle-rs` fork，其中包含 Oracle 11g 兼容与 Oracle 18c 完成报文解析修复。

支持 Oracle Database 11g Release 2 (11.2) 及更高版本。早于 11g R2 的服务端会被识别并明确报告不支持的协议版本，而不会误报为认证失败。

## 输出风格

输出采用固定列格式，风格接近 NetExec：

```text
SSH        192.168.10.5     22     [-] admin:123456
SSH        192.168.10.5     22     [+] root:toor  Linux - Shell access!
SSH        192.168.10.5     22     [+] Executed command
SSH        192.168.10.5     22     uid=0(root) gid=0(root) groups=0(root)
```

启用彩色输出时，成功凭据会高亮显示。

## 凭据数据库

成功登录的凭据会自动保存到本地 SQLite 数据库：

```text
~/.config/brute/brute.db
```

首次运行时，`brute` 会初始化数据库、创建默认 workspace，并输出初始化信息。已有数据库会静默打开。

保存字段包括：

- `id`
- `workspace`
- `protocol`
- `host`
- `port`
- `username`
- `password`
- `conn_url`

数据库以明文保存凭据，请根据项目授权范围和本地安全要求保护 `~/.config/brute/brute.db`。

### Workspace

workspace 用于按项目隔离凭据。默认 workspace 为 `default`。

```bash
brute workspace current
brute workspace new project-a
brute workspace use project-a
brute workspace delete project-a
brute workspace list
```

说明：

- `workspace new <NAME>` 创建 workspace，但不切换。
- `workspace use <NAME>` 切换到已有 workspace。
- `workspace delete <NAME>` 删除 workspace 及其保存凭据。
- `default` 不能删除。
- 如果删除当前 workspace，会自动回到 `default`。

### 检索凭据

```bash
brute creds list
brute creds list --workspace project-a
brute creds list --protocol ssh
brute creds list --host 192.168.10.5
brute creds list --protocol ssh --host 192.168.10.5
brute creds list --protocol ssh --conn-url
```

默认输出不包含 `conn_url`。

添加 `--conn-url` 时，仅输出：

```text
ID     PROTOCOL     CONN_URL
1      ssh          ssh://admin:123456@192.168.10.5:22
```

这样可以避免重复显示已经包含在 URL 中的 host、port、username、password。

### 复用保存凭据

使用 `--id` 从当前 workspace 读取保存凭据：

```bash
brute ssh 192.168.10.5 --id 3
```

`--id` 不校验协议一致性，这是有意设计，便于进行跨协议密码复用验证和密码喷洒。

## HTTP Basic Auth

通用 HTTP Basic Auth 登录与字典爆破（默认端口 `80`）。使用 `--path` 指定请求路径（默认 `/`）。使用 `--protocol {http,https}` 选择 URL 方案（默认 `http`）。当指定 `--protocol https` 时，默认跳过 TLS 证书校验（接受自签名与无效证书）。并发走全局 `--threads`。不提供 `-x` / `--execute`。

```bash
brute http 192.168.10.5 -u admin -p 123456 --path /
brute http 192.168.10.5 -u users.txt -p pass.txt --port 8080 --path /manager/html --threads 16
brute http 192.168.10.5 -u admin -p secret --protocol https --port 8443 --path /
```

判断逻辑：

- `2xx`: 认证成功
- `403 Forbidden`: 凭据被接受，但资源拒绝访问（仍记为命中）
- `401 Unauthorized`: 认证失败
- 其它状态码 / 传输错误: 记为 error

表单登录、Digest、NTLM、Bearer、Cookie 流程与严格 CA 校验尚未实现。

## Tomcat Manager

`tomcat-manager` 是针对 Tomcat Manager 的 HTTP Basic Auth 专项模块，支持 `tomcat` 别名。

```bash
brute tomcat 192.168.10.5 -u user.txt -p passwd.txt --port 8080 --path /manager/html
```

判断逻辑：

- `200 OK`: 认证成功
- `403 Forbidden`: 凭据有效，但账号可能缺少 `manager-*` 角色
- `401 Unauthorized`: 认证失败

## 工程结构

```text
src/
  app.rs            # 命令调度
  cli.rs            # clap 命令定义
  credentials.rs    # 用户名/密码加载与展开
  database.rs       # SQLite workspace 和凭据存储
  error.rs          # 错误类型
  output.rs         # 控制台输出
  targets.rs        # 目标与目标文件加载
  engine/           # 可编程验证/喷洒/查询引擎
  mcp/              # MCP stdio 服务与工具 schema

  protocol/
    mod.rs          # 协议抽象
    ssh.rs
    ftp.rs
    mysql.rs
    postgresql.rs
    oracle.rs
    redis.rs
    tomcat.rs
    http.rs         # HTTP Basic Auth
    stub.rs         # 预留协议占位实现
```

## 开发

格式化：

```bash
cargo fmt
```

检查：

```bash
cargo check
```

测试：

```bash
cargo test
```

本地 release 构建：

```bash
scripts/local_build.sh --release
```

提交前执行与 CI 一致的检查：

```bash
scripts/pre_commit_check.sh
```

需要先自动格式化 Rust 代码时，可使用 `scripts/pre_commit_check.sh --fix`。

## 安全与法律声明

本工具仅应用于：

- 获得明确授权的安全评估。
- 实验和训练环境。
- 自有或获准测试资产的口令审计。

请勿用于未授权目标。使用者需自行承担法律、合规和操作后果。
