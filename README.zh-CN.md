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

已预留但尚未实现：

- `smb`
- `rdp`
- `winrm`
- `http`
- `vnc`

当前协议待办见：[docs/TODO.md](docs/TODO.md)。

## 安装与构建

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
brute ssh 192.168.1.10 -u root admin -p 123456 password --port 22
brute ssh 192.168.5.5 -u admin -p 123456 -x 'id'
brute ssh targets.txt -u users.txt -p pass.txt --threads 32
brute ftp 10.10.10.20 -u users.txt -p pass.txt -x 'PWD'
brute mysql db.internal -u root -p weakpass --port 3306 -x 'show databases;'
brute postgresql 172.16.1.50 -u pg_users.txt -p pg_pass.txt -x 'select version();'
brute oracle db.internal -u system -p oracle --service-name ORCLPDB1 -x 'select * from dual'
brute oracle db.internal -u users.txt -p pass.txt --service-name services.txt
brute redis 192.168.10.5 -u '' -p redis_pass.txt -x 'INFO server'
brute tomcat 192.168.10.1 -u user.txt -p passwd.txt --port 8080 --path /manager/html
```

## 常用参数

- `TARGET`: 目标 IP、主机名、FQDN，或包含目标列表的文件；可传入多个。
- `-u, --username <USERNAME...>`: 用户名或用户名文件；空用户名使用 `-u ''`。
- `-p, --password <PASSWORD...>`: 密码或密码文件；空密码使用 `-p ''`。
- `--id <ID>`: 从当前 workspace 读取已保存凭据；与 `-u/-p` 互斥。
- `--port <PORT>`: 覆盖协议默认端口。
- `--threads <N>`: 全局并发尝试数，默认 `16`，最小值为 `1`。
- `--target-threads <N>`: 单目标最大并发尝试数，默认 `1`，最小值为 `1`。
- `--retries <N>`: 传输层临时错误重试次数，默认 `3`。
- `--timeout-ms <MS>`: 单次尝试超时，默认 `5000`，最小值为 `1`。
- `--continue-on-success`: 命中成功凭据后仍继续尝试该目标剩余凭据。
- `--no-color`: 关闭彩色输出。

`-u/-p` 与 `--id` 二选一：普通爆破使用 `-u/-p`，复用保存凭据使用 `--id`。

## 命令执行

以下模块支持登录成功后执行命令：

- `ssh`: 远程 shell 命令，例如 `-x 'id'`
- `ftp`: FTP 控制命令，例如 `-x 'PWD'`
- `mysql`: SQL 查询，例如 `-x 'show databases;'`
- `postgresql`: SQL 查询，例如 `-x 'select version();'`
- `oracle`: SQL 查询，例如 `-x 'select * from dual'`
- `redis`: Redis 命令，例如 `-x 'INFO server'`

示例：

```bash
brute ssh 192.168.5.5 -u admin -p 123456 -x 'id'
```

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

认证已成功但认证后命令执行失败时，工具会单独输出命令错误，并仍将已验证凭据保存到当前 workspace。

## 输出风格

输出采用固定列格式，风格接近 NetExec：

```text
SSH        192.168.5.5     22     [-] admin:123456
SSH        192.168.5.5     22     [+] root:toor  Linux - Shell access!
SSH        192.168.5.5     22     [+] Executed command
SSH        192.168.5.5     22     uid=0(root) gid=0(root) groups=0(root)
```

启用彩色输出时，成功凭据会高亮显示。

## 凭据数据库

成功登录的凭据会自动保存到本地 SQLite 数据库：

```text
~/.brute/brute.db
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

数据库以明文保存凭据，请根据项目授权范围和本地安全要求保护 `~/.brute/brute.db`。

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
brute creds list --host 192.168.5.5
brute creds list --protocol ssh --host 192.168.5.5
brute creds list --protocol ssh --conn-url
```

默认输出不包含 `conn_url`。

添加 `--conn-url` 时，仅输出：

```text
ID     PROTOCOL     CONN_URL
1      ssh          ssh://admin:123456@192.168.5.5:22
```

这样可以避免重复显示已经包含在 URL 中的 host、port、username、password。

### 复用保存凭据

使用 `--id` 从当前 workspace 读取保存凭据：

```bash
brute ssh 192.168.1.10 --id 3
```

`--id` 不校验协议一致性，这是有意设计，便于进行跨协议密码复用验证和密码喷洒。

## Tomcat Manager

`tomcat-manager` 是针对 Tomcat Manager 的 HTTP Basic Auth 专项模块，支持 `tomcat` 别名。

```bash
brute tomcat 192.168.10.1 -u user.txt -p passwd.txt --port 8080 --path /manager/html
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
  protocol/
    mod.rs          # 协议抽象
    ssh.rs
    ftp.rs
    mysql.rs
    postgresql.rs
    oracle.rs
    redis.rs
    tomcat.rs
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
