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
- `tomcat-manager`，别名 `tomcat`

已预留但尚未实现：

- `smb`
- `rdp`
- `winrm`
- `oracle`
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
brute redis 192.168.10.5 -u '' -p redis_pass.txt -x 'INFO server'
brute tomcat 192.168.10.1 -u user.txt -p passwd.txt --port 8080 --path /manager/html
```

## 常用参数

- `TARGET`: 目标 IP、主机名、FQDN，或包含目标列表的文件；可传入多个。
- `-u, --username <USERNAME...>`: 用户名或用户名文件；空用户名使用 `-u ''`。
- `-p, --password <PASSWORD...>`: 密码或密码文件；空密码使用 `-p ''`。
- `--id <ID>`: 从当前 workspace 读取已保存凭据；与 `-u/-p` 互斥。
- `--port <PORT>`: 覆盖协议默认端口。
- `--threads <N>`: 全局并发尝试数，默认 `16`。
- `--target-threads <N>`: 单目标最大并发尝试数，默认 `1`。
- `--retries <N>`: 传输层临时错误重试次数，默认 `3`。
- `--timeout-ms <MS>`: 单次尝试超时，默认 `5000`。
- `--continue-on-success`: 命中成功凭据后仍继续尝试该目标剩余凭据。
- `--no-color`: 关闭彩色输出。

`-u/-p` 与 `--id` 二选一：普通爆破使用 `-u/-p`，复用保存凭据使用 `--id`。

## 命令执行

以下模块支持登录成功后执行命令：

- `ssh`: 远程 shell 命令，例如 `-x 'id'`
- `ftp`: FTP 控制命令，例如 `-x 'PWD'`
- `mysql`: SQL 查询，例如 `-x 'show databases;'`
- `postgresql`: SQL 查询，例如 `-x 'select version();'`
- `redis`: Redis 命令，例如 `-x 'INFO server'`

示例：

```bash
brute ssh 192.168.5.5 -u admin -p 123456 -x 'id'
```

## 输出风格

输出采用固定列格式，风格接近 NetExec：

```text
SSH                      192.168.5.5     22     192.168.5.5     [-] admin:123456
SSH                      192.168.5.5     22     192.168.5.5     [+] root:toor  Linux - Shell access!
SSH                      192.168.5.5     22     192.168.5.5     [+] Executed command
SSH                      192.168.5.5     22     192.168.5.5     uid=0(root) gid=0(root) groups=0(root)
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

发布构建：

```bash
cargo build --release
```

## 安全与法律声明

本工具仅应用于：

- 获得明确授权的安全评估。
- 实验和训练环境。
- 自有或获准测试资产的口令审计。

请勿用于未授权目标。使用者需自行承担法律、合规和操作后果。
