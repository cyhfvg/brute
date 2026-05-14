# 开发过程说明

## 目标

围绕“类 NetExec 风格的 Rust 爆破工具”构建首版工程，优先实现：

- `ssh`
- `ftp`
- `mysql`
- `postgresql`
- `redis`
- `tomcat manager`

同时为后续协议扩展保留统一抽象。

## 设计原则

1. 使用 `clap` 做清晰稳定的 CLI 定义
2. 使用协议模块抽象，避免逻辑堆在 `main.rs`
3. 对同步库采用 `spawn_blocking + timeout` 包裹
4. 对异步库采用 Tokio 并发编排
5. 输出层与协议层解耦，便于后续增加 JSON 输出
6. 通过占位模块为未来协议扩展保留接口稳定性
7. 将目标来源解析与协议尝试上下文分离，便于支持目标文件、CIDR 与范围扩展
8. 将 SQLite 凭据存储封装为独立模块，避免协议实现直接感知数据库细节

## 当前实现范围

### 已实现

- `ssh`: 基于纯 Rust SSH 客户端 `russh`
- `ftp`: 基于 `suppaftp`
- `mysql`: 基于 `mysql`
- `postgresql`: 基于 `tokio-postgres`
- `redis`: 基于 `redis`
- `tomcat`: 基于 `reqwest` + Basic Auth

### 命令执行

`ssh`、`ftp`、`mysql`、`postgresql`、`redis` 支持模块级 `-x, --execute <COMMAND>`。该参数不会出现在 `http`、`tomcat` 等无命令执行语义的模块中；支持模块会在凭据认证成功后执行命令，并用独立输出行显示执行状态和结果。

### 凭据数据库

`database.rs` 使用 SQLite 保存成功凭据。数据库固定路径为 `~/.brute/brute.db`。启动时会检测数据库是否存在；不存在时创建父目录、初始化 schema 和默认 workspace，并输出初始化提示；存在时静默打开。Schema 包含：

- `workspaces`: 保存 workspace 名称与 `is_current` 标识，默认 workspace 为 `default`
- `credentials`: 保存 `id`、`workspace_id`、`protocol`、`host`、`port`、`username`、`password`、`conn_url` 和时间戳

协议调度层在 `AttemptOutcome::Success` 时写入数据库，并用 `(workspace_id, protocol, host, port, username, password)` 去重。`workspace current/new/use/delete/list` 负责 workspace 管理；`delete` 会级联删除该 workspace 下的凭据，且不允许删除 `default`。`creds list` 负责按当前 workspace 或指定 `--workspace` 检索，支持 `--protocol`、`--host` 和 `--conn-url`。

所有协议模块都支持 `--id <ID>`，用于从当前 workspace 读取已保存凭据并填充登录尝试。`--id` 与 `-u/-p` 互斥；读取时不校验凭据原始 protocol，允许密码喷洒和跨协议密码复用验证。

### SSH Banner

SSH banner 获取从单次登录尝试中前移到 target 级预探测阶段。每个 target 只读取一次 banner，成功时输出服务信息；失败时静默不显示 banner，但仍继续进入凭据尝试，避免因网络波动或 banner 被修改而漏测。

SSH 单次登录中的连接、session 创建、handshake 等传输层错误会内部重试一次；重试后仍失败时按普通认证失败行输出，不暴露 `Failed getting banner` 等低层错误细节。

调度层使用全局 `--threads` 和单目标 `--target-threads` 双层限流，并将尝试队列按 credential -> target 交错展开，避免默认并发集中打到同一台 SSH 服务。`--target-threads` 默认值为 1，优先保证 SSH 场景下的稳健性。SSH 传输层重试次数由 `--retries` 控制，默认 3 次，并使用短退避降低握手碰撞概率。

默认情况下，每个 target 命中 1 组成功凭据后会停止该 target 的后续尝试；`--continue-on-success` 用于显式开启继续爆破模式。

### 目标加载

`TARGET` 支持直接传入多个目标，也支持传入文件路径。目标文件按行读取，忽略空行和以 `#` 开头的注释行。

当前版本会展开目标文件；CIDR 与 IP range 的进一步展开预留在 `targets.rs` 中继续增强。

### 已保留接口但未实现

- `smb`
- `rdp`
- `winrm`
- `oracle`
- `http`
- `vnc`

## 后续建议

1. 为已排队但尚未执行的 target 任务增加更强的主动取消控制
2. 增加 JSON/NDJSON 输出模式，便于脚本接入
3. 为 HTTP 模块做通用表单爆破与 Basic/Digest Auth 支持
4. 为 SMB/WinRM/RDP 选择合适 Rust 库或封装外部安全测试组件
