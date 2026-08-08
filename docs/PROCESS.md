# 开发过程说明

## 目标

围绕“类 NetExec 风格的 Rust 爆破工具”构建首版工程，优先实现：

- `ssh`
- `ftp`
- `mysql`
- `postgresql`
- `redis`
- `oracle`
- `tomcat manager`
- `smb`
- `rdp`
- `winrm`
- `vnc`
- `http` (HTTP Basic Auth)

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
- `oracle`: 基于纯 Rust 的 `oracle-rs`，使用互斥且必选的 `--service-name` 或 `--sid`；两者均支持多值与字典文件，并与 `-u`/`-p` 做 `identifier × user × password` 笛卡尔展开；支持 Oracle Database 11g R2 (11.2)+，无需 Oracle Client 或动态链接库；依赖 cyhfvg/oracle-rs 的 11g 兼容与 18c 完成报文修复；`-x` 查询受 `--timeout-ms` 约束，执行前移除 SQL 尾部空白与客户端分号
- `tomcat`: 基于 `reqwest` + Basic Auth
- `smb`: 基于纯 Rust 的 `smb2`（SMB2/3 + NTLM），默认端口 `445`；不提供 `-x`/`--execute`；可选 `--shares` 在认证成功后枚举 share 名称与 Access（tree-connect 为 READ，磁盘 share 可额外探测 WRITE）；share 枚举失败不回退为认证失败；目标探测在服务可达时输出简要就绪信息
- `rdp`: 基于纯 Rust 协议栈 `rdp-rs`（NLA/CredSSP + NTLM），默认端口 `3389`；仅登录/爆破，不提供 `-x`/`--execute`；用户名支持 `DOMAIN\\user` / `user@domain`。依赖选择说明：IronRDP 0.8+ 与现有 `smb2` 在 `aes-gcm` 版本上冲突且禁止 vendor patch，故采用 `rdp-rs`；TLS 经 `native-tls` 走 OpenSSL 时使用 `openssl` 的 `vendored` 特性静态编入，避免运行时依赖 `libssl.so`
- `winrm`: 基于 git 依赖 [`cyhfvg/winrm-rs`](https://github.com/cyhfvg/winrm-rs)（密封 NTLM + 真 PSRP），默认端口 `5985`；支持登录/并发爆破、`-x`/`--execute` 与 `--shell-type {cmd,powershell}`（**默认 powershell**；省略时 `-x` 用 powershell）；`-x @path` 本地脚本；
- `vnc`: 纯 Rust RFB 握手 + VNC Authentication（security type 2，DES challenge-response，密码有效 8 字节 bit-reverse 密钥），默认端口 `5900`；仅登录/爆破，不提供 `-x`/`--execute`。经典 VNC Auth 为密码-only（CLI 仍接受 `-u`，与 NetExec 一致可忽略用户名）。若对端未发送 RFB banner（常见于 linuxserver webtop / noVNC 等 HTTPS 网关），则回退为 HTTPS HTTP Basic Auth，用 `-u`/`-p` 校验凭据。无模块级全局互斥锁，并发走调度层 `--threads`。源码按职责拆分为 `protocol/vnc/{mod,auth,rfb,web,util}.rs`（单文件 ≤600 行）
- `http`: 基于 `reqwest` 的 HTTP Basic Auth 登录/爆破，默认端口 `80`；`--path` 指定请求路径（默认 `/`）；`--protocol {http,https}` 选择 URL 方案（默认 `http`）；对 `{scheme}://host:port<path>` 发起带 `Authorization: Basic` 的 GET；`https` 时默认跳过 TLS 证书校验（自签名/无效证书可连）；`2xx` 与 `403` 记为凭据命中（403 表示认证通过但资源/角色受限），`401` 为认证失败，其它状态与传输错误记为 error。无模块级全局互斥锁，并发走调度层 `--threads`。不提供 `-x`/`--execute`。表单登录、Digest、NTLM、Bearer、Cookie、严格 CA 校验等后续扩展

### 命令执行

`ssh`、`ftp`、`mysql`、`postgresql`、`oracle`、`redis`、`winrm` 支持模块级 `-x, --execute <COMMAND>`。`oracle` 必须且只能指定 `--service-name` 或 `--sid`；两者均可传多个值或字典文件，调度层将数据库标识并入凭据维度并与用户名/密码做全组合展开，输出格式为 `SERVICE/user:pass` 或 `sid:SID/user:pass`。其 `-x` 执行 SQL 查询并最多预览 10 行结果。`winrm` 额外支持 `--shell-type` 选择 `cmd` 或 `powershell`，以及 `-x @script.bat` / `-x @script.ps1` 本地脚本装载。该参数不会出现在 `http`、`tomcat`、`smb`、`rdp`、`vnc` 等无命令执行语义的模块中；支持模块会在凭据认证成功后执行命令，并用独立输出行显示执行状态和结果。

`smb` 使用 `--shares` 代替 `-x`：认证成功后枚举 shares 与 Access，输出挂在成功登录行之后（不打印 “Executed command” 横幅）。

### 凭据展开

`-u` / `-p` 支持内联多值与字典文件；路径存在且为文件时按行展开（去空行）。`oracle` 的 `--service-name` 与 `--sid` 使用同一规则（二者互斥）。展开后：

- 无 Oracle 标识（非 Oracle 协议）：`usernames × passwords`
- 有 Service Name：`service_names × usernames × passwords`
- 有 SID：`sids × usernames × passwords`

账号级成功跳过键为 `(host, service_name, sid, username)`，避免同一用户在不同 Service Name/SID 上被误跳过。目标级首次成功即停策略不变；多标识枚举需 `--continue-on-success`。

### 凭据数据库

`database.rs` 使用 SQLite 保存成功凭据。数据库固定路径为 `~/.brute/brute.db`。启动时会检测数据库是否存在；不存在时创建父目录、初始化 schema 和默认 workspace，并输出初始化提示；存在时静默打开。Schema 包含：

- `workspaces`: 保存 workspace 名称与 `is_current` 标识，默认 workspace 为 `default`
- `credentials`: 保存 `id`、`workspace_id`、`protocol`、`host`、`port`、`username`、`password`、`conn_url` 和时间戳

每个 SQLite 连接都会启用外键约束，因此删除 workspace 会级联删除其凭据。认证成功后的命令执行错误会作为认证成功的附加状态输出，确保有效凭据仍会写入数据库。保存的 `conn_url` 会对用户名和密码进行 URL 编码，并为 IPv6 主机添加方括号。

协议调度层在 `AttemptOutcome::Success` 时写入数据库，并用 `(workspace_id, protocol, host, port, username, password)` 去重。`workspace current/new/use/delete/list` 负责 workspace 管理；`delete` 会级联删除该 workspace 下的凭据，且不允许删除 `default`。`creds list` 负责按当前 workspace 或指定 `--workspace` 检索，支持 `--protocol`、`--host` 和 `--conn-url`。

所有协议模块都支持 `--id <ID>`，用于从当前 workspace 读取已保存凭据并填充登录尝试。`--id` 与 `-u/-p` 互斥；读取时不校验凭据原始 protocol，允许密码喷洒和跨协议密码复用验证。

### SSH Banner

SSH banner 获取从单次登录尝试中前移到 target 级预探测阶段。每个 target 只读取一次 banner，成功时输出服务信息；失败时静默不显示 banner，但仍继续进入凭据尝试，避免因网络波动或 banner 被修改而漏测。

SSH 单次登录中的连接、session 创建、handshake 等传输层错误会内部重试一次；重试后仍失败时按普通认证失败行输出，不暴露 `Failed getting banner` 等低层错误细节。

调度层使用 `for_each_concurrent` 实施全局 `--threads` 限流：跨目标与凭据的同时进行尝试数不超过该值。不再使用 `--target-threads` 或单目标信号量。任务按 credential -> target 惰性生成，成功账号状态按需记录，不会预分配完整的凭据与目标笛卡尔积。`--threads` 和 `--timeout-ms` 必须大于 0。RDP 尝试走 `spawn_blocking`（`run_blocking_with_timeout`），不在模块内加全局互斥锁。SSH 传输层重试次数由 `--retries` 控制，默认 3 次，并使用短退避降低握手碰撞概率。

默认情况下，每个 target 命中 1 组成功凭据后会停止该 target 的后续尝试；`--continue-on-success` 用于显式开启继续爆破模式。

### 出站代理 (`--proxy`)

`--proxy <PROXY_URL>` 是与 `--version` / `--no-color` 同级的**顶级** CLI 参数（定义在 `Cli` 上，写在协议子命令之前）。`run_protocol` 将其注入到运行时 `CommonArgs.proxy`（`#[arg(skip)]`，非子命令 flag）供各协议模块读取。URL 形式为 `protocol://[username[:password]@]host:port`，协议支持 `http`（HTTP CONNECT）与 `socks5`；用户名/密码可省略。解析与隧道逻辑集中在 `src/proxy.rs`：

- HTTP 系（`http` / `tomcat` / `winrm` / VNC web Basic）：`reqwest::Proxy`（`reqwest` 启用 `socks` feature）；`winrm-rs` 使用 `WinrmConfig.proxy`
- 可注入 stream 的协议（`ssh` / `ftp` / `postgresql` / `rdp` / `vnc` RFB）：SOCKS5 经 `tokio-socks`，HTTP CONNECT 经 `async-http-proxy`（async）或自实现握手（blocking）
- 仅接受 `host:port` 的协议（`mysql` / `redis` / `oracle` / `smb`）：本机 `127.0.0.1:ephemeral` TCP bridge，将客户端连接经代理隧道转发到真实目标；bridge 生命周期与单次 attempt 绑定

代理作用于登录、爆破、目标探测与认证后命令路径。

### 目标加载

`TARGET` 支持直接传入多个目标，也支持传入文件路径。目标文件按行读取，忽略空行和以 `#` 开头的注释行。

当前版本会展开目标文件；CIDR 与 IP range 的进一步展开预留在 `targets.rs` 中继续增强。

### 已保留接口但未实现

（当前无 CLI 预留但未实现的协议占位）

## 后续建议

1. 为已排队但尚未执行的 target 任务增加更强的主动取消控制
2. 增加 JSON/NDJSON 输出模式，便于脚本接入
3. 为 HTTP 模块扩展表单爆破、Digest Auth、严格 CA 校验开关等（Basic Auth 与 `--protocol http|https` 已实现）
4. 为 WinRM 增加 HTTPS(5986)、Kerberos、CredSSP 与 NTLM hash 登录（按需）
5. 增强 SMB 目标探测，在可解析时输出 `name:` / `domain:`（当前为服务可达性探测）
6. 若 IronRDP 与 `smb2` 的 `aes-gcm` 依赖冲突消除，可评估迁移 RDP 至 IronRDP 并去掉 vendored OpenSSL

### 输出前缀

控制台固定前缀仅显示协议、目标和端口；协议专属的探测信息使用独立输出行，避免不可靠或重复的通用主机名列。

SMB 目标级探测在服务响应时输出独立 `[*]` 行；后续可在解析 NTLM TargetInfo 后补充 `name:` / `domain:`。
