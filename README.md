# brute

`brute` is a Rust-based multi-protocol credential attack and login verification CLI.
It is designed for authorized security testing, lab validation, and internal credential auditing.

Chinese documentation is available here: [README.zh-CN.md](README.zh-CN.md).

## Focus

`brute` is built for field-friendly usage:

- Static single-file release builds.
- No runtime OpenSSL/libssh2/native-tls dynamic library dependency.
- Offline-environment friendly deployment.
- NetExec-style protocol-first command layout.
- Clean terminal output with highlighted successful credentials.
- Local SQLite credential storage with workspace isolation.

The intended workflow is simple: build once, copy one binary to an authorized test environment, run it without installing extra shared libraries.

## Acknowledgements

Thanks to [NetExec](https://github.com/Pennyw0rth/NetExec) for inspiring the protocol-oriented CLI style and readable operator output. `brute` also borrows common usage ideas from Hydra and Medusa for HTTP/Tomcat-style authentication testing.

This project was implemented with coding assistance from the AI tool Codex.

## Supported Protocols

Implemented modules:

- `ssh`
- `ftp`
- `mysql`
- `postgresql`
- `redis`
- `tomcat-manager` alias: `tomcat`

Reserved but not implemented yet:

- `smb`
- `rdp`
- `winrm`
- `oracle`
- `http`
- `vnc`

See [docs/TODO.md](docs/TODO.md) for the current protocol backlog.

## Installation

Build a normal development binary:

```bash
cargo build
```

Build an optimized release binary:

```bash
cargo build --release
```

Build a static Linux musl release:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The static binary will be generated at:

```text
target/x86_64-unknown-linux-musl/release/brute
```

You can verify static linking with:

```bash
ldd target/x86_64-unknown-linux-musl/release/brute
```

Expected result:

```text
statically linked
```

## Quick Start

Basic command shape:

```bash
brute <protocol> <target|target_file>... (-u <username|user_file>... -p <password|pass_file>... | --id <credential_id>) [options]
```

Examples:

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

## Common Options

- `TARGET`: Target IP, hostname, FQDN, or a file containing targets. Multiple targets are allowed.
- `-u, --username <USERNAME...>`: Username values or files containing usernames. Use `-u ''` for an empty username.
- `-p, --password <PASSWORD...>`: Password values or files containing passwords. Use `-p ''` for an empty password.
- `--id <ID>`: Load a saved credential from the current workspace. Mutually exclusive with `-u/-p`.
- `--port <PORT>`: Override the protocol default port.
- `--threads <N>`: Global concurrent attempt count. Default: `16`.
- `--target-threads <N>`: Max concurrent attempts against one target. Default: `1`.
- `--retries <N>`: Retry count for transient transport errors. Default: `3`.
- `--timeout-ms <MS>`: Per-attempt timeout in milliseconds. Default: `5000`.
- `--continue-on-success`: Continue attempts against a target after a successful credential is found.
- `--no-color`: Disable colored output.

`-u/-p` and `--id` are mutually exclusive. Use `-u/-p` for normal spraying or brute force, and `--id` to reuse a saved credential.

## Command Execution

The following modules support post-auth command execution with `-x, --execute <COMMAND>`:

- `ssh`: remote shell command, for example `-x 'id'`
- `ftp`: FTP control command, for example `-x 'PWD'`
- `mysql`: SQL query, for example `-x 'show databases;'`
- `postgresql`: SQL query, for example `-x 'select version();'`
- `redis`: Redis command, for example `-x 'INFO server'`

Example:

```bash
brute ssh 192.168.5.5 -u admin -p 123456 -x 'id'
```

## Output

Output uses fixed NetExec-style columns:

```text
SSH                      192.168.5.5     22     192.168.5.5     [-] admin:123456
SSH                      192.168.5.5     22     192.168.5.5     [+] root:toor  Linux - Shell access!
SSH                      192.168.5.5     22     192.168.5.5     [+] Executed command
SSH                      192.168.5.5     22     192.168.5.5     uid=0(root) gid=0(root) groups=0(root)
```

Successful credential pairs are highlighted when color output is enabled.

## Credential Database

Successful logins are saved automatically to a local SQLite database:

```text
~/.brute/brute.db
```

On first run, `brute` initializes the database, creates the default workspace, and prints an initialization message. Existing databases are opened silently.

Saved credential fields include:

- `id`
- `workspace`
- `protocol`
- `host`
- `port`
- `username`
- `password`
- `conn_url`

Database values are stored in plaintext. Protect `~/.brute/brute.db` according to your engagement rules and local security requirements.

### Workspaces

Workspaces isolate saved credentials by project. The default workspace is `default`.

```bash
brute workspace current
brute workspace new project-a
brute workspace use project-a
brute workspace delete project-a
brute workspace list
```

Notes:

- `workspace new <NAME>` creates a workspace without switching to it.
- `workspace use <NAME>` switches to an existing workspace.
- `workspace delete <NAME>` deletes the workspace and its saved credentials.
- `default` cannot be deleted.
- If the current workspace is deleted, `brute` falls back to `default`.

### Searching Saved Credentials

```bash
brute creds list
brute creds list --workspace project-a
brute creds list --protocol ssh
brute creds list --host 192.168.5.5
brute creds list --protocol ssh --host 192.168.5.5
brute creds list --protocol ssh --conn-url
```

Default output does not include `conn_url`.

With `--conn-url`, output is reduced to only:

```text
ID     PROTOCOL     CONN_URL
1      ssh          ssh://admin:123456@192.168.5.5:22
```

This avoids repeating host, port, username, and password because they are already encoded in the URL.

### Reusing Saved Credentials

Use `--id` to load a saved credential from the current workspace:

```bash
brute ssh 192.168.1.10 --id 3
```

`--id` does not enforce protocol matching. This is intentional so operators can test password reuse and credential spraying across protocols.

## Tomcat Manager

The `tomcat-manager` module is a dedicated HTTP Basic Auth module for Tomcat Manager. It supports `tomcat` as an alias.

```bash
brute tomcat 192.168.10.1 -u user.txt -p passwd.txt --port 8080 --path /manager/html
```

Result handling:

- `200 OK`: authentication succeeded
- `403 Forbidden`: credential is valid, but the user may lack `manager-*` roles
- `401 Unauthorized`: authentication failed

## Project Layout

```text
src/
  app.rs            # command orchestration
  cli.rs            # clap command definitions
  credentials.rs    # username/password loading and expansion
  database.rs       # SQLite workspace and credential storage
  error.rs          # error types
  output.rs         # console rendering
  targets.rs        # target and target-file loading
  protocol/
    mod.rs          # protocol abstraction
    ssh.rs
    ftp.rs
    mysql.rs
    postgresql.rs
    redis.rs
    tomcat.rs
    stub.rs         # reserved protocol placeholder
```

## Development

Format:

```bash
cargo fmt
```

Check:

```bash
cargo check
```

Test:

```bash
cargo test
```

Release:

```bash
cargo build --release
```

## Security and Legal Notice

Use this tool only for:

- Explicitly authorized security assessments.
- Lab and training environments.
- Credential auditing on assets you own or are permitted to test.

Do not use `brute` against unauthorized targets. You are responsible for legal, compliance, and operational consequences.
