# TODO

## Completed Maintenance

- Default SQLite path moved to `~/.config/brute/brute.db` (XDG-style config dir);
- Release CI matrix builds natively per OS runner: Linux musl on
  `ubuntu-latest`, Windows MSVC on `windows-latest` (Strawberry Perl + NASM for
  vendored OpenSSL; pwsh build shell), Apple Silicon on `macos-latest`; Intel
  macOS target dropped; shared package/upload path and GitHub Release publish job.
- Outbound top-level `--proxy` (same level as `--version`/`--no-color`) for all protocol modules
  (`http`/`socks5`, optional credentials); injected into runtime `CommonArgs.proxy`; shared
  `src/proxy.rs` parser + async/blocking tunnels + local TCP bridge for host:port-only clients;
  CLI parse/reject tests and docs (README / PROCESS).
- SQLite foreign-key enforcement, credential URL encoding, and regression coverage.
- Lazy attempt scheduling with validated concurrency and timeout inputs.
- Post-auth command failures preserve successfully verified credentials.
- Oracle Service Name/SID connection identifier support with CLI validation and regression coverage.
- Oracle authentication and post-auth SQL query support with `-x`.
- Oracle pure-Rust `oracle-rs` migration with 11g R2 (11.2)+ protocol validation and pre-11g R2 detection.
- Oracle `-x` query normalization removes trailing whitespace and client-side semicolons before execution.
- Updated the cyhfvg/oracle-rs Git dependency with Oracle 11g compatibility and the TTC 18c completion-message fix; validated with `SELECT 1 FROM dual` against an authorized Oracle 11g test instance.
- Oracle `--service-name` multi-value/wordlist enumeration with full `service × user × password` cartesian expansion, Service Name-aware console display and account skip keys.
- Oracle `--sid` multi-value/wordlist enumeration with full `sid × user × password` cartesian expansion, SID-aware console display (`sid:SID/user:pass`) and account skip keys.

- MCP stdio server (`brute mcp`) via official `rmcp`: `verify_account`, `spray_passwords`, `list_credentials`, plus workspace/protocol discovery. CLI and MCP share `src/engine`. Natural-language usage examples: `docs/MCP.example.md`.
- `TARGET` CIDR expansion in `src/targets.rs`: IPv4 prefixes (including
  network and broadcast) for every protocol via shared `load_targets`; inline
  and target-file tokens; 65536-address cap; IPv6 targets rejected; CLI/MCP
  docs and unit/integration coverage.

## Completed Protocol Work

- `smb`: pure-Rust `smb2` login/brute (default port 445); no `-x`/`--execute`; `--shares` enumerates
  share names and Access after successful authentication. Share enum failure does not downgrade a
  verified login. Target probe reports service readiness; optional `name:` / `domain:` enrichment
  remains a follow-up when NTLM TargetInfo is parsed without credentials.
- `rdp`: pure-Rust `rdp-rs` NLA/CredSSP login/brute (default port 3389); no `-x`/`--execute`.
  IronRDP could not be used: aes-gcm pin conflict with `smb2` (no vendor patch). OpenSSL is
  vendored statically so release binaries do not require system `libssl`.
- `winrm`: git dependency [`cyhfvg/winrm-rs`](https://github.com/cyhfvg/winrm-rs) (fork with
  sealed NTLM + real PSRP; default port 5985). Login/brute under global `--threads`;
  `-x`/`--execute` with `--shell-type {cmd,powershell}` (default **powershell** for `-x` when
  omitted). No-`-x` sprays: auto serial probe powershell then cmd (short-circuit);
- Scheduler concurrency: only `--threads` (removed `--target-threads` / per-host semaphore);
  global `for_each_concurrent` is sufficient for concurrent RDP/WinRM and other protocol sprays.
- `vnc`: pure-Rust RFB 003.003/003.007/003.008 handshake + VNC Authentication type 2 (DES
  challenge-response with bit-reversed 8-byte key); default port 5900; login/brute only (no `-x`).
  Username accepted by CLI and ignored for classic password-only VNC Auth. When the peer does not
  speak RFB (HTTPS web-VNC gateways), falls back to HTTPS HTTP Basic Auth so user/password pairs
  against linuxserver-style frontends can be validated. Concurrent sprays use global `--threads`
  only (no module mutex). Source layout: `protocol/vnc/{mod,auth,rfb,web,util}.rs` (≤600 lines each).
- `http`: HTTP Basic Auth login/brute via `reqwest` GET + `Authorization: Basic` (default port
  `80`); `--path` sets the request path (default `/`); `--protocol {http,https}` selects the URL
  scheme (default `http`). HTTPS skips TLS certificate verification by default. Concurrent sprays
  use global `--threads` only (no module mutex). No `-x`/`--execute`. Form-based login, Digest,
  NTLM, Bearer, cookies, and strict CA verification remain deferred.

## Unsupported Protocols

(none currently reserved as unimplemented stubs)
