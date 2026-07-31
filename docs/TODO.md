# TODO

## Completed Maintenance

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

## Unsupported Protocols

The following protocol modules are reserved in the CLI but not implemented yet:

- `http`
- `vnc`
