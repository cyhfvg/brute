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

## Unsupported Protocols

The following protocol modules are reserved in the CLI but not implemented yet:

- `smb`
- `rdp`
- `winrm`
- `http`
- `vnc`

## Planned SMB Target Probe

- When implementing smb, add a target-level probe that enumerates the remote host name and
  domain. Report the data on a dedicated probe line rather than restoring a shared hostname column:

    SMB  192.168.5.5  445  [*] name:DESKTOP-APL87RT domain:LAB.LOCAL
