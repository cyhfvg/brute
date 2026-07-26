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

## Unsupported Protocols

The following protocol modules are reserved in the CLI but not implemented yet:

- `smb`
- `rdp`
- `winrm`
- `http`
- `vnc`
