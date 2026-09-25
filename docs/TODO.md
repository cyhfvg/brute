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
- `creds list` and `creds delete` operate on the current workspace only. Neither accepts `--workspace`; other workspaces require `workspace use` first, and each command prints the current workspace name. MCP `list_credentials` and `delete_credentials` still accept an explicit workspace because MCP does not switch the global current workspace. Unscoped deletes are refused. CLI and MCP share `engine::query_credentials` and `engine::delete_credentials`.
- `brute combo` / `urls` and MCP `verify_connections` parse paired connection URLs (`ssh://root:password@192.168.5.1:22`). Empty username, empty password, and omitted port are attempted; `https` with no port uses 443. Mixed-protocol files are grouped and run through `engine::run_paired_spray` without changing cartesian `-u`/`-p` spray.
- HTTP credential status classification is shared by `src/protocol/http_auth.rs`. 401 is always an auth failure, 2xx is always a hit, and 403 follows a per-protocol `CredentialHit` or `AuthFailure` policy.
- HTTP-family modules accept optional `--protocol http|https`. Omitted values use `https` for kubelet and websphere, otherwise `http`. The scheme is applied to both the client and the request URL. MCP uses the same default.

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
- `zookeeper`: `zookeeper-client` SASL DIGEST-MD5 login/brute (default port 2181, alias `zk`);
  empty `-u '' -p ''` probes unauthorized `getChildren("/")`; `-x` runs zkCli-style commands
  (`ls`/`get`/`stat`/`create`/`set`/`delete`/`deleteall`/`mkdir`). Four-letter `srvr` target
  probe. Host:port client uses the shared TCP proxy bridge. No vendor patch; `sasl-gssapi` is
  not enabled so release binaries stay free of `libgssapi`.
- `memcached`: pure-Rust binary SASL PLAIN login/brute plus unauthorized `STAT`
  (default port 11211, alias `memcache`); empty `-u '' -p ''` probes anonymous access;
  `-x` runs `stats`/`version`/`get`/`set`/`delete`/`flush_all`. Binary VERSION target probe
  with ASCII fallback. Stream-injectable `--proxy` via `connect_async`. No extra crate.
- `mongodb`: official `mongodb` crate (`bson-3` + `rustls-tls`, no `mongocrypt`) login/brute
  (default port 27017, alias `mongo`); empty `-u '' -p ''` probes anonymous `admin.listDatabases`;
  non-empty credentials use `authSource=admin` SCRAM; `-x` runs JSON or shorthand
  `ping`/`listDatabases`/`serverStatus`/`buildInfo`. `buildInfo`/`hello` target probe.
  Host:port client uses the shared TCP proxy bridge.
- `elasticsearch`: `reqwest` HTTP Basic login/brute (default port 9200, alias `es`); empty
  `-u '' -p ''` probes anonymous `GET /`; `-x` GETs `_cat/indices`, `_cluster/health`, or a
  caller path. Root JSON `version.number` target probe. HTTP `--proxy` via `reqwest`.
- `docker`: `reqwest` Docker Engine API (default port 2375, alias `docker-api`); empty
  `-u '' -p ''` probes anonymous `GET /version`; `-x` GETs `/info`, `/containers/json`,
  `/images/json`, or a caller path. HTTP `--proxy` via `reqwest`.
- `snmp`: pure-Rust SNMPv2c (default port 161/udp); password is the community (empty
  credentials probe `public`); `-x` GETs a dotted OID or `sysDescr`/`sysName`/`sysUptime`.
  No TCP `--proxy`.
- `activemq`: pure-Rust STOMP CONNECT (default port 61613, alias `amq`); empty `-u '' -p ''`
  probes anonymous CONNECT; `-x` SENDs to `/queue/brute`. Stream-injectable `--proxy`.
- `rabbitmq`: `amqprs` AMQP 0-9-1 (default port 5672, alias `amqp`); empty `-u '' -p ''`
  probes `guest`/`guest`; `-x` `queue.declare`. Host:port TCP proxy bridge.
- `rsync`: pure-Rust rsync daemon AUTHREQD (default port 873); `--module` (default
  `files`). Empty credentials succeed only if the module has no password. No `-x`.
- `mssql`: `tiberius` TDS (default port 1433, alias `sqlserver`); `-x` SQL
  preview (10 rows). Host:port TCP proxy bridge.
- `kafka`: pure-Rust Kafka SASL/PLAIN (default port 9092); `SaslHandshake` +
  `SaslAuthenticate`; `-x` Metadata. Stream-injectable `--proxy`.
- `kibana`: `reqwest` Kibana login (default port 5601); empty credentials probe
  `GET /api/status`; `-x` GET API with session cookie. HTTP `--proxy`.
- `nfs`: pure-Rust NFSv3 ONC RPC (default port 2049); AUTH_NULL for empty
  credentials, AUTH_UNIX uid for non-empty username. `-x` MOUNT DUMP. No password.
- `telnet`: pure-Rust IAC + login/password prompts (default port 23); empty
  `-u '' -p ''` probes unauthorized shell; `-x` runs a remote shell command.
  Stream-injectable `--proxy`.
- `ldap`: `ldap3` simple bind (default port 389); `-u` is the bind DN; empty
  `-u '' -p ''` probes anonymous Root DSE; `-x` whoami/rootdse/filter/DN search.
  Host:port TCP proxy bridge.
- `grafana`: `reqwest` POST `/login` (default port 3000); empty credentials probe
  `GET /api/org`; `-x` GET API with session cookie. HTTP `--proxy`.
- `prometheus`: `reqwest` HTTP Basic (default port 9090, alias `prom`); empty
  `-u '' -p ''` probes anonymous buildinfo; `-x` query/targets/metrics.
  HTTP `--proxy`.
- `jenkins`: `reqwest` HTTP Basic (default port 8080); empty credentials probe
  `GET /api/json`; `-x` whoami/queue/computers. HTTP `--proxy`.
- `couchdb`: `reqwest` HTTP Basic (default port 5984, alias `couch`); empty
  credentials probe `GET /`; `-x` `_all_dbs`/`_up`. HTTP `--proxy`.
- `clickhouse`: `reqwest` HTTP (default port 8123, alias `ch`); empty credentials
  probe `SELECT 1` without Authorization; `-x` SQL (`version`/`databases`).
  HTTP `--proxy`.
- `neo4j`: `reqwest` HTTP Cypher (default port 7474); empty credentials probe
  `RETURN 1` without Authorization; `-x` Cypher (`ping`/`labels`). HTTP `--proxy`.
- `etcd`: `reqwest` etcd v3 HTTP (default port 2379); empty credentials probe
  `/v3/kv/range`; non-empty POST `/v3/auth/authenticate`; `-x` version/range.
  HTTP `--proxy`.
- `influxdb`: `reqwest` InfluxDB 1.x HTTP Basic (default port 8086, alias
  `influx`); empty credentials probe `SHOW DATABASES`; `-x` InfluxQL.
  HTTP `--proxy`.
- `solr`: `reqwest` Solr HTTP (default port 8983); empty credentials probe
  `/solr/admin/info/system`; non-empty HTTP Basic Auth. `-x` cores/system.
  HTTP `--proxy`.
- `minio`: `reqwest` MinIO console HTTP (default port 9001); POST `/api/v1/login`
  with accessKey/secretKey; empty credentials are rejected when anonymous is
  off. `-x` buckets/info. HTTP `--proxy`.
- `nacos`: `reqwest` Nacos HTTP (default port 8848); empty credentials probe
  config list; non-empty POST `/nacos/v1/auth/login`. `-x` namespaces/configs.
  HTTP `--proxy`.
- `nexus`: `reqwest` Nexus REST (default port 8081); login GET
  `/service/rest/v1/security/users` with HTTP Basic; empty credentials fail when
  anonymous is off. `-x` repos/status. HTTP `--proxy`.
- `jboss`: `reqwest` WildFly HTTP management Digest (default port 9990, alias
  `wildfly`); empty credentials probe `GET /management`; `-x` version/state.
  HTTP `--proxy`.
- `druid`: `reqwest` Druid HTTP (default port 8888); login GET
  `/druid/coordinator/v1/isLeader` with HTTP Basic; `-x` status/sql.
  HTTP `--proxy`.
- `spark`: `reqwest` Spark master UI (default port 8080); empty credentials
  probe `GET /json/`; non-empty HTTP Basic Auth. `-x` json/env.
  HTTP `--proxy`.
- `hadoop`: `reqwest` Hadoop NameNode HTTP (default port 9870, alias `hdfs`);
  empty credentials probe `GET /jmx`; non-empty HTTP Basic Auth. `-x` jmx/webhdfs.
  HTTP `--proxy`.
- `kubelet`: `reqwest` kubelet HTTPS (default port 10250); empty credentials
  probe `GET /runningpods/`; token in `-p` as Bearer. 401 auth fail, 403/2xx hit.
  `-x` pods/healthz. HTTP `--proxy`.
- `gitlab`: `reqwest` GitLab HTTP (default port 80); empty credentials probe
  `/api/v4/user`; non-empty POST `/oauth/token` password grant. `-x`
  user/projects. HTTP `--proxy`.
- `harbor`: `reqwest` Harbor HTTP (default port 80); empty credentials probe
  `/api/v2.0/users`; non-empty HTTP Basic Auth. `-x` projects/users.
  HTTP `--proxy`.
- `weblogic`: `reqwest` WebLogic console form login (default port 7001, alias
  `wls`); POST `/console/j_security_check`; `-x` console portal. HTTP `--proxy`.
- `websphere`: `reqwest` WebSphere console form login over HTTPS (default port
  9043, alias `was`); POST `/ibm/console/j_security_check`; `-x` console.
  HTTP `--proxy`.

(none currently reserved as unimplemented stubs)
