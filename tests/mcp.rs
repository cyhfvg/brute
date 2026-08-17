//! MCP stdio handshake and tool-call integration tests.

use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use brute::{cli::Protocol, credentials::CredentialSet, database::CredentialDatabase};
use serde_json::{Value, json};

fn brute_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brute")
}

struct TempHome {
    path: PathBuf,
}

impl TempHome {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("brute-{prefix}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("failed to create temporary home");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

struct McpClient {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl McpClient {
    fn start(home: &TempHome) -> Self {
        let mut child = Command::new(brute_bin())
            .arg("mcp")
            .env("HOME", home.path())
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start brute mcp");
        let stdin = child.stdin.take().expect("mcp stdin");
        let stdout = child.stdout.take().expect("mcp stdout");
        Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
            next_id: 1,
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        writeln!(self.stdin, "{message}").expect("write MCP request");
        self.stdin.flush().expect("flush MCP request");

        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read MCP response");
        assert!(
            !line.trim().is_empty(),
            "MCP server closed stdout without a response"
        );
        let value: Value = serde_json::from_str(line.trim()).unwrap_or_else(|err| {
            panic!("invalid MCP JSON: {err}; line={line:?}");
        });
        assert_eq!(value["id"], id, "MCP response id mismatch: {value}");
        assert!(
            value.get("error").is_none(),
            "MCP error for {method}: {value}"
        );
        value["result"].clone()
    }

    fn notify(&mut self, method: &str, params: Value) {
        let message = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        writeln!(self.stdin, "{message}").expect("write MCP notification");
        self.stdin.flush().expect("flush MCP notification");
    }

    fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let result = self.request(
            "tools/call",
            json!({
                "name": name,
                "arguments": arguments,
            }),
        );
        assert_eq!(
            result["isError"], false,
            "tool {name} returned isError: {result}"
        );
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("tool {name} missing text content: {result}"));
        serde_json::from_str(text).unwrap_or_else(|err| {
            panic!("tool {name} did not return JSON text: {err}; text={text}");
        })
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn initialize(client: &mut McpClient) -> Value {
    let result = client.request(
        "initialize",
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "brute-mcp-test", "version": "0.0.1"}
        }),
    );
    client.notify("notifications/initialized", json!({}));
    result
}

/// Verifies MCP initialize advertises brute tools and does not pollute stdout.
#[test]
fn mcp_initialize_lists_expected_tools() {
    let home = TempHome::new("mcp-init");
    let mut client = McpClient::start(&home);
    let info = initialize(&mut client);

    assert_eq!(info["serverInfo"]["name"], "brute");
    assert!(info["capabilities"]["tools"].is_object());

    let listed = client.request("tools/list", json!({}));
    let names: Vec<&str> = listed["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect();
    for expected in [
        "verify_account",
        "spray_passwords",
        "list_credentials",
        "list_workspaces",
        "list_protocols",
    ] {
        assert!(
            names.contains(&expected),
            "missing tool {expected} in {names:?}"
        );
    }
}

/// Verifies credential query tools read the same SQLite store as the CLI.
#[test]
fn mcp_lists_saved_credentials_and_workspaces() {
    let home = TempHome::new("mcp-creds");
    let db_path = home.path().join(".config/brute/brute.db");
    let database = CredentialDatabase::open(&db_path).expect("open temp database");
    database
        .save_success(
            "default",
            Protocol::Ssh,
            "10.0.0.8",
            22,
            &CredentialSet {
                username: Some("root".into()),
                password: Some("toor".into()),
                service_name: None,
                sid: None,
            },
        )
        .expect("save credential");

    let mut client = McpClient::start(&home);
    initialize(&mut client);

    let workspaces = client.call_tool("list_workspaces", json!({}));
    assert!(
        workspaces
            .as_array()
            .expect("workspace array")
            .iter()
            .any(|row| row["name"] == "default" && row["is_current"] == true),
        "current default workspace missing: {workspaces}"
    );

    let credentials = client.call_tool(
        "list_credentials",
        json!({"protocol": "ssh", "host": "10.0.0.8"}),
    );
    assert_eq!(credentials[0]["username"], "root");
    assert_eq!(credentials[0]["password"], "toor");
    assert_eq!(credentials[0]["protocol"], "ssh");
    assert_eq!(credentials[0]["host"], "10.0.0.8");
    assert_eq!(credentials[0]["port"], 22);
}

/// Verifies a single-account check returns a structured report without hanging.
#[test]
fn mcp_verify_account_returns_structured_report() {
    let home = TempHome::new("mcp-verify");
    let mut client = McpClient::start(&home);
    initialize(&mut client);

    let report = client.call_tool(
        "verify_account",
        json!({
            "protocol": "ssh",
            "target": "127.0.0.1",
            "username": "root",
            "password": "invalid",
            "options": {
                "port": 1,
                "timeout_ms": 400,
                "retries": 0
            }
        }),
    );
    assert_eq!(report["protocol"], "ssh");
    assert_eq!(report["workspace"], "default");
    assert!(
        report["attempts"]
            .as_array()
            .map(|rows| !rows.is_empty())
            .unwrap_or(false)
            || report["successes"]
                .as_array()
                .map(Vec::is_empty)
                .unwrap_or(false),
        "verify report should include attempt outcome: {report}"
    );
}
