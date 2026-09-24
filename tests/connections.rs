//! Parser coverage for paired connection URLs.

use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

use brute::{
    cli::{HttpUrlScheme, Protocol},
    connections::{load_connection_sources, parse_connection_line},
};

#[test]
fn parses_paired_forms_and_empty_credentials() {
    let full = parse_connection_line("ssh://root:password@192.168.5.1:22").unwrap();
    assert_eq!(full.protocol, Protocol::Ssh);
    assert_eq!(full.host, "192.168.5.1");
    assert_eq!(full.port, Some(22));
    assert_eq!(full.credential_username().as_deref(), Some("root"));
    assert_eq!(full.credential_password().as_deref(), Some("password"));

    let omitted = parse_connection_line("ssh://root:password@192.168.5.1").unwrap();
    assert_eq!(omitted.port, None);

    let empty_pass = parse_connection_line("ssh://root:@192.168.5.1:22").unwrap();
    assert_eq!(empty_pass.credential_password(), None);
    assert_eq!(empty_pass.port, Some(22));

    let empty_user = parse_connection_line("ssh://:password@192.168.5.1").unwrap();
    assert_eq!(empty_user.credential_username(), None);
    assert_eq!(
        empty_user.credential_password().as_deref(),
        Some("password")
    );

    for raw in [
        "ssh://:@192.168.5.1",
        "ssh://@192.168.5.1",
        "ssh://192.168.5.1",
    ] {
        let conn = parse_connection_line(raw).unwrap();
        assert_eq!(conn.credential_username(), None, "{raw}");
        assert_eq!(conn.credential_password(), None, "{raw}");
        assert_eq!(conn.port, None, "{raw}");
    }

    let user_only = parse_connection_line("ssh://root@192.168.5.1").unwrap();
    assert_eq!(user_only.credential_username().as_deref(), Some("root"));
    assert_eq!(user_only.credential_password(), None);

    let colon = parse_connection_line("ssh://root:p:ass@192.168.5.1").unwrap();
    assert_eq!(colon.password, "p:ass");
    let at = parse_connection_line("ssh://root:p@ss@192.168.5.1:22").unwrap();
    assert_eq!(at.password, "p@ss");
    assert_eq!(at.port, Some(22));

    let encoded = parse_connection_line("ssh://admin%40example.com:p%40ss@192.168.5.1:22").unwrap();
    assert_eq!(encoded.username, "admin@example.com");
    assert_eq!(encoded.password, "p@ss");
    let plus = parse_connection_line("ssh://user:a+b@192.168.5.1").unwrap();
    assert_eq!(plus.password, "a+b");

    let empty_port = parse_connection_line("ssh://user:pass@host:").unwrap();
    assert_eq!(empty_port.host, "host");
    assert_eq!(empty_port.port, None);
}

#[test]
fn parses_https_oracle_rsync_and_aliases() {
    let https = parse_connection_line("https://admin:secret@10.0.0.9:8443/admin").unwrap();
    assert_eq!(https.protocol, Protocol::Http);
    assert_eq!(https.scheme, HttpUrlScheme::Https);
    assert_eq!(https.port, Some(8443));
    assert_eq!(https.path.as_deref(), Some("/admin"));

    let https_default = parse_connection_line("https://admin:secret@10.0.0.9").unwrap();
    assert_eq!(https_default.port, Some(443));
    assert_eq!(https_default.path, None);

    let service = parse_connection_line("oracle://system:oracle@db.internal?service=XE").unwrap();
    assert_eq!(service.service_name.as_deref(), Some("XE"));
    assert_eq!(service.sid, None);
    let sid = parse_connection_line("oracle://system:oracle@db.internal?sid=ORCL").unwrap();
    assert_eq!(sid.sid.as_deref(), Some("ORCL"));

    let zk = parse_connection_line("zk://:@192.168.5.10").unwrap();
    assert_eq!(zk.protocol, Protocol::Zookeeper);
    assert_eq!(zk.credential_username(), None);

    let rsync = parse_connection_line("rsync://admin:secret@10.0.0.9/files").unwrap();
    assert_eq!(rsync.path.as_deref(), Some("files"));
    let module = parse_connection_line("rsync://admin:secret@10.0.0.9?module=public").unwrap();
    assert_eq!(module.path.as_deref(), Some("public"));
}

#[test]
fn rejects_invalid_urls() {
    for raw in [
        "root:password@192.168.5.1",
        "ssh://[::1]:22",
        "ssh://2001:db8::1",
        "ssh://user:pass@192.168.5.1:0",
        "ssh://user:pass@192.168.5.1:99999",
        "ssh://user:bad%zz@192.168.5.1",
        "oracle://system:oracle@db.internal",
        "ssh://user:pass@192.168.5.1?service=XE",
        "ssh://user:pass@192.168.5.1?foo=1",
        "ssh://user:pass@192.168.5.1/tmp",
        "oracle://system:oracle@db.internal?service=XE&sid=ORCL",
    ] {
        assert!(parse_connection_line(raw).is_err(), "{raw}");
    }
}

#[test]
fn loads_file_comments_bom_and_line_numbers() {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("brute-conn-{nanos}.txt"));
    fs::write(
        &path,
        "\u{feff}# comment\n\nssh://root:password@192.168.5.1\nnot-a-url\n",
    )
    .expect("write");
    let err = load_connection_sources(&[path.to_str().unwrap()]).unwrap_err();
    let message = format!("{err:#}");
    assert!(message.contains(":4:"), "{message}");
    let _ = fs::remove_file(&path);

    let empty = std::env::temp_dir().join(format!("brute-conn-empty-{nanos}.txt"));
    fs::write(&empty, "# only\n\n").expect("write empty");
    assert!(load_connection_sources(&[empty.to_str().unwrap()]).is_err());
    let _ = fs::remove_file(&empty);
}
