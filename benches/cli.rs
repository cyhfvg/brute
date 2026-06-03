use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

fn brute_bin() -> &'static str {
    env!("CARGO_BIN_EXE_brute")
}

#[derive(Debug)]
struct TempHome {
    path: PathBuf,
}

impl TempHome {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "brute-bench-{prefix}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("failed to create temporary home");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run<I, S>(home: &TempHome, args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(brute_bin())
        .args(args)
        .env("HOME", home.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("failed to run brute benchmark command");

    assert!(
        output.status.success(),
        "benchmark command failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn bench_cli_help(c: &mut Criterion) {
    let home = TempHome::new("help");

    c.bench_function("cli_help", |b| {
        b.iter(|| run(&home, ["--help"]));
    });
}

fn bench_workspace_list(c: &mut Criterion) {
    c.bench_function("workspace_list_existing_database", |b| {
        b.iter_batched(
            || {
                let home = TempHome::new("workspace-list");
                run(&home, ["workspace", "new", "audit"]);
                home
            },
            |home| run(&home, ["workspace", "list"]),
            BatchSize::SmallInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_cli_help, bench_workspace_list
}
criterion_main!(benches);
