//! Target source parsing.

use std::{fs, path::Path};

use anyhow::{Context, Result};

use crate::cli::CommonArgs;

/// Loads targets from inline values and line-based target files.
pub fn load_targets(args: &CommonArgs) -> Result<Vec<String>> {
    let mut targets = Vec::new();

    for source in &args.targets {
        let path = Path::new(source);
        if path.exists() && path.is_file() {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read target file: {}", path.display()))?;
            targets.extend(
                content
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty() && !line.starts_with('#'))
                    .map(ToOwned::to_owned),
            );
        } else {
            targets.push(source.to_owned());
        }
    }

    Ok(targets)
}
