#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly MANIFEST_PATH="${PROJECT_ROOT}/Cargo.toml"

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Run the local checks required before committing changes.

Options:
  --fix      Format Rust sources before running checks.
  -h, --help Print this help message.

Checks:
  bash syntax, rustfmt, clippy, tests, and a debug build.
EOF
}

log() {
    printf "[pre_commit] %s\n" "$*"
}

die() {
    printf "[pre_commit] error: %s\n" "$*" >&2
    exit 1
}

on_error() {
    local exit_code="$?"
    local line_number="$1"

    printf "[pre_commit] error: check failed near line %s (exit %s)\n" \
        "${line_number}" "${exit_code}" >&2
    exit "${exit_code}"
}

trap "on_error \${LINENO}" ERR

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

main() {
    local format_mode="check"

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --fix)
                format_mode="write"
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument: $1; use --help to see supported options"
                ;;
        esac
    done

    require_command bash
    require_command cargo
    [[ -f "${MANIFEST_PATH}" ]] || die "missing manifest: ${MANIFEST_PATH}"

    log "checking shell script syntax"
    bash -n "${SCRIPT_DIR}/local_build.sh" "${SCRIPT_DIR}/pre_commit_check.sh"

    if [[ "${format_mode}" == "write" ]]; then
        log "formatting Rust sources"
        cargo fmt --manifest-path "${MANIFEST_PATH}"
    else
        log "checking Rust formatting"
        cargo fmt --manifest-path "${MANIFEST_PATH}" --check
    fi

    log "running Clippy"
    cargo clippy --manifest-path "${MANIFEST_PATH}" --locked --all-targets --all-features -- -D warnings

    log "running tests"
    cargo test --manifest-path "${MANIFEST_PATH}" --locked

    log "verifying debug build"
    cargo build --manifest-path "${MANIFEST_PATH}" --locked

    log "all checks passed"
}

main "$@"
