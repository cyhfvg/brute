#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly MANIFEST_PATH="${PROJECT_ROOT}/Cargo.toml"

BUILD_MODE="debug"
TARGET=""

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Build the brute binary for local development or a selected Rust target.

Options:
  --release          Build an optimized release binary.
  --target <TRIPLE>  Build for a Rust target triple.
  -h, --help         Print this help message.

Environment:
  CARGO_TARGET_DIR   Override Cargo output directory.

Examples:
  scripts/local_build.sh
  scripts/local_build.sh --release
  scripts/local_build.sh --release --target x86_64-unknown-linux-musl
EOF
}

log() {
    printf "[local_build] %s\n" "$*"
}

die() {
    printf "[local_build] error: %s\n" "$*" >&2
    exit 1
}

on_error() {
    local exit_code="$?"
    local line_number="$1"

    printf "[local_build] error: command failed near line %s (exit %s)\n" \
        "${line_number}" "${exit_code}" >&2
    exit "${exit_code}"
}

trap 'on_error "${LINENO}"' ERR

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --release)
                BUILD_MODE="release"
                shift
                ;;
            --target)
                [[ "$#" -ge 2 ]] || die "--target requires a Rust target triple"
                TARGET="$2"
                shift 2
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument '$1'; use --help to see supported options"
                ;;
        esac
    done
}

main() {
    parse_args "$@"
    require_command cargo
    [[ -f "${MANIFEST_PATH}" ]] || die "missing manifest: ${MANIFEST_PATH}"

    local -a cargo_args=(
        build
        --manifest-path "${MANIFEST_PATH}"
        --locked
    )

    if [[ "${BUILD_MODE}" == "release" ]]; then
        cargo_args+=(--release)
    fi
    if [[ -n "${TARGET}" ]]; then
        cargo_args+=(--target "${TARGET}")
    fi

    log "project root: ${PROJECT_ROOT}"
    log "build mode: ${BUILD_MODE}"
    [[ -z "${TARGET}" ]] || log "target: ${TARGET}"
    cargo "${cargo_args[@]}"
    log "build completed successfully"
}

main "$@"
