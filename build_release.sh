#!/usr/bin/env bash
set -Eeuo pipefail

readonly BINARY_NAME="brute"
readonly TARGET_LINUX="x86_64-unknown-linux-musl"
readonly TARGET_WINDOWS="x86_64-pc-windows-gnu"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
readonly MANIFEST_PATH="${SCRIPT_DIR}/Cargo.toml"
readonly LOCKFILE_PATH="${SCRIPT_DIR}/Cargo.lock"

if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    if [[ "${CARGO_TARGET_DIR}" == /* ]]; then
        BUILD_DIR="${CARGO_TARGET_DIR}"
    else
        BUILD_DIR="${SCRIPT_DIR}/${CARGO_TARGET_DIR}"
    fi
else
    BUILD_DIR="${SCRIPT_DIR}/target"
fi
readonly BUILD_DIR

declare -a TARGETS=()
NORMALIZED_TARGET=""

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Build release binaries for ${BINARY_NAME} with locked dependencies.

Options:
  --target <TARGET>  Build one supported target. May be repeated.
                     Values: linux, windows, ${TARGET_LINUX}, ${TARGET_WINDOWS}
                     Default: linux and windows
  -h, --help         Print this help message

Environment:
  CARGO_TARGET_DIR   Override Cargo's output directory.

Outputs:
  ${BUILD_DIR}/${TARGET_LINUX}/release/${BINARY_NAME}
  ${BUILD_DIR}/${TARGET_WINDOWS}/release/${BINARY_NAME}.exe
EOF
}

log() {
    printf '[build_release] %s\n' "$*"
}

die() {
    printf '[build_release] error: %s\n' "$*" >&2
    exit 1
}

on_error() {
    local exit_code="$?"
    local line_number="$1"
    printf '[build_release] error: command failed near line %s (exit %s)\n' \
        "${line_number}" "${exit_code}" >&2
    exit "${exit_code}"
}

trap 'on_error "${LINENO}"' ERR

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

append_target() {
    local target="$1"
    local selected

    for selected in "${TARGETS[@]:-}"; do
        if [[ "${selected}" == "${target}" ]]; then
            return
        fi
    done
    TARGETS+=("${target}")
}

normalize_target() {
    case "$1" in
        linux | "${TARGET_LINUX}")
            NORMALIZED_TARGET="${TARGET_LINUX}"
            ;;
        windows | "${TARGET_WINDOWS}")
            NORMALIZED_TARGET="${TARGET_WINDOWS}"
            ;;
        *)
            die "unsupported target '$1'; use --help to see supported targets"
            ;;
    esac
}

binary_path_for_target() {
    case "$1" in
        "${TARGET_LINUX}")
            printf '%s/%s/release/%s\n' "${BUILD_DIR}" "$1" "${BINARY_NAME}"
            ;;
        "${TARGET_WINDOWS}")
            printf '%s/%s/release/%s.exe\n' "${BUILD_DIR}" "$1" "${BINARY_NAME}"
            ;;
        *)
            die "internal error: no binary path for target '$1'"
            ;;
    esac
}

ensure_rust_target_installed() {
    local target="$1"
    local installed_targets
    local installed

    if ! command -v rustup >/dev/null 2>&1; then
        log "rustup not found; Cargo will validate availability of target ${target}"
        return
    fi

    installed_targets="$(rustup target list --installed)"
    while IFS= read -r installed; do
        if [[ "${installed}" == "${target}" ]]; then
            return
        fi
    done <<< "${installed_targets}"

    die "Rust target '${target}' is not installed; run: rustup target add ${target}"
}

warn_if_linker_missing() {
    local target="$1"
    local linker=""
    local install_hint=""

    case "${target}" in
        "${TARGET_LINUX}")
            linker="musl-gcc"
            install_hint="install musl-tools or configure an equivalent linker"
            ;;
        "${TARGET_WINDOWS}")
            linker="x86_64-w64-mingw32-gcc"
            install_hint="install a MinGW-w64 toolchain or configure an equivalent linker"
            ;;
    esac

    if [[ -n "${linker}" ]] && ! command -v "${linker}" >/dev/null 2>&1; then
        log "warning: '${linker}' was not found; ${install_hint} if this build fails"
    fi
}

build_target() {
    local target="$1"
    local binary_path

    binary_path="$(binary_path_for_target "${target}")"
    ensure_rust_target_installed "${target}"
    warn_if_linker_missing "${target}"

    log "building ${target}"
    cargo build \
        --manifest-path "${MANIFEST_PATH}" \
        --locked \
        --release \
        --target "${target}" \
        --target-dir "${BUILD_DIR}"

    [[ -f "${binary_path}" ]] || die "build completed but binary is missing: ${binary_path}"
    log "built ${binary_path}"
}

parse_args() {
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --target)
                [[ "$#" -ge 2 ]] || die "--target requires a value"
                normalize_target "$2"
                append_target "${NORMALIZED_TARGET}"
                shift 2
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument '$1'; use --help for usage"
                ;;
        esac
    done

    if [[ "${#TARGETS[@]}" -eq 0 ]]; then
        TARGETS=("${TARGET_LINUX}" "${TARGET_WINDOWS}")
    fi
}

main() {
    local target

    parse_args "$@"
    require_command cargo
    [[ -f "${MANIFEST_PATH}" ]] || die "missing manifest: ${MANIFEST_PATH}"
    [[ -f "${LOCKFILE_PATH}" ]] || die "missing lockfile required for release build: ${LOCKFILE_PATH}"

    log "project root: ${SCRIPT_DIR}"
    log "output directory: ${BUILD_DIR}"

    for target in "${TARGETS[@]}"; do
        build_target "${target}"
    done

    log "release build completed successfully"
}

main "$@"
