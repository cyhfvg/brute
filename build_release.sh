#!/usr/bin/env bash
set -e

TARGET_LINUX="x86_64-unknown-linux-musl"
TARGET_WINDOWS="x86_64-pc-windows-gnu"

function build() {
    local path="$1"
    local target="$2"

    local old_pwd="${PWD}"
    cd "${path}"
    cargo build --release --target "${target}"
    cd "${old_pwd}"
}

base_path="$(dirname "$0")"

echo "Building for Linux and Windows..."

echo "Building brute..."
build "${base_path}" "${TARGET_LINUX}"
build "${base_path}" "${TARGET_WINDOWS}"
