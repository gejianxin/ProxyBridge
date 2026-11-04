#!/usr/bin/env bash
# Typecheck the workspace for every platform named in the README.
# `cargo check` does not link, so Windows and macOS targets can be checked
# from Linux once rustup has the standard libraries. A full link of those
# targets still needs the platform linker (or a cross toolchain).
set -euo pipefail

cd "$(dirname "$0")/.."

targets=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-pc-windows-msvc
  x86_64-apple-darwin
  aarch64-apple-darwin
)

for target in "${targets[@]}"; do
  echo "==> rustup target add ${target}"
  rustup target add "${target}"
  echo "==> cargo check --workspace --target ${target}"
  cargo check --workspace --target "${target}"
done

echo "all listed targets passed cargo check"
