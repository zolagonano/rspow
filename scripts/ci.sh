#!/usr/bin/env bash
set -euo pipefail

# Minimal CI script: fmt check, clippy (deny warnings), tests.
# - Pass `--offline` to avoid network; ensure dependencies are pre-fetched.

OFFLINE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--offline) OFFLINE=1; shift ;;
    -h|--help)
      cat <<'USAGE'
Usage: scripts/ci.sh [--offline]

Steps:
  1) cargo fmt -- --check
  2) clippy (deny warnings)
  3) cargo test

Options:
  --offline   set CARGO_NET_OFFLINE=1
USAGE
      exit 0
      ;;
    *) echo "[error] unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ $OFFLINE -eq 1 ]]; then
  export CARGO_NET_OFFLINE=1
fi

echo "[1/3] cargo fmt --check"
cargo fmt -- --check || { echo "[warn] rustfmt check failed" >&2; exit 1; }

echo "[2/3] clippy (deny warnings)"
cargo clippy --all-features -- -D warnings || { exit 1; }

echo "[3/3] cargo test"
cargo test --all-features || { exit 1; }

echo "[OK] CI checks passed"

