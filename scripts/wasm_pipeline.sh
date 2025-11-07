#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="release"
OFFLINE=0
SKIP_TEST=0
SERVE=0
PORT=8000

usage() {
  cat <<'EOF'
Usage: scripts/wasm_pipeline.sh [options]

 -d, --dev           Build in debug profile (default: release)
 -o, --offline       Enable offline mode (sets CARGO_NET_OFFLINE=1)
 -s, --serve         After building, serve wasm-demo/www via python3 http.server
 -p, --port <port>   Port used together with --serve (default: 8000)
 -t, --skip-test     Skip cargo test
 -h, --help          Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--dev)
      MODE="dev"
      shift
      ;;
    -o|--offline)
      OFFLINE=1
      shift
      ;;
    -s|--serve)
      SERVE=1
      shift
      ;;
    -p|--port)
      PORT="${2:-}"
      if [[ -z "$PORT" ]]; then
        echo "[error] --port requires a value" >&2
        exit 1
      fi
      shift 2
      ;;
    -t|--skip-test)
      SKIP_TEST=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[error] unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[error] command not found: $1" >&2
    exit 1
  fi
}

require_cmd cargo
require_cmd wasm-pack

if [[ $SERVE -eq 1 ]]; then
  require_cmd python3
fi

if [[ $OFFLINE -eq 1 ]]; then
  export CARGO_NET_OFFLINE=1
  export WASM_PACK_PROFILE=offline
else
  unset CARGO_NET_OFFLINE || true
fi

echo "[step 1/5] cargo fmt check"
cargo fmt -- --check || echo "[note] fmt check failed; you can rerun without --check" >&2

if [[ $SKIP_TEST -eq 0 ]]; then
  echo "[step 2/5] cargo test"
  cargo test
else
  echo "[step 2/5] skipping cargo test"
fi

WASM_BUILD_FLAG="--release"
if [[ "$MODE" == "dev" ]]; then
  WASM_BUILD_FLAG="--dev"
fi

echo "[step 3/5] cargo build --target wasm32-unknown-unknown $MODE"
cargo build --target wasm32-unknown-unknown "--$MODE"

echo "[step 4/5] wasm-pack build $WASM_BUILD_FLAG"
pushd wasm-demo >/dev/null
if [[ $OFFLINE -eq 1 ]]; then
  CARGO_NET_OFFLINE=1 wasm-pack build --target web $WASM_BUILD_FLAG
else
  wasm-pack build --target web $WASM_BUILD_FLAG
fi
popd >/dev/null

echo "[step 5/5] sync pkg output to wasm-demo/www/pkg"
mkdir -p wasm-demo/www/pkg
rsync -a --delete wasm-demo/pkg/ wasm-demo/www/pkg/

echo "[done] wasm bundle ready under wasm-demo/pkg and mirrored to wasm-demo/www/pkg"

if [[ $SERVE -eq 1 ]]; then
  echo "[serve] hosting wasm-demo/www at http://127.0.0.1:$PORT"
  (cd wasm-demo/www && python3 -m http.server "$PORT")
fi
