#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Building Rust workspace (native check)..."
cargo check --workspace

echo "==> Building oneauth WASM with wasm-pack..."
if command -v wasm-pack &> /dev/null; then
  cd oneauth
  wasm-pack build --target bundler --out-dir ../ts/src/wasm/oneauth
  cd ..
  echo "    WASM built to ts/src/wasm/oneauth/"
else
  echo "    [SKIP] wasm-pack not installed. Install with: cargo install wasm-pack"
fi

echo "==> Installing TS dependencies..."
cd ts
if command -v pnpm &> /dev/null; then
  pnpm install
elif command -v npm &> /dev/null; then
  npm install
fi

echo "==> Done!"
