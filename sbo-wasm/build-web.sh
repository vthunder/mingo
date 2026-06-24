#!/usr/bin/env bash
# Build the browser-consumable `sbo-wasm` package (Phase 7.4).
#
# Produces an ES-module package under `pkg/` (`--target web`): `sbo_wasm.js`
# (glue + default `init()`) and `sbo_wasm_bg.wasm`. This is what the browserid-ng
# agent loads to build canonical SBO signing bytes in-browser, guaranteeing
# byte-parity with sbo-core (it is the same Rust). Release + wasm-opt keeps the
# artifact small (~150 KB).
#
# Requires `wasm-pack` (https://rustwasm.github.io/wasm-pack/). Usage:
#   ./build-web.sh            # → pkg/  (target: web)
#   ./build-web.sh nodejs out # → out/  (target: nodejs, for the Node smoke test)
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${1:-web}"
OUT="${2:-pkg}"

exec wasm-pack build --target "$TARGET" --out-dir "$OUT" --no-typescript
