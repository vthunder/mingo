#!/usr/bin/env bash
# Dependency + secrets audit, the same gate locally and in CI (modelled on
# browserid-ng's scripts/supply-chain-audit.sh). Usage:
#
#   scripts/supply-chain-audit.sh [rust|secrets|all]   (default all)
#
# Policy (one place, so CI and `make release-check` cannot drift):
#   rust    `cargo audit` fails on any RUSTSEC vulnerability not ignored in
#           .cargo/audit.toml (warnings for unsound/unmaintained are printed).
#   secrets `gitleaks git` over the full history (default rules). In CI the
#           gitleaks action runs this instead.
#
# Tools: cargo-audit (`cargo install cargo-audit --locked`), gitleaks
# (`brew install gitleaks`). A missing tool fails its section rather than
# silently passing. There is no Node or Python in this repo to audit.
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"
FAIL=0

section() { printf '\n==> %s\n' "$*"; }

run_rust() {
  section "cargo audit"
  command -v cargo-audit >/dev/null || { echo "cargo-audit not installed"; return 1; }
  cargo audit
}

run_secrets() {
  section "gitleaks (full history)"
  command -v gitleaks >/dev/null || { echo "gitleaks not installed"; return 1; }
  gitleaks git --no-banner --redact .
}

case "$MODE" in
  rust)    run_rust || FAIL=1 ;;
  secrets) run_secrets || FAIL=1 ;;
  all)     run_rust || FAIL=1; run_secrets || FAIL=1 ;;
  *) echo "usage: $0 [rust|secrets|all]" >&2; exit 2 ;;
esac
exit $FAIL
