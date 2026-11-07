#!/usr/bin/env bash
# The fast local equivalent of .github/workflows/release-candidate.yml: run it
# before pushing a branch to the staging mirror. It does not qualify a
# submission (the mirror's check runs do, sandmill-infra/ip-approval/PLAN.md);
# it catches what they would catch, sooner. Runs every step, prints one line
# per step, and exits non-zero if any step failed or the tree was left dirty.
#
#   scripts/release-check.sh            # from anywhere in the repo, clean tree
#   RELEASE_CHECK_SKIP="supply-chain" scripts/release-check.sh   # dev only
#
# Not covered locally: the image builds and container smoke tests (they need
# docker; CI runs them), and the network isolation of the test run (CI runs
# the tests in a loopback-only network namespace; macOS has none).
#
# On the dev box run it through `ssh localtest` so cargo's test binaries are
# not stalled by Gatekeeper. Needs: cargo + rustup, cargo-audit, gitleaks.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"
export PATH="$HOME/.cargo/bin:$PATH"
LOGDIR="${RELEASE_CHECK_LOGDIR:-/tmp/release-check-mingo}"
mkdir -p "$LOGDIR"
SKIP=" ${RELEASE_CHECK_SKIP:-} "
declare -a RESULTS=()
FAILED=0

if [ -n "$(git status --porcelain)" ]; then
  echo "refusing: the tree is dirty (commit or stash first, so the run checks a commit):"
  git status --short | sed 's/^/  /'
  exit 1
fi

step() {
  local name="$1"; shift
  if [[ "$SKIP" == *" $name "* ]]; then RESULTS+=("skip  $name"); return 0; fi
  local log="$LOGDIR/$name.log"
  printf '==> %s\n' "$name"
  if "$@" >"$log" 2>&1; then
    RESULTS+=("ok    $name")
  else
    RESULTS+=("FAIL  $name  (log: $log)")
    FAILED=1
    tail -40 "$log" | sed 's/\x1b\[[0-9;]*m//g'
  fi
}

dockerfile_rust() { sed -nE 's/^FROM rust:([0-9.]+)-.*/\1/p' "$1" | head -1; }
dockerfile_image() { sed -nE 's/^FROM (rust:[^ ]+) AS chef.*/\1/p' "$1" | head -1; }

# Same assertions as the first step of rc / rust.
pins() {
  local a b ci core revs
  [ "$(dockerfile_image deploy/mingo/Dockerfile)" = "$(dockerfile_image deploy/sbo-daemon/Dockerfile)" ] \
    || { echo "Dockerfiles disagree on the rust image"; return 1; }
  a="$(dockerfile_rust deploy/mingo/Dockerfile)"
  ci="$(grep -oE 'rust-toolchain@[0-9a-f]+ # [0-9.]+' .github/workflows/release-candidate.yml | sed 's/.*# //' | sort -u)"
  [ "$ci" = "$a" ] || { echo "release-candidate.yml pins rust $ci, the Dockerfiles $a"; return 1; }
  # (CI also checks the digest really carries $a; that needs docker.)
  core="$(sed -nE 's/^sbo-core = .*rev = "([0-9a-f]+)".*/\1/p' Cargo.toml)"
  revs="$(sed -nE 's/^ARG SBO_REV=([0-9a-f]+)/\1/p' deploy/sbo-daemon/Dockerfile | sort -u)"
  [ -n "$core" ] && [ "$revs" = "$core" ] || { echo "SBO_REV ($revs) differs from the sbo-core rev ($core)"; return 1; }
  echo "rust $a, sbo $core"
}

# The workspace tests with the toolchain CI and the images build with, not
# whatever rustup's stable is on this box.
rust_pinned() {
  local v tc
  v="$(dockerfile_rust deploy/mingo/Dockerfile)"
  rustup toolchain install "$v" --profile minimal >/dev/null 2>&1 || return 1
  tc="$(rustup toolchain list | grep -oE "^$v-" | head -1 | sed 's/-$//')"
  [ -n "$tc" ] || { echo "toolchain $v not installed"; return 1; }
  echo "testing with $tc"
  cargo "+$tc" test --workspace --locked
}

supply_chain() { scripts/supply-chain-audit.sh all; }

step pins          pins
step rust-pinned   rust_pinned
step supply-chain  supply_chain

echo
echo "release-check summary ($(git rev-parse --short HEAD)):"
printf '  %s\n' "${RESULTS[@]}"
if [ -z "$(git status --porcelain)" ]; then
  echo "  ok    tree clean after the run"
else
  echo "  FAIL  the run left the tree dirty:"; git status --short | sed 's/^/    /'; FAILED=1
fi
exit $FAILED
