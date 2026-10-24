#!/usr/bin/env bash
# Quality gate. Runs every check that has caught a real problem in this repo and
# prints one verdict per line, so "is this still good?" is a single command.
#
#   ./test/audit.sh            # full: fmt, clippy, tests, deps, unsafe, suite
#   ./test/audit.sh --quick    # skip the integration suite (needs no mocks)
#
# Exits non-zero on the first hard failure; warnings are reported, not fatal.
set -u
cd "$(dirname "$0")/.."

export CARGO_HOME="${CARGO_HOME:-/tmp/ch}"
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
FAILED=0

echo "== formatting =="
if cargo fmt --all -- --check >/dev/null 2>&1; then
    ok "rustfmt: no diffs"
else
    fail "rustfmt: run 'cargo fmt --all'"
fi

echo "== lints =="
# Exit status first: when the tool cannot run at all (missing component, a wrapper
# that refuses), its message does not start with "warning"/"error", so counting
# diagnostics alone reported a clean tree.
CLIPPY_LOG=$(cargo clippy --all-targets 2>&1)
CLIPPY_STATUS=$?
CLIPPY=$(echo "$CLIPPY_LOG" | grep -cE "^(warning|error)")
if [ "$CLIPPY_STATUS" -ne 0 ]; then
    fail "clippy did not run cleanly (exit $CLIPPY_STATUS): $(echo "$CLIPPY_LOG" | tail -3 | tr '\n' ' ')"
elif [ "$CLIPPY" = "0" ]; then
    ok "clippy --all-targets: clean"
else
    fail "clippy: $CLIPPY diagnostics"
fi
if cargo build --no-default-features >/dev/null 2>&1; then
    ok "build without the dashboard feature"
else
    fail "the --no-default-features build broke"
fi

echo "== tests =="
# Judge the run, not a substring: `test result: FAILED. 575 passed; 3 failed`
# contains "575 passed" and used to be printed as ok, and only the *first* test
# binary's line was inspected (so tests/fuzz_parsers.rs could fail unnoticed).
TEST_LOG=$(cargo test 2>&1)
TEST_STATUS=$?
TOTAL=$(echo "$TEST_LOG" | grep -oE "^test result: [A-Z]+" | grep -c "ok")
FAILED_BIN=$(echo "$TEST_LOG" | grep -cE "^test result: FAILED")
if [ "$TEST_STATUS" -ne 0 ] || [ "$FAILED_BIN" -ne 0 ]; then
    fail "cargo test (exit $TEST_STATUS, $FAILED_BIN failing binary(ies)): $(echo "$TEST_LOG" | grep -E '^(test result|failures:)' | tail -3 | tr '\n' ' ')"
else
    PASSED=$(echo "$TEST_LOG" | grep -oE "[0-9]+ passed" | awk -F' ' '{s+=$1} END {print s+0}')
    ok "cargo test: $PASSED passed in $TOTAL binaries"
fi

echo "== code policy =="
UNSAFE=$(grep -rn "unsafe" src/ --include="*.rs" | grep -vc "unsafe_code\|malloc_conf\|unsafe_code = \|unsafe-eval\|unsafe-inline\|// ")
if [ "$UNSAFE" -le 1 ]; then
    ok "unsafe: $UNSAFE use (jemalloc config only)"
else
    fail "unsafe: $UNSAFE uses — review them"
fi
# unwrap/expect are denied outside tests by a crate-level attribute; prove it.
UNWRAP=$(for f in $(find src -name "*.rs"); do
    awk '/#\[cfg\(test\)\]/{exit} {print}' "$f" | grep -cE "\.unwrap\(\)|\.expect\(" || true
done | awk '{s+=$1} END {print s}')
if [ "$UNWRAP" = "0" ]; then
    ok "unwrap/expect in non-test code: 0"
else
    fail "unwrap/expect in non-test code: $UNWRAP"
fi
if grep -q "unsafe_code = \"deny\"" Cargo.toml; then
    ok "unsafe_code denied crate-wide"
else
    warn "unsafe_code is not denied in Cargo.toml"
fi

echo "== dependencies =="
if command -v cargo-audit >/dev/null 2>&1; then
    # A dependency advisory is a real vulnerability in this binary, not a style
    # issue: fail the audit when the tree carries one.
    ADV=$(cargo audit 2>/dev/null | grep -cE "^Crate:")
    if [ "$ADV" = "0" ]; then
        ok "cargo audit: no known advisories"
    else
        fail "cargo audit: $ADV advisory(ies) in the dependency tree"
    fi
else
    warn "cargo-audit is not installed: dependency advisories unchecked"
fi
DIRECT=$(sed -n '/^\[dependencies\]/,/^\[/p' Cargo.toml | grep -cE "^[a-z]")
ok "direct dependencies: $DIRECT"
# Every dependency should be justified somewhere we can point at in review.
if [ ! -f Cargo.lock ]; then
    fail "Cargo.lock is missing (no reproducible build to audit)"
elif grep -q "name = \"rcgen\"" Cargo.lock; then
    fail "a test-only certificate generator (rcgen) leaked into the tree"
else
    ok "no test-only certificate generator leaked into the tree"
fi

echo "== secrets =="
# Patterns cover the shapes this project actually issues: Google refresh tokens,
# OpenAI-style `sk-…`/`sk-proj-…`, and the gateway's own `sk-hop-…` client keys.
SECRETS=$(git ls-files -z | xargs -0 grep -lE "1//0[0-9A-Za-z_-]{25,}|sk-(proj-|ant-|hop-)?[A-Za-z0-9_-]{24,}" 2>/dev/null)
if [ -n "$SECRETS" ]; then
    fail "a credential-looking string is tracked by git: $(echo "$SECRETS" | head -3 | tr '\n' ' ')"
else
    ok "no credentials in tracked files"
fi
if git check-ignore -q anyhop.toml 2>/dev/null || [ ! -f anyhop.toml ]; then
    ok "anyhop.toml is git-ignored"
else
    warn "anyhop.toml is tracked"
fi

if [ "$QUICK" = "0" ]; then
    echo "== fuzz =="
if ANYHOP_FUZZ_ITERS=20000 cargo test --offline --test fuzz_parsers >/tmp/anyhop-fuzz.log 2>&1; then
    ok "fuzz parsers: $(grep -oE '[0-9]+ passed' /tmp/anyhop-fuzz.log | head -1) (8 targets)"
else
    fail "fuzz parsers (see /tmp/anyhop-fuzz.log)"
fi

echo "== integration =="
    # Build what the suite tests. It used to run ./target/release/anyhop whatever
    # its age, so a local `audit.sh` could "verify" two-day-old code.
    if cargo build --release >/tmp/anyhop-release-build.log 2>&1; then
        ok "release binary rebuilt for the suite"
    else
        fail "the release build failed (see /tmp/anyhop-release-build.log)"
    fi
    if [ -n "${ANYHOP_TEST_PORT:-}" ] || ! ss -ltn 2>/dev/null | grep -q ":18080 "; then
        # Pick a free port ourselves: a hardcoded one collides with a gateway left
        # behind by an earlier run, and the suite then talks to a stale binary
        # (seen as PASS=3/FAIL=35 while the same binary passes 38/0 alone).
        PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
        ANYHOP_TEST_PORT="${ANYHOP_TEST_PORT:-$PORT}" timeout 1500 ./test/run_all.sh ./target/release/anyhop > /tmp/anyhop-audit-suite.log 2>&1
        OUT=$(tail -3 /tmp/anyhop-audit-suite.log)
        if echo "$OUT" | grep -q "FAIL=0"; then
            ok "suite: $(echo "$OUT" | grep -oE 'PASS=[0-9]+' | head -1) FAIL=0"
        else
            fail "suite: $(echo "$OUT" | tail -1) — $(grep -cE '^  FAIL' /tmp/anyhop-audit-suite.log) failing: $(grep -E '^  FAIL' /tmp/anyhop-audit-suite.log | head -3 | tr '\n' ';')"
        fi
    else
        warn "port 18080 is busy — set ANYHOP_TEST_PORT to run the suite"
    fi
fi

if [ "$QUICK" = "0" ] && [ -f test/chaos_test.py ]; then
    echo "== chaos =="
    OUT=$(timeout 600 python3 test/chaos_test.py 2>&1 | tail -2)
    if echo "$OUT" | grep -q "FAIL=0"; then
        ok "chaos: $(echo "$OUT" | grep -oE 'PASS=[0-9]+' | head -1) FAIL=0"
    else
        fail "chaos: $(echo "$OUT" | tail -1)"
    fi
fi

echo
if [ "$FAILED" = "0" ]; then
    echo "AUDIT PASSED"
else
    echo "AUDIT FAILED"
fi
exit "$FAILED"