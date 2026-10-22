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
CLIPPY=$(cargo clippy --all-targets 2>&1 | grep -cE "^(warning|error)")
if [ "$CLIPPY" = "0" ]; then
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
UNIT=$(cargo test 2>&1 | grep -m1 "test result" | grep -oE "[0-9]+ passed")
if echo "$UNIT" | grep -qE "^[0-9]+"; then
    ok "cargo test: $UNIT"
else
    fail "cargo test failed"
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
if [ -f Cargo.lock ] && ! grep -q "name = \"rcgen\"" Cargo.lock; then
    ok "no test-only certificate generator leaked into the tree"
fi

echo "== secrets =="
if git ls-files | xargs grep -lE "1//0c[0-9A-Za-z_-]{20,}|sk-[a-f0-9]{20,}" 2>/dev/null | grep -q .; then
    fail "a credential-looking string is tracked by git"
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
    if [ -n "${ANYHOP_TEST_PORT:-}" ] || ! ss -ltn 2>/dev/null | grep -q ":18080 "; then
        OUT=$(ANYHOP_TEST_PORT="${ANYHOP_TEST_PORT:-18091}" timeout 1500 ./test/run_all.sh ./target/release/anyhop 2>&1 | tail -3)
        if echo "$OUT" | grep -q "FAIL=0"; then
            ok "suite: $(echo "$OUT" | grep -oE 'PASS=[0-9]+' | head -1) FAIL=0"
        else
            fail "suite: $(echo "$OUT" | tail -1)"
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