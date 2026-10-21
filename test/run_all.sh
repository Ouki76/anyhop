#!/usr/bin/env bash
# Full regression suite: starts mocks + anyhop on :18080, runs checks, cleans up.
# Usage: ./test/run_all.sh [path-to-anyhop-binary]
set -u
cd "$(dirname "$0")/.."

BIN="${1:-./target/release/anyhop}"
BASE="http://127.0.0.1:18080"
AUTH="Authorization: Bearer test-gw-key"
CT="Content-Type: application/json"

MOCKS=""
# The suite mutates the test config through the API (client keys, disabled models)
# and normally restores it at the end. Snapshot it anyway: a failing or interrupted
# run must not leave the repo dirty for the next one.
CFG_SNAPSHOT=$(mktemp)
cp test/anyhop.test.toml "$CFG_SNAPSHOT"

cleanup() {
    [ -n "${AH_PID:-}" ] && kill "$AH_PID" 2>/dev/null
    for m in $MOCKS; do kill "$m" 2>/dev/null; done
    [ -f "$CFG_SNAPSHOT" ] && cp "$CFG_SNAPSHOT" test/anyhop.test.toml && rm -f "$CFG_SNAPSHOT"
}
trap cleanup EXIT

for m in mock_upstream mock_gemini mock_antigravity mock_codex mock_anthropic; do
    python3 "test/$m.py" >/dev/null 2>&1 &
    MOCKS="$MOCKS $!"
done
ANYHOP_CONFIG=test/anyhop.test.toml "$BIN" > /tmp/anyhop-regress.log 2>&1 &
AH_PID=$!
sleep 2

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }

chat() { # model, user-msg, extra-json
    curl -s --max-time 15 "$BASE/v1/chat/completions" -H "$AUTH" -H "$CT" \
        -d "{\"model\":\"$1\",\"messages\":[{\"role\":\"user\",\"content\":\"$2\"}]${3:-}}"
}
content() { python3 -c 'import json,sys; r=json.load(sys.stdin); m=r["choices"][0]["message"]; print(m.get("content") or "")'; }

expect() { # name, haystack, needle
    if echo "$2" | grep -q "$3"; then ok "$1"; else fail "$1 → $(echo "$2" | head -c 120)"; fi
}

echo "== non-stream =="
expect "openai"      "$(chat mock/test-model hi)"             "ok via"
expect "gemini"      "$(chat gemini/test-gemini hi)"          "sys"
expect "antigravity" "$(chat ag/gemini-3-flash hi)"           "gemini-3-flash"
expect "anthropic"   "$(chat claude/claude-test hi)"          "sys"
expect "codex"       "$(chat codex/gpt-codex-test hi)"        "Codex"
expect "combo"       "$(chat testcombo hi)"                   "sys"

echo "== tool calls =="
R=$(chat gemini/test-gemini "call tool")
expect "gemini tool_calls" "$R" "tool_calls"

echo "== streams =="
for m in gemini/test-gemini ag/gemini-3-flash claude/claude-test codex/gpt-codex-test; do
    N=$(curl -sN --max-time 15 "$BASE/v1/chat/completions" -H "$AUTH" -H "$CT" \
        -d "{\"model\":\"$m\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}" | grep -c '^data:')
    [ "$N" -ge 3 ] && ok "stream $m ($N chunks)" || fail "stream $m ($N chunks)"
done

echo "== auth =="
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/chat/completions" -H "$CT" -d '{"model":"mock/test-model","messages":[]}')
[ "$CODE" = 401 ] && ok "401 without key" || fail "auth: got $CODE"

echo "== api =="
curl -s "$BASE/api/providers" -H "$AUTH" | grep -q '"name":"mock"' && ok "/api/providers" || fail "/api/providers"

echo "== protocol hardening =="
# Security headers must be present on every response, including 401s (they are
# added by the outermost layer, so a mistake there is easy to spot here).
HDRS=$(curl -sI "$BASE/healthz")
echo "$HDRS" | grep -qi "x-content-type-options: nosniff" && ok "nosniff header" || fail "nosniff header"
echo "$HDRS" | grep -qi "x-frame-options: DENY" && ok "frame DENY header" || fail "frame DENY header"
echo "$HDRS" | grep -qi "referrer-policy: no-referrer" && ok "no-referrer header" || fail "no-referrer header"
UNAUTH_HDRS=$(curl -sI "$BASE/v1/models")
echo "$UNAUTH_HDRS" | grep -qi "x-content-type-options: nosniff" && ok "headers on 401 too" || fail "headers on 401 too"

# The dashboard document must ship a CSP that hashes its inline scripts; without
# matching hashes the SPA silently refuses to boot (blank page).
CSP=$(curl -sI "$BASE/dashboard" | tr -d '\r' | grep -i "^content-security-policy:")
echo "$CSP" | grep -q "default-src 'none'" && ok "dashboard CSP present" || fail "dashboard CSP present"
echo "$CSP" | grep -q "sha256-" && ok "dashboard CSP hashes inline scripts" || fail "CSP script hashes"
echo "$CSP" | grep -q "'wasm-unsafe-eval'" && ok "dashboard CSP allows wasm" || fail "dashboard CSP allows wasm"
curl -s -o /dev/null -w '%{http_code}' "$BASE/dashboard/../anyhop.toml" | grep -q 404 \
    && ok "path traversal rejected" || fail "path traversal rejected"

echo "== metrics =="
M=$(curl -s "$BASE/metrics" -H "$AUTH")
echo "$M" | grep -q "^anyhop_up 1$" && ok "/metrics up" || fail "/metrics up"
echo "$M" | grep -q "^anyhop_key_requests_total{provider=\"mock\"" && ok "/metrics per-key series" || fail "/metrics per-key series"
echo "$M" | grep -q "^anyhop_keys_available " && ok "/metrics available keys" || fail "/metrics available keys"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/metrics")
[ "$CODE" = 401 ] && ok "/metrics requires auth" || fail "/metrics requires auth (got $CODE)"

echo "== exhaustion carries Retry-After =="
# One key, upstream always 500 -> key cools down, nothing left -> 503, but the
# client must be told when retrying is worth it.
R=$(curl -s --max-time 15 -D /tmp/ah-hdr.txt -o /dev/null -w '%{http_code}' "$BASE/v1/chat/completions" \
    -H "$AUTH" -H "$CT" -d '{"model":"err500/err-model","messages":[{"role":"user","content":"hi"}]}')
[ "$R" = 503 ] && ok "exhausted provider -> 503" || fail "exhausted provider: $R"
grep -qi "^retry-after:" /tmp/ah-hdr.txt && ok "503 carries Retry-After" || fail "503 without Retry-After"
rm -f /tmp/ah-hdr.txt

echo "== embeddings =="
EMB=$(curl -s --max-time 15 "$BASE/v1/embeddings" -H "$AUTH" -H "$CT" \
    -d '{"model":"mock/test-model","input":["a","b"]}')
expect "embeddings openai_compat" "$EMB" '"embedding"'
expect "embeddings batch size"   "$EMB" '"index": *1'
EMB_G=$(curl -s --max-time 15 "$BASE/v1/embeddings" -H "$AUTH" -H "$CT" \
    -d '{"model":"gemini/test-gemini","input":"hello"}')
expect "embeddings gemini translated" "$EMB_G" '"embedding"'
expect "embeddings openai shape"      "$EMB_G" '"object": *"list"'
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/embeddings" -H "$AUTH" -H "$CT" \
    -d '{"model":"claude/claude-test","input":"hi"}')
[ "$CODE" = 400 ] && ok "embeddings unsupported provider -> 400" || fail "embeddings unsupported provider: $CODE"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/embeddings" -H "$CT" -d '{"model":"mock/test-model","input":"hi"}')
[ "$CODE" = 401 ] && ok "embeddings requires auth" || fail "embeddings auth: $CODE"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/embeddings" -H "$AUTH" -H "$CT" -d '{"input":"hi"}')
[ "$CODE" = 400 ] && ok "embeddings without model -> 400" || fail "embeddings no model: $CODE"

echo "== client keys & models =="
if python3 test/client_keys_and_models_test.py; then
    ok "client keys and models access control"
else
    fail "client keys and models access control"
fi

echo "== canary (mock providers) =="
if timeout 120 python3 test/canary.py --config test/canary.test.toml --bin "$BIN"; then
    ok "canary harness (chat/stream/embeddings per provider)"
else
    fail "canary harness"
fi

echo "== ui navigation (CDP) =="
if command -v chromium-browser >/dev/null && python3 -c 'import websocket' 2>/dev/null; then
    if python3 test/cdp_nav_test.py > /tmp/cdp-nav.out 2>&1; then
        ok "ui navigation, no panics"
    else
        fail "ui navigation"; tail -5 /tmp/cdp-nav.out
    fi
else
    echo "  skip (chromium/websocket-client missing)"
fi

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
