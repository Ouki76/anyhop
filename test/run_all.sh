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
cleanup() {
    [ -n "${AH_PID:-}" ] && kill "$AH_PID" 2>/dev/null
    for m in $MOCKS; do kill "$m" 2>/dev/null; done
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
curl -s "$BASE/api/providers" | grep -q '"name":"mock"' && ok "/api/providers" || fail "/api/providers"

echo
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" = 0 ]
