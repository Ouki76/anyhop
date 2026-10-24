#!/usr/bin/env bash
# Full regression suite: starts mocks + anyhop on :18080, runs checks, cleans up.
# Usage: ./test/run_all.sh [path-to-anyhop-binary]
set -u
cd "$(dirname "$0")/.."

BIN="${1:-./target/release/anyhop}"
# Port is configurable so a run cannot be hijacked by whatever already owns 18080
# (CI runners and other local projects collide surprisingly often).
PORT="${ANYHOP_TEST_PORT:-18080}"
export ANYHOP_TEST_PORT="$PORT"
BASE="http://127.0.0.1:$PORT"
AUTH="Authorization: Bearer test-gw-key"
CT="Content-Type: application/json"

MOCKS=""
# The suite mutates the test config through the API (client keys, disabled models).
# It works on a private copy: two runs in parallel used to share the file and leak
# each other's client keys into the "reload removes keys" check.
CFG=$(mktemp --suffix=.toml)
cp test/anyhop.test.toml "$CFG"

cleanup() {
    [ -n "${AH_PID:-}" ] && kill "$AH_PID" 2>/dev/null
    for m in $MOCKS; do kill "$m" 2>/dev/null; done
    rm -f "$CFG"
}
trap cleanup EXIT

for m in mock_upstream mock_gemini mock_antigravity mock_codex mock_anthropic; do
    python3 "test/$m.py" >/dev/null 2>&1 &
    MOCKS="$MOCKS $!"
done
# Media/audio/WS provider used by the hardening stage.
python3 test/mock_media.py 9105 >/dev/null 2>&1 &
MOCKS="$MOCKS $!"
# RESP double so the multi-instance rate-limit check needs no real Redis.
python3 test/mock_redis.py 6399 >/dev/null 2>&1 &
MOCKS="$MOCKS $!"
# Wait for every mock before touching the gateway: a fixed `sleep 2` raced a cold
# Python start and, worse, a *stale* mock from an earlier run kept the suite green
# against old code. Each port is probed instead.
for p in 9100 9101 9102 9103 9104 9105 6399; do
    for _ in $(seq 1 100); do
        python3 - "$p" <<'PY' && break
import socket, sys
s = socket.socket()
s.settimeout(0.1)
try:
    s.connect(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
finally:
    s.close()
PY
        sleep 0.1
    done
done
# The antigravity OAuth flow reads its client id/secret from the environment; the
# real pair lives outside the repository (~/.config/anyhop/env, loaded by
# scripts/run.sh). Without a default the OAuth checks were unrunnable on a fresh
# checkout *and in CI* — they asserted a 200 that the server refused with 409. The
# flow only builds the authorization URL and binds the loopback port here, so dummy
# values exercise the real code path without contacting Google.
export ANYHOP_ANTIGRAVITY_CLIENT_ID="${ANYHOP_ANTIGRAVITY_CLIENT_ID:-test-client.apps.googleusercontent.com}"
export ANYHOP_ANTIGRAVITY_CLIENT_SECRET="${ANYHOP_ANTIGRAVITY_CLIENT_SECRET:-test-client-secret}"

# Point the private config copy at the chosen port.
sed -i "s|^listen = .*|listen = \"127.0.0.1:$PORT\"|" "$CFG"
export ANYHOP_TEST_CONFIG="$CFG"
ANYHOP_CONFIG="$CFG" "$BIN" > /tmp/anyhop-regress.log 2>&1 &
AH_PID=$!
# Probe the gateway itself rather than sleeping: a binary that cannot start (bad
# config, missing ui/dist) must fail the suite, not produce 40 confusing FAILs.
GATEWAY_UP=0
for _ in $(seq 1 100); do
    if curl -sf --max-time 1 "$BASE/healthz" >/dev/null 2>&1; then GATEWAY_UP=1; break; fi
    if ! kill -0 "$AH_PID" 2>/dev/null; then break; fi
    sleep 0.1
done
if [ "$GATEWAY_UP" != 1 ]; then
    echo "!!! FAIL: the gateway did not start — see /tmp/anyhop-regress.log"
    tail -20 /tmp/anyhop-regress.log
    exit 1
fi

PASS=0; FAIL=0; SKIP=0
ok()   { PASS=$((PASS+1)); echo "  ok   $1"; }
fail() { FAIL=$((FAIL+1)); echo "  FAIL $1"; }
warn() { SKIP=$((SKIP+1)); echo "  skip $1"; }
SKIP=0

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
# The needle must not be the model id: `no provider serves model 'ag/gemini-3-flash'`
# and `model '…' is not allowed` both contain it, so a routing rejection read as a
# served completion. The mock returns "[gemini-3-flash][sys:…".
expect "antigravity" "$(chat ag/gemini-3-flash hi)"           "\[gemini-3-flash\]\[sys"
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
# `--path-as-is` is required: curl otherwise squashes `../` before sending, so the
# request never left the router and the 404 came from "no such route".
TRAV=$(curl -s --path-as-is -o /dev/null -w '%{http_code}' "$BASE/dashboard/../anyhop.toml")
TRAV2=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/dashboard/%2e%2e%2fanyhop.toml")
[ "$TRAV" = 404 ] && [ "$TRAV2" = 404 ] \
    && ok "path traversal rejected ($TRAV/$TRAV2)" || fail "path traversal rejected ($TRAV/$TRAV2)"

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

echo "== routing integrity =="
# A duplicate `model` key used to be authorized by its FIRST value (the scanner
# stopped once `stream` was seen) and forwarded verbatim, so the upstream executed
# the LAST one: an allowlisted client key could spend any model. The request must
# now be routed and authorized by the value the upstream would use.
# Two *different* models: the reply must carry the marker of the LAST one
# (`gemini`'s mock echoes "[sys:…]"), never the mock provider's "ok via …".
DUP=$(curl -s --max-time 15 "$BASE/v1/chat/completions" -H "$AUTH" -H "$CT" \
    -d '{"messages":[{"role":"user","content":"hi"}],"model":"mock/test-model","stream":false,"model":"gemini/test-gemini"}')
if echo "$DUP" | grep -q "\[sys:" && ! echo "$DUP" | grep -q "ok via"; then
    ok "duplicate model key routes by the last value"
else
    fail "duplicate model key: $(echo "$DUP" | head -c 160)"
fi

echo "== responses store flag =="
# `store: false` is a contract: the response is still answered, but it must not be
# persisted, so chaining to it is refused.
RID=$(curl -s --max-time 15 "$BASE/v1/responses" -H "$AUTH" -H "$CT" \
    -d '{"model":"mock/test-model","input":"hi","store":false}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))')
[ -n "$RID" ] && ok "store:false still returns an id ($RID)" || fail "store:false returned no id"
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 "$BASE/v1/responses" -H "$AUTH" -H "$CT" \
    -d "{\"model\":\"mock/test-model\",\"input\":\"again\",\"previous_response_id\":\"$RID\"}")
[ "$CODE" = 400 ] && ok "an unstored response cannot be chained" || fail "store:false id was replayable ($CODE)"

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

echo "== fim =="
# FIM had no end-to-end test at all: a regression in its request shaping or stop
# handling would ship silently.
FIM=$(curl -s --max-time 15 "$BASE/v1/fim/completions" -H "$AUTH" -H "$CT" \
    -d '{"model":"mock/test-model","prompt":"def add(a, b):","max_tokens":16}')
echo "$FIM" | grep -q '"choices"' && ok "/v1/fim/completions answers" || fail "fim: $(echo "$FIM" | head -c 120)"
FIM2=$(curl -s --max-time 15 "$BASE/v1/completions" -H "$AUTH" -H "$CT" \
    -d '{"model":"mock/test-model","prompt":"def add(a, b):","max_tokens":16}')
echo "$FIM2" | grep -q '"choices"' && ok "/v1/completions alias answers" || fail "fim alias: $(echo "$FIM2" | head -c 120)"
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/v1/fim/completions" -H "$CT" -d '{"model":"mock/test-model","prompt":"x"}')
[ "$CODE" = 401 ] && ok "fim requires auth" || fail "fim auth: $CODE"

echo "== soak (latency + leaks) =="
# Short by default so it fits a regression run; ANYHOP_SOAK_SECS=60 for a real one.
SOAK_SECS="${ANYHOP_SOAK_SECS:-10}"
# Worker count and the p99 ceiling are machine-dependent: a 2-vCPU CI runner needs
# fewer workers and a looser ceiling than a workstation, or the stage reports the
# runner's scheduling jitter as a gateway defect.
SOAK_WORKERS="${ANYHOP_SOAK_WORKERS:-8}"
SOAK_P99="${ANYHOP_SOAK_MAX_P99:-250}"
if timeout 300 python3 test/soak.py --url "$BASE" --key test-gw-key \
        --duration "$SOAK_SECS" --workers "$SOAK_WORKERS" --pid "$AH_PID" --max-p99-ms "$SOAK_P99" \
        > /tmp/anyhop-soak.log 2>&1; then
    ok "soak ${SOAK_SECS}s: $(grep -oE '[0-9,]+ req/s' /tmp/anyhop-soak.log | head -1), $(grep -oE 'p99=[0-9.]+ms' /tmp/anyhop-soak.log | head -1) p99, $(grep -oE 'delta [+-][0-9]+MB' /tmp/anyhop-soak.log | head -1) RSS"
else
    fail "soak (see /tmp/anyhop-soak.log): $(tail -1 /tmp/anyhop-soak.log)"
fi

echo "== redis token bucket (real server) =="
# The shipped Lua used to be executed by nobody: the suite's RESP double and the
# Rust fallback are two independent re-implementations, so they could only agree
# with each other. Runs the exact script text against redis:7-alpine.
if command -v docker >/dev/null 2>&1; then
    if python3 test/redis_lua_test.py --binary "$BIN" > /tmp/anyhop-redis.log 2>&1; then
        ok "redis token bucket Lua: $(grep -oE 'PASS=[0-9]+' /tmp/anyhop-redis.log | tail -1)"
    else
        RC=$?
        if [ "$RC" = 2 ]; then
            warn "redis Lua not verified (no docker/image) — see /tmp/anyhop-redis.log"
        else
            fail "redis token bucket Lua (see /tmp/anyhop-redis.log)"
        fi
    fi
else
    warn "redis Lua not verified (docker is not installed)"
fi

echo "== hot reload (SIGHUP) =="
# Advertised in the README, never tested: a failed reload must keep the old config
# live instead of leaving a half-applied state.
kill -HUP "$AH_PID" 2>/dev/null
sleep 1
CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/healthz")
[ "$CODE" = 200 ] && ok "gateway survives SIGHUP" || fail "SIGHUP killed the gateway ($CODE)"
grep -q "SIGHUP: config reloaded" /tmp/anyhop-regress.log \
    && ok "SIGHUP reloaded the config" || fail "SIGHUP reload did not happen"
R=$(chat mock/test-model hi)
expect "requests still served after SIGHUP" "$R" "ok via"

echo "== hardening (tls, lockout, concurrency, histograms) =="
if ANYHOP_BIN="$BIN" timeout 300 python3 test/hardening_test.py; then
    ok "hardening checks (tls, lockout, concurrency, histograms, media, realtime)"
else
    fail "hardening checks"
fi

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
    warn "ui navigation (chromium/websocket-client missing)"
fi

echo
# SKIP is reported, never folded into PASS: a run that skipped the Redis check or
# the browser stage must be visibly different from one that ran them.
echo "PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" = 0 ]
