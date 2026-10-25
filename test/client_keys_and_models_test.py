#!/usr/bin/env python3
"""
Test client API keys, model restrictions, and model enable/disable functionality.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

PORT = os.environ.get("ANYHOP_TEST_PORT", "18080")
BASE = f"http://127.0.0.1:{PORT}"
ADMIN_KEY = "test-gw-key"


def request(method, path, data=None, token=ADMIN_KEY):
    url = f"{BASE}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            try:
                parsed = json.loads(content) if content else {}
            except Exception:
                parsed = {"raw": content}
            return resp.status, parsed
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = {"raw": content}
        return e.code, parsed


def main():
    print("=== Testing Client Keys and Models Functionality ===")

    # The suite runs against a private copy (see run_all.sh) so parallel runs
    # cannot corrupt each other; fall back to the checked-in file when run alone.
    test_toml = os.environ.get("ANYHOP_TEST_CONFIG", "test/anyhop.test.toml")
    with open(test_toml, "r") as f:
        original_toml = f.read()

    try:
        run_tests(original_toml)
    finally:
        with open(test_toml, "w") as f:
            f.write(original_toml)
        # Reload anyhop config so it resets to original
        request("POST", "/api/reload")


def run_tests(original_toml):

    # 1. Check /api/models
    status, models = request("GET", "/api/models")
    assert status == 200, f"Expected 200, got {status}: {models}"
    print(f"  ok /api/models returned {len(models)} models")
    mock_model = next((m for m in models if m["id"] == "mock/test-model"), None)
    assert mock_model is not None, "mock/test-model not found in /api/models"
    assert mock_model["enabled"] is True, "mock/test-model should be enabled initially"

    # 2. Check /v1/models with master key
    status, v1_models = request("GET", "/v1/models", token=ADMIN_KEY)
    assert status == 200, f"Expected 200, got {status}: {v1_models}"
    ids = [m["id"] for m in v1_models["data"]]
    assert "mock/test-model" in ids, "mock/test-model should be in /v1/models"
    print(f"  ok /v1/models with master key returns {len(ids)} models")

    # 3. Create a client API key with specific model: only "gemini/test-gemini"
    status, key1 = request("POST", "/api/client-keys/add", {
        "name": "Gemini-Only-Key",
        "key": "sk-hop-test-gemini-only",
        "models": ["gemini/test-gemini"]
    })
    assert status == 200, f"Expected 200, got {status}: {key1}"
    assert key1["key"] == "sk-hop-test-gemini-only"
    assert key1["models"] == ["gemini/test-gemini"]
    print("  ok created client key with restricted models")

    # 4. Create another client API key with all models (empty models list)
    status, key2 = request("POST", "/api/client-keys/add", {
        "name": "All-Models-Key",
        "key": "",  # auto-generated
        "models": []
    })
    assert status == 200, f"Expected 200, got {status}: {key2}"
    assert key2["key"].startswith("sk-hop-"), f"Expected auto-generated key, got {key2['key']}"
    assert key2["models"] == []
    print(f"  ok created auto-generated key: {key2['masked']}")

    # 5. List client keys
    status, keys_list = request("GET", "/api/client-keys")
    assert status == 200
    assert any(k["key"] == "sk-hop-test-gemini-only" for k in keys_list)
    assert any(k["key"] == key2["key"] for k in keys_list)
    print(f"  ok /api/client-keys listed {len(keys_list)} keys")

    # 6. Test /v1/models with restricted client key
    status, v1_restricted = request("GET", "/v1/models", token="sk-hop-test-gemini-only")
    assert status == 200, f"Expected 200, got {status}: {v1_restricted}"
    restr_ids = [m["id"] for m in v1_restricted["data"]]
    assert restr_ids == ["gemini/test-gemini"], f"Expected only gemini/test-gemini, got: {restr_ids}"
    print("  ok /v1/models with restricted client key returned ONLY allowed models")

    # 6b. The single-model variant must filter identically, or a restricted key can
    # enumerate the catalogue one id at a time (200 vs 404) and probe models it may
    # not use. The allowed id still resolves (200).
    status, _ = request("GET", "/v1/models/gemini/test-gemini", token="sk-hop-test-gemini-only")
    assert status == 200, f"the allowed model must resolve, got {status}"
    status, _ = request("GET", "/v1/models/mock/test-model", token="sk-hop-test-gemini-only")
    assert status >= 400, f"a disallowed model must not resolve, got {status}"
    print("  ok /v1/models/{id} honours the client-key allowlist")

    # 6c. ...and so does the bare-name spelling of a disabled model.
    status, _ = request("POST", "/api/models/disable", {"model": "mock/test-model"})
    assert status == 200, f"disable failed: {status}"
    status, _ = request("GET", "/v1/models/mock/test-model")
    assert status == 404, f"disabled model resolved by its qualified id, got {status}"
    status, _ = request("POST", "/api/models/enable", {"model": "mock/test-model"})
    assert status == 200, f"enable failed: {status}"
    print("  ok /v1/models/{id} honours the disabled set")

    # 7. Test /v1/chat/completions with restricted client key:
    # 7a. Allowed model: gemini/test-gemini -> 200 OK
    status, chat_resp = request("POST", "/v1/chat/completions", {
        "model": "gemini/test-gemini",
        "messages": [{"role": "user", "content": "hi"}]
    }, token="sk-hop-test-gemini-only")
    assert status == 200, f"Expected 200, got {status}: {chat_resp}"
    print("  ok chat/completions with allowed model succeeded (200)")

    # 7b. Disallowed model: mock/test-model -> 403 Forbidden
    status, err_resp = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token="sk-hop-test-gemini-only")
    assert status == 403, f"Expected 403, got {status}: {err_resp}"
    assert err_resp.get("error", {}).get("type") == "model_not_allowed", f"Got: {err_resp}"
    print("  ok chat/completions with disallowed model was blocked (403 model_not_allowed)")

    # 7c. Invalid key -> 401 Unauthorized
    status, err_auth = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token="invalid-key-xyz")
    assert status == 401, f"Expected 401, got {status}: {err_auth}"
    print("  ok chat/completions with invalid key was blocked (401)")

    # 8. Test /v1/chat/completions with all-models client key -> allowed for mock/test-model
    status, chat_resp2 = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token=key2["key"])
    assert status == 200, f"Expected 200, got {status}: {chat_resp2}"
    print("  ok chat/completions with all-models client key succeeded (200)")

    # 9. Test model disabling: disable mock/test-model
    status, dis_res = request("POST", "/api/models/disable", {"model": "mock/test-model"})
    assert status == 200 and dis_res["enabled"] is False, f"Disable failed: {dis_res}"
    print("  ok disabled mock/test-model via /api/models/disable")

    # 9a. /v1/models should NO LONGER return mock/test-model
    status, v1_after_dis = request("GET", "/v1/models", token=ADMIN_KEY)
    assert status == 200
    assert "mock/test-model" not in [m["id"] for m in v1_after_dis["data"]], "Disabled model returned in /v1/models!"
    print("  ok disabled model excluded from /v1/models")

    # 9b. calling mock/test-model should return 404 (model disabled)
    status, err_dis = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token=ADMIN_KEY)
    assert status == 404, f"Expected 404, got {status}: {err_dis}"
    assert "disabled" in err_dis.get("error", {}).get("message", ""), f"Expected disabled message, got: {err_dis}"
    print("  ok request to disabled model returned 404 disabled")

    # 10. Re-enable mock/test-model via /api/models/enable
    status, en_res = request("POST", "/api/models/enable", {"model": "mock/test-model"})
    assert status == 200 and en_res["enabled"] is True
    print("  ok re-enabled mock/test-model via /api/models/enable")

    # 10a. /v1/models should have mock/test-model again
    status, v1_after_en = request("GET", "/v1/models", token=ADMIN_KEY)
    assert "mock/test-model" in [m["id"] for m in v1_after_en["data"]]
    print("  ok re-enabled model is back in /v1/models")

    # 10b. calling mock/test-model should succeed now
    status, chat_after_en = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token=ADMIN_KEY)
    assert status == 200
    print("  ok request to re-enabled model succeeded (200)")

    # 11. Test updating client key allowed models
    status, updated_key = request("POST", "/api/client-keys/update", {
        "key": "sk-hop-test-gemini-only",
        "name": "Gemini-And-Mock-Key",
        "models": ["gemini/test-gemini", "mock/test-model"]
    })
    assert status == 200
    assert set(updated_key["models"]) == {"gemini/test-gemini", "mock/test-model"}
    assert updated_key["name"] == "Gemini-And-Mock-Key"
    print("  ok updated client key allowed models")

    # Now sk-hop-test-gemini-only can call mock/test-model
    status, chat_now_allowed = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token="sk-hop-test-gemini-only")
    assert status == 200
    print("  ok previously restricted key now succeeds on newly allowed model")

    # 12. Test deleting client keys
    status, _ = request("POST", "/api/client-keys/delete", {"key": "sk-hop-test-gemini-only"})
    assert status == 200
    status, _ = request("POST", "/api/client-keys/delete", {"key": key2["key"]})
    assert status == 200
    print("  ok deleted client keys")

    # Deleted key now returns 401
    status, _ = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token="sk-hop-test-gemini-only")
    assert status == 401
    print("  ok deleted key is rejected with 401")

    # 13. Test /api/models/refresh
    status, refreshed_models = request("POST", "/api/models/refresh", {})
    assert status == 200, f"Expected 200 from /api/models/refresh, got {status}: {refreshed_models}"
    assert len(refreshed_models) >= 8, f"Expected at least 8 models, got {len(refreshed_models)}"
    print(f"  ok /api/models/refresh succeeded and returned {len(refreshed_models)} models")

    # 14. Allowlist bypass: qualified entry must NOT match upstream name via another provider.
    #     Key allows "gemini/test-gemini"; request "mock/gemini/test-gemini" must be 403.
    status, key3 = request("POST", "/api/client-keys/add", {
        "name": "Bypass-Test",
        "key": "sk-hop-bypass-test",
        "models": ["gemini/test-gemini"],
    })
    assert status == 200
    status, bypass_resp = request("POST", "/v1/chat/completions", {
        "model": "mock/gemini/test-gemini",
        "messages": [{"role": "user", "content": "hi"}]
    }, token="sk-hop-bypass-test")
    assert status == 403, f"allowlist bypass! expected 403, got {status}: {bypass_resp}"
    print("  ok qualified allowlist entry does not leak across providers (403)")

    # Bare entry DOES match bare upstream name intentionally
    status, key4 = request("POST", "/api/client-keys/add", {
        "name": "Bare-Test",
        "key": "sk-hop-bare-test",
        "models": ["test-model"],
    })
    assert status == 200
    status, bare_resp = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token="sk-hop-bare-test")
    assert status == 200, f"bare allowlist entry should match, got {status}: {bare_resp}"
    print("  ok bare allowlist entry matches provider-qualified request")

    # 15. Bare disable blocks qualified request
    status, _ = request("POST", "/api/models/disable", {"model": "test-model"})
    assert status == 200
    status, dis_bare = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token=ADMIN_KEY)
    assert status == 404, f"expected 404 for bare-disabled model, got {status}: {dis_bare}"
    status, _ = request("POST", "/api/models/enable", {"model": "test-model"})
    assert status == 200
    print("  ok bare disabled_models entry blocks provider-qualified request")

    # 16. Reload must REMOVE client keys absent from the config file
    status, put_resp = request("PUT", "/api/config", {"toml": original_toml})
    assert status == 200, f"PUT /api/config failed: {put_resp}"
    status, keys_after = request("GET", "/api/client-keys")
    assert status == 200 and keys_after == [], f"client keys survived config reload: {keys_after}"
    status, rel_resp = request("POST", "/v1/chat/completions", {
        "model": "mock/test-model",
        "messages": [{"role": "user", "content": "hi"}]
    }, token="sk-hop-bypass-test")
    assert status == 401, f"deleted key must be 401 after reload, got {status}: {rel_resp}"
    print("  ok reload removes client keys that are gone from the config")

    # 17. `?key=` is percent-decoded (the dashboard URL-encodes it for EventSource)
    #     and stays GET-only. Raw + encoded must both work, POST must not.
    import urllib.request as _ur
    def code(url, method="GET", token=None):
        r = _ur.Request(url, method=method, data=b"{}" if method == "POST" else None)
        if method == "POST":
            r.add_header("Content-Type", "application/json")
        if token:
            r.add_header("Authorization", f"Bearer {token}")
        try:
            with _ur.urlopen(r) as resp:
                return resp.status
        except urllib.error.HTTPError as e:
            return e.code

    assert code(f"{BASE}/api/providers?key={ADMIN_KEY}") == 200, "raw ?key= must auth"
    assert code(f"{BASE}/api/providers?key=test%2Dgw%2Dkey") == 200, "encoded ?key= must auth"
    assert code(f"{BASE}/api/providers?key=nope") == 401, "wrong ?key= must be rejected"
    assert code(f"{BASE}/api/models/refresh?key={ADMIN_KEY}", "POST") == 401, \
        "?key= must not authenticate POST (keys in URLs leak)"
    print("  ok ?key= is GET-only and percent-decoded")

    # 18. Per-key rate limiting: rpm/burst are enforced and reported.
    status, rl_key = request("POST", "/api/client-keys/add", {
        "name": "Rate-Limited", "key": "sk-hop-rate-limited", "models": [], "rpm": 60, "burst": 2
    })
    assert status == 200, f"add failed: {rl_key}"
    assert rl_key["rpm"] == 60 and rl_key["burst"] == 2, f"limits not echoed: {rl_key}"
    # burst=2 → first two pass, the third is rejected with 429 + Retry-After.
    codes = []
    for _ in range(3):
        codes.append(code(f"{BASE}/v1/models", "GET", token="sk-hop-rate-limited"))
    assert codes[0] == 200 and codes[1] == 200, f"burst should allow 2 requests: {codes}"
    assert codes[2] == 429, f"third request must be rate limited: {codes}"
    # The rejection carries Retry-After and an OpenAI-style error body.
    r = _ur.Request(f"{BASE}/v1/models")
    r.add_header("Authorization", "Bearer sk-hop-rate-limited")
    try:
        _ur.urlopen(r)
        raise AssertionError("rate limiting stopped working")
    except urllib.error.HTTPError as e:
        assert e.headers.get("Retry-After"), "429 must carry Retry-After"
        payload = json.loads(e.read().decode())
        assert payload["error"]["type"] == "rate_limit_exceeded", payload
    # Unlimited keys are unaffected by another key's limit.
    assert code(f"{BASE}/v1/models", "GET", token=ADMIN_KEY) == 200
    # The limit is visible in /metrics.
    m = _ur.urlopen(_ur.Request(f"{BASE}/metrics", headers={"Authorization": f"Bearer {ADMIN_KEY}"})).read().decode()
    assert "anyhop_client_key_rate_limited_total" in m, "rate limit metric missing"
    # Two rejections by now: the burst probe above and this Retry-After probe.
    assert 'anyhop_client_key_rate_limited_total{key="Rate-Limited"} 2' in m, m
    print("  ok per-key rate limit (burst, 429 + Retry-After, metrics)")

    # 19. Updating the limit keeps the key usable and can clear it.
    status, upd = request("POST", "/api/client-keys/update",
                          {"key": "sk-hop-rate-limited", "models": [], "rpm": 0})
    assert status == 200 and upd["rpm"] == 0, f"clearing rpm failed: {upd}"
    assert code(f"{BASE}/v1/models", "GET", token="sk-hop-rate-limited") == 200
    print("  ok clearing the rate limit restores unlimited access")
    request("POST", "/api/client-keys/delete", {"key": "sk-hop-rate-limited"})

    # 20. Combos: create / update / delete through the API (writes the TOML).
    status, _ = request("POST", "/api/combos/add",
                        {"name": "apitest", "chain": ["mock/test-model", "gemini/test-gemini"]})
    assert status == 200, f"combo add failed: {status}"
    status, combos = request("GET", "/api/combos")
    assert status == 200 and any(c["name"] == "apitest" for c in combos), combos
    # A combo is immediately addressable as a model.
    status, resp = request("POST", "/v1/chat/completions",
                           {"model": "apitest", "messages": [{"role": "user", "content": "hi"}]})
    assert status == 200, f"combo not usable: {status} {resp}"
    status, _ = request("POST", "/api/combos/update", {"name": "apitest", "chain": ["mock/test-model"]})
    assert status == 200
    status, combos = request("GET", "/api/combos")
    chain = next(c["chain"] for c in combos if c["name"] == "apitest")
    assert chain == ["mock/test-model"], chain
    # Bad input is rejected before anything is written.
    assert request("POST", "/api/combos/add", {"name": "x", "chain": ["noslash"]})[0] == 400
    assert request("POST", "/api/combos/add", {"name": "apitest", "chain": ["mock/test-model"]})[0] == 409
    assert request("POST", "/api/combos/add", {"name": "a/b", "chain": ["mock/test-model"]})[0] == 400
    assert request("POST", "/api/combos/delete", {"name": "apitest"})[0] == 200
    assert request("POST", "/api/combos/delete", {"name": "apitest"})[0] == 404
    print("  ok combos API (add/list/update/delete + validation)")

    # 20b. Per-model limits: view, override, and reset straight from the dashboard.
    #      They must reach /v1/models (in the ecosystem's spelling), survive a
    #      reload, and disappear from the file when the last field is cleared.
    status, _ = request("POST", "/api/models/limits",
                        {"model": "mock/test-model", "context_window": 131072,
                         "max_output_tokens": 8192})
    assert status == 200, status
    status, models = request("GET", "/api/models")
    row = next(m for m in models if m["id"] == "mock/test-model")
    assert row["limits"]["context_window"] == 131072, row
    assert row["overrides"]["context_window"] == 131072, row
    assert row["overrides"]["max_output_tokens"] == 8192, row
    # The operator's own numbers are reported as overrides, not as provider facts.
    assert row["sources"]["context_window"] == "override", row
    assert row["sources"]["max_input_tokens"] == "unknown", row
    status, cat = request("GET", "/v1/models")
    entry = next(m for m in cat["data"] if m["id"] == "mock/test-model")
    assert entry["context_length"] == 131072, entry
    assert entry["max_completion_tokens"] == 8192, entry
    # An inherited bare-name entry is materialised, not shared: editing
    # "mock/test-model" must not rewrite a limit set on "test-model".
    with open(os.environ.get("ANYHOP_TEST_CONFIG", "test/anyhop.test.toml")) as f:
        assert "[[model_limits]]" in f.read()
    # Out-of-range values are refused before the file is touched.
    assert request("POST", "/api/models/limits",
                   {"model": "mock/test-model", "context_window": 100,
                    "max_output_tokens": 500})[0] == 400
    # Reset one field, then the last one: the block leaves the file.
    assert request("POST", "/api/models/limits",
                   {"model": "mock/test-model", "max_output_tokens": None})[0] == 200
    status, _ = request("POST", "/api/models/limits",
                        {"model": "mock/test-model", "context_window": None})
    assert status == 200, status
    status, cat = request("GET", "/v1/models")
    entry = next(m for m in cat["data"] if m["id"] == "mock/test-model")
    assert "context_length" not in entry, entry
    with open(os.environ.get("ANYHOP_TEST_CONFIG", "test/anyhop.test.toml")) as f:
        assert "model_limits" not in f.read(), "reset left the block behind"
    print("  ok per-model limits (set/publish/reset, validated, file cleaned)")

    # 21. Provider settings: update is persisted and validated.
    status, providers = request("GET", "/api/providers")
    mock = next(p for p in providers if p["name"] == "mock")
    assert "max_concurrent" in mock and "oauth" in mock, mock
    status, _ = request("POST", "/api/providers/update",
                        {"name": "mock", "max_concurrent": 2, "drain_below_pct": 15})
    assert status == 200, status
    status, providers = request("GET", "/api/providers")
    mock = next(p for p in providers if p["name"] == "mock")
    assert mock["max_concurrent"] == 2 and mock["drain_below_pct"] == 15, mock
    assert request("POST", "/api/providers/update",
                   {"name": "mock", "strategy": "nonsense"})[0] == 400
    assert request("POST", "/api/providers/update", {"name": "ghost"})[0] == 404
    # Restore the original settings.
    assert request("POST", "/api/providers/update",
                   {"name": "mock", "max_concurrent": 0, "drain_below_pct": 0})[0] == 200
    print("  ok provider settings API (update + validation)")

    # 22. Provider + key lifecycle: create, add key, delete key, delete provider.
    status, created = request("POST", "/api/providers/add",
                              {"kind": "openai_compat", "name": "tmp-prov",
                               "base_url": "http://127.0.0.1:9100/v1", "key": "tmp-key-1"})
    assert status == 200, f"provider_add failed: {created}"
    status, providers = request("GET", "/api/providers")
    tmp = next(p for p in providers if p["name"] == "tmp-prov")
    assert len(tmp["keys"]) == 1, tmp
    status, _ = request("POST", "/api/keys/add", {"provider": "tmp-prov", "secret": "tmp-key-2"})
    assert status == 200
    status, providers = request("GET", "/api/providers")
    tmp = next(p for p in providers if p["name"] == "tmp-prov")
    assert len(tmp["keys"]) == 2, tmp
    # Deleting a key removes it from the live pool and from the config file.
    toml_before = open(os.environ.get("ANYHOP_TEST_CONFIG", "test/anyhop.test.toml")).read()
    victim = tmp["keys"][0]["id"]
    status, body = request("POST", "/api/keys/delete", {"provider": "tmp-prov", "id": victim})
    assert status == 200, f"key_delete failed: {status} {body}"
    status, providers = request("GET", "/api/providers")
    tmp = next(p for p in providers if p["name"] == "tmp-prov")
    assert len(tmp["keys"]) == 1 and all(k["id"] != victim for k in tmp["keys"]), tmp
    # Whichever secret went away must be gone from the file too (a reload would
    # otherwise bring it back).
    toml_after = open(os.environ.get("ANYHOP_TEST_CONFIG", "test/anyhop.test.toml")).read()
    assert toml_after != toml_before, "the config file was not rewritten"
    assert not (("tmp-key-1" in toml_after) and ("tmp-key-2" in toml_after)), "deleted key still in the TOML"
    # The last credential of a provider cannot be deleted (the provider would be
    # left unusable) — the API says so instead of writing a broken config.
    last = (next(p for p in providers if p["name"] == "tmp-prov"))["keys"][0]["id"]
    status, body = request("POST", "/api/keys/delete", {"provider": "tmp-prov", "id": last})
    assert status == 409, f"expected 409 for the last key, got {status}: {body}"
    assert request("POST", "/api/keys/delete", {"provider": "tmp-prov", "id": "deadbeef"})[0] == 404
    # Provider deletion is validated and removes the provider for good.
    status, _ = request("POST", "/api/providers/delete", {"name": "tmp-prov"})
    assert status == 200, f"provider_delete failed: {status}"
    status, providers = request("GET", "/api/providers")
    assert all(p["name"] != "tmp-prov" for p in providers)
    assert request("POST", "/api/providers/delete", {"name": "tmp-prov"})[0] == 404
    print("  ok provider + key lifecycle (create/add/delete/delete-provider)")

    # 23. [server] settings: readable, validated, and honest about restarts.
    status, srv = request("GET", "/api/server")
    assert status == 200, srv
    assert srv["api_key_set"] is True, "api_key_set must reflect the configured key"
    assert "listen" in srv and "max_retries" in srv
    assert "api_key" not in srv, "secrets must never be returned"
    assert request("POST", "/api/server/update", {"max_retries": 0})[0] == 400
    assert request("POST", "/api/server/update", {"attempt_timeout_secs": 0})[0] == 400
    assert request("POST", "/api/server/update", {"max_body_bytes": 10})[0] == 400
    assert request("POST", "/api/server/update", {"api_key": "short"})[0] == 400
    original_listen = srv["listen"]
    status, upd = request("POST", "/api/server/update",
                          {"max_retries": 3, "listen": "127.0.0.1:18099"})
    assert status == 200, upd
    assert "max_retries" in upd["changed"] and "max_retries" not in upd["restart_required"], upd
    assert "listen" in upd["restart_required"], f"listen must need a restart: {upd}"
    status, srv = request("GET", "/api/server")
    assert srv["max_retries"] == 3 and srv["listen"] == "127.0.0.1:18099", srv
    # Put the listen address back (the running listener is not affected either way).
    assert request("POST", "/api/server/update", {"listen": original_listen})[0] == 200
    # A wrong listen value is rejected too (must look like host:port).
    assert request("POST", "/api/server/update", {"listen": "nonsense"})[0] == 400
    assert request("POST", "/api/server/update", {"max_retries": 4})[0] == 200
    # Re-submitting the same values (what the form does) must report no changes,
    # otherwise the dashboard would demand a restart after every save.
    # Use whatever listen the gateway actually runs with (the suite port is
    # configurable), otherwise this "no-op" save is a real change.
    status, cur = request("GET", "/api/server")
    status, again = request("POST", "/api/server/update",
                            {"max_retries": 4, "listen": cur["listen"]})
    assert status == 200 and again["changed"] == [], again
    assert again["restart_required"] == [], again
    print("  ok [server] settings API (read/validate/restart_required, no-op save)")

    # 24. [tuning]: every previously hardcoded knob is readable and editable.
    status, srv = request("GET", "/api/server")
    assert status == 200 and "tuning" in srv, srv
    tuning = srv["tuning"]
    for key in ("max_cooldown_secs", "base_backoff_secs", "models_cache_ttl_secs",
                "sticky_ttl_secs", "event_channel_capacity", "ui_refresh_secs"):
        assert key in tuning, f"missing tuning.{key}"
    original_cooldown = tuning["max_cooldown_secs"]
    status, upd = request("POST", "/api/server/update", {"tuning": {"max_cooldown_secs": 1234}})
    assert status == 200 and "max_cooldown_secs" in upd["changed"], upd
    status, srv = request("GET", "/api/server")
    assert srv["tuning"]["max_cooldown_secs"] == 1234, srv["tuning"]
    # Out-of-range values must be refused, not clamped silently.
    assert request("POST", "/api/server/update", {"tuning": {"max_cooldown_secs": 0}})[0] == 400
    assert request("POST", "/api/server/update", {"tuning": {"base_backoff_secs": 10_000}})[0] == 400
    assert request("POST", "/api/server/update", {"tuning": {"session_prefix_bytes": 4}})[0] == 400
    # No-op resubmission is still a no-op.
    status, again = request("POST", "/api/server/update", {"tuning": {"max_cooldown_secs": 1234}})
    assert again["changed"] == [], again
    request("POST", "/api/server/update", {"tuning": {"max_cooldown_secs": original_cooldown}})
    print("  ok [tuning] readable, editable, validated")

    # 25. Per-provider attempt budget (overrides the global one).
    status, provs = request("GET", "/api/providers")
    target = provs[0]["name"]
    assert "timeout_secs" in provs[0] and "max_retries" in provs[0], provs[0]
    status, _ = request("POST", "/api/providers/update",
                        {"name": target, "timeout_secs": 90, "max_retries": 2})
    assert status == 200, status
    status, provs = request("GET", "/api/providers")
    mine = [p for p in provs if p["name"] == target][0]
    assert mine["timeout_secs"] == 90 and mine["max_retries"] == 2, mine
    assert request("POST", "/api/providers/update",
                   {"name": target, "timeout_secs": 0})[0] == 400
    assert request("POST", "/api/providers/update",
                   {"name": target, "max_retries": 99})[0] == 400
    print("  ok per-provider timeout/max_retries")

    # 26. Requests are attributed to the client key that made them.
    status, created = request("POST", "/api/client-keys/add",
                              {"name": "attrib-key", "key": "sk-hop-attrib", "models": []})
    assert status == 200, created
    status, _ = request("POST", "/v1/chat/completions",
                        {"model": "mock/test-model",
                         "messages": [{"role": "user", "content": "hi"}]},
                        token="sk-hop-attrib")
    assert status == 200, status
    status, reqs = request("GET", "/api/requests")
    attributed = [r for r in reqs if r.get("client_key") == "attrib-key"]
    assert attributed, f"no request attributed to attrib-key: {reqs[:2]}"
    request("POST", "/api/client-keys/delete", {"key": "sk-hop-attrib"})
    print("  ok requests carry the client key name")

    # 27. Input bounds: a 70 KB "name" must not reach the config file.
    big = "x" * 70_000
    with open(os.environ.get("ANYHOP_TEST_CONFIG", "test/anyhop.test.toml")) as f:
        before_size = len(f.read())
    assert request("POST", "/api/client-keys/add",
                   {"name": big, "key": "sk-hop-big", "models": []})[0] == 400
    assert request("POST", "/api/client-keys/add",
                   {"name": "bad name/with slash", "key": "sk-hop-bad", "models": []})[0] == 400
    assert request("POST", "/api/providers/add",
                   {"name": big, "kind": "openai_compat", "base_url": "http://x/v1", "key": "k"})[0] == 400
    assert request("POST", "/api/providers/add",
                   {"name": "no-scheme", "kind": "openai_compat", "base_url": "example.com/v1", "key": "k"})[0] == 400
    assert request("POST", "/api/keys/add", {"provider": "mock", "secret": "k" * 9000})[0] == 400
    with open(os.environ.get("ANYHOP_TEST_CONFIG", "test/anyhop.test.toml")) as f:
        assert len(f.read()) <= before_size + 2048, "config grew from a rejected request"
    print("  ok input bounds (names, urls, secrets)")

    # 28. OAuth flows target a *named* provider, so a second provider of the same
    #     type can have its own account pool.
    status, st = request("POST", "/api/auth/start",
                         {"kind": "antigravity", "provider": "ag-second"})
    assert status == 200 and "url" in st, st
    status, cur = request("GET", "/api/auth/status")
    assert cur["kind"] == "antigravity" and cur.get("provider") == "ag-second", cur
    request("POST", "/api/auth/cancel")
    # a name that belongs to another type must be refused, not silently reused
    status, err = request("POST", "/api/auth/start",
                          {"kind": "antigravity", "provider": "mock"})
    assert status == 409, err
    status, err = request("POST", "/api/auth/start",
                          {"kind": "codex", "provider": "bad name/x"})
    assert status == 400, err
    request("POST", "/api/auth/cancel")
    print("  ok OAuth targets a named provider (collision/validation guarded)")

    # 29. Public OAuth callback: with [server] public_url the flow redirects to
    #     this gateway, and the unauthenticated callback validates the state.
    status, upd = request("POST", "/api/server/update", {"public_url": "https://gw.example.com"})
    assert status == 200 and "public_url" in upd["changed"], upd
    status, started = request("POST", "/api/auth/start",
                              {"kind": "antigravity", "provider": "ag-public"})
    assert status == 200, started
    assert started["mode"] == "public", started
    import urllib.parse as up
    q = up.parse_qs(up.urlparse(started["url"]).query)
    assert q["redirect_uri"][0] == "https://gw.example.com/api/auth/callback", q
    token = started["state"]
    # The browser callback carries no admin key — it must still be accepted,
    # and a wrong `state` must be rejected with 400.
    bad = urllib.request.Request(
        f"{BASE}/api/auth/callback?code=x&state=wrong-state", method="GET")
    try:
        urllib.request.urlopen(bad, timeout=10)
        fail_state = None
    except urllib.error.HTTPError as e:
        fail_state = e.code
    assert fail_state == 400, "callback accepted a foreign state"
    # A pasted URL with the right state is delivered to the waiting flow.
    status, ok = request("POST", "/api/auth/complete",
                         {"url": f"http://localhost:51121/oauth-callback?code=fake&state={token}"})
    assert status == 200 and ok.get("ok") is True, ok
    request("POST", "/api/auth/cancel")
    request("POST", "/api/server/update", {"public_url": ""})
    print("  ok public OAuth callback (state-checked, no admin key needed)")

    print("\nALL CLIENT KEYS AND MODELS TESTS PASSED!")


if __name__ == "__main__":
    main()
