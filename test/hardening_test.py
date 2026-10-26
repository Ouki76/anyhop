#!/usr/bin/env python3
"""
Hardening checks that need their own gateway instance.

The main suite runs against a shared instance, but these deliberately trip
protective limits (auth lockout, per-key concurrency) or change transport (TLS),
so they must not poison the shared state.

Each check starts a throwaway gateway with a temp config, exercises the feature
and tears it down. Mocks from run_all.sh are already listening on their ports.
"""
import base64
import json
import os
import struct
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.environ.get("ANYHOP_BIN", os.path.join(ROOT, "target/release/anyhop"))
MOCK_URL = "http://127.0.0.1:9100/v1"
KEY = "hardening-gw-key"

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  ok   {msg}")


def fail(msg):
    global FAIL
    FAIL += 1
    print(f"  FAIL {msg}")


def redis_available():
    try:
        with socket.create_connection(("127.0.0.1", REDIS_PORT), timeout=1) as s:
            s.sendall(b"PING\r\n")
            return b"PONG" in s.recv(64)
    except OSError:
        return False


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def write_config(path, port, extra_server=""):
    with open(path, "w") as f:
        f.write(
            f"""[server]
listen = "127.0.0.1:{port}"
api_key = "{KEY}"
# /api/* accepts only admin_key: the gateway key is handed to every client, so
# it must not be able to read provider secrets (middleware::require_admin_key).
admin_key = "{KEY}"
state_file = ""
{extra_server}
[[providers]]
name = "mock"
type = "openai_compat"
base_url = "{MOCK_URL}"
strategy = "round_robin"
keys = ["hardening-key-1"]
models = ["test-model"]
"""
        )


class Gateway:
    def __init__(self, config, port):
        self.port = port
        self.proc = subprocess.Popen(
            [BIN], env={**os.environ, "ANYHOP_CONFIG": config}, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def wait(self, timeout=15):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return True
            except OSError:
                time.sleep(0.1)
        return False

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def request(port, path, data=None, token=KEY, method=None, timeout=10, binary=False):
    url = f"http://127.0.0.1:{port}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method or ("GET" if data is None else "POST"))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (raw if binary else raw.decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, (raw if binary else raw.decode("utf-8", "replace"))


def check_auth_lockout():
    """Repeated bad keys must be throttled, not compared forever."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    write_config(cfg.name, port, "auth_fail_burst = 3\nauth_fail_window_secs = 30")
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("auth lockout: gateway did not start")
            return
        codes = []
        for _ in range(5):
            status, _ = request(port, "/api/providers", token="wrong-key")
            codes.append(status)
        if codes[0] != 401:
            fail(f"auth lockout: first bad key should be 401, got {codes[0]}")
            return
        if 429 not in codes:
            fail(f"auth lockout: never throttled, codes={codes}")
            return
        # A *valid* key must still work while the window lasts. The lockout is a
        # response to a failed credential, never a pre-filter: behind a reverse
        # proxy every client shares one address, so a pre-filter would let anyone
        # lock every legitimate caller out with ten bad keys.
        status, _ = request(port, "/api/providers")
        if status != 200:
            fail(f"auth lockout: a valid key was blocked during the window ({status})")
            return
        ok(f"auth lockout (401 → 429 after 3 failures; codes={codes[:3]}…; valid key still 200)")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def check_per_key_concurrency():
    """A client key's in-flight cap must return 429 rather than queue."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    write_config(cfg.name, port, "")
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("concurrency: gateway did not start")
            return
        status, body = request(
            port,
            "/api/client-keys/add",
            {"name": "cap", "key": "sk-hop-cap-key", "models": [], "max_concurrent": 1},
        )
        if status != 200:
            fail(f"concurrency: cannot create the key ({status}: {body[:80]})")
            return
        # Hold one request open by pointing it at a mock that streams slowly is
        # overkill: fire two concurrently and require at least one 429.
        import threading

        results = []

        def hit():
            results.append(request(port, "/v1/chat/completions",
                                   {"model": "mock/test-model",
                                    "messages": [{"role": "user", "content": "hi"}]},
                                   token="sk-hop-cap-key"))

        threads = [threading.Thread(target=hit) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        codes = sorted({status for status, _ in results})
        if 429 not in codes:
            fail(f"concurrency: cap never hit, codes={codes}")
            return
        if 200 not in codes:
            fail(f"concurrency: nothing succeeded, codes={codes}")
            return
        ok(f"per-key concurrency cap (codes={codes})")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def check_tls():
    """The gateway must speak HTTPS itself when cert/key are configured."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    # A private key is not committed (see scripts/gen-test-certs.sh): make sure the
    # throwaway pair exists before starting the TLS instance.
    cert = os.path.join(ROOT, "test/certs/localhost.crt")
    key = os.path.join(ROOT, "test/certs/localhost.key")
    if not (os.path.exists(cert) and os.path.exists(key)):
        subprocess.run(["sh", os.path.join(ROOT, "scripts/gen-test-certs.sh")],
                       cwd=ROOT, check=False, capture_output=True)
    write_config(cfg.name, port, f'tls_cert = "{cert}"\ntls_key = "{key}"')
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("tls: gateway did not start")
            return
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with ctx.wrap_socket(raw) as tls:
                    tls.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    data = tls.recv(4096)
            text = data.decode("latin-1", "replace")
        except Exception as e:  # noqa: BLE001 - any failure is a failed check
            fail(f"tls: handshake failed: {e}")
            return
        if "200 OK" not in text:
            fail(f"tls: unexpected response: {text.splitlines()[:1]}")
            return
        ok("TLS in-process (handshake + /healthz over https)")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def responses_stream(port, model="mock/test-model"):
    """POST /v1/responses with stream:true and return the parsed event list."""
    url = f"http://127.0.0.1:{port}/v1/responses"
    body = json.dumps({"model": model, "input": "hi", "stream": True}).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {KEY}"})
    events = []
    with urllib.request.urlopen(req, timeout=15) as r:
        if r.status != 200:
            raise RuntimeError(f"status {r.status}")
        for raw in r:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            if payload:
                events.append(json.loads(payload))
    return events


def check_observability():
    """Histograms, the new endpoints and the response store on one instance."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    # The response store lives in the redb state file, so this instance needs one.
    state_dir = tempfile.mkdtemp()
    state = os.path.join(state_dir, "state.redb")
    write_config(cfg.name, port, "")
    raw = open(cfg.name).read().replace('state_file = ""', f'state_file = "{state}"')
    open(cfg.name, "w").write(raw)
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("observability: gateway did not start")
            return
        status, body = request(port, "/v1/responses",
                               {"model": "mock/test-model", "input": "hi"})
        if status != 200:
            fail(f"/v1/responses returned {status}: {body[:100]}")
        elif json.loads(body).get("object") != "response":
            fail(f"/v1/responses shape: {body[:100]}")
        else:
            ok("/v1/responses returns a Response object")

        # A tool turn that continues through previous_response_id: the stored turn
        # must replay the assistant's function_call, or the follow-up answers a call
        # the model can never see and the upstream rejects the whole conversation.
        tools = [{"type": "function", "name": "lookup",
                  "parameters": {"type": "object", "properties": {"q": {"type": "string"}}}}]
        status, body = request(port, "/v1/responses", {
            "model": "mock/test-model",
            "input": "find it",
            "tools": tools,
            "store": True,
        })
        call = None
        rid = None
        if status == 200:
            parsed = json.loads(body)
            rid = parsed.get("id")
            calls = [i for i in parsed.get("output", []) if i.get("type") == "function_call"]
            call = calls[0] if calls else None
        if not call:
            fail(f"tool turn: no function_call item ({status}): {body[:160]}")
        else:
            ok("/v1/responses returns a function_call item")
            status, body = request(port, "/v1/responses", {
                "model": "mock/test-model",
                "input": [{"type": "function_call_output",
                           "call_id": call["call_id"], "output": "100"}],
                "previous_response_id": rid,
            })
            if status != 200:
                fail(f"tool follow-up on previous_response_id: {status}: {body[:160]}")
            else:
                kind = json.loads(body).get("object")
                ok(f"tool follow-up replays the call (previous_response_id, {kind})")

        status, body = request(port, "/v1/models/mock/test-model")
        if status != 200 or json.loads(body).get("id") != "mock/test-model":
            fail(f"/v1/models/{{id}} returned {status}: {body[:100]}")
        else:
            ok("/v1/models/{id} resolves a single model")

        # Response store: a second turn must replay through previous_response_id.
        status, first = request(port, "/v1/responses", {"model": "mock/test-model", "input": "first turn"})
        rid = json.loads(first).get("id") if status == 200 else None
        if not rid:
            fail(f"response store: first turn failed ({status})")
        else:
            status, second = request(
                port, "/v1/responses",
                {"model": "mock/test-model", "input": "second turn", "previous_response_id": rid},
            )
            if status != 200:
                fail(f"previous_response_id rejected: {status} {second[:120]}")
            elif json.loads(second).get("previous_response_id") != rid:
                fail("previous_response_id was not echoed back")
            else:
                ok("previous_response_id replays a stored conversation")
            status, _ = request(
                port, "/v1/responses",
                {"model": "mock/test-model", "input": "x", "previous_response_id": "resp_doesnotexist"},
            )
            if status != 400:
                fail(f"unknown previous_response_id should be 400, got {status}")
            else:
                ok("unknown previous_response_id is a 400")

        # Streaming /v1/responses: the event sequence and the streamed usage were
        # never exercised over HTTP (only the mapper's unit tests).
        try:
            events = responses_stream(port)
        except Exception as e:  # noqa: BLE001
            fail(f"/v1/responses stream: {e}")
            events = []
        if events:
            names = [e.get("type") for e in events]
            text = "".join(
                e.get("delta", "") for e in events
                if e.get("type") == "response.output_text.delta"
            )
            seqs = [e.get("sequence_number") for e in events]
            final = next((e for e in events if e.get("type") == "response.completed"), None)
            usage = ((final or {}).get("response") or {}).get("usage") or {}
            if names[0] != "response.created":
                fail(f"responses stream starts with {names[:3]}")
            elif "response.output_item.added" not in names:
                fail(f"no output_item.added in {names}")
            elif "ok via" not in text:
                fail(f"streamed text was {text!r}")
            elif names[-1] != "response.completed" or final is None:
                fail(f"responses stream ends with {names[-1]}")
            elif seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
                fail(f"sequence_number is not strictly increasing: {seqs}")
            elif usage.get("input_tokens") != 7 or usage.get("output_tokens") != 3:
                fail(f"streamed usage is {usage} (include_usage not plumbed?)")
            else:
                ok(f"/v1/responses streams {len(events)} events with usage "
                   f"{usage.get('input_tokens')}/{usage.get('output_tokens')}")

        status, body = request(port, "/metrics")
        if status != 200:
            fail(f"/metrics returned {status}")
        elif "anyhop_http_request_duration_seconds_bucket" not in body:
            fail("no latency histograms in /metrics")
        else:
            ok("Prometheus latency histograms exposed")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def check_media_and_realtime():
    """Images/audio pass-through and the WebSocket realtime proxy, end to end."""
    port = free_port()
    cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
    with open(cfg.name, "w") as f:
        f.write(
            f"""[server]
listen = "127.0.0.1:{port}"
api_key = "{KEY}"
state_file = ""

[[providers]]
name = "media"
type = "openai_compat"
base_url = "http://127.0.0.1:9105/v1"
strategy = "round_robin"
keys = ["media-key-1"]
models = ["test-model", "tts-1", "whisper-1", "gpt-image-1"]
capabilities = ["images", "audio", "realtime"]

[[providers]]
name = "plain"
type = "openai_compat"
base_url = "http://127.0.0.1:9105/v1"
strategy = "round_robin"
keys = ["plain-key-1"]
models = ["test-model"]
"""
        )
    gw = Gateway(cfg.name, port)
    try:
        if not gw.wait():
            fail("media: gateway did not start")
            return

        status, body = request(port, "/v1/images/generations",
                               {"model": "media/gpt-image-1", "prompt": "a cat"})
        data = json.loads(body) if status == 200 else {}
        if status != 200 or not data.get("data", [{}])[0].get("b64_json"):
            fail(f"/v1/images/generations returned {status}: {body[:100]}")
        else:
            ok("/v1/images/generations relays an image payload")

        # Multipart must be forwarded byte-for-byte (boundary intact).
        boundary = "----anyhopTestBoundary"
        mp = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n"
            f"media/gpt-image-1\r\n--{boundary}\r\nContent-Disposition: form-data; "
            f"name=\"image\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n"
            f"BINARYDATA\r\n--{boundary}--\r\n"
        ).encode()
        url = f"http://127.0.0.1:{port}/v1/images/edits"
        req = urllib.request.Request(
            url, data=mp,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                     "Authorization": f"Bearer {KEY}"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                echo = json.loads(r.read().decode())
            if boundary not in echo.get("echo_content_type", ""):
                fail(f"multipart boundary lost: {echo.get('echo_content_type')}")
            else:
                ok("/v1/images/edits forwards multipart untouched")
        except urllib.error.HTTPError as e:
            fail(f"/v1/images/edits returned {e.code}")

        status, audio = request(
            port, "/v1/audio/speech",
            {"model": "media/tts-1", "input": "hi", "voice": "alloy"}, binary=True,
        )
        if status != 200:
            fail(f"/v1/audio/speech returned {status}")
        elif not isinstance(audio, bytes) or len(audio) < 10:
            fail("/v1/audio/speech returned no audio")
        else:
            ok(f"/v1/audio/speech relays {len(audio)} bytes of audio")

        # Multipart audio uploads: boundary and body must survive the relay. These
        # two routes had no end-to-end coverage at all.
        for route, label in (("/v1/audio/transcriptions", "transcriptions"),
                             ("/v1/audio/translations", "translations")):
            mp = (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n"
                f"media/whisper-1\r\n--{boundary}\r\nContent-Disposition: form-data; "
                f"name=\"file\"; filename=\"a.wav\"\r\nContent-Type: audio/wav\r\n\r\n"
                f"RIFFDATA\r\n--{boundary}--\r\n"
            ).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}{route}", data=mp,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}",
                         "Authorization": f"Bearer {KEY}"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    body = json.loads(r.read().decode())
                if body.get("text") != "hello":
                    fail(f"/v1/audio/{label} answered {body}")
                elif boundary not in body.get("echo_content_type", ""):
                    fail(f"/v1/audio/{label} lost the multipart boundary: "
                         f"{body.get('echo_content_type')}")
                else:
                    ok(f"/v1/audio/{label} relays a multipart upload untouched")
            except urllib.error.HTTPError as e:
                fail(f"/v1/audio/{label} returned {e.code}: {e.read()[:120]}")

        # Capability gating: a provider that does not declare `images` must refuse
        # the request instead of mis-routing it to a chat-only endpoint.
        status, body = request(port, "/v1/images/generations",
                               {"model": "plain/test-model", "prompt": "x"})
        if status == 400 and "capability" in body:
            ok("/v1/images/generations refuses a provider without the capability")
        else:
            fail(f"capability gating returned {status}: {body[:120]}")

        # WebSocket realtime through the gateway.
        try:
            reply = ws_roundtrip(port, "/v1/realtime?model=media/test-model")
            if reply.get("type") == "session.created" and reply.get("key") == "media-key-1":
                ok("/v1/realtime upgrades, forwards to the provider and streams back")
            else:
                fail(f"realtime: unexpected first frame {reply}")
        except Exception as e:  # noqa: BLE001
            fail(f"realtime: {e}")
    finally:
        gw.stop()
        os.unlink(cfg.name)


def ws_roundtrip(port, path):
    """Minimal WS client: handshake, send one text frame, read one back."""
    key = base64.b64encode(os.urandom(16)).decode()
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    req = (
        f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        f"Authorization: Bearer {KEY}\r\n\r\n"
    )
    sock.sendall(req.encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed during handshake")
        head += chunk
    if b"101" not in head.split(b"\r\n")[0]:
        raise RuntimeError(f"no upgrade: {head.split(chr(13).encode())[0]}")
    frame = read_ws_frame(sock)
    sock.close()
    return json.loads(frame.decode())


def read_ws_frame(sock):
    header = sock.recv(2)
    if len(header) < 2:
        raise RuntimeError("no frame")
    opcode = header[0] & 0x0F
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack(">H", sock.recv(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", sock.recv(8))[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    if opcode == 8:
        raise RuntimeError("server closed the connection")
    return data


REDIS_PORT = 6399


def check_multi_instance():
    """Two gateway processes must share one rate-limit budget through Redis."""
    # Fresh key per run: the Redis bucket outlives this process.
    key = f"sk-hop-shared-{os.urandom(4).hex()}"
    port_a, port_b = free_port(), free_port()
    cfgs = []
    gws = []
    try:
        for port in (port_a, port_b):
            cfg = tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False)
            write_config(cfg.name, port, "")
            raw = open(cfg.name).read()
            # Client keys live in the config file, so instances that must share
            # one key declare it there (the deployment model: same file content,
            # per-instance listen). The limit itself is shared through Redis.
            raw += (
                f'\n[ratelimit]\nbackend = "redis"\n'
                f'redis_url = "redis://127.0.0.1:{REDIS_PORT}/0"\nfail_open = false\n'
                f'\n[[client_keys]]\nkey = "{key}"\nname = "shared"\n'
                'rpm = 3\nburst = 3\n'
            )
            open(cfg.name, "w").write(raw)
            cfgs.append(cfg.name)
            gw = Gateway(cfg.name, port)
            gws.append(gw)
            if not gw.wait():
                fail("multi-instance: a gateway did not start")
                return
        # The key is declared in both configs with rpm=3; requests alternate
        # between the two processes and must share that budget.
        codes = []
        for i in range(6):
            port = port_a if i % 2 == 0 else port_b
            status, _ = request(
                port, "/v1/chat/completions",
                {"model": "mock/test-model", "messages": [{"role": "user", "content": "hi"}]},
                token=key,
            )
            codes.append(status)
        allowed = codes.count(200)
        if allowed != 3 or 429 not in codes:
            fail(f"multi-instance: budget not shared, codes={codes}")
        else:
            ok(f"two instances share one Redis budget (codes={codes})")
    finally:
        for gw in gws:
            gw.stop()
        for c in cfgs:
            os.unlink(c)


def main():
    print("== hardening (own gateway instances) ==")
    check_tls()
    check_auth_lockout()
    check_per_key_concurrency()
    check_observability()
    check_media_and_realtime()
    if redis_available():
        check_multi_instance()
    else:
        print("  skip multi-instance (fake redis not running on 6399)")
    print(f"HARDENING PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())