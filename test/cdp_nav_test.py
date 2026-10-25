#!/usr/bin/env python3
"""CDP-driven functional test of the dashboard.

The old version clicked `.tab` / `.provider-tile` / `.provider-grid` selectors that
the Sycamore rewrite never emitted, so every click was a silent no-op and the only
assertion left ("no console errors") passed even when the UI rendered nothing. It
also never set the admin key, so with `api_key` configured in the test config every
`/api/*` call returned 401 and all lists were empty.

This version:
  * injects the admin key into localStorage (as the login modal does),
  * asserts each tab actually renders its page title,
  * asserts the Providers tab lists the configured providers,
  * asserts the Events tab receives SSE events (regression: EventSource needs ?key=),
  * fails on any console error / uncaught exception.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

import websocket

PORT = os.environ.get("ANYHOP_TEST_PORT", "18080")
BASE = f"http://127.0.0.1:{PORT}"
ADMIN_KEY = "test-gw-key"

# Per-run profile and DevTools port: two suite runs (or an agent's probe) used to
# share /tmp/anyhop-cdp-profile + port 9222, so the second chromium attached to a
# dead instance and the stage failed with "connection to remote host was lost".
_CDP_PORT = None


def _free_port():
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


CDP_PORT = _free_port()
CDP_PROFILE = f"/tmp/anyhop-cdp-profile-{os.getpid()}-{CDP_PORT}"

CHROME = ["chromium-browser", "--headless=new", "--no-sandbox", "--disable-gpu",
          # explicit profile dir: sandboxed environments can't create the default one
          f"--user-data-dir={CDP_PROFILE}",
          f"--remote-debugging-port={CDP_PORT}", "--remote-allow-origins=*", "about:blank"]

# Nav label (as rendered) -> page title (as rendered by the tab component).
TABS = {
    "OVERVIEW": "Overview",
    "PROVIDERS": "Providers",
    "MODELS": "Models",
    "API KEYS": "API Keys",
    "QUOTAS": "Quotas",
    "EVENTS": "Events",
    "REQUESTS": "Requests",
    "SETTINGS": "Settings",
    "CONFIG": "Config",
}


def api(method, path, payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=body, method=method)
    req.add_header("Authorization", f"Bearer {ADMIN_KEY}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def fail(msg):
    print(f"\n!!! FAIL: {msg}")
    sys.exit(1)


def main():
    # Seed one event so the Events tab has something to show over SSE. Creating a
    # client key emits an "auth" event on the bus (see api/client_keys.rs).
    api("POST", "/api/client-keys/delete", {"key": "sk-hop-cdp-test"})
    status, _ = api("POST", "/api/client-keys/add",
                    {"name": "cdp-test", "key": "sk-hop-cdp-test", "models": []})
    if status != 200:
        fail(f"could not seed an event via the API (status {status})")

    proc = subprocess.Popen(CHROME, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    try:
        tabs = [t for t in json.load(urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json"))
                if t.get("type") == "page"]
        ws = websocket.create_connection(tabs[0]["webSocketDebuggerUrl"], timeout=15)
        mid = 0

        def send(method, params=None):
            nonlocal mid
            mid += 1
            ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
            while True:
                msg = json.loads(ws.recv())
                if msg.get("id") == mid:
                    return msg.get("result", {})

        def js(expr):
            r = send("Runtime.evaluate", {"expression": expr, "returnByValue": True,
                                          "awaitPromise": True})
            return r.get("result", {}).get("value")

        send("Page.enable")
        send("Runtime.enable")
        send("Log.enable")

        errors = []

        def collect():
            """Drain queued console events; unbuffered errors abort the test."""
            ws.settimeout(0.3)
            try:
                while True:
                    msg = json.loads(ws.recv())
                    if (msg.get("method") == "Runtime.consoleAPICalled"
                            and msg["params"]["type"] == "error"):
                        txt = " ".join(str(a.get("value", a.get("description", "")))[:400]
                                       for a in msg["params"]["args"])
                        errors.append("CONSOLE-ERR: " + txt)
                    if msg.get("method") == "Runtime.exceptionThrown":
                        d = msg["params"]["exceptionDetails"]
                        errors.append(str(d.get("exception", {}).get("description", d.get("text", "?")))[:500])
            except Exception:
                pass
            ws.settimeout(15)

        # 1. Load the dashboard, then inject the admin key the way the modal does and
        #    reload — this is what creates the "authenticated" state a real user has.
        send("Page.navigate", {"url": f"{BASE}/dashboard"})
        time.sleep(3)
        js(f"localStorage.setItem('anyhop_admin_key', '{ADMIN_KEY}'), 'ok'")
        send("Page.reload")
        time.sleep(4)
        collect()

        if not js("!!document.querySelector('.side-nav')"):
            fail("dashboard shell did not render (.side-nav missing)")

        nav_count = js("document.querySelectorAll('.side-nav .nav-item').length")
        print(f"nav items: {nav_count}")
        if nav_count != len(TABS):
            fail(f"expected {len(TABS)} nav items, found {nav_count}")

        # 2. Every tab must render its own page title.
        for label, title in TABS.items():
            clicked = js(f"""
              [...document.querySelectorAll('.side-nav .nav-item')]
                .find(t => t.textContent.trim().toUpperCase() === {json.dumps(label)})
                ?.click(), 'clicked'
            """)
            if clicked != "clicked":
                fail(f"nav item '{label}' not found")
            time.sleep(1.2)
            got = js("document.querySelector('.page-title')?.textContent?.trim()")
            collect()
            if got != title:
                fail(f"tab '{label}': expected page title {title!r}, got {got!r}")
            print(f"  ok {label:9s} -> {got}")

        # 3. Providers tab must list the providers from the config (proves /api/providers
        #    authenticated and the Rust DTOs deserialise).
        status, body = api("GET", "/api/providers")
        if status != 200:
            fail(f"GET /api/providers returned {status}")
        expected = len(json.loads(body))
        js("""
          [...document.querySelectorAll('.side-nav .nav-item')]
            .find(t => t.textContent.trim().toUpperCase() === 'PROVIDERS')?.click(), 'ok'
        """)
        time.sleep(1.5)
        # Configured providers + the "Available" list, which now always offers every
        # known type (a second provider of an existing kind is legitimate).
        rows = js("""
          (() => {
            const sections = [...document.querySelectorAll('.section-title')];
            const configured = sections.find(s => /Configured/i.test(s.textContent));
            let n = 0;
            for (let el = configured?.nextElementSibling; el; el = el.nextElementSibling) {
              if (el.classList.contains('section-title')) break;
              n += el.querySelectorAll('.prov-row').length;
            }
            return n;
          })()
        """)
        available = js("""
          (() => {
            const sections = [...document.querySelectorAll('.section-title')];
            const avail = sections.find(s => /Available/i.test(s.textContent));
            return avail ? avail.nextElementSibling.querySelectorAll('.prov-row').length : 0;
          })()
        """)
        collect()
        if rows != expected:
            fail(f"configured list shows {rows} rows, API reports {expected}")
        if available == 0:
            fail("no available provider types listed — 'add provider' is unreachable")
        print(f"  ok providers list ({rows} configured rows, {available} available types)")
        if rows == 0:
            fail("no providers rendered — the dashboard is not authenticated")

        # 3b. Per-model limits: the row shows what is set, the panel edits it and
        #     the per-field Reset button actually clears the override.
        status, body = api("GET", "/api/models")
        if status != 200 or not json.loads(body):
            fail(f"GET /api/models returned {status}")
        first = next(m for m in json.loads(body) if m["provider"] != "combo")
        model_id = first["id"]
        api("POST", "/api/models/limits",
            {"model": model_id, "context_window": 65536, "max_output_tokens": 4096})
        js("""
          [...document.querySelectorAll('.side-nav .nav-item')]
            .find(t => t.textContent.trim().toUpperCase() === 'MODELS')?.click(), 'ok'
        """)
        time.sleep(1.5)
        chip = js("""
          (() => {
            const row = [...document.querySelectorAll('.model-row')]
              .find(r => r.querySelector('.model-row-id')?.textContent.trim() === %s);
            return row?.querySelector('.chip-btn')?.textContent.trim() || '';
          })()
        """ % json.dumps(model_id))
        collect()
        if "ctx" not in chip or "65.5k" not in chip:
            fail(f"model row does not show the limits ({chip!r} for {model_id})")
        print(f"  ok models row shows limits ({chip})")

        opened = js("""
          (() => {
            const row = [...document.querySelectorAll('.model-row')]
              .find(r => r.querySelector('.model-row-id')?.textContent.trim() === %s);
            // The row's ghost buttons only appear on hover; the limits chip is the
            // always-visible way in (and the one an operator will find).
            const chip = row.querySelector('.chip-btn');
            const btn = [...row.querySelectorAll('button')].find(b => b.textContent.trim() === 'Limits');
            const target = chip || btn;
            if (!target) return 'missing';
            target.click();
            return 'clicked';
          })()
        """ % json.dumps(model_id))
        time.sleep(1.0)
        panel = js("""
          (() => {
            const card = document.querySelector('.model-limits');
            if (!card) return {error: 'no panel'};
            return {
              inputs: card.querySelectorAll('input[type=number]').length,
              resets: [...card.querySelectorAll('button')].filter(b => b.textContent.trim() === 'Reset').length,
              ctx: card.querySelector('input[type=number]')?.value,
            };
          })()
        """)
        collect()
        if opened != "clicked" or not isinstance(panel, dict) or panel.get("error"):
            fail(f"limits panel did not open: {opened} {panel}")
        if panel["inputs"] != 3 or panel["resets"] < 1 or panel["ctx"] != "65536":
            fail(f"limits panel is wrong: {panel}")
        print(f"  ok limits panel (3 fields, {panel['resets']} reset button(s))")

        # Reset the context window: the override disappears, the input empties, and
        # the row chip drops the value.
        js("""
          (() => {
            const card = document.querySelector('.model-limits');
            const btn = [...card.querySelectorAll('button')].find(b => b.textContent.trim() === 'Reset');
            btn?.click();
            return 'ok';
          })()
        """)
        time.sleep(2.0)
        after = js("""
          (() => {
            const card = document.querySelector('.model-limits');
            const row = [...document.querySelectorAll('.model-row')]
              .find(r => r.querySelector('.model-row-id')?.textContent.trim() === %s);
            return {
              ctx: card?.querySelector('input[type=number]')?.value ?? 'gone',
              chip: row?.querySelector('.chip-btn')?.textContent.trim() || '',
            };
          })()
        """ % json.dumps(model_id))
        collect()
        if isinstance(after, dict) and after.get("ctx") == "65536":
            fail(f"reset did not clear the override: {after}")
        print(f"  ok limits reset ({after})")
        api("POST", "/api/models/limits",
            {"model": model_id, "context_window": None, "max_output_tokens": None})

        # 4. Events tab must receive SSE events. Regression guard: EventSource cannot
        #    set headers, so without ?key= the stream is 401 and the list stays empty.
        api("POST", "/api/client-keys/add",
            {"name": "cdp-test-2", "key": "sk-hop-cdp-test-2", "models": []})
        js("""
          [...document.querySelectorAll('.side-nav .nav-item')]
            .find(t => t.textContent.trim().toUpperCase() === 'EVENTS')?.click(), 'ok'
        """)
        time.sleep(2.5)
        evs = js("document.querySelectorAll('.ev').length")
        collect()
        if not evs:
            fail("events tab is empty — SSE stream not authorised (missing ?key=) or not relaying")
        print(f"  ok events tab received {evs} event(s) over SSE")

        # 5. Mobile: the sidebar collapses into a burger menu at narrow widths.
        send("Emulation.setDeviceMetricsOverride", {
            "width": 420, "height": 820, "deviceScaleFactor": 1, "mobile": True,
        })
        time.sleep(1.5)
        state = js("""
          (() => {
            const burger = document.querySelector('.nav-burger');
            const nav = document.querySelector('.side-nav');
            if (!burger) return {error: 'no burger button'};
            const burgerVisible = getComputedStyle(burger).display !== 'none';
            const navHidden = nav ? getComputedStyle(nav).display === 'none' : true;
            burger.click();
            const navOpen = nav ? getComputedStyle(nav).display !== 'none' : false;
            const items = document.querySelectorAll('.side-nav .nav-item').length;
            const item = [...document.querySelectorAll('.side-nav .nav-item')]
              .find(t => t.textContent.trim().toUpperCase() === 'MODELS');
            item.click();
            const navClosedAfterClick = nav ? getComputedStyle(nav).display === 'none' : true;
            return {burgerVisible, navHidden, navOpen, items, navClosedAfterClick};
          })()
        """)
        collect()
        if not isinstance(state, dict) or state.get("error"):
            fail(f"mobile menu: {state}")
        if not state["burgerVisible"]:
            fail("burger button is not visible at 420px")
        if not state["navHidden"]:
            fail("nav should be collapsed at 420px")
        if not state["navOpen"]:
            fail("burger did not open the nav")
        if state["items"] != len(TABS):
            fail(f"menu lost items: {state['items']}")
        if not state["navClosedAfterClick"]:
            fail("menu did not close after selecting a tab")
        print("  ok mobile menu (burger opens/closes, all tabs present)")
        send("Emulation.clearDeviceMetricsOverride")

        if errors:
            print(f"\n!!! {len(errors)} console error(s)")
            for e in errors[:5]:
                print("   ", e)
            sys.exit(1)
        print("\nno panics, no console errors ✓")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:  # noqa: BLE001 - a stuck chromium must not fail the stage
            proc.kill()
        # A leaked profile or chromium (a crashed earlier run) used to break the
        # *next* run of this stage; clean up after ourselves.
        import shutil

        shutil.rmtree(CDP_PROFILE, ignore_errors=True)
        api("POST", "/api/client-keys/delete", {"key": "sk-hop-cdp-test"})
        api("POST", "/api/client-keys/delete", {"key": "sk-hop-cdp-test-2"})


if __name__ == "__main__":
    main()