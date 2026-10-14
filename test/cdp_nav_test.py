#!/usr/bin/env python3
"""CDP-driven navigation test: tab clicks + provider detail + back + re-enter.
Catches the BorrowMutError panic."""
import json, subprocess, time, urllib.request, sys
import websocket

CHROME = ["chromium-browser", "--headless=new", "--no-sandbox", "--disable-gpu",
          "--remote-debugging-port=9222", "--remote-allow-origins=*", "about:blank"]

proc = subprocess.Popen(CHROME, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)

try:
    tabs = [t for t in json.load(urllib.request.urlopen("http://127.0.0.1:9222/json")) if t.get("type") == "page"]
    ws_url = tabs[0]["webSocketDebuggerUrl"]
    ws = websocket.create_connection(ws_url, timeout=15)
    mid = 0
    def send(method, params=None):
        global mid
        mid += 1
        ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(ws.recv())
            if msg.get("id") == mid:
                return msg.get("result", {})
    def js(expr):
        r = send("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        return r.get("result", {}).get("value")

    send("Page.enable")
    send("Runtime.enable")
    send("Log.enable")

    url = "http://127.0.0.1:18080/dashboard"
    send("Page.navigate", {"url": url})
    time.sleep(3)

    panics = []
    def collect():
        # собираем асинхронные события консоли
        ws.settimeout(0.3)
        try:
            while True:
                msg = json.loads(ws.recv())
                if msg.get("method") == "Runtime.consoleAPICalled" and msg["params"]["type"] == "error":
                    txt = " ".join(str(a.get("value", a.get("description","")))[:400] for a in msg["params"]["args"])
                    panics.append("CONSOLE-ERR: " + txt)
                if msg.get("method") == "Runtime.exceptionThrown":
                    panics.append(str(msg["params"]["exceptionDetails"].get("exception", {}).get("description", msg["params"]["exceptionDetails"].get("text", "?"))[:500]))
        except Exception:
            pass
        ws.settimeout(15)

    def click_tab(label):
        return js(f"""
          [...document.querySelectorAll('.tab')].find(t => t.textContent.trim().toUpperCase() === '{label}')?.click(), 'clicked'
        """)

    print("1. providers tab:", click_tab("PROVIDERS")); time.sleep(1); collect()
    print("2. click first tile:", js("document.querySelector('.provider-tile')?.click(), 'ok'")); time.sleep(1); collect()
    print("   detail visible:", js("!!document.querySelector('.back-link')"))
    print("3. back link:", js("document.querySelector('.back-link')?.click(), 'ok'")); time.sleep(1); collect()
    print("   catalog back:", js("!!document.querySelector('.provider-grid')"))
    print("4. providers again:", click_tab("PROVIDERS")); time.sleep(1); collect()
    print("   catalog visible:", js("!!document.querySelector('.provider-grid')"))
    print("5. overview/events/quotas roundtrip:")
    for t in ["OVERVIEW", "EVENTS", "QUOTAS", "REQUESTS", "CONFIG", "PROVIDERS"]:
        click_tab(t); time.sleep(2.5); collect()  # даём поллинг-циклам тикнуть
    print("   alive:", js("!!document.querySelector('.wrap')"))

    if panics:
        print("\n!!! PANICS DETECTED:", len(panics))
        for p in panics[:3]: print(p)
        sys.exit(1)
    print("\nno panics ✓")
finally:
    proc.terminate()
