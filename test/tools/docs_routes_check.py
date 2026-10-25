import pathlib, re
src = "\n".join(p.read_text() for p in pathlib.Path("src").rglob("*.rs"))
routes = set(re.findall(r'\.route\(\s*"([^"]+)"', src))
readme = pathlib.Path("README.md").read_text()
paths = re.findall(r'`(/(?:v1|api|dashboard|healthz|metrics)[A-Za-z0-9/{}\.\-_|]*)`', readme)
def norm(r):
    return re.sub(r"\{[^}]*\}", "{}", r).rstrip("/")
cands = sorted({alt.split(" ")[0] for p in paths for alt in p.split("|")})
missing = [m for m in cands if m not in ("/api", "/v1")
           and not any(norm(r) == norm(m) for r in routes)]
print("\n".join(missing))
