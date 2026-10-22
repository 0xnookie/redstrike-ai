#!/usr/bin/env python3
"""
console.py -- serve the Redstrike web console against your engagements.

The console (console/) is a static web UI over the engagement data model. This
launcher builds it and feeds it the JSON real engagements produce.

    python scripts/console.py                       # ALL engagements under engagements/
    python scripts/console.py engagements/          # same (explicit)
    python scripts/console.py engagements/<client>-<date>/   # just one

Point it at the `engagements/` directory (the default) and it discovers every
engagement inside, serves a manifest, and lets you switch between them in the UI
(Engagements page / ⌘K) — one launch, all engagements. Point it at a single
engagement dir to serve just that one.

For each engagement it searches (recursively) for the files the skills emit and
serves them under per-engagement routes the console fetches on open:

  findings_consolidated.json  (reporting)               -> /e/<id>/findings_consolidated.json
  host_discovery.json         (host-discovery)          -> /e/<id>/host_discovery.json
  chains.json                 (attack-chain-discovery)  -> /e/<id>/attack_chains.json
  scope.yaml / scope.json     (engagement root)         -> /e/<id>/scope.json

plus a `/engagements.json` manifest (one entry per engagement, with parsed scope
+ a reportable-severity summary computed server-side). scope.yaml is converted to
JSON on the fly (PyYAML if available, else a small built-in reader).
"""
import argparse
import http.server
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSOLE = ROOT / "console"
OUT = CONSOLE / "out"

# canonical name -> candidate filenames the skills may use (first match wins, shallowest)
WANTED = {
    "findings_consolidated.json": ["findings_consolidated.json"],
    "host_discovery.json": ["host_discovery.json"],
    "attack_chains.json": ["attack_chains.json", "chains.json"],
    "coverage_ledger.json": ["coverage_ledger.json"],
    "scope.json": ["scope.json"],
}


def ensure_build(force: bool) -> None:
    npm = "npm.cmd" if os.name == "nt" else "npm"
    if not (CONSOLE / "node_modules").exists():
        print("· installing console dependencies (first run)…")
        subprocess.run([npm, "--prefix", str(CONSOLE), "install"], check=True)
    if force or not (OUT / "index.html").exists():
        print("· building the console…")
        subprocess.run([npm, "--prefix", str(CONSOLE), "run", "build"], check=True)


def _shallowest(root: Path, name: str):
    hits = sorted(root.rglob(name), key=lambda p: len(p.parts))
    return hits[0] if hits else None


def looks_like_engagement(d: Path) -> bool:
    # DIRECT-child signals only — a parent `engagements/` dir must NOT match itself
    # via a file nested inside one of its engagements.
    if not d.is_dir():
        return False
    return (
        (d / "scope.yaml").exists()
        or (d / "report").is_dir()
        or (d / "host-discovery").is_dir()
        or (d / "report" / "findings_consolidated.json").exists()
    )


def discover(target: Path) -> list[Path]:
    """A single engagement dir, or every engagement under a parent dir."""
    if looks_like_engagement(target):
        return [target]
    engs = []
    for child in sorted(p for p in target.iterdir() if p.is_dir()):
        if child.name.startswith((".", "_")):
            continue
        if looks_like_engagement(child):
            engs.append(child)
    return engs


def files_for(engagement: Path) -> dict:
    """canonical name -> source Path for one engagement (real files on disk only)."""
    files = {}
    for canonical, candidates in WANTED.items():
        if canonical == "scope.json":
            continue  # scope is resolved separately (scope.yaml -> JSON in memory)
        for name in candidates:
            hit = _shallowest(engagement, name)
            if hit:
                files[canonical] = hit
                break
    return files


def scope_for(engagement: Path):
    """A scope dict for one engagement: a real scope.json if present, else scope.yaml."""
    sj = _shallowest(engagement, "scope.json")
    if sj:
        return _read_json(sj)
    sy = engagement / "scope.yaml"
    if not sy.exists():
        sy = _shallowest(engagement, "scope.yaml")
    return scope_yaml_to_json(sy) if (sy and sy.exists()) else None


def _read_json(path):
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _verdict(f: dict) -> str:
    r = f.get("review") or {}
    if r.get("verdict"):
        return r["verdict"]
    st = f.get("status")
    return "rejected" if st == "rejected" else "accepted" if st == "verified" else ""


def _reportable(f: dict) -> bool:
    composite = bool(f.get("composite") or f.get("_composite"))
    return (not composite) and _verdict(f) in ("accepted", "blocked")


def _findings_list(path):
    d = _read_json(path)
    if isinstance(d, list):
        return d
    if isinstance(d, dict):
        return list(d.get("findings") or [])
    return None


def engagement_findings(eng: Path, files: dict):
    """The engagement's findings as a list, across the layouts the pipeline produces (mirrors
    verify_completion's discovery): the consolidated report if present, else a root findings.json,
    else the UNION of per-skill <eng>/<skill>/findings.json — so the console shows live findings
    before `reporting` has consolidated them. Returns (findings, consolidated?)."""
    cons = files.get("findings_consolidated.json")
    if cons:
        lst = _findings_list(cons)
        if lst is not None:
            return lst, True
    root = eng / "findings.json"
    if root.is_file():
        lst = _findings_list(root)
        if lst is not None:
            return lst, False
    union = []
    for p in sorted(eng.glob("*/findings.json")):
        part = _findings_list(p)
        if part:
            union.extend(part)
    return union, False


def summarize(eng: Path, files: dict) -> dict:
    """Reportable-severity counts + chain count, computed server-side for the list."""
    findings, _ = engagement_findings(eng, files)
    counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    total = 0
    for f in findings:
        if isinstance(f, dict) and _reportable(f):
            total += 1
            sev = f.get("severity")
            if sev in counts:
                counts[sev] += 1
    chains = 0
    cj = _read_json(files.get("attack_chains.json"))
    cons = _read_json(files.get("findings_consolidated.json"))
    if isinstance(cj, dict) and isinstance(cj.get("chains"), list):
        chains = len(cj["chains"])
    elif isinstance(cons, dict) and isinstance(cons.get("attack_chains"), list):
        chains = len(cons["attack_chains"])
    return {"findings": total, **counts, "chains": chains}


def scope_yaml_to_json(path: Path):
    """Read a scope.yaml into the console's scope.json shape. PyYAML if present."""
    try:
        import yaml  # type: ignore
        with open(path, "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except Exception:
        doc = _minimal_scope_read(path)
    if not isinstance(doc, dict):
        return None

    def block(key):
        b = doc.get(key) or {}
        return {
            "domains": list(b.get("domains") or []),
            "cidrs": list(b.get("cidrs") or []),
            "urls": list(b.get("urls") or []),
        }

    win = doc.get("window") or {}
    domains = block("in_scope")["domains"]
    target = (domains[0].lstrip("*.") if domains else "") or doc.get("engagement", "")
    return {
        "engagement": doc.get("engagement", ""),
        "target": target,
        "authorized_by": doc.get("authorized_by", ""),
        "window": {"start": str(win.get("start", "")), "end": str(win.get("end", ""))},
        "in_scope": block("in_scope"),
        "out_of_scope": block("out_of_scope"),
        "rules": doc.get("rules") or {},
        "notes": (doc.get("notes") or "").strip() if isinstance(doc.get("notes"), str) else "",
        "source": "scope.yaml",
    }


def _minimal_scope_read(path: Path) -> dict:
    """Dependency-free fallback when PyYAML is unavailable. Parses top-level
    `key: value` scalars and one level of nested maps/lists under them — enough
    for engagement / authorized_by / window / in_scope / out_of_scope / rules."""
    doc: dict = {}
    section = None
    list_key = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        if s.startswith("- "):
            if section is not None and list_key is not None:
                section.setdefault(list_key, []).append(s[2:].strip().strip("\"'"))
            continue
        if ":" not in s:
            continue
        key, _, val = s.partition(":")
        key, val = key.strip(), val.strip().strip("\"'")
        if indent == 0:
            list_key = None
            if val in ("", ">", "|"):
                section = {}
                doc[key] = section
            else:
                section = None
                doc[key] = val
        elif section is not None:
            if val in ("", ">", "|"):
                list_key = key
                section.setdefault(key, [])
            else:
                list_key = None
                section[key] = val
    return doc


def manifest_entries(target: Path) -> list:
    """One entry per discovered engagement — rebuilt live on each request, so a
    console left running reflects a scan that finished after launch."""
    entries = []
    for eng in discover(target):
        files = files_for(eng)
        cons = _read_json(files.get("findings_consolidated.json"))
        scope = scope_for(eng)
        has = {k: (k in files) for k in WANTED}
        has["scope.json"] = scope is not None
        entries.append({
            "id": eng.name,
            "scope": scope,
            "summary": summarize(eng, files),
            "generated": (cons.get("generated") if isinstance(cons, dict) else None),
            "has": has,
        })
    return entries


def make_handler(target: Path):
    def resolve(clean: str):
        """Return ('json', bytes) | ('file', Path) | None for a dynamic route."""
        if clean == "/engagements.json":
            body = json.dumps({"engagements": manifest_entries(target)}, default=str)
            return ("json", body.encode("utf-8"))
        if clean.startswith("/e/"):
            parts = clean[len("/e/"):].split("/", 1)
            if len(parts) != 2:
                return None
            eid, name = parts
            eng = next((e for e in discover(target) if e.name == eid), None)
            if not eng:
                return None
            if name == "scope.json":
                scope = scope_for(eng)
                return ("json", json.dumps(scope, default=str).encode("utf-8")) if scope else None
            if name == "findings_consolidated.json":
                files = files_for(eng)
                findings, is_cons = engagement_findings(eng, files)
                if is_cons:
                    src = files.get(name)
                    return ("file", src) if src else None
                if findings:  # live per-skill union — show findings before `reporting` runs
                    return ("json", json.dumps({"findings": findings}, default=str).encode("utf-8"))
                return None
            src = files_for(eng).get(name)
            return ("file", src) if src else None
        return None

    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(OUT), **k)

        def _serve_dynamic(self, body_only: bool) -> bool:
            r = resolve(self.path.split("?")[0])
            if r is None:
                return False
            kind, payload = r
            try:
                data = payload if kind == "json" else Path(payload).read_bytes()
            except OSError:
                self.send_error(404)
                return True
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if not body_only:
                self.wfile.write(data)
            return True

        def do_GET(self):
            if not self._serve_dynamic(body_only=False):
                super().do_GET()

        def do_HEAD(self):
            if not self._serve_dynamic(body_only=True):
                super().do_HEAD()

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, *a):  # quiet
            pass

    return Handler


def port_in_use(port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Serve the Redstrike console against your engagements.")
    ap.add_argument("target", nargs="?", default=str(ROOT / "engagements"),
                    help="an engagement dir, or a directory of engagements (default: engagements/)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--build", action="store_true", help="force a fresh console build")
    ap.add_argument("--open", action="store_true", help="open the console in a browser")
    ap.add_argument("--background", action="store_true", help="start detached, print the URL, and return")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2

    url = f"http://localhost:{args.port}/"

    # idempotent: if something is already serving this port, don't start a second one
    if port_in_use(args.port):
        print(f"  console already serving at {url}")
        if args.open:
            _open_browser(url, wait_port=args.port)
        return 0

    if not discover(target):
        print(f"error: no engagements found under {target}", file=sys.stderr)
        return 2

    # background: re-spawn self detached (so callers like `redstrike run` don't block)
    if args.background:
        cmd = [sys.executable, str(Path(__file__).resolve()), str(target), "--port", str(args.port)]
        if args.build:
            cmd.append("--build")
        devnull = open(os.devnull, "wb")
        subprocess.Popen(cmd, stdout=devnull, stderr=devnull, start_new_session=True)
        print(f"  console (background) → {url}")
        if args.open:
            _open_browser(url, wait_port=args.port)
        return 0

    ensure_build(args.build)
    entries = manifest_entries(target)
    print(f"\n  source     : {target}")
    print(f"  engagements: {len(entries)}")
    for e in entries:
        s = e["summary"]
        print(f"    · {e['id']:<40} {s['findings']} findings · {s['chains']} chains")
    print(f"\n  console    : {url}\n  (Ctrl+C to stop)\n")

    if args.open:
        import threading
        threading.Thread(target=_open_browser, args=(url, args.port), daemon=True).start()

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(target))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


def _open_browser(url: str, wait_port: int | None = None) -> None:
    import time
    import webbrowser
    if wait_port is not None:
        for _ in range(100):  # wait up to ~10s for the server to bind
            if port_in_use(wait_port):
                break
            time.sleep(0.1)
    try:
        webbrowser.open(url)
    except Exception:
        pass


if __name__ == "__main__":
    sys.exit(main())
