#!/usr/bin/env python3
"""
console.py -- serve the Redstrike web console against a LIVE engagement.

The console (console/) is a static web UI over the engagement data model. This
launcher builds it and feeds it the JSON a real engagement produces, so the same
UI renders YOUR engagement:

    python scripts/console.py engagements/<client>-<date>/

It searches (recursively) inside the engagement dir for the files the skills
emit and serves each at the site root under the canonical name the console
fetches on open:

  findings_consolidated.json  (reporting)               -> /findings_consolidated.json
  host_discovery.json         (host-discovery)          -> /host_discovery.json
  chains.json                 (attack-chain-discovery)  -> /attack_chains.json
  scope.yaml / scope.json     (engagement root)         -> /scope.json

scope.yaml is converted to JSON on the fly (PyYAML if available, else a small
built-in reader). Anything missing just stays an empty state in the console.
Stdlib only to serve (PyYAML optional); no Node needed once the console is built.
"""
import argparse
import http.server
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSOLE = ROOT / "console"
OUT = CONSOLE / "out"

# canonical URL name -> candidate filenames the skills may use (first match wins,
# shallowest path preferred)
WANTED = {
    "findings_consolidated.json": ["findings_consolidated.json"],
    "host_discovery.json": ["host_discovery.json"],
    "attack_chains.json": ["attack_chains.json", "chains.json"],
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


def _shallowest(engagement: Path, name: str):
    hits = sorted(engagement.rglob(name), key=lambda p: len(p.parts))
    return hits[0] if hits else None


def find_data(engagement: Path, tmp: Path) -> dict:
    found = {}
    for canonical, candidates in WANTED.items():
        for name in candidates:
            hit = _shallowest(engagement, name)
            if hit:
                found[canonical] = hit
                break
    # scope.yaml -> /scope.json (only if a scope.json wasn't already emitted)
    if "scope.json" not in found:
        sy = engagement / "scope.yaml"
        if not sy.exists():
            sy = _shallowest(engagement, "scope.yaml")
        if sy and sy.exists():
            scope = scope_yaml_to_json(sy)
            if scope:
                dest = tmp / "scope.json"
                dest.write_text(json.dumps(scope, default=str), encoding="utf-8")
                found["scope.json"] = dest
    return found


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
    section = None          # current top-level dict section, if any
    list_key = None         # key (inside section) currently collecting a `- ` list
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        if s.startswith("- "):                       # list item -> current list
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
        elif section is not None:                    # nested under a top-level section
            if val in ("", ">", "|"):
                list_key = key                       # a `- ` list follows
                section.setdefault(key, [])
            else:
                list_key = None
                section[key] = val
    return doc


def make_handler(found: dict):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(OUT), **k)

        def translate_path(self, path):
            name = path.lstrip("/").split("?")[0]
            if name in found:
                return str(found[name])
            return super().translate_path(path)

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, *a):  # quiet
            pass

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description="Serve the Redstrike console against an engagement.")
    ap.add_argument("engagement", help="path to the engagement dir (e.g. engagements/<client>-<date>/)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--build", action="store_true", help="force a fresh console build")
    args = ap.parse_args()

    eng = Path(args.engagement).resolve()
    if not eng.exists():
        print(f"error: engagement dir not found: {eng}", file=sys.stderr)
        return 2

    ensure_build(args.build)
    tmp = Path(tempfile.mkdtemp(prefix="redstrike-console-"))
    found = find_data(eng, tmp)

    print(f"\n  engagement : {eng}")
    if found:
        for name in WANTED:
            if name in found:
                src = found[name]
                where = src.name if src.parent == tmp else src.relative_to(eng)
                print(f"  loaded     : {name:<28} ({where})")
    else:
        print("  loaded     : (none found — the console will show its empty state)")
    url = f"http://localhost:{args.port}/"
    print(f"\n  console    : {url}\n  (Ctrl+C to stop)\n")

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(found))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
