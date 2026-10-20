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
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSOLE = ROOT / "console"
OUT = CONSOLE / "out"

# canonical name -> candidate filenames the skills may use (first match wins, shallowest)
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


def gather(engagement: Path, tmp: Path) -> dict:
    """canonical name -> source Path for one engagement (scope.yaml -> scope.json)."""
    files = {}
    for canonical, candidates in WANTED.items():
        for name in candidates:
            hit = _shallowest(engagement, name)
            if hit:
                files[canonical] = hit
                break
    if "scope.json" not in files:
        sy = engagement / "scope.yaml"
        if not sy.exists():
            sy = _shallowest(engagement, "scope.yaml")
        if sy and sy.exists():
            scope = scope_yaml_to_json(sy)
            if scope:
                dest = tmp / "scope.json"
                dest.write_text(json.dumps(scope, default=str), encoding="utf-8")
                files["scope.json"] = dest
    return files


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


def summarize(files: dict) -> dict:
    """Reportable-severity counts + chain count, computed server-side for the list."""
    cons = _read_json(files.get("findings_consolidated.json"))
    findings = cons if isinstance(cons, list) else (cons.get("findings") if isinstance(cons, dict) else None) or []
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


def build_routes(engagements: list[Path], tmp: Path):
    """Return (routes: url->Path, manifest: dict) for every discovered engagement."""
    routes = {}
    entries = []
    for eng in engagements:
        eid = eng.name
        sub = tmp / eid
        sub.mkdir(parents=True, exist_ok=True)
        files = gather(eng, sub)
        if not files:
            continue
        for canonical, src in files.items():
            routes[f"/e/{eid}/{canonical}"] = src
        cons = _read_json(files.get("findings_consolidated.json"))
        entries.append({
            "id": eid,
            "scope": _read_json(files.get("scope.json")),
            "summary": summarize(files),
            "generated": (cons.get("generated") if isinstance(cons, dict) else None),
            "has": {k: (k in files) for k in WANTED},
        })
    manifest = tmp / "engagements.json"
    manifest.write_text(json.dumps({"engagements": entries}), encoding="utf-8")
    routes["/engagements.json"] = manifest
    return routes, entries


def make_handler(routes: dict):
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(OUT), **k)

        def translate_path(self, path):
            clean = path.split("?")[0]
            if clean in routes:
                return str(routes[clean])
            return super().translate_path(path)

        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, *a):  # quiet
            pass

    return Handler


def main() -> int:
    ap = argparse.ArgumentParser(description="Serve the Redstrike console against your engagements.")
    ap.add_argument("target", nargs="?", default=str(ROOT / "engagements"),
                    help="an engagement dir, or a directory of engagements (default: engagements/)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--build", action="store_true", help="force a fresh console build")
    args = ap.parse_args()

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2

    engagements = discover(target)
    if not engagements:
        print(f"error: no engagements found under {target}", file=sys.stderr)
        return 2

    ensure_build(args.build)
    tmp = Path(tempfile.mkdtemp(prefix="redstrike-console-"))
    routes, entries = build_routes(engagements, tmp)

    print(f"\n  source     : {target}")
    print(f"  engagements: {len(entries)}")
    for e in entries:
        s = e["summary"]
        print(f"    · {e['id']:<40} {s['findings']} findings · {s['chains']} chains")
    url = f"http://localhost:{args.port}/"
    print(f"\n  console    : {url}\n  (Ctrl+C to stop)\n")

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(routes))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
