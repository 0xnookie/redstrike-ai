#!/usr/bin/env python3
"""
console.py -- serve the Redstrike web console against a LIVE engagement.

The console (console/) is a static web UI over the engagement data model. This
launcher serves the built console and feeds it the JSON a real engagement
produces, so the same UI that renders demo data now renders YOUR engagement:

    python scripts/console.py engagements/<client>-<date>/        # a real run
    python scripts/console.py samples/acme-demo                   # the bundled sample

It looks (recursively) inside the engagement dir for the files the skills emit --
  findings_consolidated.json   (reporting)   -> Findings / Dashboard / Report
  host_discovery.json          (host-discovery) -> Assets: Ports & services + map risk
  scope.json                   (engagement)  -> scope / rules / window
  attack_chains.json           (attack-chain-discovery) -> Attack chains
-- and serves each at the site root, where the console auto-loads it on open.
Anything missing just stays on demo data. Stdlib only; no Node needed to serve.
"""
import argparse
import http.server
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONSOLE = ROOT / "console"
OUT = CONSOLE / "out"
DATA_FILES = ("findings_consolidated.json", "scope.json", "host_discovery.json", "attack_chains.json")


def ensure_build(force: bool) -> None:
    npm = "npm.cmd" if os.name == "nt" else "npm"
    if not (CONSOLE / "node_modules").exists():
        print("· installing console dependencies (first run)…")
        subprocess.run([npm, "--prefix", str(CONSOLE), "install"], check=True)
    if force or not (OUT / "index.html").exists():
        print("· building the console…")
        subprocess.run([npm, "--prefix", str(CONSOLE), "run", "build"], check=True)


def find_data(engagement: Path) -> dict:
    found = {}
    for name in DATA_FILES:
        hits = sorted(engagement.rglob(name), key=lambda p: len(p.parts))
        if hits:
            found[name] = hits[0]
    return found


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
    ap.add_argument("engagement", help="path to the engagement dir (e.g. engagements/<client>-<date>/ or samples/acme-demo)")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--build", action="store_true", help="force a fresh console build")
    args = ap.parse_args()

    eng = Path(args.engagement).resolve()
    if not eng.exists():
        print(f"error: engagement dir not found: {eng}", file=sys.stderr)
        return 2

    ensure_build(args.build)
    found = find_data(eng)

    print(f"\n  engagement : {eng}")
    if found:
        for name in DATA_FILES:
            if name in found:
                print(f"  loaded     : {name:<28} ({found[name].relative_to(eng)})")
    else:
        print("  loaded     : (none found — the console will show demo data)")
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
