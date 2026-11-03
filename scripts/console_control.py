#!/usr/bin/env python3
"""console_control.py -- EXPERIMENTAL control plane for the Redstrike console.

`console.py` is a READ-ONLY viewer (no backend). This wraps it with a small, guarded control
plane so the web console can *launch and steer* an engagement instead of only rendering
results — closing the "viewer vs. doer" gap. The Next.js frontend's **Control plane** view
(console/app/control/) drives these routes: connect with the token, scaffold or pick an
engagement, launch an autonomous run, watch the live event stream, and approve deferrals.
init validation is minimal (delegated to the CLI), and only autonomous runs are supported
(a web server has no TTY for an interactive Claude Code session).

    SECURITY MODEL (read before enabling)
    -------------------------------------
    A read-only viewer is low-risk. An endpoint that LAUNCHES offensive tooling is a real
    attack surface — a browser-reachable path to running a pentest. So this plane:
      * refuses to start without --enable-control (opt-in, never the default),
      * binds 127.0.0.1 ONLY,
      * requires a bearer token (Authorization: Bearer <token>) on every /api/* route —
        a header, not a cookie, so a cross-site page cannot be tricked into sending it (CSRF),
      * rejects requests whose Host isn't localhost (anti DNS-rebinding) and cross-origin
        requests outright, and sends no permissive CORS headers,
      * shells out to the SAME `redstrike` CLI the terminal uses — all the governance
        (scope gate, fail-closed launch gate, deny-by-default allowlist, audit trail) is
        enforced by the launcher, not re-implemented here.

    It does NOT bypass any gate: a launched run still defers every un-allowlisted command
    for approval, exactly as `redstrike run --autonomous` does from a terminal.

    Routes (all require the bearer token):
      GET  /api/status                         -> { ok, engagements:[...], runs:{id:pid} }
      POST /api/engagements                     -> redstrike init  (body: client, domains[], authorized_by, confirm_authorization)
      POST /api/engagements/<id>/run            -> redstrike run <id> --autonomous (body: allow[], max_turns, max_budget, resume)
      GET  /api/engagements/<id>/stream         -> SSE tail of runtime/autorun.jsonl
      GET  /api/engagements/<id>/approvals      -> runtime/approvals_pending.json
      POST /api/engagements/<id>/approve        -> redstrike approve <id> (body: ids[] | all)
      POST /api/engagements/<id>/stop           -> terminate the tracked run process group

    Run:
      python scripts/console_control.py --enable-control                 # all engagements/
      python scripts/console_control.py --enable-control engagements/<id>
      REDSTRIKE_CONSOLE_TOKEN=... python scripts/console_control.py --enable-control
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from pathlib import Path

# Reuse the read-only console: same dir, stdlib import.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import console  # type: ignore  # noqa: E402  (console.py — static serving + engagement discovery)

import http.server  # noqa: E402

# in-flight runs: engagement id -> Popen (process-group leader)
_RUNS: dict[str, subprocess.Popen] = {}
_RUNS_LOCK = threading.Lock()


# --- LLM provider auth (set from the console, inherited by launched runs) ------------------
# The console's "Connect LLM" card POSTs a key/token here; we set it in THIS process's
# environment so every `redstrike run` child inherits it — the user never edits a .env file.
# In-memory only: nothing is written to disk, and it is lost on restart. Reachable only over the
# loopback, bearer-token-gated /api surface, exactly like every other control endpoint.
_PROVIDERS = {
    "claude": {"label": "Claude", "live": True,
               "methods": {"oauth_token": "CLAUDE_CODE_OAUTH_TOKEN", "api_key": "ANTHROPIC_API_KEY"},
               "model_var": "ANTHROPIC_MODEL", "default_model": "claude-opus-5-5"},
    "codex":  {"label": "Codex (OpenAI)", "live": False,
               "methods": {"api_key": "OPENAI_API_KEY"}},
    "gemini": {"label": "Gemini (Google)", "live": False,
               "methods": {"api_key": "GEMINI_API_KEY"}},
}
_CRED_SOURCE: dict[str, str] = {}  # provider -> "ui" (set here) | "env" (present at startup)


def _mask(val: str):
    return ("…" + val[-4:]) if val and len(val) >= 8 else ("set" if val else None)


def auth_snapshot() -> dict:
    """Per-provider connection state for the console (never returns the secret itself)."""
    providers = {}
    for pid, spec in _PROVIDERS.items():
        connected, via, masked = False, None, None
        for method, var in spec["methods"].items():
            v = os.environ.get(var)
            if v:
                connected, via, masked = True, method, _mask(v)
                break
        entry = {"label": spec["label"], "live": spec["live"],
                 "methods": list(spec["methods"].keys()),
                 "connected": connected, "via": via, "masked": masked,
                 "source": _CRED_SOURCE.get(pid, "env" if connected else None)}
        if spec.get("model_var"):
            entry["model"] = os.environ.get(spec["model_var"]) or spec.get("default_model")
        providers[pid] = entry
    return {"providers": providers, "engine": os.environ.get("REDSTRIKE_ENGINE", "claude-code")}


# --- redstrike CLI resolution ----------------------------------------------
def _redstrike_base() -> tuple[list[str], dict | None]:
    """argv prefix + env to invoke the `redstrike` CLI (installed binary, else module)."""
    exe = shutil.which("redstrike")
    if exe:
        return [exe], None
    env = dict(os.environ)
    cli_dir = console.ROOT / "cli"
    env["PYTHONPATH"] = str(cli_dir) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    return [sys.executable, "-m", "redstrike_cli"], env


def _run_cli(args: list[str], *, capture: bool = True, background: bool = False):
    """Invoke the redstrike CLI. Global flags (e.g. --no-banner) go before the subcommand."""
    base, env = _redstrike_base()
    argv = base + ["--no-banner", "--no-color", *args]
    cwd = str(console.ROOT)
    if background:
        return subprocess.Popen(
            argv, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,  # own process group so /stop can signal the whole run
        )
    p = subprocess.run(argv, cwd=cwd, env=env, capture_output=capture, text=True)
    return p


# --- request handler --------------------------------------------------------
def make_control_handler(target: Path, token: str):
    Base = console.make_handler(target)  # read-only GET/HEAD for static + engagement JSON

    def engagement_dir(eid: str) -> Path | None:
        return next((e for e in console.discover(target) if e.name == eid), None)

    class Control(Base):  # type: ignore[valid-type, misc]
        # -- guards ----------------------------------------------------------
        def _host_ok(self) -> bool:
            host = (self.headers.get("Host") or "").split(":")[0].lower()
            return host in ("localhost", "127.0.0.1", "::1", "")

        def _origin_ok(self) -> bool:
            origin = self.headers.get("Origin")
            if not origin:
                return True  # non-browser / same-origin fetch without Origin
            return origin.split("://")[-1].split(":")[0].lower() in ("localhost", "127.0.0.1")

        def _authed(self) -> bool:
            auth = self.headers.get("Authorization", "")
            want = f"Bearer {token}"
            # constant-time-ish compare
            return len(auth) == len(want) and secrets.compare_digest(auth, want)

        def _api_guard(self) -> bool:
            if not self._host_ok() or not self._origin_ok():
                self._json(HTTPStatus.FORBIDDEN, {"error": "bad host/origin"})
                return False
            if not self._authed():
                self.send_response(HTTPStatus.UNAUTHORIZED)
                self.send_header("WWW-Authenticate", "Bearer")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return False
            return True

        # -- helpers ---------------------------------------------------------
        def _json(self, status: int, obj: dict):
            body = json.dumps(obj, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except BrokenPipeError:
                pass

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except (ValueError, OSError):
                return {}

        # -- routing ---------------------------------------------------------
        def do_GET(self):
            path = self.path.split("?")[0]
            if path.startswith("/api/"):
                if not self._api_guard():
                    return
                return self._api_get(path)
            super().do_GET()  # read-only static + engagement JSON (console.py)

        def do_POST(self):
            path = self.path.split("?")[0]
            if not path.startswith("/api/"):
                return self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            if not self._api_guard():
                return
            self._api_post(path)

        def _api_get(self, path: str):
            if path == "/api/status":
                with _RUNS_LOCK:
                    runs = {k: v.pid for k, v in _RUNS.items() if v.poll() is None}
                return self._json(HTTPStatus.OK, {
                    "ok": True,
                    "engagements": [e.name for e in console.discover(target)],
                    "runs": runs,
                })
            if path == "/api/auth":
                return self._json(HTTPStatus.OK, auth_snapshot())
            parts = path.strip("/").split("/")  # api / engagements / <id> / <verb>
            if len(parts) == 4 and parts[1] == "engagements":
                eid, verb = parts[2], parts[3]
                eng = engagement_dir(eid)
                if not eng:
                    return self._json(HTTPStatus.NOT_FOUND, {"error": f"no engagement {eid}"})
                if verb == "approvals":
                    pend = eng / "runtime" / "approvals_pending.json"
                    data = console._read_json(pend) or {"pending": []}
                    return self._json(HTTPStatus.OK, data)
                if verb == "stream":
                    return self._stream_jsonl(eng / "runtime" / "autorun.jsonl")
            return self._json(HTTPStatus.NOT_FOUND, {"error": "unknown api route"})

        def _api_post(self, path: str):
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[1] == "auth":  # api / auth / <provider>
                return self._set_auth(parts[2], self._body())
            if path == "/api/engagements":
                return self._init_engagement(self._body())
            if len(parts) == 4 and parts[1] == "engagements":
                eid, verb = parts[2], parts[3]
                eng = engagement_dir(eid)
                if not eng and verb != "run":  # run may target a freshly-scaffolded id
                    return self._json(HTTPStatus.NOT_FOUND, {"error": f"no engagement {eid}"})
                body = self._body()
                if verb == "run":
                    return self._run_engagement(eid, body)
                if verb == "approve":
                    return self._approve(eid, body)
                if verb == "stop":
                    return self._stop(eid)
            return self._json(HTTPStatus.NOT_FOUND, {"error": "unknown api route"})

        # -- actions (thin wrappers over the redstrike CLI) ------------------
        def _init_engagement(self, body: dict):
            client = (body.get("client") or "").strip()
            domains = body.get("domains") or []
            authorized_by = (body.get("authorized_by") or "").strip()
            if not client or not domains or not authorized_by:
                return self._json(HTTPStatus.BAD_REQUEST,
                                  {"error": "client, domains[], authorized_by required"})
            if not body.get("confirm_authorization"):
                # mirrors the CLI's --i-confirm-authorization: asserting written auth is on file
                return self._json(HTTPStatus.BAD_REQUEST,
                                  {"error": "confirm_authorization:true required (written authorization on file)"})
            args = ["init", client, "--authorized-by", authorized_by, "--i-confirm-authorization"]
            for d in domains:
                args += ["--domain", str(d)]
            for c in (body.get("cidrs") or []):
                args += ["--cidr", str(c)]
            if body.get("window_days"):
                args += ["--window-days", str(int(body["window_days"]))]
            p = _run_cli(args)
            ok = p.returncode == 0
            return self._json(HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST,
                              {"ok": ok, "rc": p.returncode, "stdout": p.stdout, "stderr": p.stderr})

        def _run_engagement(self, eid: str, body: dict):
            with _RUNS_LOCK:
                existing = _RUNS.get(eid)
                if existing and existing.poll() is None:
                    return self._json(HTTPStatus.CONFLICT, {"error": "run already in progress", "pid": existing.pid})
            # Web server has no TTY -> autonomous only (interactive needs a terminal).
            args = ["run", eid, "--autonomous"]
            args += ["--max-turns", str(int(body.get("max_turns", 200)))]
            args += ["--max-budget-usd", str(float(body.get("max_budget", 20)))]
            for a in (body.get("allow") or []):
                args += ["--allow", str(a)]
            if body.get("resume"):
                args.append("--resume")
            proc = _run_cli(args, background=True)
            with _RUNS_LOCK:
                _RUNS[eid] = proc
            return self._json(HTTPStatus.ACCEPTED, {"ok": True, "pid": proc.pid, "engagement": eid})

        def _approve(self, eid: str, body: dict):
            args = ["approve", eid]
            if body.get("all"):
                args.append("--all")
            else:
                ids = body.get("ids") or []
                if not ids:
                    return self._json(HTTPStatus.BAD_REQUEST, {"error": "ids[] or all:true required"})
                for fp in ids:
                    args += ["--id", str(fp)]
            p = _run_cli(args)
            return self._json(HTTPStatus.OK, {"ok": p.returncode == 0, "rc": p.returncode,
                                              "stdout": p.stdout, "stderr": p.stderr})

        def _stop(self, eid: str):
            with _RUNS_LOCK:
                proc = _RUNS.get(eid)
            if not proc or proc.poll() is not None:
                return self._json(HTTPStatus.OK, {"ok": True, "note": "no running process"})
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)  # whole group (start_new_session)
            except (ProcessLookupError, PermissionError) as e:
                return self._json(HTTPStatus.OK, {"ok": False, "note": str(e)})
            return self._json(HTTPStatus.OK, {"ok": True, "stopped": proc.pid})

        # -- LLM provider auth ----------------------------------------------
        def _set_auth(self, provider: str, body: dict):
            spec = _PROVIDERS.get(provider)
            if not spec:
                return self._json(HTTPStatus.NOT_FOUND, {"error": f"unknown provider {provider}"})
            if body.get("action") == "disconnect":
                for var in spec["methods"].values():
                    os.environ.pop(var, None)
                _CRED_SOURCE.pop(provider, None)
                return self._json(HTTPStatus.OK, auth_snapshot())
            method = body.get("method")
            value = (body.get("value") or "").strip()
            if method not in spec["methods"]:
                return self._json(HTTPStatus.BAD_REQUEST,
                                  {"error": f"method must be one of {list(spec['methods'])}"})
            if not value:
                return self._json(HTTPStatus.BAD_REQUEST, {"error": "value required"})
            # set the chosen var; clear this provider's other method so status stays unambiguous
            for m, var in spec["methods"].items():
                if m == method:
                    os.environ[var] = value
                else:
                    os.environ.pop(var, None)
            if spec.get("model_var") and body.get("model"):
                os.environ[spec["model_var"]] = str(body["model"]).strip()
            _CRED_SOURCE[provider] = "ui"
            return self._json(HTTPStatus.OK, auth_snapshot())

        # -- SSE tail --------------------------------------------------------
        def _stream_jsonl(self, path: Path, *, max_seconds: int = 1800):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            deadline = time.time() + max_seconds
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                f = None
                while time.time() < deadline:
                    if f is None:
                        if path.is_file():
                            f = path.open("r", encoding="utf-8", errors="replace")
                            f.seek(0, os.SEEK_END)  # follow new lines only
                        else:
                            time.sleep(0.5)
                            continue
                    line = f.readline()
                    if line:
                        self.wfile.write(b"data: " + line.rstrip("\n").encode("utf-8") + b"\n\n")
                        self.wfile.flush()
                    else:
                        time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError):
                pass  # client went away
            finally:
                try:
                    if f:  # type: ignore[has-type]
                        f.close()
                except Exception:
                    pass

        def end_headers(self):
            # Base console adds Cache-Control: no-store; keep that, add nothing permissive.
            super().end_headers()

    return Control


def main() -> int:
    ap = argparse.ArgumentParser(description="EXPERIMENTAL control plane for the Redstrike console.")
    ap.add_argument("target", nargs="?", default=str(console.ROOT / "engagements"),
                    help="an engagement dir, or a directory of engagements (default: engagements/)")
    ap.add_argument("--port", type=int, default=8788, help="port (default 8788; viewer uses 8787)")
    ap.add_argument("--enable-control", action="store_true",
                    help="REQUIRED: acknowledge this exposes launch/steer endpoints (opt-in)")
    ap.add_argument("--build", action="store_true", help="force a fresh console build")
    ap.add_argument("--host", default=os.environ.get("REDSTRIKE_CONSOLE_HOST", "127.0.0.1"),
                    help="bind address (default 127.0.0.1 / $REDSTRIKE_CONSOLE_HOST). Use 0.0.0.0 ONLY "
                         "behind a trusted boundary — e.g. a container published to the host loopback "
                         "(-p 127.0.0.1:8788:8788). The bearer token and the Host/Origin checks remain "
                         "the access control regardless of bind address.")
    args = ap.parse_args()

    if not args.enable_control:
        print("refusing to start: this plane can LAUNCH engagements from the browser.", file=sys.stderr)
        print("re-run with --enable-control once you understand the security model (see the docstring),", file=sys.stderr)
        print("or use `python scripts/console.py` for the read-only viewer.", file=sys.stderr)
        return 2

    target = Path(args.target).resolve()
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2

    token = os.environ.get("REDSTRIKE_CONSOLE_TOKEN") or secrets.token_urlsafe(24)
    console.ensure_build(args.build)

    handler = make_control_handler(target, token)
    httpd = http.server.ThreadingHTTPServer((args.host, args.port), handler)
    loopback = args.host in ("127.0.0.1", "::1", "localhost")
    browse_host = "127.0.0.1" if loopback or args.host in ("0.0.0.0", "", "::") else args.host
    url = f"http://{browse_host}:{args.port}/"
    print(f"\n  Redstrike console CONTROL PLANE (experimental)")
    print(f"  source : {target}")
    print(f"  bind   : {args.host}:{args.port}")
    print(f"  url    : {url}")
    if not loopback:
        print(f"  note   : bound to {args.host} (not loopback) — expose ONLY behind a trusted boundary")
        print(f"           (e.g. published to the host loopback). The bearer token + Host/Origin checks")
        print(f"           are the access control, so keep them and never put this on a public interface.")
    print(f"  token  : {token}")
    print(f"  use    : send  Authorization: Bearer {token}  on every /api/* request")
    print(f"  (Ctrl+C to stop)\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
        with _RUNS_LOCK:
            for proc in _RUNS.values():
                if proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except Exception:
                        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
