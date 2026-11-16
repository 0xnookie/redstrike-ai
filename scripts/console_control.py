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
      POST /api/engagements/<id>/delete         -> remove the engagement directory (refused while running)

    Run:
      python scripts/console_control.py --enable-control                 # all engagements/
      python scripts/console_control.py --enable-control engagements/<id>
      REDSTRIKE_CONSOLE_TOKEN=... python scripts/console_control.py --enable-control
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import stat
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
# engagement id -> how its last run ended THIS session: {"how": "stopped"} (operator Stop)
# or {"how": "exited", "rc": n} (the run finished on its own). Lets the console say
# Paused vs Completed instead of guessing from whether a report exists.
_ENDED: dict[str, dict] = {}


def _rmtree_robust(path: Path) -> None:
    """shutil.rmtree, tolerant of Windows read-only files. On Windows rmtree raises
    PermissionError (WinError 5) trying to unlink a read-only file — and engagement dirs
    routinely contain them (tool outputs, .git objects, files the engine marked read-only).
    An onerror handler clears the read-only bit and retries, so delete works cross-platform."""
    def _onerror(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
        except OSError:
            pass
        func(p)  # retry the unlink/rmdir; if it still fails it re-raises to the caller
    shutil.rmtree(path, onerror=_onerror)


# --- LLM provider auth (set from the console, inherited by launched runs) ------------------
# The console's "Connect LLM" card POSTs a key/token here; we set it in THIS process's
# environment so every `redstrike run` child inherits it — the user never edits a .env file.
# In-memory only: nothing is written to disk, and it is lost on restart. Reachable only over the
# loopback, bearer-token-gated /api surface, exactly like every other control endpoint.
_PROVIDERS = {
    "claude": {"label": "Claude", "live": True,
               "methods": {"oauth_token": "CLAUDE_CODE_OAUTH_TOKEN", "api_key": "ANTHROPIC_API_KEY"},
               "model_var": "ANTHROPIC_MODEL", "default_model": "claude-opus-5-5",
               "models": ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-4-8"],
               "login_cmd": ["claude", "setup-token"], "cred_paths": ["~/.claude/.credentials.json"]},
    "codex":  {"label": "Codex (OpenAI)", "live": False,
               "methods": {"api_key": "OPENAI_API_KEY"},
               "model_var": "OPENAI_MODEL", "default_model": "gpt-5.5",
               "models": ["gpt-5.5", "gpt-5.4", "gpt-5.3-codex"],
               "login_cmd": ["codex", "login"], "cred_paths": ["~/.codex/auth.json"]},
    "gemini": {"label": "Gemini (Google)", "live": False,
               "methods": {"api_key": "GEMINI_API_KEY"},
               "model_var": "GEMINI_MODEL", "default_model": "gemini-2.5-pro",
               "models": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-3-pro-preview"],
               "login_cmd": ["gemini"], "cred_paths": ["~/.gemini/oauth_creds.json"]},
    "grok":   {"label": "Grok (xAI)", "live": False,
               "methods": {"api_key": "XAI_API_KEY"},
               "model_var": "XAI_MODEL", "default_model": "grok-code-fast-1",
               "models": ["grok-code-fast-1", "grok-4", "grok-4-fast-reasoning", "grok-4-fast-non-reasoning"]},
}
_CRED_SOURCE: dict[str, str] = {}   # provider -> "ui" (set here) | "env" (present at startup)
_LOGIN: dict[str, dict] = {}        # provider -> {proc, out:[lines]} for an in-flight CLI login


def _mask(val: str):
    return ("…" + val[-4:]) if val and len(val) >= 8 else ("set" if val else None)


def _login_present(spec: dict) -> bool:
    """True if the provider CLI already has a persisted login on disk (mounted config dir)."""
    for p in spec.get("cred_paths", []):
        try:
            if os.path.isfile(os.path.expanduser(p)):
                return True
        except OSError:
            pass
    return False


# The CLI login flows are terminal UIs (Ink): under a PTY they emit cursor/color codes and
# OSC-8 hyperlinks. Strip them so the captured text reads cleanly and the OAuth URL is extractable.
_ANSI_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"   # OSC … BEL / ST  (incl. OSC-8 hyperlinks)
    r"|\x1b[@-Z\\-_]"                       # two-char escapes
    r"|\x1b\[[0-?]*[ -/]*[@-~]"             # CSI … final byte
    r"|[\x00-\x08\x0b\x0c\x0e-\x1f]")       # stray control chars (keep \t \n)
_OSC8_RE = re.compile(r"\x1b\]8;[^;]*;(https?://[^\x07\x1b]+)")   # hyperlink target = clean URL
_OAT_RE = re.compile(r"sk-ant-[A-Za-z0-9._-]{20,}")              # long-lived token from setup-token


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s).replace("\r", "")


def _extract_login_url(raw: str):
    """The clean OAuth URL — from an OSC-8 hyperlink target (unwrapped by redraws) if present,
    else the first URL in the stripped visible text."""
    m = _OSC8_RE.search(raw)
    if m:
        return m.group(1)
    m = re.search(r"https?://[^\s'\"]+", _strip_ansi(raw))
    return m.group(0) if m else None


def _provider_connected(spec: dict) -> bool:
    for var in spec.get("methods", {}).values():
        if os.environ.get(var):
            return True
    return _login_present(spec)


def _login_capture(provider: str, spec: dict, out: list[str]):
    """On login-process exit, adopt a long-lived token the CLI printed (setup-token) into this
    process's env, so launched runs inherit it — the same effect as the 'Use a key' path.
    Idempotent."""
    var = spec.get("methods", {}).get("oauth_token")
    if not var or os.environ.get(var):
        return
    m = _OAT_RE.search(_strip_ansi("".join(out)))
    if m:
        os.environ[var] = m.group(0)
        _CRED_SOURCE[provider] = "ui"


def start_login(provider: str) -> dict:
    """Spawn the provider CLI's own login flow UNDER A PTY, capturing its output (the URL/code to
    follow). These login UIs are terminal apps (Ink): with no TTY they render nothing and stall,
    so we allocate a pty, surface the URL, and keep the master end writable so the console can
    submit the pasted-back OAuth code (POST .../login/code). A persisted login lands in the
    mounted config dir; a printed token is adopted into env on exit (see _login_capture)."""
    spec = _PROVIDERS.get(provider)
    if not spec or not spec.get("login_cmd"):
        return {"ok": False, "error": "no login flow for this provider"}
    cur = _LOGIN.get(provider)
    if cur and cur["proc"].poll() is None:
        raw = "".join(cur["out"])
        cur["url"] = cur.get("url") or _extract_login_url(raw)
        return {"ok": True, "running": True, "output": _strip_ansi(raw)[-2000:], "url": cur.get("url")}
    out: list[str] = []
    master = None
    try:
        import pty  # Unix only; the container is Linux
        master, slave = pty.openpty()
        proc = subprocess.Popen(spec["login_cmd"], stdin=slave, stdout=slave, stderr=slave,
                                cwd=str(console.ROOT), start_new_session=True, close_fds=True,
                                env={**os.environ, "TERM": "xterm-256color"})
        os.close(slave)  # the child holds the slave; the parent keeps the master (read + write)
    except (ImportError, OSError, FileNotFoundError):
        if master is not None:
            try:
                os.close(master)
            except OSError:
                pass
            master = None
        try:  # fallback for non-PTY platforms (may not render an interactive UI)
            proc = subprocess.Popen(spec["login_cmd"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.PIPE, text=True, bufsize=1,
                                    cwd=str(console.ROOT), start_new_session=True)
        except (FileNotFoundError, OSError) as e2:
            return {"ok": False, "error": f"could not start {spec['login_cmd'][0]}: {e2}"}

    def _pump_pty(fd: int):
        try:
            while True:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                out.append(data.decode("utf-8", "replace"))
                if len(out) > 800:
                    del out[: len(out) - 800]
        finally:
            _login_capture(provider, spec, out)

    def _pump_pipe(stream):
        try:
            for line in stream:
                out.append(line)
                if len(out) > 800:
                    del out[: len(out) - 800]
        except Exception:  # noqa: BLE001
            pass
        finally:
            _login_capture(provider, spec, out)

    if master is not None:
        threading.Thread(target=_pump_pty, args=(master,), daemon=True).start()
        _LOGIN[provider] = {"proc": proc, "out": out, "master": master, "url": None}
    else:
        threading.Thread(target=_pump_pipe, args=(proc.stdout,), daemon=True).start()
        _LOGIN[provider] = {"proc": proc, "out": out, "stdin": proc.stdin, "url": None}
    return {"ok": True, "running": True, "output": "", "url": None}


def submit_login_code(provider: str, code: str) -> dict:
    """Write the user's pasted-back OAuth code to the in-flight login process (the PTY master,
    or the pipe stdin on the fallback path) so the CLI can finish the handshake."""
    cur = _LOGIN.get(provider)
    if not cur:
        return {"ok": False, "error": "no login in progress"}
    if cur["proc"].poll() is not None:
        return {"ok": False, "error": "login process already exited"}
    data = (str(code or "").strip() + "\r")
    try:
        if cur.get("master") is not None:
            os.write(cur["master"], data.encode("utf-8"))
        elif cur.get("stdin") is not None:
            cur["stdin"].write(data)
            cur["stdin"].flush()
        else:
            return {"ok": False, "error": "login has no writable input"}
    except OSError as e:
        return {"ok": False, "error": f"could not submit code: {e}"}
    return {"ok": True, "submitted": True}


def login_status(provider: str) -> dict:
    cur = _LOGIN.get(provider)
    running = bool(cur and cur["proc"].poll() is None)
    spec = _PROVIDERS.get(provider, {})
    if cur and not running:
        _login_capture(provider, spec, cur["out"])  # idempotent; catch the token if the pump raced
    raw = "".join(cur["out"]) if cur else ""
    if cur:
        cur["url"] = cur.get("url") or _extract_login_url(raw)  # cache so it survives buffer rollover
    return {"ok": True, "running": running,
            "output": _strip_ansi(raw)[-2000:],
            "url": (cur.get("url") if cur else None),
            "connected": _provider_connected(spec) if spec else False}


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
        if not connected and _login_present(spec):
            connected, via = True, "login"
        entry = {"label": spec["label"], "live": spec["live"],
                 "methods": list(spec["methods"].keys()),
                 "connected": connected, "via": via, "masked": masked,
                 "source": _CRED_SOURCE.get(pid, "env" if connected else None),
                 "models": spec.get("models", []),
                 "can_login": bool(spec.get("login_cmd")),
                 # The console can only disconnect a credential IT holds (an env var it set / a key
                 # you typed). A login the provider CLI persisted on disk (via == "login") is NOT
                 # ours to delete — clearing env vars leaves it detected, so disconnect would no-op.
                 # Surface that so the UI shows an honest "log out via the CLI" hint instead.
                 "can_disconnect": bool(connected and via and via != "login"),
                 "login_running": bool((lp := _LOGIN.get(pid)) and lp["proc"].poll() is None)}
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
        # own process group / job so /stop can signal the whole run (CLI -> engine child tree)
        popen_kw: dict = (
            {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            if os.name == "nt"
            else {"start_new_session": True}
        )
        return subprocess.Popen(
            argv, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            **popen_kw,
        )
    p = subprocess.run(argv, cwd=cwd, env=env, capture_output=capture, text=True)
    return p


def _terminate(proc: subprocess.Popen) -> None:
    """Terminate a backgrounded run and its child tree, cross-platform.
    Windows: `taskkill /T` kills the CLI and the engine (claude) process tree it spawned.
    POSIX: signal the whole process group the run leads (spawned with start_new_session)."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    else:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)


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
                if path == "/api/bootstrap":
                    # Hand the access token to the SAME-ORIGIN console page so it self-connects
                    # (no manual paste). Host/Origin-guarded but NOT bearer-gated: a cross-origin
                    # page is rejected (can't read the token), and since a cross-origin fetch that
                    # could read the body always carries an Origin, and DNS-rebinding is caught by
                    # the Host check, the token stays unreadable to hostile sites. It therefore
                    # still can't forge /api/* calls — the CSRF/rebinding defense is unchanged.
                    if not self._host_ok() or not self._origin_ok():
                        return self._json(HTTPStatus.FORBIDDEN, {"error": "bad host/origin"})
                    return self._json(HTTPStatus.OK, {"token": token})
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
                    ended = dict(_ENDED)
                    for k, v in _RUNS.items():
                        if v.poll() is not None:  # finished on its own (still tracked)
                            ended[k] = {"how": "exited", "rc": v.returncode}
                return self._json(HTTPStatus.OK, {
                    "ok": True,
                    "engagements": [e.name for e in console.discover(target)],
                    "runs": runs,
                    "ended": ended,
                })
            if path == "/api/auth":
                return self._json(HTTPStatus.OK, auth_snapshot())
            parts = path.strip("/").split("/")  # api / engagements / <id> / <verb>
            if len(parts) == 4 and parts[1] == "auth" and parts[3] == "login":
                return self._json(HTTPStatus.OK, login_status(parts[2]))
            if len(parts) == 4 and parts[1] == "engagements":
                eid, verb = parts[2], parts[3]
                eng = engagement_dir(eid)
                if not eng:
                    return self._json(HTTPStatus.NOT_FOUND, {"error": f"no engagement {eid}"})
                if verb == "approvals":
                    pend = eng / "runtime" / "approvals_pending.json"
                    data = console._read_json(pend) or {"pending": []}
                    return self._json(HTTPStatus.OK, data)
                if verb == "coverage":
                    # authoritative per-category run state the console's live view reads
                    data = console._read_json(eng / "coverage_ledger.json") or {"categories": []}
                    return self._json(HTTPStatus.OK, data)
                if verb == "stream":
                    return self._stream_jsonl(eng / "runtime" / "autorun.jsonl", eid=eid)
            return self._json(HTTPStatus.NOT_FOUND, {"error": "unknown api route"})

        def _api_post(self, path: str):
            parts = path.strip("/").split("/")
            if len(parts) == 5 and parts[1] == "auth" and parts[3] == "login" and parts[4] == "code":
                return self._json(HTTPStatus.OK, submit_login_code(parts[2], self._body().get("code", "")))
            if len(parts) == 4 and parts[1] == "auth" and parts[3] == "login":  # api / auth / <p> / login
                return self._json(HTTPStatus.OK, start_login(parts[2]))
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
                if verb == "delete":
                    return self._delete(eid, eng)
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
                _ENDED.pop(eid, None)  # a fresh run: forget how the last one ended
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
                with _RUNS_LOCK:
                    _RUNS.pop(eid, None)
                return self._json(HTTPStatus.OK, {"ok": True, "note": "no running process"})
            try:
                _terminate(proc)
            except Exception as e:  # noqa: BLE001 — surface any platform signal/kill failure
                return self._json(HTTPStatus.OK, {"ok": False, "note": str(e)})
            # drop the handle so /status stops reporting it as a live run right away, and
            # remember it was STOPPED (paused, resumable) rather than finished
            with _RUNS_LOCK:
                _RUNS.pop(eid, None)
                _ENDED[eid] = {"how": "stopped"}
            return self._json(HTTPStatus.OK, {"ok": True, "stopped": proc.pid})

        def _delete(self, eid: str, eng: Path):
            # refuse while a run is live — the operator must stop it first
            with _RUNS_LOCK:
                proc = _RUNS.get(eid)
            if proc and proc.poll() is None:
                return self._json(HTTPStatus.CONFLICT, {"ok": False, "error": "a run is in progress — stop it first"})
            resolved = eng.resolve()
            root = target.resolve()
            # only ever remove a direct child engagement dir under the served root
            if resolved == root or resolved.parent != root or not resolved.is_dir():
                return self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "refusing to delete this path"})
            try:
                _rmtree_robust(resolved)
            except OSError as e:
                # Still failing after clearing read-only bits usually means a file is OPEN
                # (Windows WinError 32): a console tab tailing this engagement's run log, or a
                # run that didn't fully exit. Say so instead of a bare errno.
                msg = str(e)
                if getattr(e, "winerror", None) == 32:
                    msg = ("a file in this engagement is open — close any console tab viewing it "
                           "(or stop its run) and try again · " + msg)
                return self._json(HTTPStatus.OK, {"ok": False, "error": msg})
            with _RUNS_LOCK:
                _RUNS.pop(eid, None)
                _ENDED.pop(eid, None)
            return self._json(HTTPStatus.OK, {"ok": True, "deleted": eid})

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
            if body.get("action") == "set_model":
                if spec.get("model_var") and body.get("model"):
                    os.environ[spec["model_var"]] = str(body["model"]).strip()
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
        def _stream_jsonl(self, path: Path, *, eid=None, max_seconds: int = 1800):
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            deadline = time.time() + max_seconds

            def _run_live() -> bool:
                # The autonomous run is a LOOP: one wrapper process spawns many engine
                # invocations, so its pid stays in _RUNS for the WHOLE run (not just one
                # invocation). Liveness therefore tracks the whole run — True between
                # invocations, False only when the run is truly over. Unknown id → keep the
                # legacy fixed-duration tail.
                if not eid:
                    return True
                with _RUNS_LOCK:
                    proc = _RUNS.get(eid)
                return bool(proc and proc.poll() is None)

            f = None
            try:
                self.wfile.write(b": connected\n\n")
                self.wfile.flush()
                if not path.is_file():
                    # no run log yet — say so and close rather than holding the socket open
                    self.wfile.write(b": no-run\n\n")
                    self.wfile.flush()
                    return
                f = path.open("r", encoding="utf-8", errors="replace")
                # Replay the CURRENT run (from the last run-boundary marker) so a refresh or
                # late join rebuilds the live view, THEN follow new lines appended after.
                lines = f.readlines()  # reads to EOF; f is now positioned to tail new appends
                start = 0
                for i in range(len(lines) - 1, -1, -1):
                    if lines[i].lstrip().startswith("#"):
                        start = i
                        break
                for ln in lines[start:]:
                    s = ln.rstrip("\n")
                    if s:
                        self.wfile.write(b"data: " + s.encode("utf-8") + b"\n\n")
                self.wfile.flush()
                gone_since = None  # when we first hit EOF with the run no longer live
                while time.time() < deadline:
                    line = f.readline()
                    if line:
                        self.wfile.write(b"data: " + line.rstrip("\n").encode("utf-8") + b"\n\n")
                        self.wfile.flush()
                        gone_since = None
                        continue
                    # At EOF. If the run process has exited (the whole loop is done, NOT just
                    # between invocations), give the writer a short grace to flush its final
                    # lines, then close — so a finished run ends the stream cleanly instead of
                    # holding an idle socket until the deadline. A still-live run keeps tailing.
                    if not _run_live():
                        if gone_since is None:
                            gone_since = time.time()
                        elif time.time() - gone_since > 2.0:
                            break
                    time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError):
                pass  # client went away
            finally:
                try:
                    if f:
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
                        _terminate(proc)
                    except Exception:
                        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
