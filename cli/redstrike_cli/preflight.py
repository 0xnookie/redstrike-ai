"""Preflight: can we actually launch, and will the engine behave on this host?

Checks the `claude` binary + version floor + auth, the Python/Node runtimes, and the
platform (engagements want WSL2/Linux where the OS sandbox exists; native Windows runs
Bash unsandboxed). Also wraps scripts/doctor.sh for the offensive-tool roster.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import MIN_CLAUDE_VERSION

_VER = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class Check:
    level: str  # "ok" | "warn" | "err"
    label: str
    detail: str


def _run(cmd: list[str], timeout: int = 20, cwd: str | None = None) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, check=False
        )
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except Exception as e:  # pragma: no cover
        return 1, "", str(e)


def find_claude() -> str | None:
    return shutil.which("claude")


def claude_version(claude_bin: str) -> tuple[int, int, int] | None:
    rc, out, _ = _run([claude_bin, "--version"], timeout=20)
    if rc != 0:
        return None
    m = _VER.search(out)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def version_ok(v: tuple[int, int, int] | None, minimum=MIN_CLAUDE_VERSION) -> bool:
    return v is not None and v >= minimum


def claude_auth(claude_bin: str) -> tuple[bool | None, str]:
    """Best-effort: `claude auth status` exit 0 == logged in. Unknown on older builds."""
    rc, out, err = _run([claude_bin, "auth", "status"], timeout=25)
    s = (out or err or "").strip()
    # Recent builds emit JSON (loggedIn / authMethod), on both exit 0 and nonzero.
    if s.startswith("{"):
        try:
            j = json.loads(s)
            if j.get("loggedIn") is True:
                m = j.get("authMethod")
                return True, "logged in" + (f" ({m})" if m and m != "none" else "")
            if j.get("loggedIn") is False:
                return False, "not logged in — run `claude login` (or set CLAUDE_CODE_OAUTH_TOKEN)"
        except Exception:
            pass
    if rc == 0:
        return True, (s.splitlines()[0] if s else "logged in")
    if rc in (124, 127):
        return None, "could not determine (auth status unavailable)"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True, "ANTHROPIC_API_KEY set (will be billed to the key)"
    if os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        return True, "CLAUDE_CODE_OAUTH_TOKEN set"
    return False, (s.splitlines()[0] if s else "not logged in — run `claude auth login`")


def is_windows() -> bool:
    return os.name == "nt"


def is_wsl() -> bool:
    if sys.platform != "linux":
        return False
    try:
        rel = platform.uname().release.lower()
        if "microsoft" in rel or "wsl" in rel:
            return True
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower()
    except Exception:
        return False


def sandbox_deps() -> tuple[bool, list[str]]:
    missing = [t for t in ("bwrap", "socat") if not shutil.which(t)]
    return (not missing), missing


def sandbox_status() -> tuple[bool, str]:
    """Is OS-level network confinement actually available on THIS host? (ok, detail).

    When False, the sandbox.network allowlist the launcher writes cannot be enforced and the
    (input-matching, best-effort) scope gate is the only boundary — the run path surfaces this
    as a visible banner rather than leaving it buried in `doctor`."""
    if is_windows():
        return (False, "native Windows has NO OS sandbox — network confinement is OFF; the scope "
                       "gate (matches tool input) is the ONLY boundary. Run engagements in WSL2/Linux.")
    ok, missing = sandbox_deps()
    if not ok:
        return (False, f"OS sandbox deps missing ({', '.join(missing)}) — network confinement is "
                       f"LIMITED; install them, or the scope gate is the only boundary.")
    return (True, "OS sandbox network confinement available")


def find_bash() -> str | None:
    return shutil.which("bash")


def lib_present(mod: str) -> bool:
    """Is an importable Python module present, WITHOUT importing it (so a broken optional dep never
    aborts preflight)? Used to surface `jsonschema` / PyYAML — both have bundled stdlib fallbacks, so
    an absence is a ``warn`` (degraded to the built-in reader), never a blocking ``err``."""
    try:
        import importlib.util
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


def run_doctor(repo_root: Path, args: list[str] | None = None) -> tuple[int, str]:
    """Invoke scripts/doctor.sh (needs bash). Returns (exit_code, combined_output)."""
    script = repo_root / "scripts" / "doctor.sh"
    bash = find_bash()
    if not script.is_file():
        return 2, f"doctor.sh not found at {script}"
    if not bash:
        return 127, "bash not found — run `scripts/doctor.sh` on a Linux/WSL2 host"
    rc, out, err = _run([bash, str(script), *(args or [])], timeout=120, cwd=str(repo_root))
    return rc, (out + ("\n" + err if err else ""))


def exec_live(cmd: list[str], cwd: str | None = None) -> int:
    """Run a long-running / interactive command with INHERITED stdio (so the user sees live
    progress and can answer sudo/apt prompts). Returns its exit code."""
    try:
        return subprocess.run(cmd, cwd=cwd, check=False).returncode
    except KeyboardInterrupt:
        return 130
    except FileNotFoundError:
        return 127


def gather(repo_root: Path) -> list[Check]:
    checks: list[Check] = []

    claude_bin = find_claude()
    if not claude_bin:
        checks.append(Check("err", "claude CLI", "not on PATH — install Claude Code (see INSTALL.md)"))
    else:
        v = claude_version(claude_bin)
        vs = ".".join(map(str, v)) if v else "?"
        if version_ok(v):
            checks.append(Check("ok", "claude CLI", f"{claude_bin} (v{vs})"))
        else:
            need = ".".join(map(str, MIN_CLAUDE_VERSION))
            checks.append(Check("err", "claude CLI", f"v{vs} < required v{need} — update Claude Code"))
        authed, detail = claude_auth(claude_bin)
        lvl = "ok" if authed else ("warn" if authed is None else "err")
        checks.append(Check(lvl, "claude auth", detail))

    pv = sys.version_info
    checks.append(Check("ok", "python", f"{pv.major}.{pv.minor}.{pv.micro}"))

    # Optional Python validators: jsonschema (authoritative full-spec finding/schema validation) and
    # PyYAML (exact scope.yaml parsing). Both have bundled stdlib fallbacks, so absence is degraded, not
    # fatal — surface it as a `warn` with the install hint so operators know full-spec validation is off.
    for mod, label, why in (
        ("jsonschema", "python: jsonschema", "full-spec finding/schema validation"),
        ("yaml", "python: PyYAML", "exact scope.yaml parsing"),
    ):
        if lib_present(mod):
            checks.append(Check("ok", label, "present"))
        else:
            checks.append(Check(
                "warn", label,
                f"not installed — stdlib fallback in use for {why}; "
                f"`pip install 'redstrike-cli[validate]'` enables the full validator",
            ))

    node = shutil.which("node")
    checks.append(
        Check("ok", "node", node) if node else Check("warn", "node", "absent (subagents/Playwright/MCP use Node)")
    )

    if is_windows():
        checks.append(
            Check("warn", "platform", "native Windows has NO OS sandbox — run engagements in WSL2/Linux")
        )
    else:
        tag = "WSL2" if is_wsl() else "Linux/Unix"
        ok, missing = sandbox_deps()
        if ok:
            checks.append(Check("ok", "platform", f"{tag}; sandbox deps present (bwrap, socat)"))
        else:
            checks.append(
                Check("warn", "platform", f"{tag}; sandbox deps missing: {', '.join(missing)} (network boundary limited)")
            )
    return checks


def blocking(checks: list[Check]) -> list[Check]:
    return [c for c in checks if c.level == "err"]


# --- toolchain capability snapshot -------------------------------------------
# The recon/web discovery JOBS the engagement actually needs, each a PRIMARY tool plus ordered
# fallbacks (drawn from scripts/tools.manifest recon/web categories). A capability is a job, not a
# bare binary: a missing primary (httpx/dnsx/subfinder/naabu — the go/bin modern-first set) means a
# SILENT fall back to a lesser tool (nmap/dig/curl/gobuster). This snapshot makes that visible.
TOOLING_CAPABILITIES: list[tuple[str, str, list[str]]] = [
    ("subdomain-enum",    "subfinder", ["amass", "assetfinder", "findomain", "dnsenum", "fierce"]),
    ("dns-resolve",       "dnsx",      ["dig", "host", "nslookup"]),
    ("http-probe",        "httpx",     ["curl", "wget"]),
    ("port-scan",         "naabu",     ["nmap", "masscan", "rustscan"]),
    ("content-discovery", "ffuf",      ["feroxbuster", "gobuster", "dirsearch", "dirb"]),
]


def tooling_probe_prefix() -> list[str]:
    """How to ask the REAL execution environment whether a command exists. On Windows the pentest
    toolkit lives in WSL, so route `command -v` through `wsl.exe -e bash -lc` rather than the launcher's
    own (Windows) PATH; on Linux/WSL probe the local login shell.

    The `-e` (exec) separator is REQUIRED: `wsl.exe bash -lc '<script>'` without it lets wsl.exe
    re-parse the trailing tokens, mangling any script containing spaces / `;` / `(` / quotes — the
    probe then returns rc 1 with no output, so EVERY capability reads as degraded-with-no-fallback
    even when the tools are present. `wsl.exe -e …` passes the command vector through intact."""
    if is_windows():
        return ["wsl.exe", "-e", "bash", "-lc"]
    return ["bash", "-lc"]


def _probe_present(tools: list[str], prefix: list[str]) -> set[str]:
    """Return the subset of `tools` present in the probed environment, in ONE shell invocation (the
    shell prints the name of each tool that resolves). Best-effort: on any failure — no WSL, no bash,
    a timeout — returns the empty set (so every capability reads as degraded, which is the honest,
    fail-loud default rather than a false 'present')."""
    uniq = [t for t in dict.fromkeys(tools) if t]
    if not uniq:
        return set()
    script = 'for t in %s; do command -v "$t" >/dev/null 2>&1 && printf "%%s\\n" "$t"; done' % (
        " ".join(shlex.quote(t) for t in uniq))
    rc, out, _ = _run([*prefix, script], timeout=30)
    if not out:
        return set()
    allow = set(uniq)
    return {ln.strip() for ln in out.splitlines() if ln.strip() in allow}


def tooling_snapshot(repo: Path | None = None, *, shell=None) -> dict:
    """Probe the REAL execution environment for each recon/web capability's primary + fallbacks and
    classify it ``ok`` (primary present) or ``degraded`` (primary absent → a fallback, or nothing, in
    use). Emits per-CAPABILITY results plus an ``overall`` rollup, written to ``runtime/tooling.json``
    by :func:`write_tooling`.

    ``shell`` overrides how presence is probed (the test seam): a command-PREFIX list such as
    ``["bash", "-lc"]``, or a callable taking the tool-name list and returning the set of present
    names. ``repo`` is accepted for symmetry with the other preflight entry points (the roster is
    fixed, not read from the repo) and is currently unused.
    """
    all_tools: list[str] = []
    for _, primary, fbs in TOOLING_CAPABILITIES:
        all_tools.append(primary)
        all_tools.extend(fbs)

    if callable(shell):
        present = set(shell(list(dict.fromkeys(all_tools))))
        probe_desc = "injected"
    else:
        prefix = list(shell) if shell else tooling_probe_prefix()
        present = _probe_present(all_tools, prefix)
        probe_desc = " ".join(prefix)

    caps: list[dict] = []
    degraded = 0
    for name, primary, fbs in TOOLING_CAPABILITIES:
        has_primary = primary in present
        fallback = None
        if not has_primary:
            degraded += 1
            fallback = next((f for f in fbs if f in present), None)
        caps.append({
            "capability": name,
            "primary": primary,
            "present": has_primary,
            # the fallback actually AVAILABLE when the primary is absent (None = none present);
            # null when the primary is present (no fallback needed).
            "fallback": fallback,
            "status": "ok" if has_primary else "degraded",
        })
    return {
        "generated_at": _now_iso(),
        "probe": probe_desc,
        "capabilities": caps,
        "overall": {"degraded_count": degraded, "status": "degraded" if degraded else "ok"},
    }


def write_tooling(eng_dir: Path, snapshot: dict) -> Path:
    """Persist a tooling snapshot to ``<engagement>/runtime/tooling.json`` (creates ``runtime/``).
    Returns the path written."""
    eng_dir = Path(eng_dir)
    runtime = eng_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    path = runtime / "tooling.json"
    path.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    return path
