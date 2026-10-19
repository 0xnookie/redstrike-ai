"""Preflight: can we actually launch, and will the engine behave on this host?

Checks the `claude` binary + version floor + auth, the Python/Node runtimes, and the
platform (engagements want WSL2/Linux where the OS sandbox exists; native Windows runs
Bash unsandboxed). Also wraps scripts/doctor.sh for the offensive-tool roster.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import MIN_CLAUDE_VERSION

_VER = re.compile(r"(\d+)\.(\d+)\.(\d+)")


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


def find_bash() -> str | None:
    return shutil.which("bash")


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
