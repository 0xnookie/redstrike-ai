"""Wrap the repo's deterministic gate (verify_completion.py) + a findings status view."""
from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from . import scope as scopemod
from . import ui
from . import yamlio


def _verify_script(repo_root: Path) -> Path:
    return repo_root / "skills" / "_contract" / "verify_completion.py"


def verify(repo_root: Path, eng_dir: Path, *, skill: str | None = None, as_json: bool = False) -> int:
    script = _verify_script(repo_root)
    if not script.is_file():
        print(ui.err(f"verify_completion.py not found at {script}"))
        return 2
    if skill:
        cmd = [sys.executable, str(script), "--skill", f"skills/{skill}", "--out", str(eng_dir / skill)]
    else:
        cmd = [sys.executable, str(script), "--engagement", str(eng_dir)]
    if as_json:
        cmd.append("--json")
    return subprocess.run(cmd, cwd=str(repo_root), check=False).returncode


_SEV_ORDER = ["critical", "high", "medium", "low", "info", "informational"]


def status(repo_root: Path, eng_dir: Path) -> int:
    print(ui.rule(f"engagement {eng_dir.name}"))

    # scope
    scope_json = eng_dir / "runtime" / "scope.json"
    scope_yaml = eng_dir / "scope.yaml"
    scope = None
    if scope_json.is_file():
        try:
            scope = json.loads(scope_json.read_text(encoding="utf-8"))
        except Exception:
            scope = None
    if scope is None and scope_yaml.is_file():
        try:
            scope = scopemod.build_projection(yamlio.load(scope_yaml))
        except Exception:
            scope = None
    if scope:
        for line in scopemod.summary_lines(scope):
            print(ui.kv(*line.split(" : ", 1)) if " : " in line else f"  {line}")
        open_, why = scopemod.window_open(scope)
        print(ui.ok(why) if open_ else ui.warn(why))
    else:
        print(ui.warn("no scope.yaml / scope.json yet — run `redstrike init`"))

    # findings
    fj = eng_dir / "findings.json"
    if not fj.is_file():
        print(ui.info("no findings.json yet (no consolidated findings recorded)"))
        return 0
    try:
        findings = json.loads(fj.read_text(encoding="utf-8"))
        assert isinstance(findings, list)
    except Exception as e:
        print(ui.err(f"findings.json unreadable: {e}"))
        return 2

    by_sev = Counter(str(f.get("severity", "?")).lower() for f in findings)
    by_status = Counter(str(f.get("status", "?")).lower() for f in findings)
    print(ui.rule("findings"))
    print(ui.kv("total", str(len(findings))))
    sev_line = "  ".join(
        f"{s}={by_sev[s]}" for s in _SEV_ORDER if by_sev[s]
    ) or "none"
    print(ui.kv("by severity", sev_line))
    print(ui.kv("by status", "  ".join(f"{k}={v}" for k, v in sorted(by_status.items())) or "none"))

    reviews = eng_dir / "reviews"
    n_verdicts = len(list(reviews.glob("*.verdict.json"))) if reviews.is_dir() else 0
    print(ui.kv("verdicts", f"{n_verdicts} reviewer verdict file(s)"))
    accepted = sum(1 for f in findings if str(f.get("status", "")).lower() in ("verified", "accepted", "remediated"))
    print(ui.kv("accepted", str(accepted)))
    return 0
