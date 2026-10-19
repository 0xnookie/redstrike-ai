"""Scope projection + checks.

scope.yaml is the signed canonical authorization record. The launcher derives a
machine-readable runtime/scope.json from it (re-derived on every `run`, so the YAML
stays the single edit surface) which the PreToolUse scope gate consumes. Keeping the
gate on JSON means the enforcement path is stdlib-only and never parses YAML live.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from . import yamlio


def _to_iso(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, _dt.datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=_dt.timezone.utc)
        return v.astimezone(_dt.timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(v, _dt.date):
        return v.isoformat()
    return str(v)


def parse_iso(s: str) -> _dt.datetime | None:
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    try:
        d = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=_dt.timezone.utc)
    return d


def _strlist(v: Any) -> list[str]:
    if not v:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if x is not None]
    return [str(v)]


def build_projection(scope_yaml: dict) -> dict:
    ins = scope_yaml.get("in_scope", {}) or {}
    out = scope_yaml.get("out_of_scope", {}) or {}
    win = scope_yaml.get("window", {}) or {}
    oob = scope_yaml.get("oob", {}) or {}
    return {
        "engagement": str(scope_yaml.get("engagement", "")),
        "authorized_by": str(scope_yaml.get("authorized_by", "")),
        "window": {"start": _to_iso(win.get("start")), "end": _to_iso(win.get("end"))},
        "in_scope": {
            "domains": _strlist(ins.get("domains")),
            "cidrs": _strlist(ins.get("cidrs")),
            "urls": _strlist(ins.get("urls")),
        },
        "out_of_scope": {
            "domains": _strlist(out.get("domains")),
            "cidrs": _strlist(out.get("cidrs")),
            "urls": _strlist(out.get("urls")),
        },
        "rules": scope_yaml.get("rules", {}) or {},
        "oob": {"collaborator": str(oob.get("collaborator", ""))},
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "scope.yaml",
    }


def derive_scope_json(scope_yaml_path: str | Path, out_json_path: str | Path) -> dict:
    data = yamlio.load(scope_yaml_path)
    proj = build_projection(data)
    Path(out_json_path).write_text(json.dumps(proj, indent=2) + "\n", encoding="utf-8")
    return proj


def window_open(scope: dict, now: _dt.datetime | None = None) -> tuple[bool, str]:
    now = now or _dt.datetime.now(_dt.timezone.utc)
    win = scope.get("window", {}) or {}
    start, end = parse_iso(win.get("start", "")), parse_iso(win.get("end", ""))
    if start is None or end is None:
        return False, "engagement window is missing or unparseable"
    if now < start:
        return False, f"engagement window has not opened yet (starts {win.get('start')})"
    if now > end:
        return False, f"engagement window has closed (ended {win.get('end')})"
    return True, "window open"


def is_complete(scope: dict) -> tuple[bool, list[str]]:
    """A scope is launchable only if authorization + a target + a window are present."""
    problems = []
    if not scope.get("authorized_by") or scope["authorized_by"].startswith("<"):
        problems.append("authorized_by is not filled in")
    ins = scope.get("in_scope", {}) or {}
    if not (ins.get("domains") or ins.get("cidrs") or ins.get("urls")):
        problems.append("in_scope has no domains/cidrs/urls")
    win = scope.get("window", {}) or {}
    if not win.get("start") or not win.get("end"):
        problems.append("window.start/end missing")
    return (not problems), problems


def summary_lines(scope: dict) -> list[str]:
    ins = scope.get("in_scope", {}) or {}
    out = scope.get("out_of_scope", {}) or {}
    in_count = len(ins.get("domains", [])) + len(ins.get("cidrs", [])) + len(ins.get("urls", []))
    out_count = len(out.get("domains", [])) + len(out.get("cidrs", []))
    rules = scope.get("rules", {}) or {}
    phases = ", ".join(rules.get("approval_required_phases", []) or []) or "none"
    return [
        f"engagement : {scope.get('engagement', '?')}",
        f"authz      : {scope.get('authorized_by', '?')}",
        f"window     : {scope.get('window', {}).get('start', '?')} .. {scope.get('window', {}).get('end', '?')}",
        f"in-scope   : {in_count} target(s)  ({', '.join(ins.get('domains', [])[:4]) or '—'})",
        f"excludes   : {out_count}",
        f"rules      : no_dos={rules.get('no_dos', True)} rate={rules.get('rate_limit_rps', '?')}rps "
        f"approval=[{phases}]",
    ]
