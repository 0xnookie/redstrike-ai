"""Approval store for autonomous deferrals.

Both files live in the engagement's `runtime/` (launcher-owned; the agent is denied
writing there by the scope gate + settings deny rules):
  approvals.json          = {"approved": [<fingerprint>, ...]}   — the hook reads this
  approvals_pending.json  = [{fingerprint, tool_name, summary, deferred_at}, ...]

A deferral the hook raised lands in pending; `redstrike approve` moves chosen ones into
approvals; on `--resume` the hook sees the fingerprint and lets that exact call run.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from .hooks.scope_gate import fingerprint  # identical to the hook's — must match


def _load(path: str | Path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def _save(path: str | Path, data) -> None:
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def ensure_files(approvals_path: str | Path, pending_path: str | Path) -> None:
    if not Path(approvals_path).exists():
        _save(approvals_path, {"approved": []})
    if not Path(pending_path).exists():
        _save(pending_path, [])


def _summary(name: str, inp: dict) -> str:
    inp = inp or {}
    for k in ("command", "url", "file_path", "description"):
        if inp.get(k):
            return f"{name}: {str(inp[k])[:140]}"
    return name


def record_deferred(pending_path: str | Path, deferred_items) -> int:
    """Merge deferred_tool_use items into pending (dedupe by fingerprint). Returns # added."""
    pending = _load(pending_path, [])
    have = {p.get("fingerprint") for p in pending}
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    added = 0
    for d in deferred_items or []:
        name = (d or {}).get("name", "")
        inp = (d or {}).get("input", {}) or {}
        fp = fingerprint(name, inp)
        if fp in have:
            continue
        command = inp.get("command") or inp.get("url") or ""
        pending.append({"fingerprint": fp, "tool_name": name, "command": command,
                        "summary": _summary(name, inp), "deferred_at": now})
        have.add(fp)
        added += 1
    _save(pending_path, pending)
    return added


def list_pending(pending_path: str | Path) -> list[dict]:
    return _load(pending_path, [])


def approve(approvals_path: str | Path, pending_path: str | Path, fingerprints) -> list[dict]:
    """Move the given fingerprints from pending → approved. Also queue the commands for the
    next --resume (so the launcher can tell the model exactly what it may re-run). The hook
    only reads `approved`; `resume_queue` is the launcher's. Returns the moved entries."""
    pending = _load(pending_path, [])
    appr = _load(approvals_path, {"approved": []})
    approved_set = set(appr.get("approved", []) or [])
    queue = list(appr.get("resume_queue", []) or [])
    want = set(fingerprints)
    moved, remaining = [], []
    for p in pending:
        if p.get("fingerprint") in want:
            approved_set.add(p.get("fingerprint"))
            queue.append({"fingerprint": p.get("fingerprint"), "command": p.get("command", ""),
                          "summary": p.get("summary", "")})
            moved.append(p)
        else:
            remaining.append(p)
    appr["approved"] = sorted(approved_set)
    appr["resume_queue"] = queue
    _save(approvals_path, appr)
    _save(pending_path, remaining)
    return moved


def take_resume_queue(approvals_path: str | Path) -> list[dict]:
    """Return and CLEAR the queue of approved-but-not-yet-resumed actions."""
    appr = _load(approvals_path, {"approved": []})
    q = list(appr.get("resume_queue", []) or [])
    if q:
        appr["resume_queue"] = []
        _save(approvals_path, appr)
    return q
