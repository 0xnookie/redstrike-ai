"""Autonomous (headless `-p`) run: stream Claude Code's events, show progress, summarize.

Merges stderr into stdout and skips non-JSON lines, so a chatty warning can't deadlock
the pipe. Every raw event is teed to runtime/autorun.jsonl as the run's audit trail.
"""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import approvals as approvalsmod
from . import ui


@dataclass
class RunSummary:
    subtype: str = ""
    num_turns: int = 0
    cost_usd: float = 0.0
    stop_reason: str = ""
    skills_loaded: int = 0
    tool_calls: int = 0
    denials: list = field(default_factory=list)
    deferred: list = field(default_factory=list)
    result_text: str = ""


_INPUT_KEYS = ("command", "url", "file_path", "pattern", "path", "description", "prompt")


def _tool_uses(obj: dict):
    msg = obj.get("message") or {}
    for b in msg.get("content") or []:
        if isinstance(b, dict) and b.get("type") == "tool_use":
            yield b.get("name", ""), (b.get("input") or {})


def _short_input(inp: dict) -> str:
    for k in _INPUT_KEYS:
        if k in inp:
            v = str(inp[k]).replace("\n", " ")
            return (v[:70] + "…") if len(v) > 71 else v
    return ""


def handle_event(o: dict, s: RunSummary, stream) -> None:
    t = o.get("type")
    if t == "system" and o.get("subtype") == "init":
        sc = o.get("slash_commands") or []
        s.skills_loaded = sum(1 for x in sc if "redstrike" in str(x).lower())
        print(
            ui.info(
                f"engine up · model {o.get('model')} · {s.skills_loaded} redstrike skills · "
                f"mcp {len(o.get('mcp_servers') or [])}"
            ),
            file=stream,
        )
    elif t == "assistant":
        for name, inp in _tool_uses(o):
            s.tool_calls += 1
            si = _short_input(inp)
            arrow = ui.style("→", ui.CYAN, stream=stream)
            tail = f"  {ui.style(si, ui.DIM, stream=stream)}" if si else ""
            print(f"  {arrow} {name}{tail}", file=stream)
    elif t == "result":
        s.subtype = o.get("subtype", "")
        s.num_turns = o.get("num_turns", 0)
        s.cost_usd = o.get("total_cost_usd", 0.0) or 0.0
        s.stop_reason = o.get("stop_reason", "")
        s.denials = o.get("permission_denials") or []
        d = o.get("deferred_tool_use")
        if d:
            s.deferred = d if isinstance(d, list) else [d]
        s.result_text = o.get("result") or ""


def _print_summary(s: RunSummary, rc: int, stream) -> None:
    print("", file=stream)
    print(ui.rule("autonomous run summary", stream=stream), file=stream)
    good = s.subtype == "success"
    head = f"outcome: {s.subtype or 'unknown'}  (stop: {s.stop_reason or '-'}, exit {rc})"
    print((ui.ok if good else ui.warn)(head, stream=stream), file=stream)
    print(ui.kv("turns", str(s.num_turns), stream=stream), file=stream)
    print(ui.kv("cost", f"${s.cost_usd:.4f}", stream=stream), file=stream)
    print(ui.kv("tool calls", str(s.tool_calls), stream=stream), file=stream)
    print(ui.kv("denied", str(len(s.denials)), stream=stream), file=stream)
    for d in s.denials[:5]:
        nm = (d or {}).get("tool_name") or (d or {}).get("name") or "?"
        print(f"    {ui.style('✗', ui.RED, stream=stream)} {nm}", file=stream)
    if s.deferred:
        print(ui.warn(f"{len(s.deferred)} action(s) deferred for approval", stream=stream), file=stream)
        for d in s.deferred[:5]:
            inp = (d or {}).get("input") or {}
            what = inp.get("command") or inp.get("url") or (d or {}).get("name", "?")
            print(f"    • {str(what)[:90]}", file=stream)
        print(ui.info("review + approve: `redstrike approve <eng>`  →  `redstrike run <eng> --autonomous --resume`", stream=stream), file=stream)
    if s.result_text.strip():
        print(ui.kv("note", s.result_text.strip().splitlines()[0][:120], stream=stream), file=stream)


def run_autonomous(
    claude_bin: str, argv: list[str], cwd: Path, audit_path: Path, pending_path: Path | None = None, stream=None
) -> tuple[int, RunSummary]:
    stream = stream or sys.stdout
    s = RunSummary()
    try:
        audit = open(audit_path, "a", encoding="utf-8")  # append: keep the chain of custody across resumes
        audit.write(f"# --- redstrike autonomous run {_dt.datetime.now(_dt.timezone.utc).isoformat()} ---\n")
    except Exception:
        audit = None
    try:
        proc = subprocess.Popen(
            argv, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, encoding="utf-8", errors="replace",
        )
    except FileNotFoundError:
        print(ui.err("`claude` not found on PATH", stream=stream), file=stream)
        if audit:
            audit.close()
        return 127, s
    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            if audit:
                audit.write(raw)
            line = raw.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            handle_event(o, s, stream)
    except KeyboardInterrupt:
        proc.terminate()
        print(ui.warn("interrupted — terminating engine", stream=stream), file=stream)
    rc = proc.wait()
    if audit:
        audit.close()
    if s.deferred and pending_path is not None:
        approvalsmod.record_deferred(pending_path, s.deferred)
    _print_summary(s, rc, stream)
    return rc, s
