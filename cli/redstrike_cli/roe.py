"""Render runtime/roe.md — appended to Claude Code's system prompt at launch.

Defense in depth with the scope-gate hook: the hook mechanically blocks, this tells
the model the rules up front AND that authorization intake is already satisfied, so a
launched session doesn't stall re-asking for a go-ahead it cannot collect headlessly.
"""
from __future__ import annotations

from pathlib import Path

from . import scope as scopemod

# Canonical always-on anti-pattern reminder. The markdown file is the single source of truth; this module
# reads it and folds it into the appended prompt so every launched leg (autonomous AND interactive) carries
# the cross-cutting discipline — the recurring mistakes avoided BEFORE the reviewer, not only at verify time.
_DISCIPLINE_PATH = Path(__file__).resolve().parents[2] / "skills" / "_contract" / "engagement-discipline.md"

# Terse inline fallback so the appended prompt never loses the block if the contract file is unreadable
# (broken install / relocated module). Kept in sync in spirit with the markdown; the file wins when present.
_DISCIPLINE_FALLBACK = """## Engagement discipline — always-on anti-pattern reminders
- Reflection is not execution — prove the sink actually ran the input.
- IDOR / BOLA need two distinct identities (account A reaching account B's resource).
- A WAF/403 means the path EXISTS, not that it is vulnerable — pivot, don't bypass.
- Error-message / behaviour divergence is a SIGNAL, not a finding — confirm the bug.
- Prove blind bugs with an attributable OOB callback or controlled timing — quantify, don't guess.
- Benign PoC only; defer destructive / exploit / RCE steps to the approval gate.
- A feeder-class finding is not a report until chained or ruled out — never silently dropped."""


def _discipline_block() -> str:
    """Return the always-on anti-pattern reminder, folded in as an `##` section.

    Reads the canonical contract file and demotes its standalone `#` title to `##` so it slots into the
    RoE's `##`-section structure; falls back to a terse inline copy if the file can't be read.
    """
    try:
        text = _DISCIPLINE_PATH.read_text(encoding="utf-8").strip()
    except Exception:
        return _DISCIPLINE_FALLBACK
    if text.startswith("# "):
        text = "#" + text  # demote the standalone H1 to an `##` section within the appended prompt
    return text


def render_roe(scope: dict, engagement_id: str, *, autonomous: bool = False) -> str:
    rules = scope.get("rules", {}) or {}
    ins = scope.get("in_scope", {}) or {}
    out = scope.get("out_of_scope", {}) or {}
    phases = ", ".join(rules.get("approval_required_phases", []) or []) or "exploitation, post-exploitation"

    def _lines(items):
        return "\n".join(f"  - {i}" for i in items) if items else "  - (none)"

    autonomous_note = (
        """
## AUTONOMOUS run
You run the FULL engagement end to end within scope — do NOT stop after recon. Complete recon,
build the coverage + surface + **notebook** ledgers, then hunt EVERY routed vulnerability class
(non-destructive detection with a benign PoC — xss, sqli, idor, ssrf, and the rest), each through
its context feeder and its independent reviewer subagent; re-converge, run the recall-audit, then
chain accepted findings and assemble the report. Record findings as you go.

For the approval-gated phases ({phases}) and any destructive / RCE step: if a command was not
pre-allowed it is **deferred for operator approval**. When that happens, record it, SKIP that step
for now, and CONTINUE other in-scope, non-gated work — the operator approves pending items and the
run resumes. A deferral is the intended gate, not an error, and is NEVER a reason to stop the whole
run; do not retry it or route around the gate. Anything out of scope, or outside the window, is a
HARD STOP.
""".format(phases=phases)
        if autonomous
        else ""
    )

    win = scope.get("window", {})
    discipline = _discipline_block()
    return f"""# Redstrike engagement — operating context (launcher-injected)
{autonomous_note}

You are running under the **redstrike CLI** for engagement `{engagement_id}`. This is a
real, authorized offensive security test. The canonical scope + authorization record is
`engagements/{engagement_id}/scope.yaml`; a machine copy is `runtime/scope.json`.

## Authorization — ALREADY ESTABLISHED (do not re-ask)
The operator confirmed written authorization and recorded scope at launcher start, which
is the human go-ahead the RoE gate (`skills/_contract/roe-gate.md`) requires.
- authorized_by: {scope.get('authorized_by', '?')}
- window: {win.get('start', '?')} .. {win.get('end', '?')} (confirmed open at launch)

Treat the orchestrator's §0 authorization-and-scope intake as **SATISFIED**. Do NOT pause
to ask for authorization or a go-ahead for active scanning. Only STOP if `scope.yaml` is
missing/incomplete, the window is closed, or a target falls outside scope.

## In scope
  domains:
{_lines(ins.get('domains', []))}
  cidrs:
{_lines(ins.get('cidrs', []))}
  urls:
{_lines(ins.get('urls', []))}

## Out of scope (explicit excludes — these ALWAYS win)
  domains:
{_lines(out.get('domains', []))}
  cidrs:
{_lines(out.get('cidrs', []))}

## Rules of engagement
- no_dos: {rules.get('no_dos', True)} · no_destructive: {rules.get('no_destructive', True)} · rate_limit: {rules.get('rate_limit_rps', '?')} rps
- Approval-gated phases (pause for explicit human approval before the first active action): {phases}
- Anything out of scope or outside the window ⇒ **HARD STOP**.

## Guardrails you are running under
- A PreToolUse **scope gate** is active: it denies tool calls that reach an out-of-scope
  asset and blocks writes to `runtime/` and `scope.yaml`. Do not attempt to edit, disable,
  or work around it; if it denies something you believe is in scope, surface it to the
  operator to fix `scope.yaml` rather than routing around it.
- Write evidence, findings and PoCs under the engagement directory (the chain of custody).

{discipline}
"""
