"""Render runtime/roe.md — appended to Claude Code's system prompt at launch.

Defense in depth with the scope-gate hook: the hook mechanically blocks, this tells
the model the rules up front AND that authorization intake is already satisfied, so a
launched session doesn't stall re-asking for a go-ahead it cannot collect headlessly.
"""
from __future__ import annotations

from . import scope as scopemod


def render_roe(scope: dict, engagement_id: str, *, autonomous: bool = False) -> str:
    rules = scope.get("rules", {}) or {}
    ins = scope.get("in_scope", {}) or {}
    out = scope.get("out_of_scope", {}) or {}
    phases = ", ".join(rules.get("approval_required_phases", []) or []) or "exploitation, post-exploitation"

    def _lines(items):
        return "\n".join(f"  - {i}" for i in items) if items else "  - (none)"

    autonomous_note = (
        """
## AUTONOMOUS run — no human is watching
You are running headless with no interactive approval available. Do recon and
non-destructive analysis, drive the recon/context skills and their reviewer subagents,
and record findings. When you reach an **approval-gated phase** ({phases}) or ANY
destructive / RCE-class / data-modifying action, **STOP and summarize** what you would
do next and why it needs sign-off — do NOT proceed. Shell/offensive tools are not
pre-approved; a tool the operator did not allow will simply be denied, so note it and
move on rather than retrying.
""".format(phases=phases)
        if autonomous
        else ""
    )

    win = scope.get("window", {})
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
"""
