#!/usr/bin/env python3
"""Redstrike PreToolUse never-submit → chain-anchor gate — a Claude Code hook (BUG-BOUNTY ONLY).

WHY this exists: bug-bounty programs routinely CLOSE / mark NOT-APPLICABLE a set of classes when they are
reported ALONE — missing security headers, self-XSS, a bare open-redirect, a CORS wildcard with no
credentialed read, a blind/DNS-only SSRF, clickjacking on a trivial action, a version/banner disclosure.
A triager rejects "no impact", and a wall of such reports burns the researcher's reputation on the program.
`skills/bug-bounty/refs/report_quality.md` + `skills/attack-chain-discovery/refs/chain_anchors.md` are
clear: these are FEEDERS — only worth submitting once CHAINED to demonstrated impact. This gate catches a
SUBMISSION draft that reports one of these signals WITHOUT chain language and DENIES it, returning the
specific chain anchor to pursue (from `skills/bug-bounty/refs/never_submit.md`).

CRITICAL SCOPING (this is the whole safety of the guard): it fires ONLY for a BUG-BOUNTY engagement — a
`mission: bug-bounty` marker in scope.json, or a `program_scope.json` in the engagement dir — AND only on a
SUBMISSION draft (a file under `submissions/`). A redstrike PENTEST report legitimately includes
informational findings (missing headers, version disclosure) for the client's defence-in-depth, so outside
a bug-bounty engagement, and for any non-submission file, the gate NO-OPs. It must NEVER fire on a pentest.

HONESTY / fail direction: a quality net, not a boundary — it FAILS OPEN. Any internal error, missing
scope, or ambiguity ⇒ PASS. It only DENIES when it POSITIVELY sees a never-submit signal in a bug-bounty
submission draft AND finds no chain/impact language. "Chain language present" is the escape hatch: the
moment the draft demonstrates the escalation, it is a real submission and passes.

Decision contract (same shape as scope_gate): on DENY print a PreToolUse JSON decision to stdout and
exit 0; on PASS print nothing and exit 0. Any internal error ⇒ PASS (fail open).

Usage (wired by the launcher into settings.json):
  python never_submit_gate.py --scope <engagement>/runtime/scope.json  < payload.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

_WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")

# Never-submit signals → (detector regex, the chain anchor to pursue). The anchors mirror
# skills/bug-bounty/refs/never_submit.md. Each regex is a POSITIVE signal that the draft is reporting that
# class; the chain-language escape hatch below is what makes a chained draft pass.
_SIGNALS: list[tuple[str, "re.Pattern[str]", str]] = [
    ("missing-headers-alone",
     re.compile(r"(?i)\b(missing|absent|no)\b[^.\n]{0,40}\b(security header|x-frame-options|"
                r"content-security-policy|\bcsp\b|strict-transport-security|\bhsts\b|x-content-type-options)"),
     "pursue a PoC: XFO/frame-ancestors gap → a framed sensitive state-changing action (clickjacking); "
     "HSTS gap → an MITM/downgrade scenario (auth-bypass). A missing header alone is a best-practice note."),
    ("self-xss",
     re.compile(r"(?i)\bself[\s\-]?xss\b"),
     "pursue a delivery vector that makes ANOTHER user execute it: CSRF-to-set the value, login-CSRF, or a "
     "stored sink rendered to an admin (csrf → xss-stored / auth-bypass). Self-XSS has no victim."),
    ("open-redirect-alone",
     re.compile(r"(?i)\bopen[\s\-]?redirect(ion)?\b"),
     "pursue OAuth/OIDC redirect_uri reflection → auth code to attacker domain → ATO, or a token/code in "
     "the redirected URL (oauth). A bare external redirect is low/no impact."),
    ("cors-wildcard-no-impact",
     re.compile(r"(?i)(\bcors\b|access-control-allow-origin)[^.\n]{0,60}"
                r"(wildcard|:\s*\*|\breflect)|\bacao\b"),
     "pursue a credentialed endpoint (ACAC:true) reflecting the attacker origin that reads sensitive data "
     "cross-origin (cors → bola-bfla/idor). A wildcard ACAO without a credentialed read is cosmetic."),
    ("blind-dns-only-ssrf",
     re.compile(r"(?i)\bssrf\b[^.\n]{0,60}(blind|dns[\s\-]?only|dns\s+(ping|callback|lookup)|"
                r"oob\s+dns|interactsh|collaborator)|\b(dns[\s\-]?only|blind)\b[^.\n]{0,30}\bssrf\b"),
     "pursue HTTP reach: cloud metadata → IAM creds (ssrf-cloud), or an internal admin/API the server can "
     "hit (ssrf-inband). A DNS-only OOB ping does not prove exploitable reach."),
    ("clickjacking-no-impact",
     re.compile(r"(?i)\bclickjack(ing)?\b"),
     "frame a SENSITIVE state-changing action (email/password/role/payment change) and drive it via UI "
     "redress. Clickjacking on a trivial action is no loss."),
    ("version-disclosure",
     re.compile(r"(?i)\b(version|banner|software[\s\-]version)\s+disclosure\b|"
                r"\bdiscloses?\b[^.\n]{0,30}\bversion\b"),
     "pursue a version-matched, reachable CVE on THAT exact version → the matching exploit path "
     "(cve-intelligence → the component executor). A leaked version is a recon aid, not a finding."),
]

# Chain / demonstrated-impact language — the escape hatch. If any of these is present, the draft is treated
# as showing the escalation (a real submission) and the gate passes.
_CHAIN_LANGUAGE = re.compile(
    r"(?i)\b(chain(ed|ing)?|kill[\s\-]?chain|leads?\s+to|escalat(e|es|ed|ion)|"
    r"account\s+takeover|\bato\b|combined\s+with|pivot(s|ed)?\s+to|results?\s+in|"
    r"enabl(e|es|ed)\b|which\s+allows|thereby|used\s+to)\b"
    r"|\bchain-[0-9]{3,}\b"
)


# --- bug-bounty detection (pure) --------------------------------------------
def is_bug_bounty(eng_dir: Path | None, scope: dict | None) -> bool:
    """True ONLY for a bug-bounty engagement — the scope.json carries a bug-bounty `mission` marker, or a
    `program_scope.json` exists in the engagement dir. Everything else (a pentest) is NOT bug-bounty."""
    if isinstance(scope, dict):
        for key in ("mission", "engagement_type", "type"):
            v = str(scope.get(key) or "").strip().lower()
            if "bug" in v and "bount" in v:
                return True
        rules = scope.get("rules")
        if isinstance(rules, dict):
            v = str(rules.get("mission") or "").strip().lower()
            if "bug" in v and "bount" in v:
                return True
    if eng_dir:
        try:
            if (Path(eng_dir) / "program_scope.json").is_file():
                return True
        except Exception:
            pass
    return False


def is_submission_draft(path: Path, eng_dir: Path | None) -> bool:
    """True when the write targets a bug-bounty SUBMISSION draft — a file under a `submissions/` dir, or a
    `submission*.md` basename. (Inside the engagement dir when the dir is known.)"""
    try:
        rp = path.resolve()
    except Exception:
        rp = path
    parts = [x.lower() for x in rp.parts]
    name = rp.name.lower()
    if "submissions" in parts or "submission" in parts:
        in_dir = True
    elif name.startswith("submission") and name.endswith((".md", ".txt")):
        in_dir = True
    else:
        return False
    if eng_dir:
        try:
            er = Path(eng_dir).resolve()
            if rp != er and er not in rp.parents:
                return False
        except Exception:
            pass
    return in_dir


# --- content scan (pure) ----------------------------------------------------
def _write_text(tool_name: str, tool_input: dict) -> str:
    ti = tool_input or {}
    parts: list[str] = []
    for key in ("content", "new_string", "new_str"):
        v = ti.get(key)
        if isinstance(v, str):
            parts.append(v)
    edits = ti.get("edits")
    if isinstance(edits, list):
        for e in edits:
            if isinstance(e, dict):
                v = e.get("new_string") or e.get("new_str")
                if isinstance(v, str):
                    parts.append(v)
    return "\n".join(parts)


def detect_never_submit(text: str) -> list[tuple[str, str]]:
    """The never-submit signals present in the text, as (signal_name, chain_anchor). Empty if none."""
    out: list[tuple[str, str]] = []
    for name, rx, anchor in _SIGNALS:
        if rx.search(text):
            out.append((name, anchor))
    return out


def has_chain_language(text: str) -> bool:
    return bool(_CHAIN_LANGUAGE.search(text))


# --- decision (pure) --------------------------------------------------------
def evaluate(tool_name: str, tool_input: dict, eng_dir: Path | None, scope: dict | None,
             cwd: Path) -> dict:
    """Return {'decision': 'deny'|'pass', 'reason': str}. NO-OPs (pass) outside a bug-bounty engagement,
    off a submission draft, or on any ambiguity (fail open)."""
    if tool_name not in _WRITE_TOOLS:
        return _pass()
    if not is_bug_bounty(eng_dir, scope):
        return _pass()  # HARD scoping: never fire outside a bug-bounty engagement
    ti = tool_input or {}
    raw_path = ti.get("file_path") or ti.get("notebook_path") or ti.get("path")
    if not raw_path:
        return _pass()
    p = Path(str(raw_path))
    if not p.is_absolute():
        p = cwd / p
    if not is_submission_draft(p, eng_dir):
        return _pass()
    text = _write_text(tool_name, ti)
    if not text.strip():
        return _pass()
    if has_chain_language(text):
        return _pass()  # escape hatch — the draft demonstrates the escalation
    signals = detect_never_submit(text)
    if not signals:
        return _pass()
    names = ", ".join(s[0] for s in signals)
    anchors = " | ".join(f"[{s[0]}] {s[1]}" for s in signals[:3])
    return _deny(
        f"submission draft '{p.name}' reports never-submit signal(s) ({names}) with NO chain/impact "
        f"language — these are closed as 'no impact' when reported ALONE. Pursue the chain anchor and "
        f"submit the escalated chain, not the bare signal: {anchors}"
    )


def _deny(reason: str) -> dict:
    return {"decision": "deny", "reason": reason}


def _pass() -> dict:
    return {"decision": "pass", "reason": ""}


# --- hook I/O ---------------------------------------------------------------
def _emit_deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"[redstrike never-submit-gate] bug-bounty submission policy (quality net) — {reason}."
            ),
        }
    }))


def _eng_dir_from_scope(scope_arg: str) -> Path | None:
    if not scope_arg:
        return None
    try:
        return Path(scope_arg).resolve().parent.parent
    except Exception:
        return None


def _load_scope(scope_arg: str) -> dict | None:
    if not scope_arg:
        return None
    try:
        return json.loads(Path(scope_arg).read_text(encoding="utf-8"))
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Redstrike never-submit → chain-anchor gate (bug-bounty, fail-open).")
    ap.add_argument("--scope", default=os.environ.get("REDSTRIKE_SCOPE_FILE", ""))
    args = ap.parse_args(argv)
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except Exception:
        return 0  # fail open
    try:
        tool_name = payload.get("tool_name", "")
        tool_input = payload.get("tool_input", {}) or {}
        cwd = Path(payload.get("cwd") or os.getcwd())
        eng_dir = _eng_dir_from_scope(args.scope)
        scope = _load_scope(args.scope)
        decision = evaluate(tool_name, tool_input, eng_dir, scope, cwd)
        if decision["decision"] == "deny":
            _emit_deny(decision["reason"])
    except Exception:
        return 0  # fail open — never wedge a write
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
