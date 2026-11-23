#!/usr/bin/env python3
"""Redstrike SubagentStop chain-pressure hook — a Claude Code hook.

WHY this exists: several finding classes are LOW or INFORMATIONAL alone and only earn their rating once
CHAINED (open-redirect → OAuth `redirect_uri` → ATO; CORS misconfig → credentialed read; info-disclosure
→ secret-in-bundle → privesc; …). `skills/attack-chain-discovery/refs/chain_anchors.md` calls each such
class a FEEDER — "a CONFIRMED finding in a feeder class is a FEEDER, not a report" — and lists the
specific anchors to probe before the finding is treated as terminal. The failure this guards against is a
run that accepts a batch of feeder findings and marches straight to report-ready without ever composing
them, leaving real kill chains on the table (thin-evidence / low-recall).

WHAT it does: on every SubagentStop it rescans the engagement's findings for ACCEPTED findings in a
feeder class that carry NO chain reference yet (not a step in any chain, not already probed), and writes
`runtime/chain-pending.json` — the flagged findings plus the anchors to probe for each (aligned with
`chain_anchors.md`). The autonomous resume loop (`runloop.py`) reads that file and, while it is non-empty,
keeps the engagement OUT of report-ready and tells the next leg to dispatch `attack-chain-discovery` on
exactly those feeders. It also emits a non-blocking advisory.

BOUNDED (no unbounded loop): a feeder stops being "pending" the moment chaining has been ATTEMPTED for it
— its id becomes a chain step, OR it is recorded in `attack-chain-discovery/probes.json` (a dropped
hypothesis counts as attempted). So one pass of attack-chain-discovery drains it whether it chained or
dead-ended. If the engine never actually runs the chainer, the loop makes no progress and the existing
no-progress breaker (plus the invocation / budget / wall-clock ceilings) stops it. An empty pending set
is still WRITTEN (count 0) so a stale file from a prior leg clears.

HONESTY / fail direction: a quality net, not a boundary — it FAILS OPEN. Any error writes nothing and
exits 0; it never blocks a subagent from stopping (no `decision: block`).

Usage (wired by the launcher into settings.json, SubagentStop):
  python chain_pressure.py --scope <engagement>/runtime/scope.json  < payload.json
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path

# The feeder classes (canonical names) from refs/chain_anchors.md. A CONFIRMED finding in one of these is
# a FEEDER, not a report — it must be probed for a chain before it is treated as terminal.
FEEDER_CLASSES = frozenset({
    "open-redirect", "cors", "info-disclosure", "csrf", "subdomain-takeover",
    "xxe", "file-upload", "race-condition", "business-logic", "privesc",
})

# Concrete executor classes that PRODUCE an info-disclosure feeder (chain_anchors.md: "secrets / exposed
# surface / verbose errors"). Mapped onto the canonical `info-disclosure` feeder so their accepted findings
# are flagged too. Keys are the class names a finding may carry; values are the canonical feeder.
_CLASS_ALIASES = {
    "secrets": "info-disclosure",
    "exposed-surface": "info-disclosure",
    "sensitive-disclosure": "info-disclosure",
    "sensitive-data": "info-disclosure",
    "information-disclosure": "info-disclosure",
    "privilege-escalation": "privesc",
    "xxe-inband": "xxe",
    "xxe-blind": "xxe",
    "xxe-context": "xxe",
    "upload-rce": "file-upload",
    "open-redirect": "open-redirect",
}

# The anchors to probe for each feeder (condensed from chain_anchors.md) + the Tier-2 executor each routes
# to. Kept in code so the hook stays self-contained/stdlib-only; mirrors the reference doc.
FEEDER_ANCHORS: dict[str, list[str]] = {
    "open-redirect": [
        "OAuth/OIDC redirect_uri reflection → auth code to attacker domain → ATO (oauth)",
        "returnTo/next/continue after auth executes or leaks post-login (oauth/auth-bypass)",
        "token/code present in the redirected URL query → directly stealable (oauth)",
        "sibling-subdomain redirect target → cookie/token handoff (subdomain-takeover)",
    ],
    "cors": [
        "credentialed endpoint with ACAC:true reflecting the attacker origin (cors)",
        "sensitive-data endpoint reachable cross-origin (/api/me, billing, tokens) (bola-bfla/idor)",
        "Origin: null / allow-list regex flaw breaks the origin check (cors)",
        "secret in the CORS-readable body (secrets)",
    ],
    "info-disclosure": [
        "secret in a JS bundle / source map / config → oauth client_secret or jwt signing key (secrets→oauth/jwt)",
        "stack trace leaks internal IPs/hostnames → SSRF target (ssrf-inband/ssrf-blind)",
        ".git/.env/backup/wp-config exposed → DB creds/signing keys (exposed-surface→privesc/jwt)",
        "live over-broad API key → other-user data (secrets→idor)",
        "cloud metadata reachable via an SSRF context → IMDS creds (ssrf-cloud)",
    ],
    "csrf": [
        "state-change is password/email/phone → account takeover (auth-bypass)",
        "MFA disable / second-factor enrollment → MFA bypass (auth-bypass)",
        "role change / permission grant / team invite → privesc (privesc)",
        "payment-method / withdrawal-address change → financial impact (business-logic)",
        "state-change renders to a higher-priv user → CSRF-to-stored-XSS pivot (xss-stored)",
    ],
    "subdomain-takeover": [
        "subdomain is an OAuth redirect_uri / SAML ACS / OIDC issuer → token delivery → ATO (oauth)",
        "parent shares cookies (.target.tld) → cookie-set / fixation on the parent (auth-bypass)",
        "subdomain in the parent's CSP script-src → claiming it defeats CSP → escalates XSS (xss-stored)",
        "subdomain referenced from prod JS → trusted-domain script delivery (secrets/xss-stored)",
    ],
    "xxe": [
        "SSRF via XXE → cloud metadata → IAM creds (ssrf-cloud)",
        "OOB exfil to an attacker DTD → blind config/file read (xxe-blind)",
        "SAML-assertion XXE → auth-flow impact (auth-bypass/oauth)",
        "DOCX/XLSX/SVG upload carrying XXE fires in an internal viewer (upload-rce→xxe-blind)",
        "php://filter / jar: / ldap: wrapper reach → source read / classloader RCE (xxe-inband/deserialization)",
    ],
    "file-upload": [
        "upload to web root + executable → web shell → RCE (upload-rce)",
        "SVG/HTML rendered inline → stored XSS in the viewer (xss-stored)",
        "path traversal in the filename → overwrite config/cron/authorized_keys (path-traversal-lfi→privesc)",
        "filename/EXIF renders in an admin panel → stored XSS in admin context (xss-stored)",
        "upload triggers a server-side processor → SSRF / processor-CVE RCE (ssrf-inband/cve-intelligence)",
    ],
    "race-condition": [
        "financial action (transfer/withdrawal/debit) → quantify the dollar amount (business-logic)",
        "coupon/gift-card/referral redemption → free value × N (business-logic)",
        "one-shot token (reset/invite/MFA-enroll) → double-redeem → ATO (auth-bypass)",
        "TOCTOU on a file-write/check → privesc/RCE (privesc)",
        "rate-limit/quota check bypass → mass enumeration / IDOR amplification (idor/bola-bfla)",
    ],
    "business-logic": [
        "manipulated artifact shown to a higher-priv user becomes source-of-truth (privesc/xss-stored)",
        "tampered value persists + re-renders in an admin/settlement view (idor)",
        "workflow skip → access a feature you didn't pay for (auth-bypass)",
        "negative/huge values → integer overflow / sign flip → financial chain (business-logic)",
        "replayed payment/success callback → re-use a paid order reference (business-logic)",
    ],
    "privesc": [
        "mass-assignment set role/permission/tenant → escalated account sees other-tenant data (idor/bola-bfla)",
        "JWT claim manipulation → which other claims (sub/aud/iss/tenant) are unprotected (jwt)",
        "admin endpoint reachable but confirm WRITE actions not just GET (privesc)",
        "forced-browse an admin URL → test DELETE/PATCH/PUT too (bola-bfla)",
        "escalated role unlocks an API-key mint / webhook → persistent-credential chain (secrets)",
    ],
}

_RS_ID = re.compile(r"\bRS-[0-9]{4}-[0-9]{3,}\b")
_PENDING_FILENAME = "chain-pending.json"


# --- class / acceptance derivation (pure) -----------------------------------
def _canonical_class(name: str) -> str | None:
    """Map a raw class/reviewer name to its canonical feeder class, or None if it isn't a feeder."""
    if not name:
        return None
    n = name.strip().lower()
    if n.endswith("-verify"):
        n = n[: -len("-verify")]
    if n in FEEDER_CLASSES:
        return n
    return _CLASS_ALIASES.get(n)


def finding_class(finding: dict, source_dir_name: str | None = None) -> str | None:
    """Canonical feeder class of a finding, or None. Tries an explicit field, then the reviewer name
    (`cors-verify` → `cors`), then the per-skill directory the findings file lived in."""
    if not isinstance(finding, dict):
        return None
    for key in ("class", "skill", "category_id"):
        c = _canonical_class(str(finding.get(key) or ""))
        if c:
            return c
    rev = ((finding.get("review") or {}) if isinstance(finding.get("review"), dict) else {}).get("reviewer")
    c = _canonical_class(str(rev or ""))
    if c:
        return c
    if source_dir_name:
        return _canonical_class(source_dir_name)
    return None


def is_accepted(finding: dict) -> bool:
    """A finding reached report-ready acceptance: reviewer verdict accepted/blocked, or status verified."""
    if not isinstance(finding, dict):
        return False
    rev = finding.get("review")
    if isinstance(rev, dict) and str(rev.get("verdict", "")).lower() in ("accepted", "blocked"):
        return True
    return str(finding.get("status", "")).lower() == "verified"


def is_composite(finding: dict) -> bool:
    return bool(finding.get("composite") or finding.get("_composite"))


# --- engagement corpus reads (fail-safe) ------------------------------------
def _read_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def _findings_in(doc) -> list:
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        return [f for f in (list(doc.get("findings") or []) + list(doc.get("attack_chains") or []))
                if isinstance(f, dict)]
    return []


def load_findings(eng_dir: Path) -> list[tuple[dict, str | None]]:
    """Every finding across the engagement as (finding, source_dir_name), de-duped by id. Reads the
    top-level findings.json, each per-skill `<eng>/*/findings.json`, and report/findings_consolidated.json.
    The source-dir name lets `finding_class` fall back to the per-skill directory (e.g. `cors`)."""
    eng = Path(eng_dir)
    out: list[tuple[dict, str | None]] = []
    seen: set[str] = set()

    def _ingest(path: Path, src: str | None):
        for f in _findings_in(_read_json(path)):
            fid = str(f.get("id") or "")
            key = fid or f"{src}:{f.get('title', '')}"
            if key in seen:
                continue
            seen.add(key)
            out.append((f, src))

    _ingest(eng / "findings.json", None)
    for p in sorted(eng.glob("*/findings.json")):
        _ingest(p, p.parent.name)
    _ingest(eng / "report" / "findings_consolidated.json", None)
    return out


def chained_ids(eng_dir: Path) -> set:
    """Finding ids that ALREADY appear as a step in some chain — i.e. they have been chained. Collected
    from every `*/chains.json` (attack_chain schema: chains[].steps[].finding_id) and from composite
    findings' step references."""
    eng = Path(eng_dir)
    ids: set = set()
    for p in sorted(eng.glob("*/chains.json")) + [eng / "chains.json"]:
        doc = _read_json(p)
        if not isinstance(doc, dict):
            continue
        for ch in doc.get("chains") or []:
            if not isinstance(ch, dict):
                continue
            for st in ch.get("steps") or []:
                if isinstance(st, dict) and st.get("finding_id"):
                    ids.add(str(st["finding_id"]))
    # composite findings may embed their legs as steps too
    for f, _src in load_findings(eng):
        if is_composite(f):
            for st in f.get("steps") or []:
                if isinstance(st, dict) and st.get("finding_id"):
                    ids.add(str(st["finding_id"]))
    return ids


def attempted_ids(eng_dir: Path) -> set:
    """Finding ids for which chaining was ATTEMPTED (so they are no longer pending). A feeder counts as
    attempted once it is named anywhere in a probes.json drop/hypothesis log — a dropped hypothesis is a
    completed attempt (chain_anchors.md: a dropped hypothesis is recorded in probes.json). Deep string
    scan for RS-ids so it survives whatever exact shape the chainer wrote."""
    eng = Path(eng_dir)
    ids: set = set()
    for p in sorted(eng.glob("*/probes.json")) + [eng / "probes.json"]:
        try:
            raw = Path(p).read_text(encoding="utf-8")
        except Exception:
            continue
        for m in _RS_ID.finditer(raw):
            ids.add(m.group(0))
    return ids


# --- flagging (pure) --------------------------------------------------------
def flag_feeders(findings_with_src: list[tuple[dict, str | None]], chained: set,
                 attempted: set) -> list[dict]:
    """The accepted feeder findings that still lack a chain reference — the pending set. One entry per
    flagged finding: {id, class, title, asset, anchors}. Composite/chain findings are never themselves
    feeders. A finding already chained OR already probed is dropped (bounded — see module docstring)."""
    out: list[dict] = []
    for f, src in findings_with_src:
        if is_composite(f) or not is_accepted(f):
            continue
        cls = finding_class(f, src)
        if cls is None:
            continue
        fid = str(f.get("id") or "")
        if fid and (fid in chained or fid in attempted):
            continue
        out.append({
            "id": fid,
            "class": cls,
            "title": str(f.get("title") or ""),
            "asset": str(f.get("asset") or ""),
            "anchors": list(FEEDER_ANCHORS.get(cls, [])),
        })
    return out


def build_pending(eng_dir: Path, now: _dt.datetime | None = None) -> dict:
    """The chain-pending document for runtime/chain-pending.json (fail-safe end to end)."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    try:
        findings = load_findings(eng_dir)
        pending = flag_feeders(findings, chained_ids(eng_dir), attempted_ids(eng_dir))
    except Exception:
        pending = []
    return {
        "generated_at": now.isoformat(),
        "tool": "chain_pressure.py",
        "count": len(pending),
        "pending": pending,
    }


def write_pending(eng_dir: Path, doc: dict) -> Path | None:
    """Write runtime/chain-pending.json atomically. Best-effort; returns the path or None on failure."""
    try:
        out = Path(eng_dir) / "runtime" / _PENDING_FILENAME
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.parent / (out.name + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, out)
        return out
    except Exception:
        return None


# --- hook I/O ---------------------------------------------------------------
def _emit_advisory(count: int, pending: list[dict]) -> None:
    """A non-blocking SubagentStop advisory (never `decision: block`). Shown via systemMessage."""
    if count <= 0:
        return
    classes = sorted({p.get("class", "?") for p in pending})
    msg = (f"[redstrike chain-pressure] {count} accepted FEEDER finding(s) in "
           f"{', '.join(classes)} lack a chain reference — run attack-chain-discovery on them before "
           f"report-ready (see runtime/chain-pending.json for the anchors to probe).")
    try:
        print(json.dumps({"systemMessage": msg}))
    except Exception:
        pass


def _eng_dir_from_scope(scope_arg: str) -> Path | None:
    if not scope_arg:
        return None
    try:
        return Path(scope_arg).resolve().parent.parent
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Redstrike SubagentStop chain-pressure hook (fail-open).")
    ap.add_argument("--scope", default=os.environ.get("REDSTRIKE_SCOPE_FILE", ""))
    ap.add_argument("--engagement", default="", help="engagement dir (overrides --scope derivation)")
    args = ap.parse_args(argv)
    try:
        _ = sys.stdin.read()  # drain the payload; we derive the engagement from --scope, not the event
    except Exception:
        pass
    try:
        eng_dir = Path(args.engagement).resolve() if args.engagement else _eng_dir_from_scope(args.scope)
        if not eng_dir or not Path(eng_dir).is_dir():
            return 0  # fail open — nothing to scan
        doc = build_pending(eng_dir)
        write_pending(eng_dir, doc)
        _emit_advisory(doc.get("count", 0), doc.get("pending", []))
    except Exception:
        return 0  # fail open — never block a subagent from stopping
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
