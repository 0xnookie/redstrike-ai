#!/usr/bin/env python3
"""Redstrike PreToolUse dangling-evidence-reference gate — a Claude Code hook.

WHY this exists: `scripts/evidence_seal.py` SEALS the artifacts that really exist (hashing every
screenshot/PoC/HAR under the vault and stamping `evidence[].sha256`). But it cannot catch the OPPOSITE
failure — a report NARRATIVE that CITES an artifact which was never produced: "see poc/sqli-dump.png",
"[request/response](evidence/req.har)", `"ref": "idor/poc/missing.txt"`. A triager (or a client) who
clicks a dead link loses trust in the whole report, and the finding reads as fabricated. This gate runs
BEFORE a Write/Edit lands on a REPORT / FINDINGS output file, extracts the LOCAL artifact paths the
content cites, and DENIES the write when a cited path does not exist on disk — "never cite an artifact
that was never produced." It complements evidence_seal (which seals real artifacts); this catches the
reference to an unreal one.

HONESTY / fail direction: this is a QUALITY NET, not a security boundary. Unlike `scope_gate.py` (the
real boundary, which fails CLOSED), this gate FAILS OPEN — on any internal error, a missing scope
record, an unparseable file, or an ambiguous reference it PASSES. A dangling citation is a quality
defect, never a safety breach, so a bug here must never wedge a legitimate write. It only DENIES when it
POSITIVELY finds a cited local artifact path that definitively does not resolve to a file on disk.

SCOPING (do NOT fire on arbitrary writes): the gate acts only when the target is one of the engagement's
report/findings outputs — a file under `report/` or `submissions/`, a `findings*.json`, or an
engagement-docs report (`report.md` / `summary.md` / `attestation*.md` / `retest*.md`) — AND the file is
inside the engagement dir. Writes to `runtime/` (launcher-owned) and ordinary working files are ignored.

Decision contract (same shape as scope_gate): on DENY print a PreToolUse JSON decision to stdout and
exit 0; on PASS print nothing and exit 0. Any internal error ⇒ PASS (fail open).

Usage (wired by the launcher into settings.json):
  python evidence_ref_gate.py --scope <engagement>/runtime/scope.json  < payload.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

_WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")

# Extensions that mark a cited path as an EVIDENCE/PoC ARTIFACT (vs a section anchor, another doc, or a
# code reference). A citation must end in one of these to be checked — this keeps the gate off prose links
# ("see the appendix") and narrows it to the artifacts a report actually attaches.
_ARTIFACT_EXTS = frozenset("""
png jpg jpeg gif webp svg bmp tiff tif ico
har pcap pcapng cap
mp4 webm mov mkv
pdf
html htm
json jsonl ndjson
txt log csv tsv md
""".split())

# Markdown image  ![alt](target "title")  and link  [text](target)  — target captured, title dropped later.
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*([^)]+?)\s*\)")
_MD_LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(\s*([^)]+?)\s*\)")
# A JSON evidence/cleanup reference  "ref": "poc/x.png"  (fallback when the file does not parse as JSON).
_JSON_REF = re.compile(r'"ref"\s*:\s*"([^"]+)"')
_URL_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


# --- cited-reference extraction (pure) --------------------------------------
def _clean_target(raw: str) -> str:
    """A markdown link/image target: drop a trailing ` "title"`, surrounding <angle brackets>/quotes,
    and any #fragment or ?query — leaving the bare path."""
    s = raw.strip().strip("<>").strip().strip("'\"").strip()
    # a markdown title after the path:  path "Caption"
    m = re.match(r'^(\S+)\s+["\'(].*$', s)
    if m:
        s = m.group(1)
    s = s.split("#", 1)[0].split("?", 1)[0].strip()
    return s


def is_local_artifact_ref(ref: str) -> bool:
    """True when `ref` is a LOCAL path to an evidence-style artifact (checkable), False for a URL, an
    in-page anchor, a mailto/tel/data target, a protocol-relative URL, or a non-artifact extension."""
    if not ref:
        return False
    if _URL_SCHEME.match(ref) or "://" in ref:
        return False
    low = ref.lower()
    if low.startswith(("#", "mailto:", "tel:", "data:", "//")):
        return False
    ext = ref.rsplit(".", 1)[-1].lower() if "." in ref else ""
    return ext in _ARTIFACT_EXTS


def cited_refs(text: str, *, is_json: bool) -> list[str]:
    """Every local artifact path the content cites, de-duped in order of appearance.

    For a JSON findings file: the `evidence[].ref` + `cleanup.ref` values (parsed structurally when the
    JSON is well-formed, else recovered with a regex). For any text: markdown image targets (always a
    file) and markdown link targets that carry an artifact extension. Only LOCAL artifact refs survive.
    """
    found: list[str] = []

    if is_json:
        parsed = None
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
        if parsed is not None:
            found.extend(_refs_from_findings(parsed))
        else:
            found.extend(m.group(1) for m in _JSON_REF.finditer(text))

    for m in _MD_IMAGE.finditer(text):
        found.append(_clean_target(m.group(1)))
    for m in _MD_LINK.finditer(text):
        found.append(_clean_target(m.group(1)))

    seen: set[str] = set()
    uniq: list[str] = []
    for r in found:
        r = (r or "").strip()
        if r and r not in seen and is_local_artifact_ref(r):
            seen.add(r)
            uniq.append(r)
    return uniq


def _findings_list(doc) -> list:
    """The finding dicts in a loaded findings doc (bare array, or {findings, attack_chains} object)."""
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        return [f for f in (list(doc.get("findings") or []) + list(doc.get("attack_chains") or []))
                if isinstance(f, dict)]
    return []


def _refs_from_findings(doc) -> list[str]:
    """Collect `evidence[].ref` and `cleanup.ref` across a parsed findings doc (skips code_citation
    `file` fields — those are source paths into a possibly-pruned source tree, not vault artifacts)."""
    out: list[str] = []
    for f in _findings_list(doc):
        ev = f.get("evidence")
        if isinstance(ev, list):
            for item in ev:
                if isinstance(item, dict) and item.get("type") != "code_citation":
                    ref = item.get("ref")
                    if isinstance(ref, str) and ref:
                        out.append(ref)
        cu = f.get("cleanup")
        if isinstance(cu, dict) and isinstance(cu.get("ref"), str) and cu["ref"]:
            out.append(cu["ref"])
    return out


# --- resolution (checks disk) -----------------------------------------------
def resolve_ref(eng_dir: Path, findings_dir: Path, ref: str) -> Path | None:
    """Resolve a cited artifact ref to an existing file, else None. Mirrors evidence_seal._resolve_ref:
    tries the ref relative to the findings file's own dir, the engagement root, the vault roots, then a
    basename fallback in the usual evidence/poc locations. NO full-tree walk (fast + no false matches)."""
    ref = ref.split("#", 1)[0].split("?", 1)[0].strip()
    if not ref:
        return None
    p = Path(ref)
    cands: list[Path] = []
    if p.is_absolute():
        cands.append(p)
    else:
        cands += [
            findings_dir / ref,
            eng_dir / ref,
            eng_dir / "evidence" / ref,
            eng_dir / "findings" / "evidence" / ref,
            findings_dir / "evidence" / ref,
        ]
        name = p.name
        cands += [
            eng_dir / "evidence" / name,
            eng_dir / "poc" / name,
            findings_dir / "evidence" / name,
            findings_dir / "poc" / name,
        ]
    for c in cands:
        try:
            if c.is_file():
                return c
        except Exception:
            continue
    return None


def dangling_refs(text: str, *, is_json: bool, eng_dir: Path, findings_dir: Path) -> list[str]:
    """The cited local artifact refs that do NOT resolve to a file on disk (the dangling citations)."""
    out: list[str] = []
    for ref in cited_refs(text, is_json=is_json):
        if resolve_ref(eng_dir, findings_dir, ref) is None:
            out.append(ref)
    return out


# --- target scoping ---------------------------------------------------------
_REPORT_MD = re.compile(r"^(report|summary|attestation|retest)\b.*\.md$", re.IGNORECASE)


def is_report_target(path: Path, eng_dir: Path) -> bool:
    """True when `path` is one of the engagement's REPORT / FINDINGS outputs (and is inside the
    engagement dir). Scoped deliberately narrow so the gate never fires on arbitrary writes."""
    try:
        rp = path.resolve()
        er = eng_dir.resolve()
        # must be inside the engagement dir
        if rp != er and er not in rp.parents:
            return False
        rel_parts = [x.lower() for x in rp.relative_to(er).parts]
    except Exception:
        return False
    if "runtime" in rel_parts:
        return False  # launcher-owned; never a report
    name = rp.name.lower()
    if "report" in rel_parts or "submissions" in rel_parts:
        return True
    if name == "findings.json" or (name.startswith("findings") and name.endswith(".json")):
        return True
    if _REPORT_MD.match(name):
        return True
    return False


# --- write content ----------------------------------------------------------
def _write_text(tool_name: str, tool_input: dict) -> str:
    """The NEW content a Write/Edit/MultiEdit introduces (what we scan for citations)."""
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


# --- decision (pure) --------------------------------------------------------
def evaluate(tool_name: str, tool_input: dict, eng_dir: Path | None, cwd: Path) -> dict:
    """Return {'decision': 'deny'|'pass', 'reason': str}. Fails OPEN (pass) on anything ambiguous."""
    if tool_name not in _WRITE_TOOLS or not eng_dir:
        return _pass()
    ti = tool_input or {}
    raw_path = ti.get("file_path") or ti.get("notebook_path") or ti.get("path")
    if not raw_path:
        return _pass()
    p = Path(str(raw_path))
    if not p.is_absolute():
        p = cwd / p
    if not is_report_target(p, eng_dir):
        return _pass()
    text = _write_text(tool_name, ti)
    if not text.strip():
        return _pass()
    is_json = p.name.lower().endswith(".json")
    try:
        missing = dangling_refs(text, is_json=is_json, eng_dir=eng_dir, findings_dir=p.parent)
    except Exception:
        return _pass()  # quality net: never wedge a write on an internal error
    if missing:
        shown = ", ".join(missing[:6])
        more = len(missing) - 6
        if more > 0:
            shown += f", …(+{more} more)"
        return _deny(
            f"'{p.name}' cites {len(missing)} evidence artifact(s) that do not exist on disk: {shown}. "
            f"Produce the artifact(s) in the engagement evidence/poc vault first, or remove the dead "
            f"citation — never cite an artifact that was never produced"
        )
    return _pass()


def _deny(reason: str) -> dict:
    return {"decision": "deny", "reason": reason}


def _pass() -> dict:
    return {"decision": "pass", "reason": ""}


# --- hook I/O ---------------------------------------------------------------
def _emit_deny(reason: str) -> None:
    # Framed as an engagement QUALITY policy so the agent fixes the citation instead of retrying around it.
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"[redstrike evidence-ref-gate] engagement report-integrity policy (quality net) — {reason}."
            ),
        }
    }))


def _eng_dir_from_scope(scope_arg: str) -> Path | None:
    """engagement dir = <eng>/runtime/scope.json → <eng>. None when no usable scope path was given."""
    if not scope_arg:
        return None
    try:
        return Path(scope_arg).resolve().parent.parent
    except Exception:
        return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Redstrike dangling-evidence-reference gate (fail-open).")
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
        decision = evaluate(tool_name, tool_input, eng_dir, cwd)
        if decision["decision"] == "deny":
            _emit_deny(decision["reason"])
    except Exception:
        return 0  # fail open — a quality net must never wedge a write
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
