#!/usr/bin/env python3
"""
close.py -- record THIS engagement's run outcome into runtime/diagnostics.json.

The only diagnostics writer is the launcher's post-run gate (cli/redstrike_cli/diagnostics.py, reached
from `redstrike run`). An engagement driven through the interactive Skill path never appends a run
record, so `runs[-1]` stays a stale CLI-init / blocked-on-approval entry — and the completion gate and
the console banner then read a FALSE "Assessment degraded" even over accepted findings (the
noxsframe-2026-11-17 engagement: a 5-finding report with a stale degraded-empty `runs[-1]`).

This closes that gap from the Skill path: it builds ONE honest run record for the engagement's current
state and appends it, so `runs[-1]` reflects this engagement. The empty/degraded/transport classification
is done by the engine's own `diagnostics.assemble()` (it reads rate_state.json -> transport health, and
the ledgers -> why an empty is degraded vs clean). `assemble` counts accepted findings from the engagement
ROOT findings.json only, so on the per-skill executor layout (findings under `<eng>/<skill>/findings.json`,
no root file) it would under-count to zero; this wrapper therefore computes the REPORTABLE-finding count
across every layout the framework produces (exactly as the completion gate does) and, when findings exist,
records `produced-findings` with that count — so the record agrees with the report and the gate's
report-has-findings consistency check passes. When the cli package can't be imported (a stripped
deployment), it falls back to a minimal record built the same layout-aware way — so the Skill path never
hard-depends on the launcher being installed.

Run it BEFORE scripts/verify_completion.py / reporting, every time (historical or fresh), so the gate
always reads a current record.

Stdlib only. Usage:
  python scripts/close.py --engagement engagements/<client>-<date>
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _load_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


# --- layout-aware reportable-finding count (mirrors verify_completion's discovery + reportable rule) ----
def _findings_from(doc):
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        return [f for f in (list(doc.get("findings") or []) + list(doc.get("attack_chains") or []))
                if isinstance(f, dict)]
    return []


def _discover_findings(eng: Path) -> list:
    """Findings across the layouts the framework produces, in the gate's priority order: root findings.json,
    else the union of per-skill `<eng>/*/findings.json`, else report/findings_consolidated.json."""
    root = _load_json(eng / "findings.json")
    if isinstance(root, (list, dict)) and _findings_from(root):
        return _findings_from(root)
    per = sorted(eng.glob("*/findings.json"))
    if per:
        out = []
        for p in per:
            out.extend(_findings_from(_load_json(p)))
        return out
    return _findings_from(_load_json(eng / "report" / "findings_consolidated.json"))


# --- orphan findings-file detection (QW-3) --------------------------------------------------------------- #
# The real incident (20min-2026-11-25, bola-bfla): an executor wrote `bola-bfla/findings_authed_bfla.json`
# (a non-default name chosen to avoid clobbering the unauth pass). But close.py / verify_completion / dedup /
# reporting all discover findings by the EXACT name `findings.json` — so the non-canonical file was invisible
# and close.py recorded a FALSE `findings=0 / clean-tested`, contradicting the real accepted finding. We do
# NOT blanket-glob `findings*.json` into the discovery set (that risks double-counting a findings_partial /
# findings.bak); instead we WARN loudly so a stray is never silently missed — the canonical set stays
# unambiguous, the miss stays visible.

def orphan_findings_files(eng: Path) -> list:
    """Non-canonical `findings*.json` files beside the canonical ones (name != `findings.json`), at the
    engagement root or one level down (the per-skill layout). These are NOT scanned by the pipeline, so a
    finding living only in one is silently dropped. Returns the stray Paths, sorted."""
    out = []
    for p in sorted(eng.glob("findings*.json")) + sorted(eng.glob("*/findings*.json")):
        if p.is_file() and p.name != "findings.json":
            out.append(p)
    return out


def warn_orphan_findings(eng: Path) -> list:
    """Emit a LOUD stderr warning for every orphan findings file (QW-3). Returns the stray paths (so a caller
    can surface them too). No-op when there are none."""
    orphans = orphan_findings_files(eng)
    for p in orphans:
        try:
            rel = p.relative_to(eng)
        except ValueError:
            rel = p
        print(f"[close] WARNING: stray findings file '{rel}' is NOT scanned by the pipeline "
              f"(discovery keys on the exact name 'findings.json'). Its findings are INVISIBLE to "
              f"close.py / verify_completion / dedup / reporting — merge it into "
              f"'{p.parent.name}/findings.json' (append to the array, de-dupe by id) so it is counted.",
              file=sys.stderr)
    return orphans


def _effective_verdict(f: dict, eng: Path) -> str:
    """A finding's effective verdict — inline review.verdict, else reviews/<id>.verdict.json (root or
    per-skill), else derived from status (verified->accepted, rejected->rejected). Mirrors
    verify_completion._review_of so this count matches the gate's _reportable_findings_count."""
    verdict = (f.get("review") or {}).get("verdict")
    if not verdict:
        fid = f.get("id")
        if fid:
            for vp in [eng / "reviews" / f"{fid}.verdict.json"] + sorted(eng.glob(f"*/reviews/{fid}.verdict.json")):
                if vp.is_file():
                    verdict = (_load_json(vp) or {}).get("verdict")
                    if verdict:
                        break
    if not verdict:
        st = f.get("status")
        verdict = "accepted" if st == "verified" else "rejected" if st == "rejected" else ""
    return verdict


def reportable_count(eng: Path) -> int:
    """Count findings that reach the report (effective verdict accepted/blocked, non-composite) — the same
    quantity the gate's report-has-findings consistency check reads, across every findings layout."""
    n = 0
    for f in _discover_findings(eng):
        if f.get("composite") or f.get("_composite"):
            continue
        if _effective_verdict(f, eng) in ("accepted", "blocked"):
            n += 1
    return n


def _fallback_record(eng: Path, *, session: str, now: str) -> dict:
    """A minimal, HONEST run record built without the cli diagnostics package (the rare case it can't be
    imported). Outcome is derived from the layout-aware reportable-finding count; transport is left empty
    and an empty is explicitly explained, so it is never mistaken for a classified clean result. Shape
    mirrors diagnostics.Diagnostics.to_record() so every consumer (gate / console) reads it the same way."""
    n = reportable_count(eng)
    if n > 0:
        outcome, reason = "produced-findings", None
    else:
        outcome, reason = "degraded-empty", (
            "close.py fallback: the cli diagnostics package could not be imported, so the outcome was "
            "derived from the findings layout alone (ledgers/transport not classified) — empty is not asserted clean")
    return {
        "session": session, "mode": "interactive", "started": now, "ended": now,
        "engine_rc": 0, "gate_rc": None, "outcome": outcome, "degraded_reason": reason,
        "findings_count": n, "tool_failures": [], "exceptions": [],
        "transport_health": {"hosts": [], "overall": {"block_rate": 0.0, "worst_host": None,
                                                       "status": "healthy"}},
        "empty_recon": {"flag": False, "surface_discovered": 0, "signals": 0, "hosts_live": 0},
        "phase_tally": [],
        "gate_summary": {"coverage": "absent", "surface": "absent", "recall": "n/a", "findings": n},
    }


def _fallback_write(eng: Path, record: dict) -> Path:
    """Append `record` to runtime/diagnostics.json runs[] without the cli writer (import-less fallback);
    mirrors diagnostics.write()'s document shape."""
    runtime = eng / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    diag_path = runtime / "diagnostics.json"
    doc = _load_json(diag_path)
    if not isinstance(doc, dict):
        doc = {}
    runs = doc.get("runs")
    if not isinstance(runs, list):
        runs = []
    runs.append(record)
    diag_path.write_text(json.dumps(
        {"engagement": doc.get("engagement") or eng.name, "generated_at": _now_iso(), "runs": runs},
        indent=2) + "\n", encoding="utf-8")
    return diag_path


def close(eng: Path, *, session: str = "") -> dict:
    """Record one honest run outcome for `eng` into runtime/diagnostics.json runs[], and return the record.
    Prefers the engine's diagnostics.assemble()/write() (its transport + empty-vs-clean classification), then
    overlays the layout-aware reportable-finding count so the record agrees with the report regardless of the
    findings layout. Falls back to an import-less record when the cli package is unavailable."""
    # Orphan-warn FIRST (QW-3): a stray non-canonical findings file would make the count below (and so this
    # run record's outcome) silently contradict reality — the exact bola-bfla false clean-tested. Loud, early.
    warn_orphan_findings(eng)
    now = _now_iso()
    sys.path.insert(0, str(ROOT / "cli"))
    try:
        from redstrike_cli import diagnostics  # type: ignore
    except Exception:
        record = _fallback_record(eng, session=session, now=now)
        _fallback_write(eng, record)
        return record
    record = diagnostics.assemble(
        eng, session=session, mode="interactive", started=now, ended=now,
        engine_rc=0, gate_rc=None, summary=None).to_record()
    # assemble counts only the ROOT findings.json; on the per-skill layout the real findings live under
    # <eng>/<skill>/findings.json, so re-count across layouts and record produced-findings when they exist.
    n = reportable_count(eng)
    if n > 0:
        record["outcome"] = "produced-findings"
        record["findings_count"] = n
        record["degraded_reason"] = None
    diagnostics.write(eng, record)
    return record


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Record an interactive engagement's run outcome into runtime/diagnostics.json "
                    "(so runs[-1] is not stale). Run before the completion gate / reporting.")
    ap.add_argument("--engagement", required=True, help="engagement directory")
    ap.add_argument("--session", default="", help="optional session id to stamp on the record")
    args = ap.parse_args(argv)
    eng = Path(args.engagement)
    if not eng.is_dir():
        ap.error(f"engagement dir not found: {eng}")
    record = close(eng, session=args.session)
    print(f"recorded outcome={record['outcome']} findings={record['findings_count']} "
          f"-> {eng / 'runtime' / 'diagnostics.json'}")
    orphans = orphan_findings_files(eng)   # already warned (stderr) inside close(); echo a one-line nudge here
    if orphans:
        print(f"[close] {len(orphans)} stray findings file(s) NOT scanned — see the warning(s) above; "
              f"merge each into its '<skill>/findings.json'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
