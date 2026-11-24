#!/usr/bin/env python3
"""
scan_diff.py -- finding-level scan-diff / retest between engagements (the reporting + retest flow). Stdlib only.

WHY THIS EXISTS:
  A retest or a recurring assessment needs to answer, mechanically: of the findings we confirmed last time,
  which are FIXED, which are still OPEN (unchanged), which are NEW since the baseline, and which CHANGED
  severity. Eyeballing two reports drifts -- a re-worded title or a re-ordered query string reads as "new"
  when it is the same bug. This diffs this engagement's `findings_consolidated.json` against a prior baseline
  JSON and classifies every finding deterministically.

IDENTITY (what makes a finding "the same bug across engagements"):
  dedup.py's `canonical_key` -- (asset-host, normalized endpoint path, query-param-name set, vuln-class).
  This is the SAME identity the cross-agent de-duplication uses, so a diff is consistent with the merge: it
  is far more robust than a naive (type, url, param) tuple (scheme/port/case/trailing-slash and param VALUE
  do not split a locus, but a different param NAME or vuln-class does).

CLASSIFICATION per canonical key:
  - in CURRENT only                       -> new
  - in BASELINE only                      -> fixed
  - in both, same severity                -> unchanged
  - in both, different severity           -> severity-changed (with direction raised/lowered)
  net_delta = new - fixed (the headline movement since the last assessment).

Pure logic (diff_findings) so it unit-tests with no network; a thin CLI wires it to two files + optional
markdown/HTML. Emits a JSON report (schema: skills/_contract/scan_diff.schema.json). Invoked as a script --
no CLI subcommand. `python scripts/scan_diff.py --selftest`.
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1

# atomic_write + dedup.canonical_key: resolve the sibling scripts the same robust way dedup.py does, so this
# runs both as `python scripts/scan_diff.py` and when imported with scripts/ on sys.path.
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover
    import importlib.util as _ilu
    _aspec = _ilu.spec_from_file_location("atomicio", str(Path(__file__).resolve().parent / "atomicio.py"))
    _amod = _ilu.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write

try:
    import dedup  # noqa: E402
except ImportError:  # pragma: no cover
    import importlib.util as _ilu2
    _dspec = _ilu2.spec_from_file_location("dedup", str(Path(__file__).resolve().parent / "dedup.py"))
    dedup = _ilu2.module_from_spec(_dspec)
    sys.modules.setdefault("dedup", dedup)
    _dspec.loader.exec_module(dedup)

canonical_key = dedup.canonical_key
_SEV_RANK = dedup._SEV_RANK


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_findings(data) -> list:
    """The findings list from either consolidated shape (bare array, or report object with `findings`),
    dropping merged duplicates and non-additive composite kill-chains -- the set of DISTINCT reported bugs."""
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("findings") or []
    else:
        items = []
    out = []
    for f in items:
        if not isinstance(f, dict):
            continue
        if f.get("composite"):
            continue
        if str(f.get("status", "")).lower() == "duplicate":
            continue
        out.append(f)
    return out


def _pick(group: list) -> dict:
    """One representative per canonical key within a scan: strongest severity, then smallest id (so a diff is
    deterministic even when a single scan has >1 finding on the same locus+class)."""
    return sorted(group, key=lambda f: (-_SEV_RANK.get(str(f.get("severity", "")).lower(), -1),
                                        str(f.get("id", ""))))[0]


def _by_key(findings: list) -> dict:
    groups: dict = {}
    for f in findings:
        groups.setdefault(canonical_key(f), []).append(f)
    return {k: _pick(v) for k, v in groups.items()}


def _summarize(finding: dict) -> dict:
    """The compact per-finding row carried in the diff report (traceable back to the full finding)."""
    k = canonical_key(finding)
    return {
        "id": str(finding.get("id", "")),
        "title": str(finding.get("title", "")),
        "asset": str(finding.get("asset", "")),
        "severity": str(finding.get("severity", "")).lower(),
        "key": {"host": k[0], "path": k[1], "params": sorted(k[2]), "class": k[3]},
    }


def diff_findings(baseline: list, current: list) -> dict:
    """Classify each canonical key as new / fixed / unchanged / severity-changed and summarize the net delta.
    Pure: takes two lists of finding dicts, returns the diff report body (no I/O)."""
    base = _by_key(baseline)
    curr = _by_key(current)
    base_keys, curr_keys = set(base), set(curr)

    new_list, fixed_list, unchanged_list, severity_changed = [], [], [], []

    for k in curr_keys - base_keys:
        new_list.append(_summarize(curr[k]))
    for k in base_keys - curr_keys:
        fixed_list.append(_summarize(base[k]))
    for k in curr_keys & base_keys:
        b_sev = str(base[k].get("severity", "")).lower()
        c_sev = str(curr[k].get("severity", "")).lower()
        if b_sev != c_sev:
            row = _summarize(curr[k])
            row["baseline_severity"] = b_sev
            row["current_severity"] = c_sev
            br, cr = _SEV_RANK.get(b_sev, -1), _SEV_RANK.get(c_sev, -1)
            row["direction"] = "raised" if cr > br else ("lowered" if cr < br else "changed")
            severity_changed.append(row)
        else:
            unchanged_list.append(_summarize(curr[k]))

    # deterministic ordering (severity desc, then id) so the report is stable
    def _ord(row):
        return (-_SEV_RANK.get(row.get("severity", ""), -1), row.get("id", ""))
    new_list.sort(key=_ord)
    fixed_list.sort(key=_ord)
    unchanged_list.sort(key=_ord)
    severity_changed.sort(key=_ord)

    summary = {
        "new": len(new_list),
        "fixed": len(fixed_list),
        "unchanged": len(unchanged_list),
        "severity_changed": len(severity_changed),
        "net_delta": len(new_list) - len(fixed_list),
        "total_baseline": len(base_keys),
        "total_current": len(curr_keys),
    }
    return {
        "summary": summary,
        "new": new_list,
        "fixed": fixed_list,
        "unchanged": unchanged_list,
        "severity_changed": severity_changed,
    }


def build_report(baseline_data, current_data, *, baseline_source="", current_source="",
                 generated=None) -> dict:
    """The full diff artifact (what gets written as JSON; validates against scan_diff.schema.json)."""
    baseline = extract_findings(baseline_data)
    current = extract_findings(current_data)
    body = diff_findings(baseline, current)
    return {
        "version": SCHEMA_VERSION,
        "generated": generated or _utc_now(),
        "baseline": {"source": str(baseline_source), "count": len(baseline)},
        "current": {"source": str(current_source), "count": len(current)},
        **body,
    }


# ------------------------------- optional human renders ------------------------------- #
def render_markdown(report: dict) -> str:
    """A simple Markdown summary + per-category table -- for the retest deliverable / exec-summary line."""
    s = report["summary"]
    lines = [
        "# Changes since last assessment",
        "",
        f"_Baseline: {report['baseline'].get('source') or 'n/a'} "
        f"({report['baseline']['count']} findings) · "
        f"Current: {report['current'].get('source') or 'n/a'} "
        f"({report['current']['count']} findings)_",
        "",
        "| Change | Count |",
        "|---|---|",
        f"| New | {s['new']} |",
        f"| Fixed | {s['fixed']} |",
        f"| Unchanged (still open) | {s['unchanged']} |",
        f"| Severity changed | {s['severity_changed']} |",
        f"| **Net delta** | **{s['net_delta']:+d}** |",
        "",
    ]

    def _tbl(title, rows, sev_cols=False):
        lines.append(f"## {title} ({len(rows)})")
        if not rows:
            lines.append("_none_")
            lines.append("")
            return
        if sev_cols:
            lines.append("| ID | Title | Asset | Baseline → Current |")
            lines.append("|---|---|---|---|")
            for r in rows:
                lines.append(f"| {r.get('id','')} | {r.get('title','')} | {r.get('asset','')} | "
                             f"{r.get('baseline_severity','')} → {r.get('current_severity','')} "
                             f"({r.get('direction','')}) |")
        else:
            lines.append("| ID | Severity | Title | Asset |")
            lines.append("|---|---|---|---|")
            for r in rows:
                lines.append(f"| {r.get('id','')} | {r.get('severity','')} | {r.get('title','')} | "
                             f"{r.get('asset','')} |")
        lines.append("")

    _tbl("New", report["new"])
    _tbl("Fixed", report["fixed"])
    _tbl("Severity changed", report["severity_changed"], sev_cols=True)
    _tbl("Unchanged (still open)", report["unchanged"])
    return "\n".join(lines) + "\n"


def render_html(report: dict) -> str:
    """A self-contained minimal HTML table (no external assets) of the same diff."""
    s = report["summary"]

    def esc(x):
        return html.escape(str(x))

    def _rows(rows, sev=False):
        out = []
        for r in rows:
            if sev:
                out.append(f"<tr><td>{esc(r.get('id',''))}</td><td>{esc(r.get('title',''))}</td>"
                           f"<td>{esc(r.get('asset',''))}</td>"
                           f"<td>{esc(r.get('baseline_severity',''))} &rarr; "
                           f"{esc(r.get('current_severity',''))} ({esc(r.get('direction',''))})</td></tr>")
            else:
                out.append(f"<tr><td>{esc(r.get('id',''))}</td><td>{esc(r.get('severity',''))}</td>"
                           f"<td>{esc(r.get('title',''))}</td><td>{esc(r.get('asset',''))}</td></tr>")
        return "\n".join(out) or "<tr><td colspan='4'><em>none</em></td></tr>"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Changes since last assessment</title>
<style>
 body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem;color:#1a1a1a}}
 table{{border-collapse:collapse;width:100%;margin:0 0 2rem}}
 th,td{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
 th{{background:#f0f0f0}} h2{{margin-top:1.5rem}}
</style></head><body>
<h1>Changes since last assessment</h1>
<p>Baseline: {esc(report['baseline'].get('source') or 'n/a')} ({report['baseline']['count']}) &middot;
 Current: {esc(report['current'].get('source') or 'n/a')} ({report['current']['count']})</p>
<table>
 <tr><th>New</th><th>Fixed</th><th>Unchanged</th><th>Severity changed</th><th>Net delta</th></tr>
 <tr><td>{s['new']}</td><td>{s['fixed']}</td><td>{s['unchanged']}</td>
     <td>{s['severity_changed']}</td><td>{s['net_delta']:+d}</td></tr>
</table>
<h2>New ({len(report['new'])})</h2>
<table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Asset</th></tr>
{_rows(report['new'])}</table>
<h2>Fixed ({len(report['fixed'])})</h2>
<table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Asset</th></tr>
{_rows(report['fixed'])}</table>
<h2>Severity changed ({len(report['severity_changed'])})</h2>
<table><tr><th>ID</th><th>Title</th><th>Asset</th><th>Baseline &rarr; Current</th></tr>
{_rows(report['severity_changed'], sev=True)}</table>
<h2>Unchanged, still open ({len(report['unchanged'])})</h2>
<table><tr><th>ID</th><th>Severity</th><th>Title</th><th>Asset</th></tr>
{_rows(report['unchanged'])}</table>
</body></html>
"""


def load_json(path) -> object:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _resolve_current(args) -> Path | None:
    if args.current:
        return Path(args.current)
    if args.engagement:
        return Path(args.engagement) / "report" / "findings_consolidated.json"
    return None


def selftest() -> None:
    def F(fid, asset, cwe="CWE-639", sev="high", **o):
        f = {"id": fid, "asset": asset, "category": {"cwe": cwe}, "severity": sev, "title": f"t-{fid}",
             "confidence": "confirmed", "status": "verified", "evidence": [{"type": "log", "ref": "r"}],
             "reproduction": ["x"]}
        f.update(o)
        return f

    # same bug, cosmetically different asset (scheme/port/case/param value) -> unchanged, not new/fixed.
    base = [F("RS-2026-001", "https://App.ACME.com:443/api/orders/?id=1")]
    curr = [F("RS-2026-010", "http://app.acme.com/api/orders?id=999")]
    d = diff_findings(base, curr)
    assert d["summary"] == {"new": 0, "fixed": 0, "unchanged": 1, "severity_changed": 0,
                            "net_delta": 0, "total_baseline": 1, "total_current": 1}, d["summary"]

    # new, fixed, severity-changed, unchanged all at once.
    base = [
        F("RS-2026-001", "https://app.acme.com/a?id=1", sev="high"),          # -> severity lowered
        F("RS-2026-002", "https://app.acme.com/b?id=1", sev="medium"),        # -> fixed
        F("RS-2026-003", "https://app.acme.com/c?id=1", sev="low"),           # -> unchanged
    ]
    curr = [
        F("RS-2026-101", "https://app.acme.com/a?id=2", sev="medium"),        # severity changed (high->medium)
        F("RS-2026-103", "https://app.acme.com/c?id=2", sev="low"),           # unchanged
        F("RS-2026-104", "https://app.acme.com/d?id=2", sev="critical"),      # new
    ]
    d = diff_findings(base, curr)
    s = d["summary"]
    assert (s["new"], s["fixed"], s["unchanged"], s["severity_changed"]) == (1, 1, 1, 1), s
    assert s["net_delta"] == 0, s
    assert d["new"][0]["id"] == "RS-2026-104"
    assert d["fixed"][0]["id"] == "RS-2026-002"
    assert d["severity_changed"][0]["direction"] == "lowered", d["severity_changed"]
    assert d["severity_changed"][0]["baseline_severity"] == "high"
    assert d["severity_changed"][0]["current_severity"] == "medium"

    # different vuln-class on the same locus is NOT the same bug.
    base = [F("RS-2026-001", "https://app.acme.com/o?id=1", cwe="CWE-639")]
    curr = [F("RS-2026-010", "https://app.acme.com/o?id=1", cwe="CWE-285")]
    d = diff_findings(base, curr)
    assert d["summary"]["new"] == 1 and d["summary"]["fixed"] == 1, d["summary"]

    # composite + duplicate are excluded from the diff set.
    base = []
    curr = [F("RS-2026-010", "https://app.acme.com/x?id=1"),
            F("RS-2026-011", "https://app.acme.com/y?id=1", status="duplicate"),
            F("RS-2026-012", "https://app.acme.com/z?id=1", composite=True)]
    d = diff_findings(extract_findings([]), extract_findings(curr))
    assert d["summary"]["new"] == 1, d["summary"]

    # object-wrapped shape is accepted; report body + renders are well-formed.
    rep = build_report({"findings": base}, {"findings": curr}, baseline_source="base.json",
                       current_source="curr.json", generated="2026-01-01T00:00:00Z")
    assert rep["version"] == SCHEMA_VERSION and rep["summary"]["new"] == 1
    assert "Changes since last assessment" in render_markdown(rep)
    assert "<table>" in render_html(rep)

    # net delta sign: more new than fixed -> positive (worse). 2 new - 1 fixed = +1.
    base = [F("RS-2026-001", "https://app.acme.com/a?id=1")]
    curr = [F("RS-2026-010", "https://app.acme.com/b?id=1"), F("RS-2026-011", "https://app.acme.com/c?id=1")]
    assert diff_findings(base, curr)["summary"]["net_delta"] == 1

    print("scan_diff selftest: OK")


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(
        description="Diff this engagement's consolidated findings against a prior baseline (retest).")
    ap.add_argument("--baseline", help="prior baseline findings_consolidated.json")
    ap.add_argument("--current", help="this engagement's findings_consolidated.json")
    ap.add_argument("--engagement", help="engagement dir (reads report/findings_consolidated.json as current)")
    ap.add_argument("--out", help="write the JSON diff report here (default: stdout)")
    ap.add_argument("--md", help="also write a Markdown table here")
    ap.add_argument("--html", help="also write an HTML table here")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0

    cur = _resolve_current(args)
    if not args.baseline or cur is None:
        ap.error("need --baseline <prior.json> and --current <this.json> (or --engagement <dir>)")
    base_path, cur_path = Path(args.baseline), cur
    for p in (base_path, cur_path):
        if not p.is_file():
            print(f"[!] not found: {p}")
            return 2
    try:
        baseline_data = load_json(base_path)
        current_data = load_json(cur_path)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] unreadable: {e}")
        return 2

    report = build_report(baseline_data, current_data,
                          baseline_source=str(base_path), current_source=str(cur_path))

    if args.out:
        atomic_write(Path(args.out), json.dumps(report, indent=2) + "\n")
    if args.md:
        atomic_write(Path(args.md), render_markdown(report))
    if args.html:
        atomic_write(Path(args.html), render_html(report))
    if not args.out:
        print(json.dumps(report, indent=2))
    else:
        s = report["summary"]
        print(f"# Scan diff -- new {s['new']}, fixed {s['fixed']}, unchanged {s['unchanged']}, "
              f"severity-changed {s['severity_changed']} (net {s['net_delta']:+d})")
        print(f"  JSON -> {args.out}" + (f" · MD -> {args.md}" if args.md else "")
              + (f" · HTML -> {args.html}" if args.html else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
