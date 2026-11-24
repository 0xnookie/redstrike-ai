#!/usr/bin/env python3
"""
export_formats.py -- engagement-wide SARIF 2.1.0 + JUnit XML exporters (the reporting flow). Stdlib only.

WHY THIS EXISTS:
  The recon JS-analysis skill already emits SARIF 2.1.0 for its own narrow finding set (secrets + DOM
  gadgets). That machine-interchange shape is just as useful for the ENGAGEMENT'S confirmed findings: a
  SARIF file folds straight into a code-scanning dashboard, and a JUnit file turns each confirmed finding
  into a failing CI test case so a pipeline can gate a release on "no new confirmed findings". This promotes
  the SAME SARIF rule/result/severity->level mapping from recon-only to engagement-wide, reading the
  reporting skill's `findings_consolidated.json` and writing `exports/findings.sarif` + `exports/junit.xml`.

WHAT COUNTS AS A REPORTED FINDING (what both exports include):
  The consolidated file is reporting's output, so it already holds the accepted + blocked findings with the
  cross-agent duplicates stamped. We include a finding when it is accepted/blocked (verdict) or already
  `verified` (status), and EXCLUDE `status:"duplicate"` (a merged duplicate, not a distinct bug) and
  `composite:true` kill-chains (they re-state already-counted component findings -> non-additive). An object
  wrapper's `attack_chains[]` are composite by construction and are never emitted as separate rows.

SARIF mapping (reused verbatim from the js-analysis recon exporter):
  severity -> level:  critical/high -> error ; medium -> warning ; low/info -> note.
  schema:  SARIF 2.1.0 (https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/
  sarif-schema-2.1.0.json). One `rule` per vuln-class (cwe -> owasp -> wstg -> title-slug), one `result`
  per finding, the finding's `asset` as the result location.

Pure logic (extract/filter/build_*) so it unit-tests with no network; a thin CLI wires it to an engagement.
OPTIONAL + config-gated in reporting: default behaviour is unchanged when it is not run.
`python scripts/export_formats.py --selftest`.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# atomic_write: the one shared findings/ledger write helper (same resolution as dedup.py / coverage.py).
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover - only hit under path-based loading without scripts/ on sys.path
    import importlib.util as _ilu
    _aspec = _ilu.spec_from_file_location("atomicio", str(Path(__file__).resolve().parent / "atomicio.py"))
    _amod = _ilu.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write


SARIF_SCHEMA = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
                "sarif-2.1/schema/sarif-schema-2.1.0.json")
SARIF_VERSION = "2.1.0"
TOOL_NAME = "redstrike"

# severity -> SARIF level, reused verbatim from the js-analysis recon SARIF exporter.
SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# verdicts that make a finding reportable (mirrors reporting's accept+blocked filter).
_REPORTABLE_VERDICTS = {"accepted", "blocked"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_findings(data) -> list:
    """The findings list from either accepted consolidated shape: a bare array, or a report object with a
    `findings` key (findings_consolidated.schema.json). Non-dict members are dropped."""
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("findings") or []
    else:
        items = []
    return [f for f in items if isinstance(f, dict)]


def is_reportable(finding: dict) -> bool:
    """A distinct, confirmed finding worth exporting: accepted/blocked (or already `verified`), and NOT a
    merged duplicate or a non-additive composite kill-chain."""
    if finding.get("composite"):
        return False
    status = str(finding.get("status", "")).lower()
    if status == "duplicate":
        return False
    verdict = str(((finding.get("review") or {}).get("verdict")) or "").lower()
    if verdict:
        return verdict in _REPORTABLE_VERDICTS
    # No inline review block: fall back to the derived lifecycle status.
    return status == "verified"


def reportable_findings(data) -> list:
    """The export set: every reportable finding from a consolidated findings artifact."""
    return [f for f in extract_findings(data) if is_reportable(f)]


def _severity(finding: dict) -> str:
    return str(finding.get("severity", "info")).lower() or "info"


def _level(severity: str) -> str:
    return SEVERITY_TO_LEVEL.get(str(severity).lower(), "note")


def _slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", str(text or "").strip().lower()).strip("-")
    return s or "finding"


def rule_id(finding: dict) -> str:
    """Vuln-class rule id for SARIF: cwe -> owasp -> wstg -> title-slug (mirrors dedup's class discriminator
    so the SARIF rule granularity matches how findings are de-duplicated)."""
    cat = finding.get("category") or {}
    for k in ("cwe", "owasp", "wstg"):
        v = str(cat.get(k) or "").strip()
        if v:
            return _slug(v)
    return _slug(finding.get("title"))


def _rule_name(finding: dict) -> str:
    cat = finding.get("category") or {}
    for k in ("cwe", "owasp", "wstg"):
        v = str(cat.get(k) or "").strip()
        if v:
            return v
    return str(finding.get("title") or "Finding")


def _help_uri(finding: dict):
    """A standard reference for the rule when a CWE is present (open, non-attributing)."""
    cwe = str((finding.get("category") or {}).get("cwe") or "").strip()
    m = re.match(r"^CWE-([0-9]+)$", cwe)
    if m:
        return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"
    return None


def build_sarif(findings: list, now: str | None = None) -> dict:
    """SARIF 2.1.0 log: one run, one rule per vuln-class, one result per reportable finding.
    Deterministic given `now`; rules are emitted in first-seen order."""
    now = now or _utc_now()
    rules = []
    rule_index = {}
    results = []
    for f in findings:
        rid = rule_id(f)
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rule = {
                "id": rid,
                "name": _rule_name(f),
                "shortDescription": {"text": str(f.get("title") or _rule_name(f))},
                "fullDescription": {"text": str(f.get("impact") or f.get("title") or _rule_name(f))},
                "defaultConfiguration": {"level": _level(_severity(f))},
            }
            help_uri = _help_uri(f)
            if help_uri:
                rule["helpUri"] = help_uri
            rules.append(rule)

        cat = f.get("category") or {}
        title = str(f.get("title") or _rule_name(f))
        impact = str(f.get("impact") or "").strip()
        message = f"{title}. {impact}" if impact else title
        props = {
            "severity": _severity(f),
            "finding_id": str(f.get("id", "")),
            "confidence": str(f.get("confidence", "")),
            "status": str(f.get("status", "")),
        }
        for k in ("cwe", "owasp", "wstg"):
            if cat.get(k):
                props[k] = str(cat[k])
        if f.get("cvss_vector"):
            props["cvss_vector"] = str(f["cvss_vector"])
        if f.get("remediation"):
            props["remediation"] = str(f["remediation"])

        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": _level(_severity(f)),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.get("asset", ""))}
                }
            }],
            "properties": props,
        })

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {"name": TOOL_NAME, "rules": rules}},
            "results": results,
            "invocations": [{"executionSuccessful": True, "endTimeUtc": now}],
        }],
    }


def _failure_body(finding: dict) -> str:
    """Multiline <failure> body: impact, reproduction, evidence refs, remediation, references."""
    parts = []
    impact = str(finding.get("impact") or "").strip()
    if impact:
        parts.append(f"Impact: {impact}")
    repro = finding.get("reproduction") or []
    if isinstance(repro, list) and repro:
        parts.append("Reproduction:")
        parts.extend(f"  {i}. {step}" for i, step in enumerate(repro, 1))
    ev_refs = []
    for ev in finding.get("evidence") or []:
        if isinstance(ev, dict):
            ev_refs.append(str(ev.get("ref") or ev.get("file") or ev.get("type") or ""))
    ev_refs = [e for e in ev_refs if e]
    if ev_refs:
        parts.append("Evidence: " + "; ".join(ev_refs))
    remediation = str(finding.get("remediation") or "").strip()
    if remediation:
        parts.append(f"Remediation: {remediation}")
    refs = finding.get("references") or []
    if isinstance(refs, list) and refs:
        parts.append("References: " + "; ".join(str(r) for r in refs))
    return "\n".join(parts) if parts else "No additional details."


def build_junit(findings: list, suite_name: str = TOOL_NAME, now: str | None = None) -> bytes:
    """JUnit XML: one <testcase> with a nested <failure> per reportable finding (CI-compatible). Each
    confirmed finding is a failing test, so a pipeline can gate on 'no confirmed findings'."""
    now = now or _utc_now()
    count = len(findings)
    testsuites = ET.Element("testsuites", {
        "name": TOOL_NAME,
        "tests": str(count),
        "failures": str(count),
        "errors": "0",
    })
    testsuite = ET.SubElement(testsuites, "testsuite", {
        "name": str(suite_name),
        "tests": str(count),
        "failures": str(count),
        "errors": "0",
        "skipped": "0",
        "timestamp": now,
    })
    for f in findings:
        fid = str(f.get("id", ""))
        title = str(f.get("title") or _rule_name(f))
        asset = str(f.get("asset", ""))
        severity = _severity(f)
        case_name = f"{fid} {title}".strip() if fid else title
        classname = _rule_name(f)
        testcase = ET.SubElement(testsuite, "testcase", {
            "classname": classname,
            "name": case_name,
            "time": "0",
        })
        failure = ET.SubElement(testcase, "failure", {
            "type": severity,
            "message": f"[{severity}] {title}" + (f" @ {asset}" if asset else ""),
        })
        failure.text = _failure_body(f)
    try:
        ET.indent(testsuites, space="  ")
    except AttributeError:  # pragma: no cover - Python <3.9
        pass
    return ET.tostring(testsuites, encoding="utf-8", xml_declaration=True)


def load_consolidated(path) -> object:
    """Read a findings_consolidated.json (bare array or report object). Raises on unreadable/invalid JSON."""
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_exports(data, out_dir) -> dict:
    """Write exports/findings.sarif + exports/junit.xml from a loaded consolidated artifact.
    Returns {sarif, junit, count}. Atomic writes so a reader never sees a torn file."""
    out = Path(out_dir)
    findings = reportable_findings(data)
    now = _utc_now()
    sarif_path = out / "findings.sarif"
    junit_path = out / "junit.xml"
    atomic_write(sarif_path, json.dumps(build_sarif(findings, now=now), indent=2) + "\n")
    atomic_write(junit_path, build_junit(findings, now=now).decode("utf-8") + "\n")
    return {"sarif": str(sarif_path), "junit": str(junit_path), "count": len(findings)}


def _resolve_input(args) -> Path | None:
    """The consolidated findings path from --input, or <engagement>/report/findings_consolidated.json."""
    if args.input:
        return Path(args.input)
    if args.engagement:
        return Path(args.engagement) / "report" / "findings_consolidated.json"
    return None


def selftest() -> None:
    accepted = {"id": "RS-2026-001", "title": "Reflected XSS in search",
                "asset": "https://app.acme.com/search?q=1", "category": {"cwe": "CWE-79", "owasp": "A03"},
                "severity": "high", "confidence": "confirmed", "status": "verified",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "impact": "Script runs in a victim session.", "remediation": "Encode output.",
                "evidence": [{"type": "request_response", "ref": "poc/xss.http"}],
                "reproduction": ["GET /search?q=<payload>", "observe alert"],
                "review": {"verdict": "accepted", "reviewer": "xss-reflected-verify"}}
    rejected = {"id": "RS-2026-002", "title": "Rejected noise", "asset": "https://app.acme.com/x",
                "category": {"cwe": "CWE-79"}, "severity": "low", "confidence": "tentative",
                "status": "rejected", "evidence": [{"type": "log", "ref": "x"}], "reproduction": ["x"],
                "review": {"verdict": "rejected", "reviewer": "xss-reflected-verify"}}
    dup = {"id": "RS-2026-003", "title": "Dup", "asset": "https://app.acme.com/search?q=9",
           "category": {"cwe": "CWE-79"}, "severity": "high", "confidence": "confirmed",
           "status": "duplicate", "evidence": [{"type": "log", "ref": "y"}], "reproduction": ["x"],
           "review": {"verdict": "accepted", "reviewer": "idor-verify"}}
    comp = {"id": "RS-2026-004", "title": "Kill chain", "asset": "https://app.acme.com/",
            "category": {"cwe": "CWE-79"}, "severity": "critical", "confidence": "confirmed",
            "status": "verified", "composite": True, "evidence": [{"type": "log", "ref": "z"}],
            "reproduction": ["x"], "review": {"verdict": "accepted", "reviewer": "attack-chain-discovery-verify"}}
    blocked = {"id": "RS-2026-005", "title": "Blind SQLi (demo limited)", "asset": "https://api.acme.com/items?id=1",
               "category": {"cwe": "CWE-89"}, "severity": "medium", "confidence": "confirmed",
               "status": "verified", "impact": "DB inference.", "evidence": [{"type": "tool_output", "ref": "p"}],
               "reproduction": ["x"], "review": {"verdict": "blocked", "reviewer": "sqli-blind-verify"}}

    # bare-array and object-wrapped shapes both resolve to the same reportable set.
    arr = [accepted, rejected, dup, comp, blocked]
    obj = {"engagement": "e", "findings": arr, "attack_chains": [comp]}
    want = {"RS-2026-001", "RS-2026-005"}
    assert {f["id"] for f in reportable_findings(arr)} == want, reportable_findings(arr)
    assert {f["id"] for f in reportable_findings(obj)} == want

    # SARIF: schema/version/level map + one rule per class + one result per reportable finding.
    sarif = build_sarif(reportable_findings(arr), now="2026-01-01T00:00:00Z")
    assert sarif["version"] == SARIF_VERSION and sarif["$schema"] == SARIF_SCHEMA
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == TOOL_NAME
    assert len(run["results"]) == 2, run["results"]
    levels = {r["properties"]["finding_id"]: r["level"] for r in run["results"]}
    assert levels["RS-2026-001"] == "error" and levels["RS-2026-005"] == "warning", levels
    rids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert rids == {"cwe-79", "cwe-89"}, rids
    # every result's ruleIndex points at its rule
    for r in run["results"]:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]

    # JUnit: parseable, one failing testcase per reportable finding, counts consistent.
    xml_bytes = build_junit(reportable_findings(arr), now="2026-01-01T00:00:00Z")
    root = ET.fromstring(xml_bytes)
    suite = root.find("testsuite")
    assert suite.get("tests") == "2" and suite.get("failures") == "2" and suite.get("errors") == "0"
    cases = suite.findall("testcase")
    assert len(cases) == 2 and all(c.find("failure") is not None for c in cases)

    # empty input -> valid, empty exports (a clean engagement still produces well-formed files).
    empty = build_sarif([], now="2026-01-01T00:00:00Z")
    assert empty["runs"][0]["results"] == []
    empty_junit = ET.fromstring(build_junit([], now="2026-01-01T00:00:00Z"))
    assert empty_junit.find("testsuite").get("tests") == "0"

    print("export_formats selftest: OK")


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(
        description="Export an engagement's consolidated findings to SARIF 2.1.0 + JUnit XML.")
    ap.add_argument("--input", help="path to findings_consolidated.json")
    ap.add_argument("--engagement", help="engagement dir (reads report/findings_consolidated.json)")
    ap.add_argument("--out-dir", help="output dir for findings.sarif + junit.xml "
                                      "(default: <input dir>/exports or <engagement>/report/exports)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0

    src = _resolve_input(args)
    if src is None:
        ap.error("choose --input <findings_consolidated.json> or --engagement <dir> (or --selftest)")
    if not src.is_file():
        print(json.dumps({"error": f"not found: {src}"}) if args.as_json else f"[!] not found: {src}")
        return 2
    try:
        data = load_consolidated(src)
    except (OSError, json.JSONDecodeError) as e:
        print(json.dumps({"error": f"unreadable: {e}"}) if args.as_json else f"[!] unreadable: {e}")
        return 2

    if args.out_dir:
        out_dir = Path(args.out_dir)
    elif args.engagement:
        out_dir = Path(args.engagement) / "report" / "exports"
    else:
        out_dir = src.parent / "exports"

    res = write_exports(data, out_dir)
    if args.as_json:
        print(json.dumps(res, indent=2))
    else:
        print(f"# Export formats -- {res['count']} finding(s)")
        print(f"  SARIF 2.1.0 -> {res['sarif']}")
        print(f"  JUnit XML   -> {res['junit']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
