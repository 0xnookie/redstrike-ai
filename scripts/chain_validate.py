#!/usr/bin/env python3
"""
chain_validate.py -- attack-chain integrity validator.

A kill chain (attack-chain-discovery) composes INDIVIDUALLY-ACCEPTED findings into higher-impact impact,
and each chain also becomes a COMPOSITE finding in findings.json (listed under Attack Chains, excluded from
the severity counts as non-additive). Two invariants keep that honest, and nothing enforced them
deterministically:

  1. Every chain `step.finding_id` must resolve to a real finding whose review verdict is accepted/blocked
     (the only reportable verdicts) -- a chain built on a rejected/unknown finding is not a real chain.
  2. Every chain finding (an entry placed in the report's `attack_chains[]`) must set `composite:true` --
     otherwise reporting double-counts it in the severity totals.

Pure logic (`validate_chains`) so it unit-tests with no network; a thin `load_and_validate(eng)` reads the
engagement's chains.json + findings. Stdlib only. `python scripts/chain_validate.py --selftest`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_REPORTABLE = {"accepted", "blocked"}


def _effective_verdict(f: dict) -> str:
    """review.verdict if present, else derived from status (verified->accepted, rejected->rejected)."""
    v = (f.get("review") or {}).get("verdict")
    if v:
        return v
    st = f.get("status")
    return "accepted" if st == "verified" else "rejected" if st == "rejected" else ""


def validate_chains(chains, findings_by_id, chain_findings=None) -> list:
    """Pure validator. Returns a list of human-readable error strings.

    chains:         [{id, steps:[{finding_id, role}], ...}]  -- the step structure (attack_chain.schema).
    findings_by_id: {finding_id: finding}                    -- every engagement finding.
    chain_findings: [finding, ...]                           -- findings placed as attack chains (must be
                                                               composite:true); typically the report's
                                                               attack_chains[]. Optional."""
    errors = []
    for ch in chains or []:
        cid = ch.get("id", "<chain>")
        steps = ch.get("steps") or []
        if len(steps) < 2:
            errors.append(f"chain {cid}: has {len(steps)} step(s); a chain needs >= 2")
        for i, st in enumerate(steps, 1):
            fid = (st or {}).get("finding_id")
            if not fid:
                errors.append(f"chain {cid} step {i}: no finding_id")
                continue
            f = findings_by_id.get(fid)
            if f is None:
                errors.append(f"chain {cid} step {i}: finding_id '{fid}' resolves to no finding")
                continue
            v = _effective_verdict(f)
            if v not in _REPORTABLE:
                errors.append(f"chain {cid} step {i}: finding '{fid}' verdict '{v or '(none)'}' is not "
                              f"accepted/blocked — a chain may only compose reportable findings")
    for cf in chain_findings or []:
        if not isinstance(cf, dict):
            continue
        if not cf.get("composite"):
            errors.append(f"attack-chain finding '{cf.get('id', '<no-id>')}' is not composite:true — it would "
                          f"be double-counted in the severity totals")
    return errors


# ------------------------------- engagement I/O (thin) ------------------------------- #
def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _discover_findings(eng: Path):
    """Reuse verify_completion's multi-layout discovery so the validator sees the gate's finding set."""
    try:
        import importlib.util
        p = ROOT / "skills" / "_contract" / "verify_completion.py"
        spec = importlib.util.spec_from_file_location("rs_vc_chain", p)
        vc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vc)
        findings, _src = vc._discover_engagement_findings(eng)
        return findings or []
    except Exception:  # noqa: BLE001
        return []


def _load_chains(eng: Path) -> list:
    """Chain step-structures from chains.json (attack_chain.schema): root + per-skill."""
    chains = []
    for p in [eng / "chains.json"] + sorted(eng.glob("*/chains.json")):
        d = _read_json(p)
        if isinstance(d, dict) and isinstance(d.get("chains"), list):
            chains.extend(d["chains"])
    return chains


def _load_chain_findings(eng: Path) -> list:
    """Findings placed as attack chains in the consolidated report (must be composite:true)."""
    d = _read_json(eng / "report" / "findings_consolidated.json")
    if isinstance(d, dict) and isinstance(d.get("attack_chains"), list):
        return d["attack_chains"]
    return []


def load_and_validate(eng: Path) -> list:
    findings = _discover_findings(eng)
    by_id = {f.get("id"): f for f in findings if isinstance(f, dict) and f.get("id")}
    return validate_chains(_load_chains(eng), by_id, _load_chain_findings(eng))


def chain_hard_errors(eng: Path) -> list:
    """HARD gate for verify_completion — active only once a report exists (mirrors the other gates)."""
    if not (eng / "report" / "findings_consolidated.json").is_file():
        return []
    return [f"attack-chain gate (report present): {e}" for e in load_and_validate(eng)]


def selftest() -> None:
    findings = {
        "RS-2026-001": {"id": "RS-2026-001", "review": {"verdict": "accepted"}},
        "RS-2026-002": {"id": "RS-2026-002", "status": "verified"},           # derives to accepted
        "RS-2026-003": {"id": "RS-2026-003", "review": {"verdict": "blocked"}},
        "RS-2026-009": {"id": "RS-2026-009", "review": {"verdict": "rejected"}},
    }
    good = [{"id": "chain-001", "steps": [{"finding_id": "RS-2026-001", "role": "entry"},
                                          {"finding_id": "RS-2026-002", "role": "escalation"}]}]
    assert validate_chains(good, findings) == [], validate_chains(good, findings)

    # blocked is reportable too
    ok2 = [{"id": "chain-002", "steps": [{"finding_id": "RS-2026-001"}, {"finding_id": "RS-2026-003"}]}]
    assert validate_chains(ok2, findings) == []

    # a step on a REJECTED finding fails
    bad = [{"id": "chain-003", "steps": [{"finding_id": "RS-2026-001"}, {"finding_id": "RS-2026-009"}]}]
    e = validate_chains(bad, findings)
    assert e and "RS-2026-009" in e[0] and "not" in e[0], e

    # a step on an UNKNOWN finding fails
    e = validate_chains([{"id": "c", "steps": [{"finding_id": "RS-2026-001"}, {"finding_id": "RS-2026-999"}]}], findings)
    assert e and "resolves to no finding" in e[0]

    # a <2-step chain fails
    e = validate_chains([{"id": "c", "steps": [{"finding_id": "RS-2026-001"}]}], findings)
    assert any("needs >= 2" in x for x in e)

    # a chain FINDING that isn't composite fails (double-count risk)
    e = validate_chains([], findings, chain_findings=[{"id": "RS-2026-050", "composite": False}])
    assert e and "composite:true" in e[0]
    assert validate_chains([], findings, chain_findings=[{"id": "RS-2026-050", "composite": True}]) == []

    # no chains at all -> clean
    assert validate_chains([], findings) == []

    print("chain_validate selftest: OK")


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description="Redstrike attack-chain integrity validator.")
    ap.add_argument("--engagement", help="engagement dir")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0
    if not args.engagement:
        ap.error("choose --engagement <dir> or --selftest")

    errs = load_and_validate(Path(args.engagement))
    if args.as_json:
        print(json.dumps({"engagement": args.engagement, "pass": not errs, "errors": errs}, indent=2))
    else:
        print(f"# Attack-chain validation -- {args.engagement}")
        for e in errs:
            print(f"  - {e}")
        print(f"\n{'PASS' if not errs else 'FAIL'}: {len(errs)} chain integrity error(s).")
    return 0 if not errs else 2


if __name__ == "__main__":
    sys.exit(main())
