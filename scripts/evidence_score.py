#!/usr/bin/env python3
"""evidence_score.py -- the quantified EVIDENCE-SUFFICIENCY score (the measured accept/downgrade floor).

WHY THIS EXISTS:
  Redstrike's own strategic roadmap flags "no measured numbers / thin evidence" as a top gap. Until now
  confidence was CATEGORICAL — one rule in verify-base.md (check #2) caps `confidence` at `probable` when
  the ONLY evidence is the skill's own log, and the semantic `*-verify` reviewer then decides accept /
  downgrade / reject by judgment alone. There was no NUMERIC, reproducible measure of *how much* a finding
  is actually proven, so "thin but plausible" and "demonstrated three ways" looked the same to every
  downstream consumer, and the engagement emitted no measured evidence numbers at all.

  This module computes a 0-100 evidence-sufficiency score from INDEPENDENT components, each fitted to
  redstrike's finding/evidence model (finding.schema.json evidence types + the reliability/chain facts a
  reviewer observes). The score is used as a HARD FLOOR on the verdict:

      score < 55  -> KILL       (the evidence is too thin — the finding cannot be accepted)
      55 <= s < 75 -> DOWNGRADE (real but under-proven — drop the severity)
      score >= 75 -> PASS       (sufficiently proven — the reviewer may accept at face severity)

  It AUGMENTS the independent reviewers; it never replaces them. The semantic `*-verify` reviewer stays the
  AUTHORITY — the score is only a floor the reviewer cannot raise above (a PASS score does not force an
  accept; a KILL score forbids one). It is pure logic (inputs injected), so it is unit-testable with no
  network, and it COMPOSES with the existing probable-cap rule rather than contradicting it:

    * the SCORE is a floor on the accept/downgrade VERDICT (how strong is the proof?);
    * the probable-cap is a ceiling on CONFIDENCE (can this read `confirmed`?). A finding whose only
      evidence is the skill's own log/tool_output has no INDEPENDENT artifact, so `probable_cap` is set and
      `confidence` cannot read `confirmed` — independently of the numeric score. By construction the two
      agree (a circular-only finding also scores low), but they are enforced as separate axes so neither can
      silently override the other.

COMPONENTS (each independent; the weights are NAMED, documented constants, summing to 100):

  request_response     (20)  a real captured HTTP request/response pair (`request_response` evidence).
                             WHITE-BOX substitution: a `code_citation` (verbatim vulnerable source at
                             file:line) is the white-box analogue of the captured HTTP pair and satisfies
                             this component when no request_response exists (flagged, so it is never silent).
  readback             (20)  in-band read-back / confirmation that the effect actually occurred — the data
                             returned, the marker observed, the traced sink reached — not merely that a
                             payload was sent. SEMANTIC: the reviewer asserts it (CLI flag); the finding-file
                             extractor defaults it off (conservative).
  impact_artifact      (20)  a distinct HARM/IMPACT artifact (an exfiltrated marker, a state change, a PoC
                             that demonstrates consequence) — DISTINCT from a mere trigger / reflection.
                             SEMANTIC: reviewer-asserted.
  browser_verification (15)  a browser-driven confirmation (a `dom_capture` from a real driven browser, per
                             the browser-exploit class). Mechanically derivable from the evidence types.
  reliability          (15)  reliability_hits / reliability_runs. A DETERMINISTIC finding (runs == 0) earns
                             full credit — it is reliable by nature. A probabilistic finding earns full
                             credit when its hit-rate >= 0.8, and PRORATED credit below that, where it is
                             also flagged "race/timing -- needs chaining" (an unreliable single trigger is a
                             chaining lead, not an accepted finding on its own).
  chain_depth          (10)  a bonus when the finding is a chain of depth >= 2 (composed impact is stronger
                             evidence of real-world consequence than an isolated trigger).

Stdlib only. Python 3.10+ safe. References no external source.

CLI (mirrors scripts/evidence_seal.py / scripts/cvss.py):
    # from explicit component flags:
    python evidence_score.py --request-response --readback --impact --reliability-runs 20 --reliability-hits 18
    # from a finding (mechanical components derived; add the semantic flags the reviewer confirmed):
    python evidence_score.py --file idor/findings.json --id RS-2026-012 --readback --impact
    # aggregate every finding's score for an engagement (the measured numbers):
    python evidence_score.py --engagement engagements/<dir> --aggregate
    python evidence_score.py --selftest
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# --- NAMED weights (sum to 100) ---------------------------------------------
W_REQUEST_RESPONSE = 20
W_READBACK = 20
W_IMPACT_ARTIFACT = 20
W_BROWSER_VERIFICATION = 15
W_RELIABILITY = 15
W_CHAIN_DEPTH = 10
_WEIGHT_TOTAL = (W_REQUEST_RESPONSE + W_READBACK + W_IMPACT_ARTIFACT
                 + W_BROWSER_VERIFICATION + W_RELIABILITY + W_CHAIN_DEPTH)
assert _WEIGHT_TOTAL == 100, f"evidence-score weights must sum to 100, got {_WEIGHT_TOTAL}"

# --- NAMED thresholds -------------------------------------------------------
RELIABILITY_MIN = 0.8   # hit-rate below this => race/timing, prorated credit + a chaining flag
CHAIN_DEPTH_MIN = 2     # a chain of this depth or deeper earns the chain bonus

# --- NAMED decision bands ---------------------------------------------------
BAND_KILL = 55          # score < BAND_KILL        -> KILL      (cannot be accepted)
BAND_PASS = 75          # BAND_KILL <= s < BAND_PASS -> DOWNGRADE (severity drop)
DECISION_KILL = "kill"
DECISION_DOWNGRADE = "downgrade"
DECISION_PASS = "pass"

# Evidence types that are INDEPENDENT, reproducible artifacts (verify-base.md check #2 / R1). Anything
# resting ONLY on the producing skill's own `log`/`tool_output` is circular -> probable_cap.
INDEPENDENT_EVIDENCE_TYPES = frozenset(
    {"request_response", "poc_script", "screenshot", "dom_capture", "code_citation"}
)
# A dom_capture is the signal that a real browser rendered/confirmed the effect (browser-exploit class).
_BROWSER_EVIDENCE_TYPES = frozenset({"dom_capture"})


def _round_half_up(x: float) -> int:
    """Deterministic half-up rounding to an int (avoids Python's banker's rounding at the .5 band edge,
    so a score of exactly 74.5 reads 75, not 74 — the band decision must be reproducible)."""
    import math
    return int(math.floor(float(x) + 0.5))


@dataclass
class EvidenceInputs:
    """The independent facts the score is computed from. A reviewer fills these (from the evidence vault +
    what the PoC measured); `inputs_from_finding` derives the mechanical ones from a finding dict.

    Booleans are PRESENCE facts (is the artifact there / was the effect confirmed). Reliability is the
    measured run/hit count of a probabilistic PoC (runs == 0 => deterministic). chain_depth is the number
    of chained legs (0/1 => not a chain)."""
    has_request_response: bool = False
    has_readback: bool = False
    has_browser_verification: bool = False
    has_impact_artifact: bool = False
    has_independent_artifact: bool = False
    reliability_runs: int = 0
    reliability_hits: int = 0
    chain_depth: int = 0
    white_box: bool = False  # set when request_response credit came from a code_citation substitution


@dataclass
class EvidenceScore:
    """The computed result: the 0-100 score, the mechanical band decision, the per-component breakdown, the
    reliability counts, the probable-cap axis, and any human-readable flags. `to_dict()` is the exact shape
    written into a finding's `evidence_score` block and printed by the CLI."""
    score: int
    decision: str
    components: dict
    reliability_runs: int
    reliability_hits: int
    probable_cap: bool
    flags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "decision": self.decision,
            "components": dict(self.components),
            "reliability_runs": self.reliability_runs,
            "reliability_hits": self.reliability_hits,
            "probable_cap": self.probable_cap,
            "flags": list(self.flags),
        }


def _reliability_component(runs: int, hits: int) -> tuple:
    """(awarded_points, hit_rate_or_None, flag_or_None) for the reliability component.

    runs <= 0  -> a DETERMINISTIC finding: full credit, no hit-rate (not probabilistic).
    runs  > 0  -> hit_rate = min(hits/runs, 1.0); full credit at/above RELIABILITY_MIN, else PRORATED credit
                  plus a 'race/timing -- needs chaining' flag (an unreliable trigger is a chaining lead)."""
    runs = max(int(runs or 0), 0)
    hits = max(int(hits or 0), 0)
    if runs <= 0:
        return float(W_RELIABILITY), None, None
    hit_rate = min(hits / runs, 1.0)
    if hit_rate >= RELIABILITY_MIN:
        return float(W_RELIABILITY), hit_rate, None
    awarded = round(W_RELIABILITY * hit_rate, 2)
    flag = (f"race/timing -- needs chaining (hit-rate {hit_rate:.2f} < {RELIABILITY_MIN:g}; "
            f"{hits}/{runs} runs hit)")
    return awarded, hit_rate, flag


def decision_for(score) -> str:
    """Map a 0-100 score to its mechanical band decision (the floor)."""
    s = float(score)
    if s < BAND_KILL:
        return DECISION_KILL
    if s < BAND_PASS:
        return DECISION_DOWNGRADE
    return DECISION_PASS


def score(inputs: EvidenceInputs) -> EvidenceScore:
    """Compute the evidence-sufficiency score from independent components. Pure — no I/O."""
    flags: list = []
    comp: dict = {}

    comp["request_response"] = W_REQUEST_RESPONSE if inputs.has_request_response else 0
    if inputs.has_request_response and inputs.white_box:
        flags.append("white-box: a code_citation substitutes for the HTTP request/response artifact")
    comp["readback"] = W_READBACK if inputs.has_readback else 0
    comp["impact_artifact"] = W_IMPACT_ARTIFACT if inputs.has_impact_artifact else 0
    comp["browser_verification"] = W_BROWSER_VERIFICATION if inputs.has_browser_verification else 0

    rel_points, _hit_rate, rel_flag = _reliability_component(inputs.reliability_runs, inputs.reliability_hits)
    comp["reliability"] = rel_points
    if rel_flag:
        flags.append(rel_flag)

    depth = max(int(inputs.chain_depth or 0), 0)
    comp["chain_depth"] = W_CHAIN_DEPTH if depth >= CHAIN_DEPTH_MIN else 0

    raw = sum(comp.values())
    total = max(0, min(100, _round_half_up(raw)))
    decision = decision_for(total)

    # The probable-cap axis: capped iff there is NO independent artifact. A `request_response` or a
    # browser `dom_capture` IS an independent artifact type (INDEPENDENT_EVIDENCE_TYPES), so asserting
    # either lifts the cap on its own — the reviewer need not separately assert `has_independent_artifact`.
    independent = (inputs.has_independent_artifact or inputs.has_request_response
                   or inputs.has_browser_verification)
    probable_cap = not independent
    if probable_cap:
        flags.append("circular-evidence: only the skill's own log/tool_output -> confidence capped at "
                     "'probable' (an independent artifact is required to read 'confirmed')")

    return EvidenceScore(
        score=total,
        decision=decision,
        components=comp,
        reliability_runs=max(int(inputs.reliability_runs or 0), 0),
        reliability_hits=max(int(inputs.reliability_hits or 0), 0),
        probable_cap=probable_cap,
        flags=flags,
    )


def score_components(**kwargs) -> EvidenceScore:
    """Convenience: score from keyword component facts (mirrors EvidenceInputs fields)."""
    return score(EvidenceInputs(**kwargs))


# --- finding extraction -----------------------------------------------------
def inputs_from_finding(finding: dict) -> EvidenceInputs:
    """Derive the MECHANICAL inputs from a finding dict (evidence types + composite flag). The SEMANTIC
    components (readback, impact_artifact) default off — the reviewer asserts those via CLI flags when it
    computes the score, because an evidence TYPE alone cannot prove the effect was read back / had impact.

    Reliability counts and an explicit chain depth are read from an already-present `evidence_score` block
    when one exists (so re-scoring preserves measured facts); otherwise reliability is 0 (deterministic) and
    chain depth is CHAIN_DEPTH_MIN for a `composite` finding, else 0."""
    if not isinstance(finding, dict):
        finding = {}
    ev = finding.get("evidence") or []
    types = [e.get("type") for e in ev if isinstance(e, dict)]
    has_rr = "request_response" in types
    has_code = "code_citation" in types
    white_box = has_code and not has_rr
    has_independent = any(t in INDEPENDENT_EVIDENCE_TYPES for t in types)
    has_browser = any(t in _BROWSER_EVIDENCE_TYPES for t in types)

    prior = finding.get("evidence_score") if isinstance(finding.get("evidence_score"), dict) else {}
    try:
        runs = int(prior.get("reliability_runs") or 0)
    except (TypeError, ValueError):
        runs = 0
    try:
        hits = int(prior.get("reliability_hits") or 0)
    except (TypeError, ValueError):
        hits = 0

    depth = CHAIN_DEPTH_MIN if finding.get("composite") else 0
    pcomp = prior.get("components") if isinstance(prior.get("components"), dict) else {}
    if "chain_depth" in pcomp:
        # a prior block that already recorded the chain bonus implies depth >= CHAIN_DEPTH_MIN
        try:
            depth = max(depth, CHAIN_DEPTH_MIN if float(pcomp["chain_depth"]) > 0 else depth)
        except (TypeError, ValueError):
            pass

    return EvidenceInputs(
        has_request_response=has_rr or white_box,
        has_readback=False,
        has_browser_verification=has_browser,
        has_impact_artifact=False,
        has_independent_artifact=has_independent,
        reliability_runs=runs,
        reliability_hits=hits,
        chain_depth=depth,
        white_box=white_box,
    )


# --- engagement findings loading + aggregation (the measured numbers) --------
def _findings_of(doc) -> list:
    """The finding dicts in a loaded findings doc (bare array, or {findings, attack_chains} object)."""
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        return [f for f in (list(doc.get("findings") or []) + list(doc.get("attack_chains") or []))
                if isinstance(f, dict)]
    return []


def load_findings(eng) -> list:
    """Every finding across the engagement layouts the framework produces: root findings.json, each
    per-skill <eng>/*/findings.json, and the consolidated report file. De-duped by finding id (first wins).
    Best-effort + stdlib-only; an unreadable file is skipped, never fatal."""
    eng = Path(eng)
    files = []
    root = eng / "findings.json"
    if root.is_file():
        files.append(root)
    files.extend(sorted(eng.glob("*/findings.json")))
    cons = eng / "report" / "findings_consolidated.json"
    if cons.is_file():
        files.append(cons)
    out, seen = [], set()
    for ff in files:
        try:
            doc = json.loads(ff.read_text(encoding="utf-8"))
        except Exception:
            continue
        for f in _findings_of(doc):
            fid = f.get("id")
            key = fid if fid else id(f)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    return out


def _effective_score(finding: dict) -> tuple:
    """(EvidenceScore, source) for one finding. Uses the reviewer-written `evidence_score` block when it
    carries a numeric score (source 'reviewer'); otherwise computes a mechanical baseline from the evidence
    types (source 'derived') so EVERY finding contributes a measured number."""
    blk = finding.get("evidence_score") if isinstance(finding.get("evidence_score"), dict) else None
    if blk and isinstance(blk.get("score"), (int, float)):
        comp = blk.get("components") if isinstance(blk.get("components"), dict) else {}
        s = int(blk["score"])
        dec = blk.get("decision") if blk.get("decision") in (DECISION_KILL, DECISION_DOWNGRADE, DECISION_PASS) \
            else decision_for(s)
        es = EvidenceScore(
            score=s,
            decision=dec,
            components=comp,
            reliability_runs=int(blk.get("reliability_runs") or 0),
            reliability_hits=int(blk.get("reliability_hits") or 0),
            probable_cap=bool(blk.get("probable_cap", False)),
            flags=list(blk.get("flags") or []),
        )
        return es, "reviewer"
    return score(inputs_from_finding(finding)), "derived"


def aggregate(findings) -> dict:
    """Aggregate evidence-sufficiency numbers over a list of findings — the measured output the engagement
    finally emits. For every finding it uses the reviewer-written score when present, else a mechanical
    baseline, so the numbers cover the whole set:

        {n, scored_by_reviewer, derived, mean, min, max,
         by_decision:{pass,downgrade,kill}, flagged_race_timing, probable_capped}

    Empty input yields an all-zero summary (n == 0) rather than raising."""
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    base = {"n": 0, "scored_by_reviewer": 0, "derived": 0, "mean": 0.0, "min": 0, "max": 0,
            "by_decision": {DECISION_PASS: 0, DECISION_DOWNGRADE: 0, DECISION_KILL: 0},
            "flagged_race_timing": 0, "probable_capped": 0}
    if not findings:
        return base
    scores, by_dec = [], {DECISION_PASS: 0, DECISION_DOWNGRADE: 0, DECISION_KILL: 0}
    reviewer = derived = race = capped = 0
    for f in findings:
        es, src = _effective_score(f)
        scores.append(es.score)
        by_dec[es.decision] = by_dec.get(es.decision, 0) + 1
        if src == "reviewer":
            reviewer += 1
        else:
            derived += 1
        if any("race/timing" in str(fl) for fl in (es.flags or [])):
            race += 1
        if es.probable_cap:
            capped += 1
    return {
        "n": len(scores),
        "scored_by_reviewer": reviewer,
        "derived": derived,
        "mean": round(sum(scores) / len(scores), 1),
        "min": min(scores),
        "max": max(scores),
        "by_decision": by_dec,
        "flagged_race_timing": race,
        "probable_capped": capped,
    }


def aggregate_engagement(eng) -> dict:
    """Load an engagement's findings and aggregate their evidence-sufficiency scores."""
    return aggregate(load_findings(eng))


# --- CLI --------------------------------------------------------------------
def _finding_by_id(eng_or_file: Path, fid: str):
    """Find a finding by id in a findings.json file OR anywhere under an engagement dir."""
    if eng_or_file.is_file():
        try:
            doc = json.loads(eng_or_file.read_text(encoding="utf-8"))
        except Exception:
            return None
        pool = _findings_of(doc)
    else:
        pool = load_findings(eng_or_file)
    if fid:
        for f in pool:
            if f.get("id") == fid:
                return f
        return None
    # no id given: only unambiguous when the file holds exactly one finding
    return pool[0] if len(pool) == 1 else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Compute the quantified evidence-sufficiency score (the accept/downgrade floor).")
    ap.add_argument("--file", help="a findings.json file (with --id) to score one finding from")
    ap.add_argument("--engagement", help="an engagement dir (with --id to score one finding, or --aggregate)")
    ap.add_argument("--id", dest="fid", help="finding id (RS-YYYY-NNN) to score from --file/--engagement")
    ap.add_argument("--aggregate", action="store_true",
                    help="with --engagement: emit the aggregate evidence-score numbers for every finding")
    # explicit component flags (set a component True; override/augment the derived ones)
    ap.add_argument("--request-response", dest="rr", action="store_true",
                    help="a real HTTP request/response pair is present")
    ap.add_argument("--readback", action="store_true", help="in-band read-back / confirmation is present")
    ap.add_argument("--browser", action="store_true", help="a browser-driven confirmation is present")
    ap.add_argument("--impact", action="store_true", help="a distinct harm/impact artifact is present")
    ap.add_argument("--independent", action="store_true",
                    help="at least one independent artifact is present (lifts the probable-cap)")
    ap.add_argument("--reliability-runs", dest="runs", type=int, default=None, help="N reliability runs")
    ap.add_argument("--reliability-hits", dest="hits", type=int, default=None, help="M successful hits of N")
    ap.add_argument("--chain-depth", dest="depth", type=int, default=None, help="chained-leg count")
    ap.add_argument("--selftest", action="store_true", help="run the module selftest")
    args = ap.parse_args(argv)

    if args.selftest:
        selftest()
        return 0

    if args.aggregate:
        if not args.engagement:
            ap.error("--aggregate requires --engagement")
        eng = Path(args.engagement)
        if not eng.is_dir():
            ap.error(f"engagement dir not found: {eng}")
        print(json.dumps(aggregate_engagement(eng), indent=2))
        return 0

    # Start from a finding (mechanical components) when --file/--engagement + --id is given, else blank.
    inputs = EvidenceInputs()
    src = None
    if args.file or (args.engagement and args.fid):
        src = Path(args.file) if args.file else Path(args.engagement)
        finding = _finding_by_id(src, args.fid)
        if finding is None:
            ap.error(f"could not resolve finding (file={args.file!r}, engagement={args.engagement!r}, "
                     f"id={args.fid!r}) — give an existing --id, or a --file with exactly one finding")
        inputs = inputs_from_finding(finding)

    # Apply explicit flags: booleans OR-in (you never need to turn a present artifact off); numbers override.
    if args.rr:
        inputs.has_request_response = True
    if args.readback:
        inputs.has_readback = True
    if args.browser:
        inputs.has_browser_verification = True
    if args.impact:
        inputs.has_impact_artifact = True
    if args.independent:
        inputs.has_independent_artifact = True
    if args.runs is not None:
        inputs.reliability_runs = args.runs
    if args.hits is not None:
        inputs.reliability_hits = args.hits
    if args.depth is not None:
        inputs.chain_depth = args.depth

    print(json.dumps(score(inputs).to_dict(), indent=2))
    return 0


def selftest() -> None:
    # 0) weights sum to 100 and the bands are ordered.
    assert _WEIGHT_TOTAL == 100
    assert 0 < BAND_KILL < BAND_PASS <= 100

    # 1) a thin reflection (request/response only, deterministic, nothing read back) -> KILL.
    r = score_components(has_request_response=True, has_independent_artifact=True)
    assert r.components["request_response"] == W_REQUEST_RESPONSE
    assert r.score == 35 and r.decision == DECISION_KILL, r  # 20 rr + 15 reliability(deterministic)

    # 2) request/response + read-back + deterministic -> 55 -> DOWNGRADE (real but under-proven).
    r = score_components(has_request_response=True, has_readback=True, has_independent_artifact=True)
    assert r.score == 55 and r.decision == DECISION_DOWNGRADE, r

    # 3) request/response + read-back + impact + deterministic -> 75 -> PASS.
    r = score_components(has_request_response=True, has_readback=True, has_impact_artifact=True,
                         has_independent_artifact=True)
    assert r.score == 75 and r.decision == DECISION_PASS, r

    # 4) RELIABILITY: a strong race (0.9 hit-rate >= 0.8) earns FULL credit and is NOT flagged.
    r = score_components(has_request_response=True, has_readback=True, has_impact_artifact=True,
                         has_independent_artifact=True, reliability_runs=20, reliability_hits=18)
    assert r.components["reliability"] == W_RELIABILITY and r.score == 75 and r.decision == DECISION_PASS
    assert not any("race/timing" in f for f in r.flags), r

    # 5) RELIABILITY: a flaky race (0.5 < 0.8) earns PRORATED credit and is flagged needs-chaining.
    r = score_components(has_request_response=True, has_readback=True, has_impact_artifact=True,
                         has_independent_artifact=True, reliability_runs=10, reliability_hits=5)
    assert r.components["reliability"] == round(W_RELIABILITY * 0.5, 2), r
    assert any("race/timing -- needs chaining" in f for f in r.flags), r
    assert r.decision == DECISION_DOWNGRADE  # 20+20+20+7.5 = 67.5 -> 68

    # 6) CHAIN-DEPTH: depth >= 2 adds the bonus; depth 1 does not.
    base = score_components(has_request_response=True, has_readback=True, has_independent_artifact=True)
    deep = score_components(has_request_response=True, has_readback=True, has_independent_artifact=True,
                            chain_depth=2)
    assert deep.components["chain_depth"] == W_CHAIN_DEPTH and deep.score == base.score + W_CHAIN_DEPTH
    assert score_components(chain_depth=1).components["chain_depth"] == 0

    # 7) PROBABLE-CAP composes as a separate axis: circular-only evidence (effect seen only in the skill's
    #    own log — no request_response / browser / independent artifact) sets probable_cap regardless of score.
    cap = score_components(has_readback=True, has_impact_artifact=True, has_independent_artifact=False)
    assert cap.probable_cap is True and any("probable" in f for f in cap.flags), cap
    # a request_response IS an independent artifact type, so asserting it alone lifts the cap.
    assert score_components(has_request_response=True).probable_cap is False
    assert score_components(has_browser_verification=True).probable_cap is False
    assert score_components(has_independent_artifact=True).probable_cap is False

    # 8) half-up rounding at the band edge: 74.5 -> 75 (PASS), not 74.
    assert _round_half_up(74.5) == 75 and _round_half_up(74.4) == 74

    # 9) finding extraction: a request_response + poc gives mechanical rr + independent; a dom_capture gives browser.
    f = {"evidence": [{"type": "request_response", "ref": "a"}, {"type": "poc_script", "ref": "b"}]}
    i = inputs_from_finding(f)
    assert i.has_request_response and i.has_independent_artifact and not i.white_box
    i2 = inputs_from_finding({"evidence": [{"type": "dom_capture", "ref": "d"}]})
    assert i2.has_browser_verification and i2.has_independent_artifact

    # 10) WHITE-BOX substitution: a code_citation (no request_response) satisfies the rr component, flagged.
    wb = {"evidence": [{"type": "code_citation", "file": "a.php", "line": 1, "snippet": "x"}]}
    iw = inputs_from_finding(wb)
    assert iw.white_box and iw.has_request_response and iw.has_independent_artifact
    rw = score(iw)
    assert rw.components["request_response"] == W_REQUEST_RESPONSE
    assert any("white-box" in f for f in rw.flags), rw

    # 11) circular-only finding (log/tool_output) -> no independent artifact -> probable_cap, low score -> KILL.
    circ = inputs_from_finding({"evidence": [{"type": "log", "ref": "x"}, {"type": "tool_output", "ref": "y"}]})
    assert not circ.has_independent_artifact
    rc = score(circ)
    assert rc.probable_cap is True and rc.decision == DECISION_KILL, rc

    # 12) aggregate: measured numbers over a mixed set (one reviewer-scored PASS + one derived KILL).
    agg = aggregate([
        {"id": "RS-2026-001", "evidence_score": {"score": 80, "decision": "pass",
                                                 "reliability_runs": 0, "reliability_hits": 0}},
        {"id": "RS-2026-002", "evidence": [{"type": "log", "ref": "x"}]},
    ])
    assert agg["n"] == 2 and agg["scored_by_reviewer"] == 1 and agg["derived"] == 1
    assert agg["by_decision"]["pass"] == 1 and agg["by_decision"]["kill"] == 1
    assert agg["probable_capped"] == 1 and agg["max"] == 80
    assert aggregate([])["n"] == 0

    # 13) decision bands at the exact boundaries.
    assert decision_for(54) == DECISION_KILL and decision_for(55) == DECISION_DOWNGRADE
    assert decision_for(74) == DECISION_DOWNGRADE and decision_for(75) == DECISION_PASS

    print("evidence_score selftest: OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    else:
        sys.exit(main())
