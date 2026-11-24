#!/usr/bin/env python3
"""reproduce.py -- the MEASURED per-finding reproducibility harness (the PRODUCER of the reliability counts
`scripts/evidence_score.py` consumes).

WHY THIS EXISTS (the gap this fills):
  `evidence_score.py` has a RELIABILITY axis: `reliability_runs` / `reliability_hits` feed a 0-15 component,
  and a measured hit-rate < 0.8 is flagged "race/timing -- needs chaining". But until now those counts were
  reviewer-ASSERTED via CLI flags (`--reliability-runs N --reliability-hits M`) -- a number somebody typed,
  not a number anything MEASURED. This module is the missing PRODUCER: it re-executes a finding's OWN already-
  accepted benign confirmation probe K times, counts the hits by the finding's OWN success criterion, and
  emits `{runs, hits, hit_rate}` -- JSON that pipes straight into `evidence_score.py --reliability-json -`.
  The hand-asserted number becomes a measured one; no evidence standard moves.

WHAT THIS IS NOT (the traps it deliberately avoids):
  * It is NOT a false-positive "replay/rescue". It never re-probes a REJECTED / false-positive finding to try
    to flip it back to real, and it never raises a finding's confidence. It re-runs the SAME benign probe the
    finding ALREADY passed, only to MEASURE how reproducible that pass is.
  * Success is judged on EXECUTION / EFFECT, never on PAYLOAD REFLECTION. There is deliberately no
    "payload appears in the response body" criterion -- reflection is not execution, and redstrike rejects it
    (see _contract/counterevidence.md). The allowed criteria are an attributable OOB callback token (exact
    match on a unique nonce), the confirmation status/effect code, a controlled timing differential, or the
    finding's OWN checker predicate. A reflection/substring criterion is REFUSED with a pointed error.
  * It does NOT lower any evidence standard. It fills a currently hand-asserted field with a measured one.

SAFETY (bounded, rate-limited, idempotent-only):
  The harness AUTO-REPEATS only READ-ONLY / IDEMPOTENT confirmation probes. It REFUSES to auto-repeat a
  state-changing / destructive / single-use probe (NonRepeatableProbe) -- firing those K times could double-
  spend, exhaust a one-shot token, or destroy state. Those keep the existing manual / bounded handling: the
  `race-condition` skill already fires its own benign, bounded burst under its reviewer and records the counts
  that way. K is small (default 5) and clamped to [1, MAX_K]; runs are rate-limited; the probe command itself
  is expected to be scope- and rate-limit-bound (same contract as every other replay helper).

The core (`reproduce`) is pure logic with an INJECTED runner + sleep, so it is unit-testable with no network
(mirrors scripts/replay_server_action.py). The CLI wires a stdlib subprocess runner for real use.

Stdlib only. Python 3.10+ safe. References no external source.

CLI:
    # measure a safely-repeatable probe, 5 runs at 2 req/s, and feed the score:
    python reproduce.py --spec probe.json -k 5 --rate-rps 2 \
        | python evidence_score.py --file idor/findings.json --id RS-2026-012 --readback --impact --reliability-json -
    # validate the spec + report the safety decision WITHOUT executing:
    python reproduce.py --spec probe.json --dry-run
    python reproduce.py --selftest
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence

# --- NAMED bounds / defaults ------------------------------------------------
DEFAULT_K = 5           # small by default; a reproducibility measure, not a flood
MAX_K = 20              # hard upper bound -- K is clamped into [1, MAX_K]
DEFAULT_RATE_RPS = 2.0  # conservative default pacing; the engagement rate cap still applies on top
DEFAULT_TIMEOUT_S = 30.0

# --- safety classification of a probe (transport-agnostic) ------------------
SAFETY_READ_ONLY = "read-only"
SAFETY_IDEMPOTENT = "idempotent"
SAFETY_NON_IDEMPOTENT = "non-idempotent"
SAFETY_STATE_CHANGING = "state-changing"
SAFETY_DESTRUCTIVE = "destructive"
SAFETY_SINGLE_USE = "single-use"
SAFETY_CLASSES = frozenset({
    SAFETY_READ_ONLY, SAFETY_IDEMPOTENT, SAFETY_NON_IDEMPOTENT,
    SAFETY_STATE_CHANGING, SAFETY_DESTRUCTIVE, SAFETY_SINGLE_USE,
})
# ONLY these two may be AUTO-REPEATED by the harness. Everything else keeps manual/bounded handling.
AUTO_REPEATABLE = frozenset({SAFETY_READ_ONLY, SAFETY_IDEMPOTENT})

# --- success-criterion kinds (judged on EXECUTION, never on payload reflection) ---
SUCCESS_OOB_CALLBACK = "oob_callback"  # an attributable, unique OOB token was observed this run (exact match)
SUCCESS_STATUS_IS = "status_is"        # the confirmation status/effect code (e.g. a 403->200 authz bypass)
SUCCESS_TIMING = "timing"              # a controlled timing differential (blind sqli / command-injection)
SUCCESS_PREDICATE = "predicate"        # the finding's OWN checker already decided result.hit (True/False)
SUCCESS_KINDS = frozenset({SUCCESS_OOB_CALLBACK, SUCCESS_STATUS_IS, SUCCESS_TIMING, SUCCESS_PREDICATE})
# Reflection-style criteria are the trap this harness exists to avoid -- refused explicitly, not silently.
_FORBIDDEN_SUCCESS = frozenset({"reflection", "substring", "body_contains", "reflected", "contains", "regex"})

RELIABILITY_MIN = 0.8  # must mirror evidence_score.RELIABILITY_MIN -- the race/timing flag threshold


class ReproduceError(Exception):
    """Base class for harness errors."""


class InvalidProbeSpec(ReproduceError):
    """The probe spec is malformed or asks for an unsupported / forbidden success criterion."""


class NonRepeatableProbe(ReproduceError):
    """The probe is not safely repeatable (state-changing/destructive/single-use) -- auto-repeat refused."""


# --------------------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------------------
@dataclass
class ProbeSpec:
    """How to RE-RUN a finding's own benign confirmation probe, and how to JUDGE a hit.

    `success` is the finding's OWN success criterion (an execution/effect test, see SUCCESS_KINDS) -- NOT a
    payload-reflection match. `command` is the benign, scope-bound probe invocation handed to the subprocess
    runner (argv list; shell=False). `request` is an opaque, transport-agnostic descriptor passed through to a
    custom runner unchanged (the harness does not interpret it)."""

    finding_id: str
    safety_class: str
    success: dict
    command: Optional[List[str]] = None
    request: Optional[dict] = None
    label: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "ProbeSpec":
        if not isinstance(d, dict):
            raise InvalidProbeSpec("probe spec must be a JSON object")
        fid = d.get("finding_id")
        if not fid or not isinstance(fid, str):
            raise InvalidProbeSpec("probe spec needs a string 'finding_id'")
        sc = d.get("safety_class")
        if sc not in SAFETY_CLASSES:
            raise InvalidProbeSpec(
                f"probe spec 'safety_class' must be one of {sorted(SAFETY_CLASSES)} (got {sc!r})")
        success = d.get("success")
        if not isinstance(success, dict):
            raise InvalidProbeSpec("probe spec needs a 'success' object (the finding's own criterion)")
        validate_success(success)  # fail fast on a forbidden/unknown criterion, even for --dry-run
        cmd = d.get("command")
        if cmd is not None and (not isinstance(cmd, list) or not all(isinstance(a, str) for a in cmd)):
            raise InvalidProbeSpec("probe spec 'command' must be a list of string argv tokens")
        return cls(
            finding_id=fid,
            safety_class=sc,
            success=success,
            command=cmd,
            request=d.get("request") if isinstance(d.get("request"), dict) else None,
            label=str(d.get("label") or ""),
        )


@dataclass
class ProbeResult:
    """The structured result of ONE probe execution. Success is decided from these EXECUTION facts only --
    there is intentionally no raw-body / reflected-payload field that could drive a hit."""

    status: Optional[int] = None
    callbacks: List[str] = field(default_factory=list)  # attributable OOB tokens observed this run
    elapsed_ms: Optional[float] = None
    hit: Optional[bool] = None  # SUCCESS_PREDICATE only: the finding's own checker's verdict
    error: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "ProbeResult":
        if not isinstance(d, dict):
            return cls(error="probe result was not a JSON object")
        cbs = d.get("callbacks") or []
        if not isinstance(cbs, list):
            cbs = [cbs]
        def _i(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return None
        def _f(v):
            try:
                return float(v)
            except (TypeError, ValueError):
                return None
        return cls(
            status=_i(d.get("status")),
            callbacks=[str(c) for c in cbs],
            elapsed_ms=_f(d.get("elapsed_ms")),
            hit=(bool(d["hit"]) if "hit" in d and d["hit"] is not None else None),
            error=(str(d["error"]) if d.get("error") else None),
        )


@dataclass
class ReproResult:
    """The measured reproducibility of a probe. `to_dict()` leads with the `{runs, hits, hit_rate}` that
    `evidence_score.py --reliability-json` consumes, then the context that made the measurement."""

    finding_id: str
    runs: int
    hits: int
    hit_rate: float
    errors: int
    k_requested: int
    k_effective: int
    rate_rps: float
    safety_class: str
    success_kind: str
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "runs": self.runs,
            "hits": self.hits,
            "hit_rate": round(self.hit_rate, 4),
            "finding_id": self.finding_id,
            "errors": self.errors,
            "k_requested": self.k_requested,
            "k_effective": self.k_effective,
            "rate_rps": self.rate_rps,
            "safety_class": self.safety_class,
            "success_kind": self.success_kind,
            "flags": list(self.flags),
        }


# --------------------------------------------------------------------------------------
# Success evaluation -- EXECUTION, not reflection
# --------------------------------------------------------------------------------------
def validate_success(success: dict) -> None:
    """Raise InvalidProbeSpec if the success criterion is forbidden (reflection-style) or unknown, or is
    missing the field its kind requires. Pure; safe to call before any execution."""
    if not isinstance(success, dict):
        raise InvalidProbeSpec("success criterion must be an object")
    kind = success.get("kind")
    if kind in _FORBIDDEN_SUCCESS:
        raise InvalidProbeSpec(
            f"success kind {kind!r} is a payload-reflection/substring match -- reflection is NOT execution "
            "and is rejected by this harness. Use an execution/effect criterion "
            f"({sorted(SUCCESS_KINDS)}): an attributable OOB callback token, the confirmation status, a "
            "controlled timing differential, or the finding's own checker predicate.")
    if kind not in SUCCESS_KINDS:
        raise InvalidProbeSpec(f"unknown success kind {kind!r}; expected one of {sorted(SUCCESS_KINDS)}")
    if kind == SUCCESS_OOB_CALLBACK and not success.get("token"):
        raise InvalidProbeSpec("success kind 'oob_callback' requires a unique, attributable 'token'")
    if kind == SUCCESS_STATUS_IS and not success.get("expect_status"):
        raise InvalidProbeSpec("success kind 'status_is' requires a non-empty 'expect_status' list")
    if kind == SUCCESS_TIMING and success.get("min_ms") is None:
        raise InvalidProbeSpec("success kind 'timing' requires a 'min_ms' threshold")


def is_hit(success: dict, result: ProbeResult) -> bool:
    """True iff this probe execution reproduced the finding's confirmed EFFECT, by its OWN criterion.

    An errored run is never a hit. No branch here matches a payload reflected in a response body."""
    validate_success(success)
    if result.error:
        return False
    kind = success["kind"]
    if kind == SUCCESS_OOB_CALLBACK:
        # Exact match on a unique, attributable nonce the probe planted -- not a substring of a reflection.
        return success["token"] in (result.callbacks or [])
    if kind == SUCCESS_STATUS_IS:
        expect = {int(s) for s in success["expect_status"]}
        return result.status is not None and result.status in expect
    if kind == SUCCESS_TIMING:
        return result.elapsed_ms is not None and result.elapsed_ms >= float(success["min_ms"])
    if kind == SUCCESS_PREDICATE:
        # The finding's own checker already decided; we only tally its verdict.
        return bool(result.hit)
    raise InvalidProbeSpec(f"unknown success kind {kind!r}")  # pragma: no cover (validate_success guards)


# --------------------------------------------------------------------------------------
# The harness (pure; runner + sleep injected)
# --------------------------------------------------------------------------------------
def _clamp_k(k: int) -> int:
    return max(1, min(int(k), MAX_K))


def reproduce(
    spec: ProbeSpec,
    runner: Callable[[ProbeSpec], ProbeResult],
    *,
    k: int = DEFAULT_K,
    rate_rps: float = DEFAULT_RATE_RPS,
    sleep: Callable[[float], None] = time.sleep,
) -> ReproResult:
    """Re-run `spec`'s benign probe up to K times, rate-limited, and count hits by its own criterion.

    REFUSES (NonRepeatableProbe) any probe that is not read-only/idempotent -- state-changing / destructive /
    single-use confirmations are never auto-fired K times. `runner` performs one execution and returns a
    ProbeResult; `sleep` is injected so pacing is testable without real time."""
    if spec.safety_class not in SAFETY_CLASSES:
        raise InvalidProbeSpec(f"unknown safety_class {spec.safety_class!r}")
    if spec.safety_class not in AUTO_REPEATABLE:
        raise NonRepeatableProbe(
            f"probe for {spec.finding_id} is '{spec.safety_class}' -- the reproducibility harness will NOT "
            "auto-repeat it. Firing a state-changing / destructive / single-use probe K times could "
            "double-spend, burn a one-shot token, or destroy state. Those keep the existing manual / bounded "
            "handling: the race-condition skill fires its own benign, bounded burst under its reviewer and "
            "records the counts that way. Only read-only / idempotent confirmation probes are measured here.")
    validate_success(spec.success)

    k_req = int(k)
    k_eff = _clamp_k(k_req)
    flags: List[str] = []
    if k_eff != k_req:
        flags.append(f"K clamped from {k_req} to {k_eff} (bound 1..{MAX_K})")
    interval = (1.0 / rate_rps) if rate_rps and rate_rps > 0 else 0.0

    runs = hits = errors = 0
    for i in range(k_eff):
        if i > 0 and interval > 0:
            sleep(interval)  # pace between executions; never before the first
        try:
            res = runner(spec)
        except Exception as e:  # a runner blowing up is a non-hit, not a crash of the measurement
            res = ProbeResult(error=f"runner-exception: {e}")
        if not isinstance(res, ProbeResult):
            res = ProbeResult(error="runner did not return a ProbeResult")
        runs += 1
        if res.error:
            errors += 1
            continue
        if is_hit(spec.success, res):
            hits += 1

    hit_rate = (hits / runs) if runs else 0.0
    if runs and hit_rate < RELIABILITY_MIN:
        flags.append(
            f"hit-rate {hit_rate:.2f} < {RELIABILITY_MIN:g} -> race/timing, needs chaining "
            "(evidence_score prorates the reliability credit and flags it)")
    if errors:
        flags.append(f"{errors}/{runs} run(s) errored (counted as non-hits)")

    return ReproResult(
        finding_id=spec.finding_id,
        runs=runs,
        hits=hits,
        hit_rate=hit_rate,
        errors=errors,
        k_requested=k_req,
        k_effective=k_eff,
        rate_rps=float(rate_rps),
        safety_class=spec.safety_class,
        success_kind=str(spec.success.get("kind")),
        flags=flags,
    )


# --------------------------------------------------------------------------------------
# Subprocess runner (CLI real-use path; not exercised by the selftest)
# --------------------------------------------------------------------------------------
def make_subprocess_runner(timeout: float = DEFAULT_TIMEOUT_S) -> Callable[[ProbeSpec], ProbeResult]:
    """A stdlib runner: run the probe `command` (argv, shell=False) and parse the LAST stdout line as a
    ProbeResult JSON. The benign probe is responsible for emitting that one line (status / callbacks /
    elapsed_ms / hit). Keeps the transport out of this module -- the command decides how it talks."""
    def _run(spec: ProbeSpec) -> ProbeResult:
        if not spec.command:
            return ProbeResult(error="probe spec has no 'command' for the subprocess runner")
        try:
            proc = subprocess.run(  # noqa: S603 -- argv list, shell=False; command is operator-defined
                spec.command, capture_output=True, text=True, timeout=timeout, shell=False)
        except subprocess.TimeoutExpired:
            return ProbeResult(error=f"probe timed out after {timeout}s")
        except Exception as e:  # noqa: BLE001
            return ProbeResult(error=f"probe failed to run: {e}")
        out = (proc.stdout or "").strip()
        if not out:
            return ProbeResult(error="probe emitted no ProbeResult JSON on stdout", status=proc.returncode)
        try:
            data = json.loads(out.splitlines()[-1])
        except Exception:  # noqa: BLE001
            return ProbeResult(error="probe stdout tail was not parseable ProbeResult JSON",
                               status=proc.returncode)
        return ProbeResult.from_dict(data)
    return _run


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------
def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Measure a finding's reproducibility by re-running its OWN benign probe K times "
                    "(read-only/idempotent only) and emit {runs, hits, hit_rate} for evidence_score.py.")
    ap.add_argument("--spec", help="path to a probe-spec JSON (finding_id, safety_class, success, command)")
    ap.add_argument("-k", "--runs", type=int, default=DEFAULT_K,
                    help=f"max re-runs (default {DEFAULT_K}; clamped to 1..{MAX_K})")
    ap.add_argument("--rate-rps", type=float, default=DEFAULT_RATE_RPS,
                    help=f"rate limit in requests/second (default {DEFAULT_RATE_RPS}; <=0 = no pacing)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S, help="per-run probe timeout (s)")
    ap.add_argument("--dry-run", action="store_true",
                    help="validate the spec + report the safety decision; do NOT execute the probe")
    ap.add_argument("--selftest", action="store_true", help="run the module selftest")
    args = ap.parse_args(argv)

    if args.selftest:
        selftest()
        return 0
    if not args.spec:
        ap.error("--spec is required (or use --selftest)")

    try:
        spec = ProbeSpec.from_dict(json.loads(Path(args.spec).read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as e:
        print(json.dumps({"error": f"could not read probe spec: {e}"}), file=sys.stderr)
        return 2
    except InvalidProbeSpec as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2

    if args.dry_run:
        repeatable = spec.safety_class in AUTO_REPEATABLE
        print(json.dumps({
            "finding_id": spec.finding_id,
            "safety_class": spec.safety_class,
            "auto_repeatable": repeatable,
            "success_kind": spec.success.get("kind"),
            "note": ("safely repeatable -- the harness will measure it"
                     if repeatable else
                     "NOT auto-repeated -- state-changing/destructive/single-use keep manual/bounded handling"),
        }, indent=2))
        return 0

    runner = make_subprocess_runner(timeout=args.timeout)
    try:
        res = reproduce(spec, runner, k=args.runs, rate_rps=args.rate_rps)
    except NonRepeatableProbe as e:
        # A structured REFUSAL -- not a measurement. Distinct exit code so a pipeline can tell it apart.
        print(json.dumps({
            "finding_id": spec.finding_id,
            "safety_class": spec.safety_class,
            "refused": True,
            "reason": str(e),
        }, indent=2))
        return 3
    except InvalidProbeSpec as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        return 2

    print(json.dumps(res.to_dict(), indent=2))
    return 0


# --------------------------------------------------------------------------------------
# Self-test (no network / no subprocess; stub runner + fake sleep). Mirrors the CI convention.
# --------------------------------------------------------------------------------------
def _spec(safety=SAFETY_READ_ONLY, success=None, **kw) -> ProbeSpec:
    return ProbeSpec(finding_id=kw.get("finding_id", "RS-2026-001"),
                     safety_class=safety,
                     success=success or {"kind": SUCCESS_OOB_CALLBACK, "token": "tok-abc"})


def _seq_runner(results: Sequence[ProbeResult]) -> Callable[[ProbeSpec], ProbeResult]:
    it = iter(results)
    def _run(spec: ProbeSpec) -> ProbeResult:
        return next(it)
    return _run


def selftest() -> None:
    # 0) constants are self-consistent and mirror the scorer's threshold.
    assert AUTO_REPEATABLE <= SAFETY_CLASSES
    assert 1 <= DEFAULT_K <= MAX_K
    assert RELIABILITY_MIN == 0.8

    # 1) SAFETY GUARD: non-idempotent / state-changing / destructive / single-use are REFUSED.
    for bad in (SAFETY_NON_IDEMPOTENT, SAFETY_STATE_CHANGING, SAFETY_DESTRUCTIVE, SAFETY_SINGLE_USE):
        try:
            reproduce(_spec(safety=bad), _seq_runner([]), k=3)
            raise AssertionError(f"{bad} must be refused")
        except NonRepeatableProbe:
            pass
    # read-only and idempotent are allowed.
    for ok in (SAFETY_READ_ONLY, SAFETY_IDEMPOTENT):
        r = reproduce(_spec(safety=ok), _seq_runner([ProbeResult(callbacks=["tok-abc"])]), k=1)
        assert r.runs == 1 and r.hits == 1, r

    # 2) OOB-callback counting: EXACT token match, deterministic probe -> hit_rate 1.0, no flag.
    r = reproduce(_spec(), _seq_runner([ProbeResult(callbacks=["tok-abc"])] * 5), k=5, rate_rps=0)
    assert (r.runs, r.hits) == (5, 5) and r.hit_rate == 1.0
    assert not any("race/timing" in f for f in r.flags), r
    # a different token is NOT a hit (no substring/reflection matching).
    r = reproduce(_spec(), _seq_runner([ProbeResult(callbacks=["tok-OTHER"])] * 4), k=4, rate_rps=0)
    assert r.hits == 0 and any("race/timing" in f for f in r.flags), r

    # 3) STATUS criterion: a 403->200 authz-bypass confirmation.
    sp = _spec(success={"kind": SUCCESS_STATUS_IS, "expect_status": [200]})
    r = reproduce(sp, _seq_runner([ProbeResult(status=200), ProbeResult(status=403),
                                   ProbeResult(status=200)]), k=3, rate_rps=0)
    assert (r.runs, r.hits) == (3, 2), r

    # 4) TIMING criterion: controlled delay differential (blind sqli/cmdi).
    sp = _spec(success={"kind": SUCCESS_TIMING, "min_ms": 500})
    r = reproduce(sp, _seq_runner([ProbeResult(elapsed_ms=800), ProbeResult(elapsed_ms=120)]), k=2, rate_rps=0)
    assert (r.runs, r.hits) == (2, 1), r

    # 5) PREDICATE criterion: the finding's own checker decided result.hit.
    sp = _spec(success={"kind": SUCCESS_PREDICATE})
    r = reproduce(sp, _seq_runner([ProbeResult(hit=True), ProbeResult(hit=False),
                                   ProbeResult(hit=True)]), k=3, rate_rps=0)
    assert (r.runs, r.hits) == (3, 2), r

    # 6) FLAKY probe -> measured hit-rate < 0.8 is flagged race/timing (the whole point of measuring).
    results = [ProbeResult(callbacks=["tok-abc"])] * 5 + [ProbeResult(callbacks=[])] * 5
    r = reproduce(_spec(), _seq_runner(results), k=10, rate_rps=0)
    assert (r.runs, r.hits) == (10, 5) and abs(r.hit_rate - 0.5) < 1e-9
    assert any("race/timing" in f for f in r.flags), r

    # 7) K is clamped into [1, MAX_K], and flagged.
    r = reproduce(_spec(), _seq_runner([ProbeResult(callbacks=["tok-abc"])] * MAX_K), k=9999, rate_rps=0)
    assert r.k_effective == MAX_K and r.k_requested == 9999
    assert any("clamped" in f for f in r.flags), r
    r = reproduce(_spec(), _seq_runner([ProbeResult(callbacks=["tok-abc"])]), k=0, rate_rps=0)
    assert r.k_effective == 1, r

    # 8) RATE LIMITING: sleep is called k-1 times with the 1/rate interval (never before the first run).
    calls: List[float] = []
    reproduce(_spec(), _seq_runner([ProbeResult(callbacks=["tok-abc"])] * 4), k=4, rate_rps=2.0,
              sleep=calls.append)
    assert len(calls) == 3 and all(abs(c - 0.5) < 1e-9 for c in calls), calls

    # 9) An ERRORED run counts in runs, not hits, and is flagged.
    results = [ProbeResult(callbacks=["tok-abc"]), ProbeResult(error="connection reset"),
               ProbeResult(callbacks=["tok-abc"])]
    r = reproduce(_spec(), _seq_runner(results), k=3, rate_rps=0)
    assert (r.runs, r.hits, r.errors) == (3, 2, 1) and any("errored" in f for f in r.flags), r

    # 10) A runner that RAISES is caught as an errored run (the measurement never crashes).
    def _boom(spec):
        raise RuntimeError("boom")
    r = reproduce(_spec(), _boom, k=2, rate_rps=0)
    assert r.runs == 2 and r.hits == 0 and r.errors == 2, r

    # 11) ANTI-TRAP: a reflection / substring success criterion is REFUSED.
    for bad_kind in sorted(_FORBIDDEN_SUCCESS):
        try:
            validate_success({"kind": bad_kind, "needle": "x"})
            raise AssertionError(f"{bad_kind} must be refused")
        except InvalidProbeSpec:
            pass
    # and an unknown kind is refused too.
    try:
        validate_success({"kind": "telepathy"})
        raise AssertionError("unknown kind must be refused")
    except InvalidProbeSpec:
        pass

    # 12) ProbeSpec.from_dict validation: good spec round-trips; missing/bad fields raise.
    good = ProbeSpec.from_dict({"finding_id": "RS-2026-002", "safety_class": "read-only",
                                "success": {"kind": "oob_callback", "token": "t"},
                                "command": ["echo", "{}"]})
    assert good.finding_id == "RS-2026-002" and good.command == ["echo", "{}"]
    for bad in ({"safety_class": "read-only", "success": {"kind": "oob_callback", "token": "t"}},   # no id
                {"finding_id": "x", "safety_class": "nope", "success": {"kind": "oob_callback", "token": "t"}},
                {"finding_id": "x", "safety_class": "read-only", "success": {"kind": "substring"}},
                {"finding_id": "x", "safety_class": "read-only", "success": {"kind": "oob_callback"}}):  # no token
        try:
            ProbeSpec.from_dict(bad)
            raise AssertionError(f"bad spec must raise: {bad}")
        except InvalidProbeSpec:
            pass

    # 13) to_dict leads with the evidence_score contract keys and is JSON-serializable.
    d = reproduce(_spec(), _seq_runner([ProbeResult(callbacks=["tok-abc"])] * 3), k=3, rate_rps=0).to_dict()
    assert list(d.keys())[:3] == ["runs", "hits", "hit_rate"], d
    assert json.dumps(d)

    # 14) ProbeResult.from_dict coerces loose JSON safely (what the subprocess runner parses).
    pr = ProbeResult.from_dict({"status": "200", "callbacks": "tok-abc", "elapsed_ms": "12.5"})
    assert pr.status == 200 and pr.callbacks == ["tok-abc"] and pr.elapsed_ms == 12.5

    print("reproduce selftest: OK")


if __name__ == "__main__":
    if "--selftest" in (sys.argv[1:]):
        selftest()
    else:
        raise SystemExit(main())
