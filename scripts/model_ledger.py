#!/usr/bin/env python3
"""
model_ledger.py -- Redstrike CROSS-MODEL diversity ledger (roadmap L-H): MEASURE what the `model:` pin
ASSERTS.

THE GAP. The framework ASSERTS cross-model verification diversity with a frontmatter `model:` pin — the
`exhaustion-adversary` is pinned to a DIFFERENT model than the executors and their `*-verify` reviewers, so a
shared-model "we're done" blind spot can't pass every gate. But the ACTUALLY DISPATCHED model is recorded
NOWHERE: the completion gate only checks that a verdict artifact EXISTS, never which model produced it. When a
safeguard terminates every subagent of one model and they all silently fall back to the SAME model, cross-model
collapses to same-model — and every gate STILL passes. The `model` field in exhaustion_review.schema.json is
self-reported free text, never cross-checked against what ran.

THE FIX (this module). Each dispatched agent records the model it ACTUALLY ran on into
`runtime/model_ledger.json`. `diversity_assessment()` answers: did the exhaustion-adversary (and/or the
`*-verify` reviewers) genuinely run on a DIFFERENT model FAMILY than the executors? The completion gate
(verify_completion.py) then surfaces "cross-model diversity unavailable" as a VISIBLE warning + a recorded
deliverable FACT — never a silent same-model pass.

It is a WARNING, not a hard fail. When a safeguard blocks the alternate model, same-model is a documented
LIMITATION, not a defect — the point is to SURFACE it, not to block the engagement. The exhaustion hard-gate's
pass condition (no_gaps_found) is unchanged.

"same model family" (the exact rule diversity_assessment uses). A model string is normalized to a family
token: lowercase, then match the Anthropic family keyword present in it — `opus` / `sonnet` / `haiku` (so
`claude-opus-4-8`, `opus`, `Opus 4.8` all normalize to `opus`). A string with no family keyword (another
vendor) is normalized by stripping its version/date digits and non-letters. Two models are the SAME FAMILY iff
their normalized tokens are EQUAL. Cross-model diversity is AVAILABLE iff the exhaustion-adversary — or a
`*-verify` reviewer — ran on a family NOT used by any executor.

Stdlib only. Lock-safe append (mirrors scripts/coverage.py). Examples:
  python scripts/model_ledger.py record --engagement <dir> --role executor --category xss --model opus
  python scripts/model_ledger.py record --engagement <dir> --role exhaustion-adversary --model sonnet \\
      --agent-id exhaustion-adversary
  python scripts/model_ledger.py assess --engagement <dir> [--json]
  python scripts/model_ledger.py read   --engagement <dir> [--json]
  python scripts/model_ledger.py --selftest
"""
import argparse
import datetime
import json
import os
import re
import sys
import time
from pathlib import Path

# atomic_write: one shared helper for ledger writes (same import dance coverage.py uses, so the module loads
# whether scripts/ is on sys.path or the module is path-loaded directly by a test / validate.py).
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover - only hit under path-based loading without scripts/ on sys.path
    import importlib.util as _ilu
    _aspec = _ilu.spec_from_file_location("atomicio", str(Path(__file__).resolve().parent / "atomicio.py"))
    _amod = _ilu.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write


SCHEMA_VERSION = 1
RUNTIME_DIR = "runtime"
LEDGER_NAME = "model_ledger.json"
# the dispatched-agent roles this ledger records (mirrors the schema enum). `other` is the catch-all.
ROLES = ("executor", "reviewer", "exhaustion-adversary", "secondary-review", "other")
_FAMILY_TOKENS = ("opus", "sonnet", "haiku")


# --- concurrent-writer safety (same advisory lock pattern as coverage.py) ------------------------- #
# A wave fans out as CONCURRENT subagents that each record their dispatched model. `atomic_write` keeps a
# reader from ever seeing a torn file, but two writers that each read-then-append would still clobber each
# other. A per-file advisory lock serializes the read-modify-append so every concurrent record survives.
class _FileLock:
    """Best-effort cross-process advisory lock via an exclusive lock file (stdlib only; identical behaviour on
    Windows + Linux/WSL). Spins up to ``timeout``; a lock older than ``stale`` is treated as abandoned and
    broken; if it still can't acquire by the deadline it proceeds anyway (degraded last-write-wins) rather than
    deadlock — ``atomic_write`` keeps the file un-torn either way."""

    def __init__(self, target, *, timeout: float = 30.0, poll: float = 0.05, stale: float = 120.0):
        self._path = str(target) + ".lock"
        self._timeout, self._poll, self._stale = timeout, poll, stale
        self._held = False

    def __enter__(self):
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self._path) > self._stale:
                        os.unlink(self._path)   # break an abandoned lock
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    return self                 # proceed un-locked rather than block the whole wave
                time.sleep(self._poll)
                continue
            try:
                os.write(fd, str(os.getpid()).encode("ascii", "replace"))
            finally:
                os.close(fd)
            self._held = True
            return self

    def __exit__(self, *exc):
        if self._held:
            try:
                os.unlink(self._path)
            except OSError:
                pass
            self._held = False
        return False


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def model_family(model) -> str:
    """Normalize a model string to its FAMILY token (the unit the same-model check compares). Lowercase, then
    match the Anthropic family keyword present (opus/sonnet/haiku) so every spelling of a family collapses to
    one token (`claude-opus-4-8` / `opus` / `Opus 4.8` -> `opus`). A string with no family keyword (another
    vendor) is normalized by stripping version/date digits + non-letters. '' for an empty/None model. Pure."""
    if not model:
        return ""
    s = str(model).strip().lower()
    if not s:
        return ""
    for tok in _FAMILY_TOKENS:
        if tok in s:
            return tok
    cleaned = re.sub(r"[^a-z]+", "-", re.sub(r"[0-9]+", "", s)).strip("-")
    return cleaned or s


def _ledger_path(engagement) -> Path:
    return Path(engagement) / RUNTIME_DIR / LEDGER_NAME


def _read_raw(path: Path):
    """Parse the ledger file, or None when absent/unreadable (a half-written ledger must never crash a read)."""
    if not path.is_file():
        return None
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    return d if isinstance(d, dict) else None


def _empty(engagement) -> dict:
    return {"version": SCHEMA_VERSION, "engagement": Path(engagement).name, "entries": []}


def record(engagement, role, category, model, agent_id=None, ts=None) -> dict:
    """Append ONE dispatched-agent record to runtime/model_ledger.json (lock-safe + atomic, like coverage.py).

    role     — one of ROLES (executor / reviewer / exhaustion-adversary / secondary-review / other).
    category — the vulnerability class/category the agent worked (e.g. 'xss'); None for an engagement-level
               role (exhaustion-adversary / secondary-review).
    model    — the model the agent ACTUALLY ran on (whatever the dispatcher really dispatched, NOT the pin).
    agent_id — the dispatched agent/subagent id, when known (optional).

    Records the raw `model` AND its derived `model_family` so the console + the diversity check never
    recompute. Returns the written entry. Raises ValueError on an unknown role / an empty model."""
    role = str(role or "").strip()
    if role not in ROLES:
        raise ValueError(f"invalid role {role!r}; choose one of {list(ROLES)}")
    if not str(model or "").strip():
        raise ValueError("model is required (the ACTUAL dispatched model, not the frontmatter pin)")
    entry = {
        "role": role,
        "category": (str(category).strip() if category not in (None, "") else None),
        "model": str(model).strip(),
        "model_family": model_family(model),
        "ts": ts or _utcnow(),
    }
    if agent_id:
        entry["agent_id"] = str(agent_id)
    path = _ledger_path(engagement)
    with _FileLock(path):
        led = _read_raw(path)
        if not isinstance(led, dict) or not isinstance(led.get("entries"), list):
            led = _empty(engagement)
        led["version"] = led.get("version") or SCHEMA_VERSION
        led["engagement"] = led.get("engagement") or Path(engagement).name
        led["entries"].append(entry)
        led["generated_at"] = _utcnow()
        atomic_write(path, json.dumps(led, indent=2) + "\n")
    return entry


def read(engagement) -> dict:
    """The engagement's model ledger as a dict (always with an `entries` list), or an empty skeleton when the
    file is absent/unreadable. Never raises."""
    led = _read_raw(_ledger_path(engagement))
    if not isinstance(led, dict):
        return _empty(engagement)
    if not isinstance(led.get("entries"), list):
        led["entries"] = []
    return led


def _families_by_role(entries) -> dict:
    """Collect the distinct model FAMILIES recorded per role-group, plus the latest adversary family.
    Returns {exec, reviewer, adversary} sets + latest_adversary. reviewer groups the `reviewer` and
    `secondary-review` roles (both are verification diversity). Pure."""
    exec_f, rev_f, adv_f = set(), set(), set()
    latest_adv = None
    for e in entries or []:
        if not isinstance(e, dict):
            continue
        role = str(e.get("role") or "")
        fam = e.get("model_family") or model_family(e.get("model"))
        if not fam:
            continue
        if role == "executor":
            exec_f.add(fam)
        elif role in ("reviewer", "secondary-review"):
            rev_f.add(fam)
        elif role == "exhaustion-adversary":
            adv_f.add(fam)
            latest_adv = fam
    return {"exec": exec_f, "reviewer": rev_f, "adversary": adv_f, "latest_adversary": latest_adv}


def diversity_assessment(engagement) -> dict:
    """Did the verification roles run on a DIFFERENT model family than the executors?

    Returns {executors_models, reviewers_models, adversary_model, cross_model_available, reason}:
      * executors_models / reviewers_models — the distinct families each role-group ran on (sorted).
      * adversary_model — the exhaustion-adversary's family (the latest recorded), or None.
      * cross_model_available — True iff the exhaustion-adversary OR a `*-verify` reviewer ran on a family
        NOT used by any executor (genuine cross-model diversity). False when every role shares the executors'
        family (the same-model collapse) OR no executor model was recorded (can't be measured).
      * reason — one honest sentence explaining the verdict (goes into the deliverable + the gate warning).

    Pure read; never raises (a missing/unreadable ledger yields cross_model_available=False with a reason)."""
    fams = _families_by_role(read(engagement).get("entries"))
    exec_f, rev_f, adv_f = fams["exec"], fams["reviewer"], fams["adversary"]
    adversary_model = fams["latest_adversary"]
    if not exec_f:
        reason = ("no executor model recorded in runtime/model_ledger.json - cross-model diversity cannot be "
                  "measured (the model ledger is empty or missing executor records)")
        cross = False
    else:
        adversary_diverse = bool(adv_f - exec_f)
        reviewer_diverse = bool(rev_f - exec_f)
        cross = adversary_diverse or reviewer_diverse
        if cross:
            parts = []
            if adversary_diverse:
                parts.append(f"exhaustion-adversary ran on {sorted(adv_f - exec_f)}")
            if reviewer_diverse:
                parts.append(f"a *-verify reviewer ran on {sorted(rev_f - exec_f)}")
            reason = ("cross-model diversity achieved: " + "; ".join(parts)
                      + f" - a different family than the executors {sorted(exec_f)}")
        elif not adv_f:
            reason = (f"the exhaustion-adversary's dispatched model was never recorded; executors ran on "
                      f"{sorted(exec_f)} - cross-model diversity at the adversary is unproven")
        else:
            reason = (f"every verification role ran on the SAME model family as the executors {sorted(exec_f)} "
                      f"(adversary {sorted(adv_f)}) - the model: pin did NOT yield a different dispatched model "
                      f"(e.g. a safeguard blocked the alternate model and every agent fell back to one model); "
                      f"a documented limitation, surfaced - not a silent same-model pass")
    return {
        "executors_models": sorted(exec_f),
        "reviewers_models": sorted(rev_f),
        "adversary_model": adversary_model,
        "cross_model_available": cross,
        "reason": reason,
    }


def selftest() -> int:
    import tempfile
    # family normalization — every spelling of a family collapses to one token
    assert model_family("claude-opus-4-8") == "opus", model_family("claude-opus-4-8")
    assert model_family("Opus 4.8") == "opus"
    assert model_family("claude-sonnet-4-5-20250101") == "sonnet"
    assert model_family("Sonnet 5.5") == "sonnet"
    assert model_family("claude-3-5-haiku-20241022") == "haiku"
    assert model_family("") == "" and model_family(None) == ""
    # record / read round-trip + diversity True/False
    with tempfile.TemporaryDirectory() as d:
        eng = Path(d)
        record(eng, "executor", "xss", "opus")
        record(eng, "executor", "sqli", "claude-opus-4-8")   # same family, different spelling
        record(eng, "reviewer", "xss", "opus", agent_id="xss-reflected-verify")
        led = read(eng)
        assert len(led["entries"]) == 3, led
        assert led["entries"][0]["model_family"] == "opus", led["entries"][0]
        a = diversity_assessment(eng)
        assert a["cross_model_available"] is False, a          # all opus so far
        assert a["executors_models"] == ["opus"], a
        assert a["adversary_model"] is None, a
        record(eng, "exhaustion-adversary", None, "sonnet", agent_id="exhaustion-adversary")
        a2 = diversity_assessment(eng)
        assert a2["cross_model_available"] is True, a2          # adversary on a different family
        assert a2["adversary_model"] == "sonnet", a2
    # empty / missing ledger -> not measurable, never raises
    with tempfile.TemporaryDirectory() as d:
        a3 = diversity_assessment(Path(d))
        assert a3["cross_model_available"] is False and a3["executors_models"] == [], a3
    print("model_ledger.py selftest: OK (family-normalize, record/read round-trip, diversity True/False, "
          "empty-ledger safe)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike cross-model diversity ledger (roadmap L-H).")
    ap.add_argument("--selftest", action="store_true", help="internal consistency check (CI)")
    sub = ap.add_subparsers(dest="cmd")

    rec = sub.add_parser("record", help="append one dispatched-agent model record")
    rec.add_argument("--engagement", required=True, help="engagement dir (ledger at <dir>/runtime/model_ledger.json)")
    rec.add_argument("--role", required=True, choices=list(ROLES), help="the dispatched agent's role")
    rec.add_argument("--category", default=None, help="vuln class/category (omit for an engagement-level role)")
    rec.add_argument("--model", required=True, help="the model the agent ACTUALLY ran on (not the pin)")
    rec.add_argument("--agent-id", dest="agent_id", default=None, help="the dispatched agent/subagent id")

    rd = sub.add_parser("read", help="print the model ledger")
    rd.add_argument("--engagement", required=True)
    rd.add_argument("--json", action="store_true", dest="as_json")

    ass = sub.add_parser("assess", help="print the cross-model diversity assessment")
    ass.add_argument("--engagement", required=True)
    ass.add_argument("--json", action="store_true", dest="as_json")

    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.cmd == "record":
        entry = record(args.engagement, args.role, args.category, args.model, args.agent_id)
        print(json.dumps(entry, indent=2))
        return 0
    if args.cmd == "read":
        led = read(args.engagement)
        if args.as_json:
            print(json.dumps(led, indent=2))
        else:
            print(f"# Model ledger -- {led.get('engagement') or '(unnamed)'}  ({len(led.get('entries', []))} record(s))")
            for e in led.get("entries", []):
                cat = e.get("category") or "-"
                aid = f"  [{e['agent_id']}]" if e.get("agent_id") else ""
                print(f"- {e.get('role'):<20} {cat:<18} {e.get('model')} (family={e.get('model_family')}){aid}")
        return 0
    if args.cmd == "assess":
        a = diversity_assessment(args.engagement)
        if args.as_json:
            print(json.dumps(a, indent=2))
        else:
            print(f"# Cross-model diversity -- {Path(args.engagement).name}")
            print(f"  executors : {a['executors_models']}")
            print(f"  reviewers : {a['reviewers_models']}")
            print(f"  adversary : {a['adversary_model']}")
            print(f"  cross_model_available: {a['cross_model_available']}")
            print(f"  {a['reason']}")
        return 0
    ap.error("choose a subcommand: record / read / assess  (or --selftest)")


if __name__ == "__main__":
    sys.exit(main())
