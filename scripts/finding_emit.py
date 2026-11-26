#!/usr/bin/env python3
"""
finding_emit.py -- the SINGLE owner of finding emission (shift-left, QW-1).

WHY THIS EXISTS (20min-2026-11-25 retro, incident 1):
  An executor hand-authored a finding that violated skills/_contract/finding.schema.json on ~8 axes at
  once -- an invented slug id (`RS-20min-bfla-extcomment-author-spoof`), TitleCase `severity:"Low"`, ~11
  non-schema props (`class`, `endpoint`, `method`, `severity_rationale`, ...), and `evidence` as a prose
  STRING instead of a list of {type,ref}. The only validator is verify_completion.py, which runs DOWNSTREAM
  (at the completion gate, after a report exists) and prints a TRUNCATED [:4] slice of errors per run -- so
  the parent orchestrator hand-fixed one violation per gate-run (~5 rounds of churn). And there was NO id
  allocator anywhere in scripts/ (RS-ids appeared only in test fixtures) -- which is WHY the executor
  invented a descriptive slug in the first place.

THE FIX (validate at WRITE time, in the actor that holds the context):
  Give the executor a gated write helper so a bad finding is refused BEFORE handback, not 5 gate-rounds
  later. Three modes, stdlib-only, mirroring coverage.py / reconverge.py:

    --alloc-id    The single owner of RS-YYYY-NNN allocation. Scans every <eng>/*/findings*.json +
                  reviews/*.verdict.json for the max used sequence in the current year and RESERVES the
                  next free id (a reservation ledger under runtime/ makes concurrent executor allocations
                  collision-free, serialized by the same _FileLock idiom coverage.py uses). The executor
                  never CHOOSES an id again -- the invention is removed at the source.
    --skeleton    Print a fully schema-conformant finding stub -- every required key, enums pre-filled
                  LOWERCASE, evidence as a list of {type,ref} (not a prose string), reproduction as a list
                  -- so the executor fills VALUES into a correct SHAPE instead of reconstructing one.
    --validate    Run the EXACT validator the gate uses (verify_completion._finding_schema_def +
                  _stdlib_schema_errors, or jsonschema when present) and print ALL violations (never the
                  gate's [:4] truncation) with per-violation COERCION HINTS. Exit non-zero on any violation.

  Executor step 7 ("write finding") becomes: id=$(finding_emit --alloc-id) -> fill the skeleton ->
  finding_emit --validate until exit 0 -> hand back. The ~5 gate rounds collapse to a write-time loop the
  executor closes itself.

Stdlib only. `python scripts/finding_emit.py --selftest`.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# atomic_write: the same shared ledger-write helper coverage.py / reconverge.py use (temp file + os.replace
# so a reader never sees a torn reservation ledger). Path-load fallback for a run without scripts/ on sys.path.
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover - only hit under path-based loading without scripts/ on sys.path
    _aspec = importlib.util.spec_from_file_location("atomicio", str(Path(__file__).resolve().parent / "atomicio.py"))
    _amod = importlib.util.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write

# The reservation ledger: ids handed out by --alloc-id but not yet written into a findings.json. Scanned
# alongside the real findings/reviews so two concurrent executor allocations never collide on the same id.
# Lives under runtime/ (never matched by the `findings*.json` discovery/orphan globs, so it is invisible to
# the findings pipeline and close.py's orphan-warn).
RESERVATIONS = "runtime/finding_id_reservations.json"
_RS_ID_TOKEN = re.compile(r"RS-[0-9]{4}-[0-9]+")


# --- concurrent-allocation safety (the coverage.py _FileLock idiom, copied to stay self-contained + stdlib
# -only; importing scripts/coverage.py by NAME is unsafe because the pip `coverage` package shadows it) --- #
class _FileLock:
    """Best-effort cross-process advisory lock via an exclusive lock file (stdlib only; no fcntl/msvcrt, so
    Windows + Linux/WSL behave identically). Spins up to ``timeout``; a lock older than ``stale`` is treated
    as abandoned and broken; if it still can't acquire by the deadline it proceeds anyway rather than
    deadlock -- ``atomic_write`` keeps the reservation ledger un-torn either way."""

    def __init__(self, target, *, timeout: float = 30.0, poll: float = 0.05, stale: float = 120.0):
        self._path = str(target) + ".lock"
        self._timeout, self._poll, self._stale = timeout, poll, stale
        self._held = False

    def __enter__(self):
        deadline = time.monotonic() + self._timeout
        while True:
            try:
                fd = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            except FileExistsError:
                try:
                    if time.time() - os.path.getmtime(self._path) > self._stale:
                        os.unlink(self._path)
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    return self
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


# --- the gate's own validator, reused verbatim (never re-implemented) ---------------------------------- #
_VC = None


def _vc():
    """Load skills/_contract/verify_completion.py by PATH and cache it, so --validate reuses the EXACT
    finding-schema check the completion gate runs (never a drifting second copy)."""
    global _VC
    if _VC is None:
        p = ROOT / "skills" / "_contract" / "verify_completion.py"
        spec = importlib.util.spec_from_file_location("rs_vc_finding_emit", p)
        _VC = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_VC)
    return _VC


# ------------------------------------------- id allocation ------------------------------------------- #
def _iter_scan_files(eng: Path):
    """Every file an allocated RS id could already live in: findings (root + per-skill, INCLUDING strays
    like findings_authed_bfla.json so a non-canonical file never leaks a reused id), reviews verdicts (root
    + per-skill), and the reservation ledger."""
    yield from sorted(eng.glob("findings*.json"))
    yield from sorted(eng.glob("*/findings*.json"))
    yield from sorted(eng.glob("reviews/*.json"))
    yield from sorted(eng.glob("*/reviews/*.json"))
    r = eng / RESERVATIONS
    if r.is_file():
        yield r


def scan_used_ids(eng: Path) -> set:
    """Every RS-YYYY-NNN id already used anywhere in the engagement. A raw-text regex sweep (not a JSON
    parse) so a malformed findings file or an id that appears only in a verdict sidecar / filename still
    reserves its sequence -- OVER-allocating is harmless, REUSING an id is the harm to avoid."""
    used = set()
    for p in _iter_scan_files(eng):
        try:
            used |= set(_RS_ID_TOKEN.findall(p.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
        # a verdict file is named <id>.verdict.json -- catch the id from the FILENAME too.
        used |= set(_RS_ID_TOKEN.findall(p.name))
    return used


def next_id(used: set, year: int) -> str:
    """The next free RS-<year>-NNN given the used-id set. Sequence is per-year (ids are engagement-unique
    within the year); >=1000 stays schema-valid (pattern is [0-9]{3,})."""
    seqs = []
    for tok in used:
        m = re.match(rf"^RS-{year}-([0-9]+)$", tok)
        if m:
            seqs.append(int(m.group(1)))
    return f"RS-{year}-{max(seqs, default=0) + 1:03d}"


def alloc_id(eng: Path, year: int = None) -> str:
    """Allocate + RESERVE the next free id under the reservation lock, so two concurrent executor
    allocations can never collide (the lock serializes the read-modify-write; the reservation ledger makes
    the serialization meaningful -- the second caller SEES the first's reservation)."""
    year = year or _dt.datetime.now(_dt.timezone.utc).year
    res_path = eng / RESERVATIONS
    res_path.parent.mkdir(parents=True, exist_ok=True)  # runtime/ must exist before the lock file is created
    with _FileLock(res_path):
        used = scan_used_ids(eng)
        fid = next_id(used, year)
        reserved = []
        if res_path.is_file():
            try:
                doc = json.loads(res_path.read_text(encoding="utf-8"))
                reserved = list(doc.get("reserved", [])) if isinstance(doc, dict) else []
            except (OSError, json.JSONDecodeError):
                reserved = []
        if fid not in reserved:
            reserved.append(fid)
        atomic_write(res_path, json.dumps(
            {"reserved": sorted(set(reserved)),
             "updated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")}, indent=2) + "\n")
    return fid


# --------------------------------------------- skeleton ---------------------------------------------- #
def skeleton(year: int = None, fid: str = None) -> dict:
    """A fully schema-conformant finding stub: every REQUIRED key present, enums pre-filled LOWERCASE,
    evidence a list of {type,ref} (the exact shape the prose-string incident got wrong), reproduction a
    list. It VALIDATES clean -- the executor replaces the REPLACE_ME values, it never rebuilds the shape."""
    year = year or _dt.datetime.now(_dt.timezone.utc).year
    return {
        "version": 1,
        "id": fid or f"RS-{year}-001",
        "title": "REPLACE_ME: concise finding title (>= 4 chars)",
        "asset": "https://REPLACE_ME.in-scope.example/path",
        "category": {"owasp": "A01:2021", "wstg": "WSTG-ATHZ-01", "cwe": "CWE-0"},
        "severity": "low",
        "confidence": "tentative",
        "status": "open",
        "evidence": [
            {"type": "request_response", "ref": "evidence/REPLACE_ME.http"}
        ],
        "reproduction": [
            "REPLACE_ME: step 1 (backtick any inline `payload`/`request`/`command`)"
        ],
        "impact": "REPLACE_ME: what the evidence proves an attacker can do.",
        "remediation": "REPLACE_ME: how to fix it.",
    }


# --------------------------------------------- validate ---------------------------------------------- #
# The exact non-schema props this engagement's executor invented, with where each BELONGS instead (the
# coercion the parent applied by hand, now printed at write time).
_STRAY_RELOCATION = {
    "class": "drop -- routing/class is tracked by coverage.py, not on the finding",
    "bugcrowd_priority": "drop -- VRT/priority is a reporting concern, not a finding field",
    "severity_rationale": "fold into `impact`",
    "endpoint": "fold into `asset` (the URL) and `reproduction` (the request line)",
    "method": "fold into `reproduction` (the request line, e.g. `POST /x`)",
    "identity": "describe in `reproduction` / `impact`",
    "differential_proof": "fold into `reproduction` + an `evidence` {type,ref} artifact",
    "repro": "use `reproduction` (the schema name)",
    "observed_mitigations": "fold into `impact` / `remediation`",
    "dedup": "drop -- de-duplication is the reviewer's job",
    "cleanup_status": "use the structured `cleanup` {mechanism,removed,verified_by,ref} object",
    "scope": "drop -- scope is checked against scope.yaml",
}


def _hint_for(err: str, finding: dict) -> str:
    """A coercion hint for one schema-violation string, inferred from the finding's content. Empty when no
    specific coercion is known."""
    # stdlib validator: "unexpected property 'X'"; jsonschema: "Additional properties are not allowed ('X' ...)"
    m = re.search(r"unexpected property '([^']+)'", err) or re.search(r"'([^']+)' (?:was|were) unexpected", err)
    if m:
        key = m.group(1)
        return _STRAY_RELOCATION.get(
            key, "not in the schema (additionalProperties:false) -- relocate into an allowed field or drop")
    if "Additional properties are not allowed" in err:
        return "a property is not in the schema (additionalProperties:false) -- relocate into an allowed field or drop"
    if "/id:" in err and "does not match pattern" in err:
        return "allocate a conformant id: python scripts/finding_emit.py --alloc-id --engagement <dir>"
    if "/severity:" in err and "not one of" in err:
        sev = finding.get("severity")
        if isinstance(sev, str) and sev.lower() in ("critical", "high", "medium", "low", "info"):
            return f"severity must be lowercase -> '{sev.lower()}'"
        return "severity must be one of critical/high/medium/low/info (lowercase)"
    if "/confidence:" in err and "not one of" in err:
        c = finding.get("confidence")
        if isinstance(c, str) and c.lower() in ("confirmed", "probable", "tentative"):
            return f"confidence must be lowercase -> '{c.lower()}'"
        return "confidence must be one of confirmed/probable/tentative (lowercase)"
    if "/status:" in err and "not one of" in err:
        return "status must be one of open/verified/rejected/duplicate/remediated (derived from the reviewer verdict)"
    if "/evidence:" in err and ("expected array" in err or "is not of type 'array'" in err):
        return "evidence must be a LIST of {type,ref} objects, not a string -- e.g. [{\"type\":\"request_response\",\"ref\":\"evidence/x.http\"}]"
    if "/evidence" in err and ("does not satisfy anyOf" in err or "is not valid under any of" in err):
        return "each evidence item is {type,ref} (vault artifact) OR {type:code_citation,file,line,snippet}"
    if "minItems" in err and "/evidence" in err:
        return "at least one evidence item is required"
    if "minItems" in err and "/reproduction" in err:
        return "at least one reproduction step is required"
    if "minLength" in err and "/title" in err:
        return "title must be >= 4 characters"
    return ""


def validate_finding(finding: dict, fid: str = None):
    """Validate ONE finding against the gate's finding schema. Returns a list of {error, hint} dicts --
    EMPTY means it passes. Reuses verify_completion's _finding_schema_def + _stdlib_schema_errors (or
    jsonschema when installed) so this is byte-for-byte the check the completion gate applies, minus the
    gate's [:4] truncation. The `_rs_*` discovery tags are stripped first (the schema is
    additionalProperties:false), exactly as the gate does."""
    vc = _vc()
    fid = fid or str(finding.get("id", "<no-id>"))
    out = []

    # 1. required-field / empty-value check (the gate's check_finding front door: a present-but-empty
    #    required field is as bad as a missing one).
    if isinstance(finding, dict):
        missing = [k for k in vc._REQUIRED_FINDING_FIELDS if k not in finding or finding.get(k) in (None, "", [], {})]
        for k in missing:
            out.append({"error": f"{fid}: missing/empty required field '{k}'",
                        "hint": "provide a non-empty value (see --skeleton for the shape)"})

    # 2. schema conformance (enums + additionalProperties + patterns + bounds) -- the authoritative full list.
    fdef, froot = vc._finding_schema_def()
    if fdef and isinstance(finding, dict):
        f_schema = {k: v for k, v in finding.items() if not str(k).startswith("_rs_")}
        serrs = []
        try:
            import jsonschema  # type: ignore
            validator = jsonschema.Draft202012Validator({**froot, **fdef})
            for e in sorted(validator.iter_errors(f_schema), key=lambda e: list(e.absolute_path)):
                loc = "/".join(str(x) for x in e.absolute_path)
                tag = f"{fid}/{loc}" if loc else fid   # match the stdlib `path/key:` shape so hints key cleanly
                serrs.append(f"{tag}: {e.message}")
        except ImportError:
            serrs = vc._stdlib_schema_errors(f_schema, fdef, froot, path=fid)
        for e in serrs:
            out.append({"error": e, "hint": _hint_for(e, finding)})
    elif not isinstance(finding, dict):
        out.append({"error": f"{fid}: finding is not a JSON object", "hint": "a finding must be a JSON object"})
    return out


def validate_file(path: Path):
    """Validate a findings file -- a single finding object OR an array of them (the findings.json shape).
    Returns (ok, report_lines, total_violations)."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False, [f"[!] no such file: {path}"], 1
    except json.JSONDecodeError as e:
        return False, [f"[!] {path} is not valid JSON: {e}"], 1

    findings = data if isinstance(data, list) else [data]
    lines, total = [], 0
    for i, f in enumerate(findings, 1):
        fid = str(f.get("id", f"<no-id>")) if isinstance(f, dict) else "<non-object>"
        viols = validate_finding(f, fid)
        if not viols:
            lines.append(f"PASS  finding #{i} [{fid}] -- schema-conformant")
            continue
        total += len(viols)
        lines.append(f"FAIL  finding #{i} [{fid}] -- {len(viols)} violation(s):")
        for v in viols:
            lines.append(f"  - {v['error']}")
            if v["hint"]:
                lines.append(f"      hint: {v['hint']}")
    return total == 0, lines, total


# ---------------------------------------------- CLI --------------------------------------------------- #
def selftest() -> int:
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        eng = Path(d)
        # alloc-id: first id is -001, and it SKIPS a sequence already used by an existing (even non-canonical) file.
        (eng / "bola-bfla").mkdir()
        (eng / "bola-bfla" / "findings_authed_bfla.json").write_text(
            json.dumps([{"id": "RS-2026-004"}]), encoding="utf-8")
        got = alloc_id(eng, year=2026)
        assert got == "RS-2026-005", got            # max used (004) + 1, from a NON-canonical file
        got2 = alloc_id(eng, year=2026)
        assert got2 == "RS-2026-006", got2          # the prior alloc was RESERVED -> not handed out twice
        assert next_id(set(), 2030) == "RS-2030-001"
        # skeleton validates clean (no violations).
        ok, _lines, n = validate_file_obj(skeleton(year=2026))
        assert ok and n == 0, (_lines, n)
        # a bad finding flags id / severity-case / extra-prop / string-evidence, ALL of them (not truncated).
        bad = {"id": "RS-20min-x", "title": "t", "asset": "a", "category": {"cwe": "CWE-1"},
               "severity": "Low", "confidence": "confirmed", "status": "open",
               "evidence": "prose string", "reproduction": ["x"], "endpoint": "/e", "method": "GET"}
        viols = validate_finding(bad)
        blob = " ".join(v["error"] for v in viols)
        assert "does not match pattern" in blob            # bad id
        assert "'Low' not one of" in blob                  # severity case
        assert "unexpected property 'endpoint'" in blob    # extra prop
        assert "unexpected property 'method'" in blob
        assert "expected array" in blob                    # string evidence
        hints = " ".join(v["hint"] for v in viols)
        assert "lowercase -> 'low'" in hints               # severity coercion hint
        assert "must be a LIST of {type,ref}" in hints     # evidence coercion hint
        assert "fold into `asset`" in hints                # endpoint relocation hint
    print("finding_emit selftest: OK")
    return 0


def validate_file_obj(obj):
    """selftest helper: validate an in-memory finding (object or array) the way validate_file does a file."""
    findings = obj if isinstance(obj, list) else [obj]
    total = sum(len(validate_finding(f)) for f in findings)
    return total == 0, [], total


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Redstrike finding-emit helper: the single owner of RS-YYYY-NNN allocation + a "
                    "write-time conformant skeleton + the gate's finding validator. Shift-left so a bad "
                    "finding is refused BEFORE handback, not 5 gate-rounds later.")
    ap.add_argument("--alloc-id", action="store_true",
                    help="allocate + reserve the next free RS-YYYY-NNN id for the engagement (needs --engagement)")
    ap.add_argument("--skeleton", action="store_true",
                    help="print a fully schema-conformant finding stub to fill in")
    ap.add_argument("--validate", metavar="FILE",
                    help="validate a findings file (object or array) against the gate's finding schema; "
                         "prints ALL violations + coercion hints; exit non-zero on any violation")
    ap.add_argument("--engagement", help="engagement dir (for --alloc-id)")
    ap.add_argument("--year", type=int, help="override the allocation/skeleton year (default: current UTC year)")
    ap.add_argument("--json", action="store_true", dest="as_json", help="machine-readable output")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if args.alloc_id:
        if not args.engagement:
            ap.error("--alloc-id needs --engagement")
        eng = Path(args.engagement)
        eng.mkdir(parents=True, exist_ok=True)
        fid = alloc_id(eng, year=args.year)
        if args.as_json:
            print(json.dumps({"id": fid}))
        else:
            print(fid)   # bare id on stdout so `id=$(finding_emit --alloc-id ...)` works
        return 0

    if args.skeleton:
        print(json.dumps(skeleton(year=args.year), indent=2))
        return 0

    if args.validate:
        ok, lines, total = validate_file(Path(args.validate))
        if args.as_json:
            # re-run to emit structured violations
            try:
                data = json.loads(Path(args.validate).read_text(encoding="utf-8"))
                findings = data if isinstance(data, list) else [data]
                report = [{"index": i, "id": (f.get("id") if isinstance(f, dict) else None),
                           "violations": validate_finding(f)} for i, f in enumerate(findings, 1)]
            except Exception as e:  # noqa: BLE001
                report = [{"error": str(e)}]
            print(json.dumps({"file": args.validate, "pass": ok, "violations": total, "findings": report}, indent=2))
        else:
            for l in lines:
                print(l)
            print(f"\n{'PASS' if ok else 'FAIL'}: {args.validate} "
                  + ("is schema-conformant." if ok else f"has {total} violation(s) (see above)."))
        return 0 if ok else 2

    ap.error("choose one of --alloc-id / --skeleton / --validate / --selftest")


if __name__ == "__main__":
    sys.exit(main())
