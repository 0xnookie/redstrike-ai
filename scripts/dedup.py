#!/usr/bin/env python3
"""
dedup.py -- deterministic cross-agent finding de-duplication engine (the reporting flow).

WHY THIS EXISTS:
  The same bug is routinely found by more than one executor on overlapping surface -- object-level authz
  by both `idor` and `bola-bfla`, an SSRF by both `ssrf-inband` and `ssrf-cloud`, an exposure by both
  `exposed-surface` and `secrets`. Reporting's "de-dupe across agents" step was PROSE ("same asset+class+
  root cause -> merge"), so the merge was a model judgment call that drifts: the same bug double-counted,
  or two genuinely different bugs collapsed. This makes the merge DETERMINISTIC.

THE CANONICAL KEY (what makes two findings "the same"):
    (asset-host, normalized endpoint path, query-param-name set, vuln-class)
  - asset-host : registrable host of the finding's asset (scheme/userinfo/port/path stripped).
  - path+params: the endpoint locus -- path lower-cased + trailing-slash-trimmed, plus the SET of query
                 parameter names (so ?q=a and ?q=b are one locus, but ?q and ?id are not).
  - vuln-class : category.cwe if present, else category.owasp, else category.wstg, else 'uncategorized'
                 -- so object-level authz reported as CWE-639 by two agents merges, while a function-level
                 CWE-285 (privesc) on the same endpoint does NOT (different root cause).
  Findings that share the key are one bug. The group's PRIMARY is chosen deterministically (strongest:
  highest severity, then confidence, then evidence count, then lexicographically smallest id); the rest
  get `status:"duplicate"`. Reporting lists the primary once and excludes the duplicates from the counts.

Pure logic (canonical_key / propose_merges / apply_merges) so it unit-tests with no network; a thin
engagement reader reuses verify_completion's multi-layout discovery. Stdlib only.
`python scripts/dedup.py --selftest`.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# atomic_write: one shared helper for findings writes (same resolution as coverage.py / surface.py).
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover - only hit under path-based loading without scripts/ on sys.path
    import importlib.util as _ilu
    _aspec = _ilu.spec_from_file_location("atomicio", str(Path(__file__).resolve().parent / "atomicio.py"))
    _amod = _ilu.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write


# --- concurrent-writer safety -------------------------------------------------------------------- #
# dedup's `main` is read-only (it PRINTS proposed merges), but the engine-core wave-merge step persists
# the result (stamping `status:"duplicate"` on a consolidated findings file) while concurrent hunters
# may also be writing. `write_findings` / `update_findings` give it an atomic + per-file-locked path so
# two concurrent writers can't clobber each other. (Mirror of coverage.py's lock; duplicated to keep
# these CLI scripts standalone.)
class _FileLock:
    """Best-effort cross-process advisory lock via an exclusive lock file (stdlib only; no fcntl/msvcrt,
    so Windows + Linux/WSL behave identically). Spins up to ``timeout``; a lock older than ``stale`` is
    treated as abandoned and broken. If it still can't acquire by the deadline it proceeds anyway
    (degraded last-write-wins) rather than deadlock — ``atomic_write`` keeps the file un-torn either way."""

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
                        os.unlink(self._path)   # break an abandoned lock
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    return self                 # proceed un-locked rather than block
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


def write_findings(path, findings) -> Path:
    """Atomically + lock-safely persist a findings list to ``path`` (a consolidated findings file).
    Concurrent-writer safe: the per-file lock serializes writers so a parallel wave-merge can't clobber,
    and ``atomic_write`` prevents a torn file. Additive — ``main`` stays print-only."""
    p = Path(path)
    with _FileLock(p):
        atomic_write(p, json.dumps(findings, indent=2) + "\n")
    return p


def update_findings(path, mutate):
    """Merge-safe read-modify-write of a consolidated findings file — the concurrent WAVE-MERGE path.
    Lock, read the CURRENT list (so a parallel writer's commit is seen, never clobbered), apply
    ``mutate(findings)`` (edit in place or return a replacement), then ``atomic_write``. Returns the
    written list, or None when the file is absent / unreadable. Stamp cross-agent duplicates race-free by
    composing with ``apply_merges``::

        update_findings(path, lambda fs: apply_merges(fs)[0])
    """
    p = Path(path)
    with _FileLock(p):
        if not p.is_file():
            return None
        try:
            findings = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        out = mutate(findings)
        if out is None:
            out = findings
        atomic_write(p, json.dumps(out, indent=2) + "\n")
        return out


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_CONF_RANK = {"confirmed": 2, "probable": 1, "tentative": 0}


def _host(asset: str) -> str:
    """Registrable host from an asset URL/endpoint (scheme, userinfo, port, path stripped)."""
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", str(asset or "")).strip()
    s = s.split("/", 1)[0]       # drop path
    s = s.split("@")[-1]         # drop userinfo
    s = s.split(":", 1)[0]       # drop port
    return s.lower()


def _path_and_params(asset: str):
    """(normalized path, frozenset of query-param NAMES) from an asset URL/endpoint."""
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", str(asset or "")).strip()
    rest = s.split("/", 1)[1] if "/" in s else ""   # everything after the host
    frag = rest.split("#", 1)[0]
    path, _, query = frag.partition("?")
    path = "/" + path.strip("/")                     # leading slash, no trailing
    path = re.sub(r"/{2,}", "/", path).lower()
    params = set()
    for pair in query.split("&"):
        if not pair:
            continue
        name = pair.split("=", 1)[0].strip().lower()
        if name:
            params.add(name)
    return path, frozenset(params)


def _class_key(finding: dict) -> str:
    """The vuln-class discriminator: cwe -> owasp -> wstg -> 'uncategorized' (normalized)."""
    cat = finding.get("category") or {}
    for k in ("cwe", "owasp", "wstg"):
        v = str(cat.get(k) or "").strip().lower()
        if v:
            return f"{k}:{v}"
    return "uncategorized"


def canonical_key(finding: dict) -> tuple:
    """Deterministic identity of a finding for de-duplication (see module docstring)."""
    asset = finding.get("asset", "")
    path, params = _path_and_params(asset)
    return (_host(asset), path, params, _class_key(finding))


def _strength(finding: dict) -> tuple:
    """Primary-selection ordering (bigger = stronger): severity, confidence, evidence count."""
    sev = _SEV_RANK.get(str(finding.get("severity", "")).lower(), -1)
    conf = _CONF_RANK.get(str(finding.get("confidence", "")).lower(), -1)
    ev = len(finding.get("evidence") or [])
    return (sev, conf, ev)


def _pick_primary(group: list) -> dict:
    """Deterministic primary: strongest first; ties broken by lexicographically smallest id."""
    return sorted(group, key=lambda f: (tuple(-x for x in _strength(f)), str(f.get("id", ""))))[0]


def propose_merges(findings: list) -> list:
    """Group findings by canonical key and propose a merge per group with >1 member.

    Returns [{key, primary, duplicates:[ids], members:[ids]}], ordered by primary id. A composite/
    chain finding (composite:true) is NEVER a merge member -- it re-states components by design."""
    groups = {}
    order = []
    for f in findings:
        if not isinstance(f, dict) or not f.get("id"):
            continue
        if f.get("composite"):
            continue
        k = canonical_key(f)
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(f)
    merges = []
    for k in order:
        grp = groups[k]
        if len(grp) < 2:
            continue
        primary = _pick_primary(grp)
        dups = sorted(str(f["id"]) for f in grp if f["id"] != primary["id"])
        merges.append({
            "key": {"host": k[0], "path": k[1], "params": sorted(k[2]), "class": k[3]},
            "primary": str(primary["id"]),
            "duplicates": dups,
            "members": sorted(str(f["id"]) for f in grp),
        })
    return sorted(merges, key=lambda m: m["primary"])


def apply_merges(findings: list):
    """Set status:"duplicate" on every non-primary member of a merge group (in place, schema-valid).

    Returns (findings, merge_map) where merge_map maps each duplicate id -> its primary id. The finding
    schema has no 'duplicate_of' field, so the primary link lives in merge_map (for reporting), not the
    finding -- the only mutation on the finding is the valid `status:"duplicate"`."""
    merges = propose_merges(findings)
    merge_map = {}
    for m in merges:
        for dup in m["duplicates"]:
            merge_map[dup] = m["primary"]
    for f in findings:
        if isinstance(f, dict) and str(f.get("id")) in merge_map:
            f["status"] = "duplicate"
    return findings, merge_map


# ------------------------------- engagement I/O (thin) ------------------------------- #
def _load_engagement_findings(eng: Path):
    """Reuse verify_completion's multi-layout finding discovery so dedup sees the same set the gate does."""
    try:
        import importlib.util
        p = ROOT / "skills" / "_contract" / "verify_completion.py"
        spec = importlib.util.spec_from_file_location("rs_verify_completion_dedup", p)
        vc = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vc)
        return vc._discover_engagement_findings(eng)
    except Exception as e:  # noqa: BLE001
        return None, f"could not load findings: {e}"


def selftest() -> None:
    # key normalization: scheme/port/case/trailing-slash don't split a locus; a different param DOES.
    a = {"id": "RS-2026-001", "asset": "https://App.ACME.com:443/api/orders/?id=1",
         "category": {"cwe": "CWE-639"}, "severity": "high", "confidence": "confirmed",
         "evidence": [{"type": "tool_output", "ref": "a"}, {"type": "log", "ref": "b"}]}
    b = {"id": "RS-2026-002", "asset": "http://app.acme.com/api/orders?id=2",
         "category": {"cwe": "CWE-639"}, "severity": "medium", "confidence": "probable",
         "evidence": [{"type": "tool_output", "ref": "c"}]}
    assert canonical_key(a) == canonical_key(b), (canonical_key(a), canonical_key(b))

    # same endpoint, DIFFERENT class (function-level privesc) -> NOT a duplicate.
    c = {"id": "RS-2026-003", "asset": "https://app.acme.com/api/orders?id=9",
         "category": {"cwe": "CWE-285"}, "severity": "high", "confidence": "confirmed",
         "evidence": [{"type": "tool_output", "ref": "d"}]}
    assert canonical_key(a) != canonical_key(c)

    # same locus but a different param name -> different locus -> NOT a duplicate.
    d = {"id": "RS-2026-004", "asset": "https://app.acme.com/api/orders?sort=x",
         "category": {"cwe": "CWE-639"}, "severity": "low", "confidence": "tentative",
         "evidence": [{"type": "log", "ref": "e"}]}
    assert canonical_key(a) != canonical_key(d)

    # propose + apply: a and b merge; a is the primary (stronger: high>medium); b -> duplicate.
    merges = propose_merges([a, b, c, d])
    assert len(merges) == 1, merges
    assert merges[0]["primary"] == "RS-2026-001" and merges[0]["duplicates"] == ["RS-2026-002"]
    findings, mm = apply_merges([dict(a), dict(b), dict(c), dict(d)])
    by = {f["id"]: f for f in findings}
    assert by["RS-2026-002"]["status"] == "duplicate"
    assert by["RS-2026-001"].get("status") != "duplicate"  # primary untouched
    assert by["RS-2026-003"].get("status") != "duplicate"  # different class untouched
    assert mm == {"RS-2026-002": "RS-2026-001"}

    # determinism: equal strength -> smallest id is primary, and the result is stable under input order.
    e1 = {"id": "RS-2026-020", "asset": "https://x.test/p", "category": {"cwe": "CWE-79"},
          "severity": "high", "confidence": "confirmed", "evidence": [{"type": "log", "ref": "x"}]}
    e2 = {"id": "RS-2026-010", "asset": "https://x.test/p", "category": {"cwe": "CWE-79"},
          "severity": "high", "confidence": "confirmed", "evidence": [{"type": "log", "ref": "y"}]}
    m1 = propose_merges([e1, e2])
    m2 = propose_merges([e2, e1])
    assert m1 == m2 and m1[0]["primary"] == "RS-2026-010", (m1, m2)

    # a composite/chain finding is never a merge member.
    comp = {"id": "RS-2026-030", "asset": "https://x.test/p", "category": {"cwe": "CWE-79"},
            "severity": "critical", "confidence": "confirmed", "composite": True,
            "evidence": [{"type": "log", "ref": "z"}]}
    assert propose_merges([e1, e2, comp])[0]["primary"] == "RS-2026-010"  # comp excluded

    # a lone finding is not a merge.
    assert propose_merges([a]) == []

    print("dedup selftest: OK")


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass
    ap = argparse.ArgumentParser(description="Redstrike deterministic cross-agent finding de-duplication.")
    ap.add_argument("--engagement", help="engagement dir: propose merges across its findings")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.selftest:
        selftest()
        return 0
    if not args.engagement:
        ap.error("choose --engagement <dir> or --selftest")

    findings, source = _load_engagement_findings(Path(args.engagement))
    if findings is None:
        print(json.dumps({"error": source}) if args.as_json else f"[!] {source}")
        return 2
    merges = propose_merges(findings)
    dup_count = sum(len(m["duplicates"]) for m in merges)
    if args.as_json:
        print(json.dumps({"engagement": args.engagement, "source": source,
                          "findings": len(findings), "merge_groups": len(merges),
                          "duplicates": dup_count, "merges": merges}, indent=2))
    else:
        print(f"# De-duplication -- {args.engagement}  ({source}, {len(findings)} finding(s))")
        if not merges:
            print("  no cross-agent duplicates (every finding has a distinct canonical key).")
        for m in merges:
            k = m["key"]
            loc = f"{k['host']}{k['path']}" + (f"?{{{','.join(k['params'])}}}" if k["params"] else "")
            print(f"  - {m['primary']} <= {', '.join(m['duplicates'])}  [{k['class']} @ {loc}]")
        print(f"\n{len(merges)} merge group(s); {dup_count} finding(s) -> status:duplicate "
              f"(excluded from the report counts).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
