#!/usr/bin/env python3
"""evidence_seal.py -- tamper-evidence + chain-of-custody for an engagement's evidence vault.

The one real engagement exposed the weak link: evidence was thin and UNSEALED. `evidence[].sha256`
was never computed (0 populated), and roe-gate.md §4 promises an "immutable audit log / chain of
custody" that no engagement actually carried. Evidence could be altered post-hoc undetected, and there
was no timestamped who/what/when trail. Court-grade output needs tamper-EVIDENCE and custody.

This module, run at report assembly, does two things:

  1. SEAL — hash every evidence/poc artifact under the engagement into `evidence/manifest.json`
     (a list of {path, sha256, bytes, captured_at}), then populate each finding's `evidence[].sha256`
     by resolving its `ref` to the on-disk artifact. A `time_anchor` block dates the whole manifest:
     a content digest over every artifact hash (the tamper-evident date) bound to the redstrike repo
     commit in force (read-only `git rev-parse HEAD`; no commit/note is ever created).

  2. VERIFY — recompute every manifest hash and report any mismatch (altered), missing (gone), or
     unsealed (present on disk but absent from the manifest = added after sealing) artifact. The lead's
     gate agent imports `verify_manifest` to HARD-FAIL on a tamper signal.

Stdlib + the repo's atomicio helper only. Writes are atomic. The module never modifies the audited
source tree (`source/`) or git state; it only reads HEAD.

CLI:
    python evidence_seal.py --engagement <dir>            # seal: write manifest + populate sha256
    python evidence_seal.py --engagement <dir> --verify   # verify: exit 0 clean, 3 on tamper
    python evidence_seal.py --engagement <dir> --json      # machine-readable summary on stdout
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

# atomic_write: the shared ledger-write helper. scripts/ is on sys.path for a direct run and for the
# validate/verify spec-loads; fall back to a path-load when a caller imports this module by path.
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover - only under path-based loading without scripts/ on sys.path
    import importlib.util as _ilu
    _aspec = _ilu.spec_from_file_location("atomicio", str(Path(__file__).resolve().parent / "atomicio.py"))
    _amod = _ilu.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_REL = "evidence/manifest.json"
AUDIT_REL = "runtime/audit.jsonl"

# Evidence/PoC artifacts live under any directory named `evidence` or `poc` (engagement root,
# `findings/`, or a per-skill dir). These components mark a file as a sealable artifact.
_ARTIFACT_DIRS = frozenset({"evidence", "poc"})
# Dirs never walked when collecting artifacts: the audited source checkout + VCS/build noise. They are
# large and are NOT evidence (code_citation evidence is CAPTURED into evidence/<id>/, never sealed from
# the live source tree).
_PRUNE_DIRS = frozenset({
    ".git", "source", "node_modules", "vendor", "__pycache__",
    ".idea", ".vscode", ".pytest_cache", ".mypy_cache", "venv", ".venv",
})
_SHA_EMPTY = "0" * 64


# --- hashing ----------------------------------------------------------------
def sha256_file(path) -> str:
    """64-hex sha256 of a file's bytes (streamed, so a large PoC/screenshot never loads whole)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(ts: _dt.datetime) -> str:
    return ts.astimezone(_dt.timezone.utc).isoformat()


def _mtime_iso(path: Path) -> str:
    try:
        return _iso(_dt.datetime.fromtimestamp(path.stat().st_mtime, _dt.timezone.utc))
    except Exception:
        return ""


# --- artifact discovery -----------------------------------------------------
def collect_artifacts(engagement_dir) -> list[Path]:
    """Every sealable evidence/poc artifact under the engagement, as absolute Paths, sorted.

    A file is an artifact when any directory component of its engagement-relative path is `evidence`
    or `poc`. The manifest itself and in-flight `.tmp` writes are excluded. Heavy/irrelevant trees
    (the audited `source/` checkout, VCS/build dirs) are pruned, so sealing a white-box engagement
    does not walk a full cloned repo."""
    eng = Path(engagement_dir).resolve()
    manifest = (eng / MANIFEST_REL).resolve()
    out: list[Path] = []
    for root, dirnames, filenames in os.walk(eng):
        dirnames[:] = [d for d in dirnames if d not in _PRUNE_DIRS]
        root_p = Path(root)
        rel_parts = set(root_p.relative_to(eng).parts) if root_p != eng else set()
        if not (rel_parts & _ARTIFACT_DIRS):
            continue
        for name in filenames:
            if name.endswith(".tmp"):
                continue
            fp = (root_p / name).resolve()
            if fp == manifest:
                continue
            out.append(fp)
    return sorted(out)


def _rel(engagement_dir: Path, path: Path) -> str:
    """Engagement-relative POSIX path (portable manifest key), falling back to the absolute path."""
    try:
        return path.resolve().relative_to(engagement_dir.resolve()).as_posix()
    except Exception:
        return path.resolve().as_posix()


# --- time anchor ------------------------------------------------------------
def _repo_commit(repo_root: Path = REPO_ROOT) -> str | None:
    """HEAD commit of the redstrike repo (read-only), or None. Binds the manifest to the code in force
    for tamper-evident dating. Never creates a commit/note / mutates git state."""
    import shutil
    git = shutil.which("git")
    if not git:
        return None
    try:
        out = subprocess.run(
            [git, "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        sha = (out.stdout or "").strip()
        return sha or None
    except Exception:
        return None


def build_time_anchor(entries: list[dict], now: _dt.datetime, repo_root: Path = REPO_ROOT) -> dict:
    """An RFC-3161-style self-anchored timestamp: a timestamp over a digest of the sealed data.

    `manifest_digest` is sha256 of the canonical (path-sorted) list of every artifact's {path, sha256}
    — a single root hash over all evidence. Altering any sealed artifact changes its sha256, which
    changes this digest; the digest is dated by `anchored_at` and bound to `repo_commit`, so the seal
    carries a verifiable "this exact set of evidence existed at this time" claim without contacting an
    external TSA (no network, no data egress)."""
    canon = json.dumps(
        [{"path": e["path"], "sha256": e["sha256"]} for e in sorted(entries, key=lambda e: e["path"])],
        sort_keys=True, separators=(",", ":"),
    )
    return {
        "method": "self-anchored",
        "anchored_at": _iso(now),
        "manifest_digest": sha256_bytes(canon.encode("utf-8")),
        "artifact_count": len(entries),
        "repo_commit": _repo_commit(repo_root),
    }


# --- manifest ---------------------------------------------------------------
def build_manifest(engagement_dir, now: _dt.datetime | None = None) -> dict:
    """The manifest document: one {path, sha256, bytes, captured_at} entry per artifact + a time anchor."""
    eng = Path(engagement_dir).resolve()
    now = now or _now()
    entries: list[dict] = []
    for fp in collect_artifacts(eng):
        try:
            size = fp.stat().st_size
            digest = sha256_file(fp)
        except Exception:
            # Unreadable artifact: record it with a sentinel hash so it is visible, not dropped.
            size, digest = -1, _SHA_EMPTY
        entries.append({
            "path": _rel(eng, fp),
            "sha256": digest,
            "bytes": size,
            "captured_at": _mtime_iso(fp),
        })
    entries.sort(key=lambda e: e["path"])
    return {
        "engagement": eng.name,
        "generated_at": _iso(now),
        "tool": "evidence_seal.py",
        "count": len(entries),
        "time_anchor": build_time_anchor(entries, now),
        "artifacts": entries,
    }


def write_manifest(engagement_dir, manifest: dict) -> Path:
    eng = Path(engagement_dir).resolve()
    out = eng / MANIFEST_REL
    atomic_write(out, json.dumps(manifest, indent=2) + "\n")
    return out


# --- finding evidence[].sha256 population -----------------------------------
def _candidate_findings_files(eng: Path) -> list[Path]:
    """Every findings file whose evidence[] should be sha256-stamped: root findings.json, each per-skill
    `<eng>/*/findings.json`, and the consolidated report file when present (all layouts the framework
    produces — see close._discover_findings)."""
    files: list[Path] = []
    root = eng / "findings.json"
    if root.is_file():
        files.append(root)
    files.extend(sorted(eng.glob("*/findings.json")))
    cons = eng / "report" / "findings_consolidated.json"
    if cons.is_file():
        files.append(cons)
    # de-dupe preserving order
    seen, uniq = set(), []
    for f in files:
        r = f.resolve()
        if r not in seen:
            seen.add(r)
            uniq.append(f)
    return uniq


def _findings_of(doc):
    """The finding dicts in a loaded findings doc (bare array, or {findings,attack_chains} object)."""
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        return [f for f in (list(doc.get("findings") or []) + list(doc.get("attack_chains") or []))
                if isinstance(f, dict)]
    return []


def _resolve_ref(eng: Path, findings_dir: Path, ref: str, by_basename: dict[str, Path]) -> Path | None:
    """Resolve an evidence `ref` to an on-disk artifact. Tries, in order: an absolute ref; the ref
    relative to the engagement root; relative to the findings file's own dir; under evidence/; finally
    a UNIQUE basename match among collected artifacts. Returns None if unresolved/ambiguous."""
    if not ref:
        return None
    p = Path(ref)
    cands = []
    if p.is_absolute():
        cands.append(p)
    else:
        cands += [eng / ref, findings_dir / ref, eng / "evidence" / ref]
    for c in cands:
        try:
            if c.is_file():
                return c
        except Exception:
            continue
    hit = by_basename.get(Path(ref).name)
    return hit


def populate_finding_hashes(engagement_dir, now: _dt.datetime | None = None) -> dict:
    """Set `evidence[].sha256` on every finding from the resolved on-disk artifact. Idempotent; writes
    each changed findings file atomically. Returns counts + the list of unresolved refs."""
    eng = Path(engagement_dir).resolve()
    artifacts = collect_artifacts(eng)
    # basename -> path, but only when the basename is UNIQUE (ambiguous basenames are not auto-matched).
    counts: dict[str, int] = {}
    for a in artifacts:
        counts[a.name] = counts.get(a.name, 0) + 1
    by_basename = {a.name: a for a in artifacts if counts[a.name] == 1}

    populated = unresolved = items = 0
    unresolved_refs: list[str] = []
    for ff in _candidate_findings_files(eng):
        try:
            doc = json.loads(ff.read_text(encoding="utf-8"))
        except Exception:
            continue
        changed = False
        for f in _findings_of(doc):
            ev = f.get("evidence")
            if not isinstance(ev, list):
                continue
            for item in ev:
                if not isinstance(item, dict):
                    continue
                ref = item.get("ref")
                if not ref:
                    continue
                items += 1
                target = _resolve_ref(eng, ff.parent, str(ref), by_basename)
                if target is None:
                    unresolved += 1
                    unresolved_refs.append(str(ref))
                    continue
                try:
                    digest = sha256_file(target)
                except Exception:
                    unresolved += 1
                    unresolved_refs.append(str(ref))
                    continue
                if item.get("sha256") != digest:
                    item["sha256"] = digest
                    changed = True
                populated += 1
        if changed:
            atomic_write(ff, json.dumps(doc, indent=2) + "\n")
    return {
        "evidence_items": items,
        "populated": populated,
        "unresolved": unresolved,
        "unresolved_refs": sorted(set(unresolved_refs)),
    }


# --- seal + verify ----------------------------------------------------------
def seal(engagement_dir, now: _dt.datetime | None = None) -> dict:
    """Full seal at report assembly: write evidence/manifest.json AND populate evidence[].sha256.
    Returns a summary dict. Best-effort appends a 'seal' custody line to runtime/audit.jsonl."""
    eng = Path(engagement_dir).resolve()
    now = now or _now()
    manifest = build_manifest(eng, now=now)
    mpath = write_manifest(eng, manifest)
    pop = populate_finding_hashes(eng, now=now)
    _append_audit(
        eng,
        action="seal",
        target=MANIFEST_REL,
        detail=(f"sealed {manifest['count']} artifact(s); populated {pop['populated']} "
                f"evidence sha256 ({pop['unresolved']} unresolved)"),
        sha256=manifest["time_anchor"]["manifest_digest"],
        now=now,
    )
    return {
        "engagement": eng.name,
        "manifest": _rel(eng, mpath),
        "artifact_count": manifest["count"],
        "manifest_digest": manifest["time_anchor"]["manifest_digest"],
        "repo_commit": manifest["time_anchor"]["repo_commit"],
        "finding_hashes": pop,
    }


def verify_manifest(engagement_dir) -> dict:
    """Recompute every manifest hash and report tamper signals. The lead's gate imports this and
    HARD-FAILS when `ok` is false.

    Returns {ok, manifest_exists, checked, mismatches[], missing[], unsealed[], digest_ok}:
      - mismatches: artifact present but its bytes no longer hash to the sealed value (ALTERED).
      - missing:    artifact listed in the manifest but gone from disk (REMOVED).
      - unsealed:   artifact on disk under evidence/poc but absent from the manifest (ADDED post-seal).
      - digest_ok:  the stored time_anchor.manifest_digest still matches the manifest's artifact list
                    (guards against editing the manifest's own hash entries).
    `ok` is false on ANY mismatch, missing, unsealed artifact, or digest mismatch."""
    eng = Path(engagement_dir).resolve()
    mpath = eng / MANIFEST_REL
    result = {
        "engagement": eng.name, "manifest_exists": mpath.is_file(),
        "checked": 0, "mismatches": [], "missing": [], "unsealed": [], "digest_ok": None, "ok": False,
    }
    if not mpath.is_file():
        result["error"] = "manifest absent — evidence was never sealed"
        return result
    try:
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
    except Exception as e:
        result["error"] = f"manifest unreadable/invalid JSON ({type(e).__name__})"
        return result

    entries = manifest.get("artifacts") or []
    sealed_paths = set()
    for e in entries:
        rel = e.get("path", "")
        sealed_paths.add(rel)
        fp = eng / rel
        result["checked"] += 1
        if not fp.is_file():
            result["missing"].append(rel)
            continue
        try:
            actual = sha256_file(fp)
        except Exception:
            result["mismatches"].append({"path": rel, "expected": e.get("sha256"), "actual": "<unreadable>"})
            continue
        if actual != e.get("sha256"):
            result["mismatches"].append({"path": rel, "expected": e.get("sha256"), "actual": actual})

    # Artifacts now on disk that were not in the manifest = added after sealing.
    for fp in collect_artifacts(eng):
        rel = _rel(eng, fp)
        if rel not in sealed_paths:
            result["unsealed"].append(rel)

    # The time anchor must still bind the recorded artifact list (catch manifest tampering).
    anchor = manifest.get("time_anchor") or {}
    recomputed = build_time_anchor(entries, _now())["manifest_digest"]
    result["digest_ok"] = (anchor.get("manifest_digest") == recomputed)

    result["ok"] = (
        not result["mismatches"] and not result["missing"]
        and not result["unsealed"] and result["digest_ok"] is True
    )
    return result


# --- audit custody line (best-effort, non-fatal) ----------------------------
def _append_audit(engagement_dir, *, action: str, target: str, detail: str,
                  sha256: str | None = None, actor: str = "evidence-seal",
                  now: _dt.datetime | None = None) -> None:
    """Append one chain-of-custody record to runtime/audit.jsonl (schema: audit.schema.json). Never
    raises — a custody-log failure must not break report assembly."""
    try:
        rec = {"ts": _iso(now or _now()), "actor": actor, "action": action,
               "target": target or "", "detail": detail or ""}
        if sha256:
            rec["sha256"] = sha256
        p = Path(engagement_dir) / AUDIT_REL
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")
    except Exception:
        pass


# --- CLI --------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Seal / verify an engagement's evidence vault (chain of custody).")
    ap.add_argument("--engagement", required=True, help="engagement directory")
    ap.add_argument("--verify", action="store_true", help="recompute hashes and report tamper (exit 3 on tamper)")
    ap.add_argument("--json", action="store_true", help="machine-readable summary on stdout")
    args = ap.parse_args(argv)

    eng = Path(args.engagement)
    if not eng.is_dir():
        print(f"error: engagement dir not found: {eng}", file=sys.stderr)
        return 2

    if args.verify:
        res = verify_manifest(eng)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            if not res.get("manifest_exists"):
                print(f"VERIFY FAIL: {res.get('error')}")
            elif res["ok"]:
                print(f"VERIFY OK: {res['checked']} artifact(s) intact; time anchor valid.")
            else:
                print(f"VERIFY FAIL: {len(res['mismatches'])} altered, {len(res['missing'])} missing, "
                      f"{len(res['unsealed'])} unsealed, digest_ok={res['digest_ok']}")
                for m in res["mismatches"]:
                    print(f"  ALTERED  {m['path']}")
                for m in res["missing"]:
                    print(f"  MISSING  {m}")
                for m in res["unsealed"]:
                    print(f"  UNSEALED {m}")
        return 0 if res.get("ok") else 3

    res = seal(eng)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        fh = res["finding_hashes"]
        print(f"sealed {res['artifact_count']} artifact(s) -> {res['manifest']}")
        print(f"digest={res['manifest_digest']}  repo_commit={res['repo_commit']}")
        print(f"evidence sha256: {fh['populated']} populated, {fh['unresolved']} unresolved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
