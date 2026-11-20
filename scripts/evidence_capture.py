#!/usr/bin/env python3
"""evidence_capture.py -- write an independent, custody-stamped evidence artifact.

Executors and skills call this to deposit ONE piece of proof into the engagement's evidence vault
(`evidence/<finding_id>/`) with consistent naming, and get back the `evidence[]` object to embed in the
finding (`{type, ref, sha256}`). Capturing through this helper, rather than hand-writing files, means:
  - every artifact lands in the vault under a predictable path, so evidence_seal.py finds + seals it;
  - the sha256 is computed at capture time (not left 0, the gap the one real engagement exposed);
  - a chain-of-custody line (who captured what, when, with what hash) is appended to runtime/audit.jsonl.

Supported evidence types (mirrors finding.schema's evidence enum, plus code_citation which the schema
agent is adding): request_response / poc_script / screenshot / dom_capture / code_citation.

For `code_citation` the helper captures the VERBATIM source bytes at file:line and records the repo
commit sha (passed in, or auto-detected read-only from the file's git repo), emitting exactly the pinned
shape `{type:"code_citation", file, line, commit, snippet, ref, sha256}` — so a white-box finding
cites immutable source, not a line number that drifts when the tree changes.

Stdlib only. Faithful by design: artifacts are stored as captured (verbatim) — redaction, where
needed, is the caller's responsibility, because the custody value is in preserving the original bytes.

CLI (for shell-based executors):
    python evidence_capture.py --engagement <dir> --finding RS-2026-001 --type request_response --in req.http
    python evidence_capture.py --engagement <dir> --finding RS-2026-001 --type code_citation \
        --path source/src/Foo.php --line 40-52 --repo source
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

AUDIT_REL = "runtime/audit.jsonl"
EVIDENCE_TYPES = ("request_response", "poc_script", "screenshot", "dom_capture", "code_citation")
# default file extension per type for content-based captures (src-file captures keep their own suffix).
_DEFAULT_EXT = {
    "request_response": ".http",
    "poc_script": ".txt",
    "screenshot": ".png",
    "dom_capture": ".html",
    "code_citation": ".txt",
}
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(ts: _dt.datetime) -> str:
    return ts.astimezone(_dt.timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _slug(s: str, maxlen: int = 48) -> str:
    s = _SLUG_RE.sub("-", str(s or "").strip()).strip("-.")
    return (s or "x")[:maxlen]


def _rel(engagement_dir: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(engagement_dir.resolve()).as_posix()
    except Exception:
        return path.resolve().as_posix()


def _evidence_dir(eng: Path, finding_id: str) -> Path:
    d = eng / "evidence" / _slug(finding_id)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _unique_path(directory: Path, base: str, ext: str) -> Path:
    """A non-colliding path `directory/base<ext>` (or base-2, base-3, ...)."""
    cand = directory / f"{base}{ext}"
    n = 2
    while cand.exists():
        cand = directory / f"{base}-{n}{ext}"
        n += 1
    return cand


# --- git commit auto-detect (read-only) -------------------------------------
def detect_commit(path) -> str | None:
    """HEAD commit of the git repo containing `path` (read-only), or None. Never mutates git state."""
    git = shutil.which("git")
    if not git:
        return None
    start = Path(path).resolve()
    repo = start if start.is_dir() else start.parent
    try:
        out = subprocess.run(
            [git, "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        sha = (out.stdout or "").strip()
        return sha or None
    except Exception:
        return None


# --- line-range slicing (verbatim bytes) ------------------------------------
def _parse_line_spec(line) -> tuple[int, int]:
    """'12' -> (12,12); '12-20' -> (12,20); int -> (n,n). 1-based inclusive."""
    if isinstance(line, int):
        return line, line
    s = str(line).strip()
    if "-" in s:
        a, b = s.split("-", 1)
        return int(a), int(b)
    n = int(s)
    return n, n


def _slice_lines(raw: bytes, start: int, end: int) -> bytes:
    """Verbatim bytes of 1-based inclusive line range [start, end], keeping line endings."""
    lines = raw.splitlines(keepends=True)
    lo = max(1, start) - 1
    hi = min(len(lines), max(start, end))
    return b"".join(lines[lo:hi])


# --- capture ----------------------------------------------------------------
def capture(
    engagement_dir,
    finding_id: str,
    etype: str,
    *,
    content: "bytes | str | None" = None,
    src_path=None,
    filename: str | None = None,
    # code_citation:
    path=None,
    line=None,
    commit: str | None = None,
    repo=None,
    # custody:
    actor: str = "evidence-capture",
    audit: bool = True,
    now: _dt.datetime | None = None,
) -> dict:
    """Write one evidence artifact into evidence/<finding_id>/ and return the embeddable evidence object.

    request_response / poc_script / screenshot / dom_capture:
        pass `content` (text/bytes) OR `src_path` (an existing file to copy into the vault). Returns
        {type, ref, sha256}. `filename` overrides the auto name; a src copy keeps the source suffix.

    code_citation:
        pass `path` (source file on disk) + `line` (int or 'a-b'); optionally `commit` (else auto-
        detected from the file's git repo) and `repo` (to record `file` relative to the repo root).
        Returns {type:"code_citation", file, line, commit, snippet, ref, sha256} — the snippet is
        also written to the vault and sealed, so the citation is hash-pinned.
    """
    eng = Path(engagement_dir).resolve()
    now = now or _now()
    if etype not in EVIDENCE_TYPES:
        raise ValueError(f"unknown evidence type {etype!r}; expected one of {EVIDENCE_TYPES}")
    vault = _evidence_dir(eng, finding_id)

    if etype == "code_citation":
        if path is None or line is None:
            raise ValueError("code_citation requires `path` and `line`")
        src = Path(path)
        raw = src.read_bytes()
        start, end = _parse_line_spec(line)
        snippet_bytes = _slice_lines(raw, start, end)
        line_label = f"{start}" if start == end else f"{start}-{end}"
        # the `file` recorded in evidence: relative to repo root if given, else as passed.
        if repo is not None:
            try:
                file_label = Path(path).resolve().relative_to(Path(repo).resolve()).as_posix()
            except Exception:
                file_label = Path(path).as_posix()
        else:
            file_label = Path(path).as_posix()
        if commit is None:
            commit = detect_commit(repo if repo is not None else src) or ""
        base = f"code_citation-{_slug(src.name)}-L{_slug(line_label)}"
        art = _unique_path(vault, base, ".txt")
        art.write_bytes(snippet_bytes)
        digest = sha256_bytes(snippet_bytes)
        ref = _rel(eng, art)
        obj = {
            "type": "code_citation",
            "file": file_label,
            "line": line_label,
            "commit": commit,
            "snippet": snippet_bytes.decode("utf-8", "replace"),
            "ref": ref,
            "sha256": digest,
        }
        if audit:
            _append_audit(eng, actor=actor, action="capture", target=ref,
                          detail=f"code_citation {file_label}:{line_label}@{commit[:12] or 'nocommit'}",
                          sha256=digest, now=now)
        return obj

    # file-backed types
    if content is None and src_path is None:
        raise ValueError(f"{etype} requires `content` or `src_path`")
    if src_path is not None:
        src = Path(src_path)
        data = src.read_bytes()
        ext = src.suffix or _DEFAULT_EXT.get(etype, ".bin")
        base = _slug(filename.rsplit(".", 1)[0]) if filename else f"{etype}-{_slug(src.stem)}"
    else:
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        if filename:
            stem, dot, suf = filename.rpartition(".")
            base = _slug(stem or filename)
            ext = f".{suf}" if dot else _DEFAULT_EXT.get(etype, ".bin")
        else:
            base = f"{etype}-{sha256_bytes(data)[:8]}"
            ext = _DEFAULT_EXT.get(etype, ".bin")
    art = _unique_path(vault, base, ext)
    art.write_bytes(data)
    digest = sha256_bytes(data)
    ref = _rel(eng, art)
    obj = {"type": etype, "ref": ref, "sha256": digest}
    if audit:
        _append_audit(eng, actor=actor, action="capture", target=ref,
                      detail=f"{etype} for {finding_id}", sha256=digest, now=now)
    return obj


# --- audit custody line (best-effort, non-fatal) ----------------------------
def _append_audit(engagement_dir, *, actor: str, action: str, target: str, detail: str,
                  sha256: str | None = None, now: _dt.datetime | None = None) -> None:
    """Append one chain-of-custody record to runtime/audit.jsonl (schema: audit.schema.json). Never
    raises — a custody-log failure must not break the executor capturing evidence."""
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
    ap = argparse.ArgumentParser(description="Capture one custody-stamped evidence artifact into the vault.")
    ap.add_argument("--engagement", required=True)
    ap.add_argument("--finding", required=True, help="finding id, e.g. RS-2026-001 (evidence/<id>/ subdir)")
    ap.add_argument("--type", required=True, choices=EVIDENCE_TYPES, dest="etype")
    ap.add_argument("--in", dest="src", help="existing file to copy into the vault")
    ap.add_argument("--content", help="inline text content (alternative to --in)")
    ap.add_argument("--filename", help="override the stored file name")
    # code_citation
    ap.add_argument("--path", help="code_citation: source file on disk")
    ap.add_argument("--line", help="code_citation: line or range, e.g. 40 or 40-52")
    ap.add_argument("--commit", help="code_citation: repo commit sha (else auto-detected)")
    ap.add_argument("--repo", help="code_citation: repo root (records `file` relative to it)")
    ap.add_argument("--no-audit", action="store_true", help="do not append a custody line")
    args = ap.parse_args(argv)

    eng = Path(args.engagement)
    if not eng.is_dir():
        print(f"error: engagement dir not found: {eng}", file=sys.stderr)
        return 2
    try:
        obj = capture(
            eng, args.finding, args.etype,
            content=args.content, src_path=args.src, filename=args.filename,
            path=args.path, line=args.line, commit=args.commit, repo=args.repo,
            audit=not args.no_audit,
        )
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(obj, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
