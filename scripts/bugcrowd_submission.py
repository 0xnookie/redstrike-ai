#!/usr/bin/env python3
"""bugcrowd_submission.py -- the bug-bounty submission generator (roadmap L-D).

For a PROGRAM-flagged engagement (scope.yaml `program.platform` = bugcrowd | hackerone) this reads the
reporting skill's `report/findings_consolidated.json` and, for each ACCEPTED, in-scope, non-duplicate
finding, emits a form-structured, paste-ready submission at `<eng>/submissions/<finding-id>.md` carrying
the platform's form fields (Summary/Title - Target - Technical severity - Vulnerability details:
description, steps to reproduce, PoC/evidence refs, impact, remediation).

Why this exists (the incident it prevents): on a live engagement the operator had to ASK for a Bugcrowd
submission, and the hand-written one shipped a FABRICATED VRT category (a category that does not exist in
the taxonomy). This generator STAMPS the VRT from the pinned taxonomy and VALIDATES it BEFORE writing:

  * if a finding already carries a `vrt{}` block (finding.schema.json), THAT block is validated;
  * otherwise the VRT is resolved from the finding's CWE/category;
  * the resolved/authored VRT is checked with the vrt core's path-existence (anti-FABRICATION) and
    elevation (anti-INFLATION) guards. If it FAILS, the submission is REFUSED and a clear error naming the
    finding is emitted -- so a fabricated/invalid VRT is STRUCTURALLY IMPOSSIBLE to emit.

Platform-aware headline:
  * bugcrowd  -> the VRT path + priority IS the technical-severity headline (a finding that can't carry a
                 valid VRT is refused -- bugcrowd needs the VRT bucket);
  * hackerone -> CWE + CVSS is the headline; a VRT is OPTIONAL supplementary context (an unresolvable VRT
                 is simply omitted, but an AUTHORED-and-invalid vrt{} block is still refused, loudly).

Secrets are redacted and evidence is referenced BY PATH (vault ref + sha256 fingerprint), never inlined
raw. Idempotent: a re-run overwrites each submission cleanly (atomic write). STDLIB ONLY.

The VRT core (scripts/vrt.py) is built in parallel; this module imports it defensively so it (and its
tests) never hard-crash before integration -- see `_require_vrt`.

CLI:
    python scripts/bugcrowd_submission.py --engagement engagements/<dir>
    python scripts/bugcrowd_submission.py --selftest

Exit codes: 0 = ran clean (incl. a no-op non-program engagement); 3 = at least one finding was REFUSED
(invalid/fabricated VRT -- the valid ones are still written; a loud attention signal); 2 = usage / the
vrt core has not landed yet / inputs missing.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve()
SCRIPTS = HERE.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

# --- shared helpers (reuse, don't duplicate) --------------------------------------------------------
# atomic_write: the one shared atomic file-write helper (same resolution as dedup.py / export_formats.py).
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover - only under path-based loading without scripts/ on sys.path
    import importlib.util as _ilu
    _aspec = _ilu.spec_from_file_location("atomicio", str(SCRIPTS / "atomicio.py"))
    _amod = _ilu.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write

# --- the vrt core (scripts/vrt.py) -- built IN PARALLEL; import defensively --------------------------
# Interface this module codes against (resolve on finding.cwe/category, then validate):
#   vrt.resolve_finding_vrt(cwe=None, category=None) -> {"path","id","priority","baseline"} | None
#   vrt.path_exists(path_or_id) -> bool
#   vrt.elevation_errors(path, priority, basis, rationale) -> list[str]   ([] == ok)
try:  # pragma: no cover - trivial import guard
    import vrt as vrt_core  # type: ignore
except ImportError:  # pragma: no cover
    vrt_core = None

_VRT_NOT_LANDED = (
    "scripts/vrt.py (the VRT core) is not importable yet -- this generator validates every submission's "
    "VRT against the pinned taxonomy before writing. Run after the vrt core lands (it exposes "
    "resolve_finding_vrt / path_exists / elevation_errors)."
)


def _require_vrt():
    """Return the vrt core or raise a clear, actionable error if it hasn't landed yet."""
    if vrt_core is None:
        raise RuntimeError(_VRT_NOT_LANDED)
    return vrt_core


PROGRAM_PLATFORMS = ("bugcrowd", "hackerone")


# ====================================================================================================
# scope.yaml (stdlib-only reader -- no hard PyYAML dependency)
# ====================================================================================================
def _strip_inline_comment(s: str) -> str:
    """Drop a trailing YAML `#` comment without breaking a quoted value that contains '#'."""
    q = None
    for i, ch in enumerate(s):
        if q:
            if ch == q:
                q = None
        elif ch in ("'", '"'):
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i]
    return s


def _minimal_scope_read(text: str) -> dict:
    """Dependency-free scope.yaml parse: top-level `key: value` scalars + one level of nested maps/lists
    under them -- enough for engagement / program{} / in_scope{} / out_of_scope{}. Mirrors the console's
    fallback reader so the two agree on the simple template shape."""
    doc: dict = {}
    section = None
    list_key = None
    for raw in text.splitlines():
        line = _strip_inline_comment(raw).rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        if s.startswith("- "):
            if section is not None and list_key is not None:
                section.setdefault(list_key, []).append(s[2:].strip().strip("\"'"))
            continue
        if ":" not in s:
            continue
        key, _, val = s.partition(":")
        key, val = key.strip(), val.strip().strip("\"'")
        if indent == 0:
            list_key = None
            if val in ("", ">", "|"):
                section = {}
                doc[key] = section
            else:
                section = None
                doc[key] = val
        elif section is not None:
            if val in ("", ">", "|"):
                list_key = key
                section.setdefault(key, [])
            elif val == "[]":
                list_key = None
                section[key] = []
            elif val == "{}":
                list_key = None
                section[key] = {}
            else:
                list_key = None
                section[key] = val
    return doc


def load_scope(scope_path) -> dict:
    """Parse a scope.yaml into a dict (PyYAML if present, else the stdlib fallback). {} if missing."""
    p = Path(scope_path)
    if not p.is_file():
        return {}
    text = p.read_text(encoding="utf-8")
    try:  # PyYAML when available -- richer, but never required
        import yaml  # type: ignore
        doc = yaml.safe_load(text) or {}
        return doc if isinstance(doc, dict) else {}
    except Exception:
        return _minimal_scope_read(text)


def program_of(scope: dict) -> dict:
    """The scope.yaml `program` block (platform/name/url/taxonomy), or {} for an ordinary pentest."""
    prog = (scope or {}).get("program")
    return prog if isinstance(prog, dict) else {}


def platform_of(program: dict) -> str:
    """Normalized platform string ('' when none/absent -> not a program engagement)."""
    plat = str((program or {}).get("platform", "none") or "none").strip().lower()
    return plat if plat in PROGRAM_PLATFORMS else ""


# ====================================================================================================
# in-scope matching (defensive -- findings_consolidated is already scope-filtered upstream)
# ====================================================================================================
def _host_of(asset: str) -> str:
    """Host of a URL/asset string, lowercased, port stripped. A bare host passes through."""
    s = str(asset or "").strip()
    if not s:
        return ""
    if "://" not in s:
        s = "//" + s  # let urlsplit treat a bare host:port/path as netloc
    netloc = urlsplit(s).netloc or urlsplit("//" + str(asset)).netloc
    host = netloc.split("@")[-1].split(":")[0].strip().lower()
    return host.rstrip(".")


def _domain_match(host: str, pattern: str) -> bool:
    """host vs an in/out-of-scope domain pattern: exact, suffix, or a leading `*.` wildcard."""
    host = host.lower().rstrip(".")
    pat = str(pattern or "").strip().lower().rstrip(".")
    if not host or not pat:
        return False
    if pat.startswith("*."):
        base = pat[2:]
        return host == base or host.endswith("." + base)
    return host == pat or host.endswith("." + pat)


def _scope_hosts(block: dict) -> list:
    """Domain patterns from a scope block: its `domains`, plus the hosts of any `urls`."""
    out = list((block or {}).get("domains") or [])
    for u in (block or {}).get("urls") or []:
        h = _host_of(u)
        if h:
            out.append(h)
    return out


def asset_in_scope(asset: str, scope: dict) -> bool:
    """Defensive in-scope check: out_of_scope wins; an in_scope match (domain/url, wildcard-aware) passes.
    When scope carries NO in_scope entries we can't decide -> include (don't over-drop; the upstream
    reporting/verify gate already dropped out-of-scope findings)."""
    host = _host_of(asset)
    if not host:
        return True
    out_block = (scope or {}).get("out_of_scope") or {}
    for pat in _scope_hosts(out_block):
        if _domain_match(host, pat):
            return False
    in_block = (scope or {}).get("in_scope") or {}
    in_hosts = _scope_hosts(in_block)
    if not in_hosts:
        return True
    return any(_domain_match(host, pat) for pat in in_hosts)


# ====================================================================================================
# reportable filter (accepted/blocked, non-duplicate, non-composite) -- mirrors reporting + export
# ====================================================================================================
_REPORTABLE_VERDICTS = {"accepted", "blocked"}


def extract_findings(data) -> list:
    """The findings list from either consolidated shape: a bare array or a {findings:[...]} report object."""
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("findings") or []
    else:
        items = []
    return [f for f in items if isinstance(f, dict)]


def is_reportable(finding: dict) -> bool:
    """accepted/blocked (or already `verified`), NOT a merged duplicate, NOT a non-additive composite
    kill-chain (same rule the reporting + export_formats filters use)."""
    if finding.get("composite"):
        return False
    status = str(finding.get("status", "")).lower()
    if status == "duplicate":
        return False
    verdict = str(((finding.get("review") or {}).get("verdict")) or "").lower()
    if verdict:
        return verdict in _REPORTABLE_VERDICTS
    return status == "verified"


# ====================================================================================================
# secret redaction (defense-in-depth; the primary guarantee is evidence-by-path)
# ====================================================================================================
# `Bearer <token>` / an Authorization value -> mask the credential, keep the label.
_BEARER_RE = re.compile(r"(?i)\b(bearer|authorization\s*[:=]?)\s+([A-Za-z0-9._~+/\-]{8,}=*)")
# key = value / key: value for the common credential labels -> mask the value only.
_KV_SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|apikey|x-api-key|access[_-]?token|refresh[_-]?token|client[_-]?secret|"
    r"session[_-]?token|auth[_-]?token|token|secret|password|passwd|pwd)"
    r"(\s*[:=]\s*)([\"']?)([^\s\"']{4,})"
)


def redact(text: str) -> str:
    """Mask obvious inline secrets in free text. Conservative: only masks credential-labelled values and
    Bearer tokens, so ordinary prose/payloads survive. Evidence is still referenced by path, never raw."""
    if not text:
        return text or ""
    s = _BEARER_RE.sub(lambda m: f"{m.group(1)} <redacted>", str(text))
    s = _KV_SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}<redacted>", s)
    return s


# ====================================================================================================
# VRT stamping + validation (the anti-fabrication / anti-inflation core)
# ====================================================================================================
def _p_str(priority) -> str:
    """Normalize a priority to 'P1'..'P5', or '' for None/'varies'/unknown."""
    if priority is None:
        return ""
    if isinstance(priority, bool):
        return ""
    if isinstance(priority, int):
        return f"P{priority}" if 1 <= priority <= 5 else ""
    s = str(priority).strip()
    if not s or s.lower() == "varies":
        return ""
    m = re.match(r"^[Pp]?([1-5])$", s)
    return f"P{m.group(1)}" if m else ""


def _category_hint(finding: dict):
    """Best-effort vuln-class hint for the VRT resolver's `category` arg: the reviewer class
    (e.g. 'idor-verify' -> 'idor'), else an OWASP/WSTG id. The CWE is the primary key; this is the
    fallback the resolver may use when the CWE doesn't map. (INTEGRATOR: confirm the resolver keys
    `category` on this class-name form; the CWE path is the load-bearing one.)"""
    rev = str(((finding.get("review") or {}).get("reviewer")) or "").strip().lower()
    if rev.endswith("-verify"):
        rev = rev[: -len("-verify")]
    if rev:
        return rev
    cat = finding.get("category") or {}
    return (cat.get("owasp") or cat.get("wstg") or None)


class _Refused(Exception):
    """A VRT that cannot be emitted (fabricated path / inflated priority / unresolvable on bugcrowd)."""


def resolve_submission_vrt(finding: dict, platform: str, vrt=None):
    """Return a normalized vrt_info dict to stamp, or None when no VRT is carried (allowed on hackerone).

    Raises `_Refused(reason)` when a VRT is present/required but invalid -- the caller turns that into a
    named, written-nothing refusal so a fabricated/inflated VRT is structurally impossible to emit.

    vrt_info = {path, id, priority(Pn|''), baseline(int|None), basis, rationale, source}
    """
    vrt = vrt or _require_vrt()

    # (1) An AUTHORED vrt{} block on the finding -> validate THAT (any platform; invalid -> refuse loudly).
    block = finding.get("vrt")
    if isinstance(block, dict) and (block.get("path") or block.get("id")):
        ref = str(block.get("path") or block.get("id"))
        if not vrt.path_exists(ref):
            raise _Refused(
                f"authored vrt {ref!r} does NOT resolve in the pinned taxonomy (fabricated VRT category)")
        errs = vrt.elevation_errors(
            block.get("path") or block.get("id"),
            block.get("priority"),
            block.get("priority_basis", "baseline"),
            block.get("priority_rationale", ""),
        )
        if errs:
            raise _Refused("authored vrt failed validation -- " + "; ".join(errs))
        return {
            "path": block.get("path") or ref,
            "id": block.get("id"),
            "priority": _p_str(block.get("priority")),
            "baseline": None,
            "basis": block.get("priority_basis", "baseline"),
            "rationale": str(block.get("priority_rationale") or ""),
            "source": "authored",
        }

    # (2) No authored block -> RESOLVE from the finding's CWE/category.
    cwe = str((finding.get("category") or {}).get("cwe") or "").strip() or None
    hint = _category_hint(finding)
    resolved = vrt.resolve_finding_vrt(cwe=cwe, category=hint)
    if not isinstance(resolved, dict) or not (resolved.get("path") or resolved.get("id")):
        if platform == "bugcrowd":
            raise _Refused(
                f"no VRT resolves from cwe={cwe!r} / category={hint!r} -- bugcrowd requires a VRT "
                f"technical-severity bucket; add a finding.vrt{{}} block or a mappable category.cwe")
        return None  # hackerone: VRT is optional -> omit it, headline is CWE/CVSS

    ref = str(resolved.get("path") or resolved.get("id"))
    if not vrt.path_exists(ref):
        if platform == "bugcrowd":
            raise _Refused(f"resolved VRT {ref!r} failed the taxonomy existence check")
        return None
    errs = vrt.elevation_errors(ref, resolved.get("priority"), "baseline", "")
    if errs:
        if platform == "bugcrowd":
            raise _Refused("resolved VRT failed validation -- " + "; ".join(errs))
        return None
    base = resolved.get("baseline")
    return {
        "path": resolved.get("path") or ref,
        "id": resolved.get("id"),
        "priority": _p_str(resolved.get("priority")) or _p_str(base),
        "baseline": base if isinstance(base, int) else None,
        "source": "resolved",
        "basis": "baseline",
        "rationale": "",
    }


# ====================================================================================================
# rendering
# ====================================================================================================
def _fenced_steps(steps) -> str:
    lines = []
    for i, step in enumerate(steps or [], 1):
        lines.append(f"{i}. {redact(str(step)).strip()}")
    return "\n".join(lines) if lines else "_No reproduction steps recorded on the finding._"


def _evidence_block(evidence) -> str:
    """Reference each evidence artifact BY PATH (+ sha256 fingerprint); never inline a raw vault artifact.
    A white-box `code_citation` keeps its file:line and a redacted snippet (the citation IS the proof)."""
    rows = []
    for ev in evidence or []:
        if not isinstance(ev, dict):
            continue
        etype = str(ev.get("type") or "artifact")
        if etype == "code_citation":
            loc = f"{ev.get('file', '?')}:{ev.get('line', '?')}"
            commit = f" @ {ev.get('commit')}" if ev.get("commit") else ""
            snip = redact(str(ev.get("snippet") or "")).rstrip()
            rows.append(f"- `code_citation` {loc}{commit}\n\n  ```\n  "
                        + "\n  ".join(snip.splitlines()) + "\n  ```")
        else:
            ref = str(ev.get("ref") or "(no ref)")
            sha = ev.get("sha256")
            fp = f" (sha256 `{str(sha)[:12]}...`)" if sha else ""
            rows.append(f"- `{etype}` -> `{ref}`{fp}")
    return "\n".join(rows) if rows else "_No evidence artifacts referenced._"


def _severity_headline(finding: dict, platform: str, vrt_info) -> str:
    """The platform's technical-severity headline line."""
    sev = str(finding.get("severity", "info")).lower()
    cvss = str(finding.get("cvss_vector") or "").strip()
    cwe = str((finding.get("category") or {}).get("cwe") or "").strip()
    if platform == "bugcrowd":
        # VRT path + priority IS the headline (vrt_info is guaranteed present for bugcrowd).
        prio = vrt_info.get("priority") or "per taxonomy baseline"
        line = f"**VRT:** `{vrt_info['path']}` - **{prio}**"
        if vrt_info.get("basis") and vrt_info["basis"] != "baseline":
            line += f" ({vrt_info['basis']}: {redact(vrt_info.get('rationale', '')).strip()})"
        extra = f"  \nDemonstrated severity: **{sev}**"
        if cvss:
            extra += f" - CVSS `{cvss}`"
        return line + extra
    # hackerone: CWE + CVSS is the headline; VRT (if resolved) is supplementary.
    head = f"**Weakness:** {cwe or 'n/a'} - **Severity:** {sev}"
    if cvss:
        head += f"  \n**CVSS:** `{cvss}`"
    if vrt_info and vrt_info.get("path"):
        prio = vrt_info.get("priority") or "baseline"
        head += f"  \n_VRT (supplementary):_ `{vrt_info['path']}` - {prio}"
    return head


def render_submission(finding: dict, program: dict, platform: str, vrt_info) -> str:
    """Render one form-structured, paste-ready submission markdown for the given platform."""
    fid = str(finding.get("id") or "RS-UNKNOWN")
    title = redact(str(finding.get("title") or "(untitled finding)")).strip()
    asset = str(finding.get("asset") or "").strip()
    handle = str((program or {}).get("name") or "").strip()
    url = str((program or {}).get("url") or "").strip()
    platform_label = {"bugcrowd": "Bugcrowd", "hackerone": "HackerOne"}.get(platform, platform)

    prog_line = f"{platform_label}"
    if handle:
        prog_line += f" - program `{handle}`"
    if url:
        prog_line += f" - {url}"

    out = []
    out.append(f"# {title}")
    out.append("")
    out.append(f"> Paste-ready {platform_label} submission for `{fid}`. Generated from "
               f"`report/findings_consolidated.json`; a human reviews + sends it.")
    out.append("")
    out.append("## Submission form")
    out.append("")
    out.append(f"- **Program:** {prog_line}")
    out.append(f"- **Title / Summary:** {title}")
    out.append(f"- **Target / Asset:** `{asset}`" if asset else "- **Target / Asset:** _(not recorded)_")
    out.append(f"- **Technical severity:** {_severity_headline(finding, platform, vrt_info)}")
    out.append("")
    out.append("## Vulnerability details")
    out.append("")
    out.append("### Description")
    impact = redact(str(finding.get("impact") or "")).strip()
    out.append(impact if impact else "_No impact/description text on the finding._")
    out.append("")
    out.append("### Steps to reproduce")
    out.append(_fenced_steps(finding.get("reproduction")))
    out.append("")
    out.append("### Proof / evidence")
    out.append("_Evidence is referenced from the sealed engagement vault; secrets appear only as "
               "redacted fingerprints._")
    out.append("")
    out.append(_evidence_block(finding.get("evidence")))
    out.append("")
    out.append("### Impact")
    out.append(impact if impact else "_See description._")
    out.append("")
    out.append("### Remediation")
    rem = redact(str(finding.get("remediation") or "")).strip()
    out.append(rem if rem else "_No remediation recorded._")
    out.append("")
    refs = [str(r) for r in (finding.get("references") or []) if str(r).strip()]
    if refs:
        out.append("### References")
        out.extend(f"- {r}" for r in refs)
        out.append("")
    if str(finding.get("status", "")).lower() == "verified" and \
            str(((finding.get("review") or {}).get("verdict")) or "").lower() == "blocked":
        pot = str(finding.get("potential_severity") or "").strip()
        out.append("> **Confirmed - demonstration limited:** full impact was blocked by target/"
                   "environment state." + (f" Potential severity: **{pot}**." if pot else ""))
        out.append("")
    out.append("---")
    out.append(f"_Finding `{fid}` - submission draft. Confirm scope + non-duplicate + severity before "
               f"sending._")
    return "\n".join(out).rstrip() + "\n"


# ====================================================================================================
# orchestration
# ====================================================================================================
def _load_findings(findings_path) -> list:
    import json
    p = Path(findings_path)
    if not p.is_file():
        return []
    return extract_findings(json.loads(p.read_text(encoding="utf-8")))


def generate(engagement_dir=None, *, findings_path=None, scope_path=None, out_dir=None, vrt=None) -> dict:
    """Emit the submissions/ set for a program-flagged engagement.

    Returns a result dict:
        {platform, program, written:[{id,path}], refused:[{id,reason}], skipped_scope:[id],
         skipped_total:int, is_program:bool}
    No-op (is_program False, nothing written) for a non-program engagement.
    """
    eng = Path(engagement_dir) if engagement_dir else None
    scope_p = Path(scope_path) if scope_path else (eng / "scope.yaml" if eng else None)
    findings_p = Path(findings_path) if findings_path else (
        eng / "report" / "findings_consolidated.json" if eng else None)
    submissions_dir = Path(out_dir) if out_dir else (eng / "submissions" if eng else None)

    scope = load_scope(scope_p) if scope_p else {}
    program = program_of(scope)
    platform = platform_of(program)
    result = {"platform": platform, "program": program, "written": [], "refused": [],
              "skipped_scope": [], "skipped_total": 0, "is_program": bool(platform)}
    if not platform:
        return result  # ordinary pentest -> no-op, byte-identical to before

    vrt = vrt or _require_vrt()
    findings = _load_findings(findings_p) if findings_p else []
    reportable = [f for f in findings if is_reportable(f)]
    result["skipped_total"] = len(findings) - len(reportable)

    for finding in reportable:
        fid = str(finding.get("id") or "RS-UNKNOWN")
        if not asset_in_scope(finding.get("asset", ""), scope):
            result["skipped_scope"].append(fid)
            continue
        try:
            vrt_info = resolve_submission_vrt(finding, platform, vrt=vrt)
        except _Refused as r:
            result["refused"].append({"id": fid, "reason": str(r)})
            continue
        md = render_submission(finding, program, platform, vrt_info)
        target = submissions_dir / f"{fid}.md"
        atomic_write(target, md)
        result["written"].append({"id": fid, "path": str(target),
                                  "vrt": (vrt_info or {}).get("path")})
    return result


def _print_report(result: dict, quiet: bool = False) -> None:
    if not result["is_program"]:
        if not quiet:
            print("bugcrowd_submission: not a program engagement (scope.yaml program.platform is "
                  "none/absent) -- no submissions emitted.")
        return
    plat = result["platform"]
    for w in result["written"]:
        if not quiet:
            print(f"  WROTE  {w['id']} -> {w['path']}"
                  + (f"  [VRT {w['vrt']}]" if w.get("vrt") else ""))
    for s in result["skipped_scope"]:
        if not quiet:
            print(f"  SKIP   {s} -- asset out of program scope")
    for r in result["refused"]:
        print(f"  REFUSED {r['id']} -- {r['reason']}", file=sys.stderr)
    if not quiet:
        print(f"bugcrowd_submission[{plat}]: {len(result['written'])} written, "
              f"{len(result['refused'])} refused, {len(result['skipped_scope'])} out-of-scope.")


# ====================================================================================================
# selftest (deterministic, no cross-dependency -- uses an in-process fake vrt core)
# ====================================================================================================
class _FakeVrt:
    """A minimal stand-in for scripts/vrt.py used by --selftest (the unit tests monkeypatch their own)."""
    _REAL = {
        "server_side_injection > content_spoofing > text_injection",
        "cross_site_scripting > stored",
        "stored",
        "text_injection",
    }
    _BY_CWE = {
        "CWE-79": {"path": "cross_site_scripting > stored", "id": "stored", "priority": "P2", "baseline": 2},
    }

    def resolve_finding_vrt(self, cwe=None, category=None):
        return self._BY_CWE.get(str(cwe or "").upper())

    def path_exists(self, ref):
        return str(ref).strip().lower() in {p.lower() for p in self._REAL}

    def elevation_errors(self, path, priority, basis, rationale):
        base = {"server_side_injection > content_spoofing > text_injection": 5}.get(
            str(path).strip().lower())
        pr = _p_str(priority)
        claimed = int(pr[1:]) if pr else None
        if claimed is not None and base is not None and claimed < base:
            if basis != "argued-elevation":
                return [f"priority {pr} stronger than baseline P{base} without argued-elevation"]
            if not str(rationale or "").strip():
                return ["argued-elevation requires a priority_rationale"]
        return []


def selftest() -> int:
    import json
    import tempfile
    fake = _FakeVrt()
    fails = []

    def check(name, cond):
        if not cond:
            fails.append(name)

    # redaction
    check("redact-bearer", "<redacted>" in redact("Authorization: Bearer abcdefgh12345678"))
    check("redact-kv", redact("api_key=SECRETVALUE1234").endswith("<redacted>"))
    check("redact-prose", "token in the url" in redact("token in the url").lower())

    # scope matching
    sc = {"in_scope": {"domains": ["*.example.com"]}, "out_of_scope": {"domains": ["admin.example.com"]}}
    check("scope-in", asset_in_scope("https://app.example.com/x", sc))
    check("scope-out", not asset_in_scope("https://admin.example.com/x", sc))
    check("scope-nomatch", not asset_in_scope("https://evil.test/x", sc))

    base_find = {"id": "RS-2026-001", "title": "Stored XSS", "asset": "https://app.example.com/p",
                 "category": {"cwe": "CWE-79"}, "severity": "high", "status": "verified",
                 "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                 "impact": "runs in victim session", "remediation": "encode output",
                 "evidence": [{"type": "request_response", "ref": "poc/x.http", "sha256": "a" * 64}],
                 "reproduction": ["GET /p", "observe alert"],
                 "review": {"verdict": "accepted", "reviewer": "xss-stored-verify"}}

    with tempfile.TemporaryDirectory() as td:
        eng = Path(td) / "eng"
        (eng / "report").mkdir(parents=True)
        (eng / "scope.yaml").write_text(
            "engagement: t\nprogram:\n  platform: bugcrowd\n  name: acme\n  taxonomy: vrt\n"
            "in_scope:\n  domains:\n    - '*.example.com'\n", encoding="utf-8")
        bad = dict(base_find, id="RS-2026-002",
                   vrt={"path": "Totally Made Up > Nope", "priority": "P1"})
        (eng / "report" / "findings_consolidated.json").write_text(
            json.dumps([base_find, bad]), encoding="utf-8")
        res = generate(eng, vrt=fake)
        check("program-detected", res["platform"] == "bugcrowd")
        check("one-written", [w["id"] for w in res["written"]] == ["RS-2026-001"])
        check("one-refused", [r["id"] for r in res["refused"]] == ["RS-2026-002"])
        check("file-exists", (eng / "submissions" / "RS-2026-001.md").is_file())
        check("no-bad-file", not (eng / "submissions" / "RS-2026-002.md").is_file())
        md = (eng / "submissions" / "RS-2026-001.md").read_text(encoding="utf-8")
        check("bugcrowd-vrt-headline", "VRT:" in md and "cross_site_scripting > stored" in md)

    # non-program -> no-op
    with tempfile.TemporaryDirectory() as td:
        eng = Path(td) / "eng"
        (eng / "report").mkdir(parents=True)
        (eng / "scope.yaml").write_text("engagement: t\nprogram:\n  platform: none\n", encoding="utf-8")
        (eng / "report" / "findings_consolidated.json").write_text(json.dumps([base_find]), "utf-8")
        res = generate(eng, vrt=fake)
        check("nonprogram-noop", not res["is_program"] and res["written"] == [])
        check("nonprogram-nodir", not (eng / "submissions").exists())

    if fails:
        print("SELFTEST FAILURES: " + ", ".join(fails), file=sys.stderr)
        return 1
    print("bugcrowd_submission selftest: OK")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Emit paste-ready bug-bounty submissions (VRT-validated).")
    ap.add_argument("--engagement", help="engagement dir (reads report/findings_consolidated.json + scope.yaml)")
    ap.add_argument("--findings", help="override path to findings_consolidated.json")
    ap.add_argument("--scope", help="override path to scope.yaml")
    ap.add_argument("--out-dir", help="override the submissions/ output dir")
    ap.add_argument("--quiet", action="store_true", help="only print refusals (to stderr)")
    ap.add_argument("--selftest", action="store_true", help="run the deterministic in-process self-test")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()
    if not (args.engagement or args.findings or args.scope):
        ap.error("choose --engagement <dir> (or --findings/--scope for an explicit run, or --selftest)")

    try:
        result = generate(args.engagement, findings_path=args.findings, scope_path=args.scope,
                          out_dir=args.out_dir)
    except RuntimeError as e:  # vrt core not landed yet
        print(f"bugcrowd_submission: {e}", file=sys.stderr)
        return 2
    _print_report(result, quiet=args.quiet)
    return 3 if result["refused"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
