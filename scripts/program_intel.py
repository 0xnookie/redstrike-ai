#!/usr/bin/env python3
"""program_intel.py -- OFFLINE, READ-ONLY bug-bounty program-intel feeder.

WHY THIS EXISTS
  Redstrike's bug-bounty mission (skills/bug-bounty) currently HAND-PARSES a program's
  scope + rules into scope.yaml and de-dupes submissions against nothing structured. This
  module is the missing feeder: given a platform + a program handle it pulls the program's
  SCOPE (in/out-of-scope assets), its POLICY (bounty/rules), and its disclosed-report
  HISTORY, and emits three artifacts into the engagement dir:

    <eng>/program_scope.json   structured scope + policy (the canonical intel record)
    <eng>/scope.yaml           MERGED in/out-of-scope targets (operator-owned keys kept)
    <eng>/hacktivity.md        a duplicate-reference list of disclosed reports

WHERE IT RUNS (and why that preserves --strict-mcp-config)
  Fetching from a live platform is an OUTWARD-FACING OPERATOR ACTION, run at SCOPE-SETUP
  time, OUTSIDE the autonomous engine — exactly like the operator typing a target URL. The
  engine itself is launched with `--strict-mcp-config` (MCP isolation): it never reaches out
  to a bug-bounty platform. By doing the (networked) intel pull here, as a plain operator
  script, the engine's MCP isolation is fully preserved — the engine only ever reads the
  already-written local artifacts, never the network. The autonomous engine does NOT invoke
  this module; a human does, before the hunt.

SAFETY INVARIANTS
  * READ-ONLY. This feeder NEVER submits a report. There is NO auto-submission path here.
  * FAIL-CLOSED. A failed or empty scope fetch writes a `scope_mode: "placeholder"` SENTINEL,
    never a clean-looking empty scope. A downstream scope check must REFUSE a placeholder
    rather than read an empty `out_of_scope` as "nothing is excluded" (the dangerous reading
    for a bounty program that *does* have exclusions). `is_usable_scope()` encodes that.
  * The scope.yaml merge NEVER overwrites operator-owned keys (authorized_by, window, rules,
    notes, source): it surgically unions only the in/out-of-scope target LISTS into the
    existing file, leaving every other byte intact.
  * Stdlib only (urllib for the operator-run fetch). Provider HTTP is injectable, so TESTS
    MOCK every response and make NO live network call.

The provider seam (`Provider` ABC + one concrete `GenericJsonProvider`) proves the shape;
named platforms (HackerOne / Bugcrowd / Intigriti) are documented stubs — a platform name is
the operator's engagement surface, like a target URL, so naming it is fine.

CLI:  python scripts/program_intel.py <platform> <handle> --engagement <dir> [--scope-url ...]
Selftest:  python scripts/program_intel.py --selftest
"""
from __future__ import annotations

import abc
import argparse
import datetime as _dt
import ipaddress
import json
import re
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional

# atomic_write: shared ledger-write helper. scripts/ is on sys.path for a direct run; fall back
# to a path-load when a test loads this module by path without scripts/ on sys.path.
try:
    from atomicio import atomic_write
except ImportError:  # pragma: no cover - only hit under path-based loading
    import importlib.util as _ilu
    _aspec = _ilu.spec_from_file_location("atomicio", str(Path(__file__).resolve().parent / "atomicio.py"))
    _amod = _ilu.module_from_spec(_aspec)
    _aspec.loader.exec_module(_amod)
    atomic_write = _amod.atomic_write  # type: ignore

SCOPE_MODE_FETCHED = "fetched"
SCOPE_MODE_PLACEHOLDER = "placeholder"

# A generic, platform-neutral User-Agent for the operator-run fetch. We never put the
# operator's name/email/project in an outbound request (privacy rule).
_USER_AGENT = "redstrike-program-intel/1 (offline scope feeder)"
_HTTP_TIMEOUT = 20

# asset_type -> scope.yaml bucket. Unknown types fall back to an identifier sniff.
_BUCKET_BY_ASSET = {
    "url": "urls", "api": "urls", "endpoint": "urls",
    "domain": "domains", "wildcard": "domains", "website": "domains", "web": "domains",
    "cidr": "cidrs", "ip_range": "cidrs", "ip": "cidrs", "ip_address": "cidrs",
}


# --------------------------------------------------------------------------- data model
def _bucket_for(identifier: str, asset_type: Optional[str]) -> str:
    """Classify a scope target into a scope.yaml bucket (domains/urls/cidrs)."""
    at = (asset_type or "").strip().lower()
    if at in _BUCKET_BY_ASSET:
        return _BUCKET_BY_ASSET[at]
    s = (identifier or "").strip()
    if s.startswith(("http://", "https://")):
        return "urls"
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False)
            return "cidrs"
        except ValueError:
            pass
    return "domains"


@dataclass
class ScopeTarget:
    """One in/out-of-scope asset. `bucket` is derived from asset_type/identifier if omitted."""
    identifier: str
    asset_type: str = ""
    bucket: str = ""
    eligible_for_submission: bool = True
    eligible_for_bounty: bool = True
    instruction: str = ""

    def __post_init__(self) -> None:
        if not self.bucket:
            self.bucket = _bucket_for(self.identifier, self.asset_type)

    def to_dict(self) -> dict:
        return {
            "identifier": self.identifier,
            "asset_type": self.asset_type,
            "bucket": self.bucket,
            "eligible_for_submission": self.eligible_for_submission,
            "eligible_for_bounty": self.eligible_for_bounty,
            "instruction": self.instruction,
        }


@dataclass
class ProgramScope:
    """A program's in/out-of-scope asset lists + the fail-closed scope_mode sentinel."""
    platform: str
    handle: str
    name: str = ""
    in_scope: List[ScopeTarget] = field(default_factory=list)
    out_of_scope: List[ScopeTarget] = field(default_factory=list)
    scope_mode: str = SCOPE_MODE_FETCHED
    placeholder_reason: str = ""

    @property
    def is_placeholder(self) -> bool:
        return self.scope_mode == SCOPE_MODE_PLACEHOLDER

    @classmethod
    def placeholder(cls, platform: str, handle: str, reason: str) -> "ProgramScope":
        """A fail-closed sentinel: fetch failed/empty, so NOTHING is authoritative here."""
        return cls(platform=platform, handle=handle, scope_mode=SCOPE_MODE_PLACEHOLDER,
                   placeholder_reason=reason or "scope fetch failed or returned empty")

    def buckets(self, targets: List[ScopeTarget]) -> dict:
        """Collapse a target list into {domains, cidrs, urls} de-duplicated identifier lists."""
        out = {"domains": [], "cidrs": [], "urls": []}
        for t in targets:
            out.setdefault(t.bucket, out["domains"]).append(t.identifier)
        return {k: _dedup(v) for k, v in out.items()}

    def to_dict(self, policy: Optional["ProgramPolicy"] = None, hacktivity_count: int = 0) -> dict:
        return {
            "version": 1,
            "platform": self.platform,
            "handle": self.handle,
            "name": self.name,
            "scope_mode": self.scope_mode,
            "placeholder_reason": self.placeholder_reason or None,
            "generated_at": _now_iso(),
            "source": "program-intel feeder (offline, operator-run; engine never fetches)",
            "in_scope": [t.to_dict() for t in self.in_scope],
            "out_of_scope": [t.to_dict() for t in self.out_of_scope],
            "policy": policy.to_dict() if policy else None,
            "hacktivity_count": hacktivity_count,
        }


@dataclass
class ProgramPolicy:
    """A program's rules: whether it pays, whether submissions are open, and the hard rules."""
    platform: str
    handle: str
    offers_bounties: bool = False
    submission_allowed: bool = True
    disallowed: List[str] = field(default_factory=list)   # e.g. ["no_dos", "no_automated_scanning"]
    safe_harbor: bool = False
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "offers_bounties": self.offers_bounties,
            "submission_allowed": self.submission_allowed,
            "disallowed": list(self.disallowed),
            "safe_harbor": self.safe_harbor,
            "notes": self.notes,
        }


@dataclass
class HacktivityEntry:
    """One disclosed report — the raw material for de-duplicating a would-be submission."""
    title: str
    severity: str = ""
    weakness: str = ""
    state: str = ""
    disclosed_at: str = ""
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity,
            "weakness": self.weakness,
            "state": self.state,
            "disclosed_at": self.disclosed_at,
            "url": self.url,
        }


# --------------------------------------------------------------------------- serializers
def scope_to_yaml(scope: ProgramScope) -> str:
    """Serialize a ProgramScope to a standalone YAML string.

    For a placeholder scope this emits a LOUD sentinel instead of empty lists, so the YAML
    itself can never be mistaken for a clean empty scope.
    """
    if scope.is_placeholder:
        return (
            f"# program scope for {scope.platform}:{scope.handle}\n"
            "# scope_mode: placeholder -- program-intel fetch FAILED/EMPTY.\n"
            "# Do NOT treat as authoritative: an empty out_of_scope here means UNKNOWN, not 'nothing excluded'.\n"
            f"scope_mode: placeholder\n"
            f"placeholder_reason: \"{_esc(scope.placeholder_reason)}\"\n"
            "in_scope: {}\n"
            "out_of_scope: {}\n"
        )
    ins = scope.buckets(scope.in_scope)
    out = scope.buckets(scope.out_of_scope)
    lines = [
        f"# program scope for {scope.platform}:{scope.handle} (scope_mode: fetched)",
        "scope_mode: fetched",
        "in_scope:",
        f"  domains:{_yaml_list(ins['domains'], '    ')}",
        f"  cidrs:{_yaml_list(ins['cidrs'], '    ')}",
        f"  urls:{_yaml_list(ins['urls'], '    ')}",
        "out_of_scope:",
        f"  domains:{_yaml_list(out['domains'], '    ')}",
        f"  cidrs:{_yaml_list(out['cidrs'], '    ')}",
        f"  urls:{_yaml_list(out['urls'], '    ')}",
    ]
    return "\n".join(lines) + "\n"


def scope_to_markdown(scope: ProgramScope) -> str:
    """Human-readable markdown view of a ProgramScope."""
    head = f"# Program scope — {scope.platform}:{scope.handle}"
    if scope.name:
        head += f" ({scope.name})"
    if scope.is_placeholder:
        return (
            f"{head}\n\n"
            "> **scope_mode: placeholder** — program-intel fetch failed/empty. "
            "Scope is UNKNOWN, not empty. Do not hunt until a real scope is populated.\n\n"
            f"Reason: {scope.placeholder_reason or 'n/a'}\n"
        )

    def _rows(targets: List[ScopeTarget]) -> str:
        if not targets:
            return "_(none)_\n"
        r = ["| asset | type | bounty | submit | notes |", "| --- | --- | --- | --- | --- |"]
        for t in targets:
            r.append(f"| `{t.identifier}` | {t.asset_type or t.bucket} | "
                     f"{'yes' if t.eligible_for_bounty else 'no'} | "
                     f"{'yes' if t.eligible_for_submission else 'no'} | {t.instruction} |")
        return "\n".join(r) + "\n"

    return (
        f"{head}\n\n(scope_mode: fetched)\n\n"
        f"## In scope ({len(scope.in_scope)})\n\n{_rows(scope.in_scope)}\n"
        f"## Out of scope ({len(scope.out_of_scope)})\n\n{_rows(scope.out_of_scope)}"
    )


def hacktivity_to_markdown(entries: List[HacktivityEntry], platform: str, handle: str) -> str:
    """A duplicate-reference list: disclosed reports to check a would-be submission against."""
    head = (
        f"# Hacktivity / disclosed-report reference — {platform}:{handle}\n\n"
        "> Offline de-duplication reference. Before drafting a submission, check it against the\n"
        "> disclosed reports below. This is READ-ONLY intel; nothing here is submitted.\n\n"
    )
    if not entries:
        return head + "_No disclosed reports retrieved (empty history, or the platform exposes none)._\n"
    rows = ["| disclosed | severity | weakness | state | title | link |",
            "| --- | --- | --- | --- | --- | --- |"]
    for e in entries:
        link = f"[report]({e.url})" if e.url else ""
        title = (e.title or "").replace("|", "\\|")
        rows.append(f"| {e.disclosed_at} | {e.severity} | {e.weakness} | {e.state} | {title} | {link} |")
    return head + "\n".join(rows) + f"\n\n_{len(entries)} disclosed report(s)._\n"


# --------------------------------------------------------------------------- scope.yaml merge
def merge_scope_into_yaml_text(existing_text: str, scope: ProgramScope) -> str:
    """Union the scope's in/out-of-scope targets into an existing scope.yaml TEXT.

    FAIL-CLOSED: refuses to merge a placeholder scope (ValueError) so an empty/failed fetch can
    never silently populate (or appear to clear) the signed authorization file.

    Operator-owned keys (authorized_by, window, rules, oob, notes, source) are preserved
    byte-for-byte; only the in_scope / out_of_scope target LISTS are edited, as a union with
    whatever the operator already listed (dedup, order-preserving).
    """
    if scope.is_placeholder:
        raise ValueError("refusing to merge a placeholder scope into scope.yaml (fail-closed)")
    text = existing_text if existing_text.strip() else _MINIMAL_SCOPE_YAML
    text = _merge_yaml_lists(text, "in_scope", scope.buckets(scope.in_scope))
    text = _merge_yaml_lists(text, "out_of_scope", scope.buckets(scope.out_of_scope))
    return text


_MINIMAL_SCOPE_YAML = (
    "# scope.yaml created by program_intel; FILL IN authorized_by before launching.\n"
    'engagement: "<program-intel>"\n'
    'authorized_by: "<FILL IN: program authorization / handle on file>"\n'
    "window:\n"
    "  start: \n"
    "  end:   \n"
    "\n"
    "in_scope:\n"
    "  domains: []\n"
    "  cidrs: []\n"
    "  urls: []\n"
    "\n"
    "out_of_scope:\n"
    "  domains: []\n"
    "  cidrs: []\n"
    "  urls: []\n"
)


def _merge_yaml_lists(text: str, top_key: str, additions: dict) -> str:
    """Union list items under a top-level block's sub-keys, preserving the rest of the file."""
    # drop buckets that add nothing
    additions = {k: v for k, v in additions.items() if v}
    if not additions:
        return text
    lines = text.split("\n")
    top_idx = None
    top_re = re.compile(r"^" + re.escape(top_key) + r":\s*(#.*)?$")
    for i, ln in enumerate(lines):
        if top_re.match(ln):
            top_idx = i
            break
    if top_idx is None:
        # no such top-level block: append a fresh one.
        block = [f"{top_key}:"]
        for sk, items in additions.items():
            block.append(f"  {sk}:" + _yaml_list(items, "    "))
        tail = "" if text.endswith("\n") else "\n"
        return text + tail + "\n".join(block) + "\n"
    # block = lines after top_key up to the next indent-0 non-blank line
    end_idx = len(lines)
    for j in range(top_idx + 1, len(lines)):
        ln = lines[j]
        if ln.strip() == "":
            continue
        if len(ln) - len(ln.lstrip(" ")) == 0:
            end_idx = j
            break
    block = lines[top_idx + 1:end_idx]
    for sk, items in additions.items():
        block = _merge_subkey(block, sk, items)
    return "\n".join(lines[:top_idx + 1] + block + lines[end_idx:])


def _merge_subkey(block: List[str], sub_key: str, new_items: List[str]) -> List[str]:
    """Within a top-level block's lines, union `new_items` into `sub_key`'s list."""
    sk_re = re.compile(r"^(\s{2}" + re.escape(sub_key) + r"):(.*)$")
    sk_idx = None
    for i, ln in enumerate(block):
        if sk_re.match(ln):
            sk_idx = i
            break
    if sk_idx is None:
        # sub-key absent: append it (before any trailing blank lines in the block).
        insert_at = len(block)
        while insert_at > 0 and block[insert_at - 1].strip() == "":
            insert_at -= 1
        new_lines = [f"  {sub_key}:" + _yaml_list(_dedup(new_items), "    ")]
        return block[:insert_at] + new_lines + block[insert_at:]

    m = sk_re.match(block[sk_idx])
    rest = m.group(2)
    value, comment = _split_value_comment(rest)
    existing = _parse_inline_list(value)
    # collect block-style item lines that follow (indent >= 4, "- ...")
    item_end = sk_idx + 1
    while item_end < len(block):
        ln = block[item_end]
        stripped = ln.strip()
        if stripped == "":
            break
        indent = len(ln) - len(ln.lstrip(" "))
        if indent >= 4 and (stripped.startswith("- ") or stripped == "-"):
            existing.append(_unquote(stripped[1:].strip()))
            item_end += 1
        else:
            break
    merged = _dedup([e for e in existing if e] + [n for n in new_items])
    comment_suffix = f"  {comment}" if comment else ""
    header = f"  {sub_key}:" + (_yaml_list(merged, "    ") if merged else " []") + \
        (comment_suffix if not merged else "")
    # when we render a block list, keep the comment on the header line
    if merged:
        header = f"  {sub_key}:{comment_suffix}" + _yaml_list(merged, "    ")
    return block[:sk_idx] + [header] + block[item_end:]


# --------------------------------------------------------------------------- provider seam
class Provider(abc.ABC):
    """Abstract program-intel source.

    `http_get(url) -> str` is INJECTABLE so tests mock every response and never touch the
    network. The default fetcher is a plain read-only urllib GET — an operator action, run
    outside the engine (see the module docstring on --strict-mcp-config).
    """

    def __init__(self, platform: str, handle: str, http_get: Optional[Callable[[str], str]] = None):
        self.platform = platform
        self.handle = handle
        self._http_get = http_get or _urllib_get

    @abc.abstractmethod
    def fetch_scope(self) -> ProgramScope:
        ...

    @abc.abstractmethod
    def fetch_policy(self) -> Optional[ProgramPolicy]:
        ...

    @abc.abstractmethod
    def fetch_hacktivity(self) -> List[HacktivityEntry]:
        ...


class GenericJsonProvider(Provider):
    """Reference provider: pulls JSON from three operator-supplied endpoints and maps it.

    Expected (platform-neutral) JSON shapes — the seam a real platform adapter would translate
    its own API into:
      scope_url      -> {"name","in_scope":[{identifier,asset_type,eligible_for_submission,
                         eligible_for_bounty,instruction}],"out_of_scope":[...]}
      policy_url     -> {"offers_bounties","submission_allowed","disallowed":[...],
                         "safe_harbor","notes"}
      hacktivity_url -> {"entries":[{title,severity,weakness,state,disclosed_at,url}]}  (or a bare list)
    """

    def __init__(self, platform: str, handle: str,
                 scope_url: Optional[str] = None, policy_url: Optional[str] = None,
                 hacktivity_url: Optional[str] = None,
                 http_get: Optional[Callable[[str], str]] = None):
        super().__init__(platform, handle, http_get=http_get)
        self.scope_url = scope_url
        self.policy_url = policy_url
        self.hacktivity_url = hacktivity_url

    def fetch_scope(self) -> ProgramScope:
        if not self.scope_url:
            raise ValueError("GenericJsonProvider needs a scope_url to fetch scope")
        data = json.loads(self._http_get(self.scope_url))
        return ProgramScope(
            platform=self.platform, handle=self.handle,
            name=str(data.get("name", "") or ""),
            in_scope=self._map_targets(data.get("in_scope")),
            out_of_scope=self._map_targets(data.get("out_of_scope")),
        )

    def fetch_policy(self) -> Optional[ProgramPolicy]:
        if not self.policy_url:
            return None
        data = json.loads(self._http_get(self.policy_url))
        return ProgramPolicy(
            platform=self.platform, handle=self.handle,
            offers_bounties=bool(data.get("offers_bounties", False)),
            submission_allowed=bool(data.get("submission_allowed", True)),
            disallowed=[str(x) for x in (data.get("disallowed") or [])],
            safe_harbor=bool(data.get("safe_harbor", False)),
            notes=str(data.get("notes", "") or ""),
        )

    def fetch_hacktivity(self) -> List[HacktivityEntry]:
        if not self.hacktivity_url:
            return []
        data = json.loads(self._http_get(self.hacktivity_url))
        rows = data.get("entries") if isinstance(data, dict) else data
        out = []
        for r in rows or []:
            out.append(HacktivityEntry(
                title=str(r.get("title", "") or ""),
                severity=str(r.get("severity", "") or ""),
                weakness=str(r.get("weakness", "") or ""),
                state=str(r.get("state", "") or ""),
                disclosed_at=str(r.get("disclosed_at", "") or ""),
                url=str(r.get("url", "") or ""),
            ))
        return out

    @staticmethod
    def _map_targets(rows) -> List[ScopeTarget]:
        out = []
        for r in rows or []:
            out.append(ScopeTarget(
                identifier=str(r.get("identifier", "") or ""),
                asset_type=str(r.get("asset_type", "") or ""),
                eligible_for_submission=bool(r.get("eligible_for_submission", True)),
                eligible_for_bounty=bool(r.get("eligible_for_bounty", True)),
                instruction=str(r.get("instruction", "") or ""),
            ))
        return [t for t in out if t.identifier]


class _PlatformStub(Provider):
    """Documented stub for a named platform. A real adapter would translate the platform's own
    API shape into the dataclasses (likely subclassing GenericJsonProvider and overriding the
    URL construction + field mapping). Left unimplemented on purpose: wiring a live platform
    endpoint + auth is an operator decision, not something shipped-and-forgotten in the repo.
    """
    _PLATFORM_NAME = "platform"

    def _todo(self):
        raise NotImplementedError(
            f"{self._PLATFORM_NAME} adapter is a stub. Point --platform generic at the program's "
            f"API/JSON via --scope-url/--policy-url/--hacktivity-url, or implement this adapter by "
            f"subclassing GenericJsonProvider."
        )

    def fetch_scope(self) -> ProgramScope:
        self._todo()

    def fetch_policy(self) -> Optional[ProgramPolicy]:
        self._todo()

    def fetch_hacktivity(self) -> List[HacktivityEntry]:
        self._todo()


class HackerOneProvider(_PlatformStub):
    _PLATFORM_NAME = "HackerOne"


class BugcrowdProvider(_PlatformStub):
    _PLATFORM_NAME = "Bugcrowd"


class IntigritiProvider(_PlatformStub):
    _PLATFORM_NAME = "Intigriti"


# registry: platform name -> provider class. `generic` is the one wired reference provider.
PROVIDERS = {
    "generic": GenericJsonProvider,
    "hackerone": HackerOneProvider,
    "bugcrowd": BugcrowdProvider,
    "intigriti": IntigritiProvider,
}


def get_provider(platform: str, handle: str, **kwargs) -> Provider:
    key = (platform or "").strip().lower()
    cls = PROVIDERS.get(key)
    if cls is None:
        raise ValueError(f"unknown platform '{platform}'. Known: {', '.join(sorted(PROVIDERS))}")
    if cls is GenericJsonProvider:
        return cls(platform=key, handle=handle,
                   scope_url=kwargs.get("scope_url"), policy_url=kwargs.get("policy_url"),
                   hacktivity_url=kwargs.get("hacktivity_url"), http_get=kwargs.get("http_get"))
    return cls(platform=key, handle=handle, http_get=kwargs.get("http_get"))


# --------------------------------------------------------------------------- collection
def collect_program_intel(provider: Provider):
    """Fetch scope (safety-critical, fail-closed) + policy + hacktivity (best-effort).

    Returns (ProgramScope, ProgramPolicy|None, [HacktivityEntry]). If the SCOPE fetch raises or
    yields no in-scope targets, the returned scope is a fail-closed PLACEHOLDER sentinel.
    Policy/hacktivity failures are non-fatal (None / []), since they do not gate hunting.
    """
    try:
        scope = provider.fetch_scope()
        if not scope.in_scope:
            scope = ProgramScope.placeholder(
                provider.platform, provider.handle,
                "scope fetch returned no in-scope assets")
    except Exception as exc:  # noqa: BLE001 - any failure must fail closed, not crash the operator
        scope = ProgramScope.placeholder(
            provider.platform, provider.handle, f"scope fetch failed: {exc}")

    policy = None
    try:
        policy = provider.fetch_policy()
    except Exception:  # noqa: BLE001 - policy is advisory; absence is noted, not fatal
        policy = None

    hacktivity: List[HacktivityEntry] = []
    try:
        hacktivity = provider.fetch_hacktivity()
    except Exception:  # noqa: BLE001 - dup-reference is best-effort
        hacktivity = []

    return scope, policy, hacktivity


def is_usable_scope(program_scope: dict) -> bool:
    """A downstream gate's check: a placeholder (or empty-in-scope) program_scope is NOT usable.

    This is the fail-closed read: never treat a placeholder's empty out_of_scope as
    "nothing excluded" — refuse instead.
    """
    if not isinstance(program_scope, dict):
        return False
    if program_scope.get("scope_mode") != SCOPE_MODE_FETCHED:
        return False
    return bool(program_scope.get("in_scope"))


# --------------------------------------------------------------------------- orchestration
def run(provider: Provider, engagement_dir, *, do_merge: bool = True) -> dict:
    """Collect intel + write the three artifacts. Returns a result summary dict.

    On a placeholder scope: writes program_scope.json (the sentinel) + a hacktivity note, SKIPS
    the scope.yaml merge, and reports usable=False. NEVER auto-submits anything.
    """
    eng = Path(engagement_dir)
    eng.mkdir(parents=True, exist_ok=True)
    scope, policy, hacktivity = collect_program_intel(provider)

    ps_path = eng / "program_scope.json"
    atomic_write(ps_path, json.dumps(scope.to_dict(policy, len(hacktivity)), indent=2) + "\n")

    hv_path = eng / "hacktivity.md"
    atomic_write(hv_path, hacktivity_to_markdown(hacktivity, provider.platform, provider.handle))

    merged_scope_yaml = False
    scope_yaml_path = eng / "scope.yaml"
    if scope.is_placeholder:
        pass  # fail-closed: do not touch scope.yaml on a placeholder
    elif do_merge:
        existing = scope_yaml_path.read_text(encoding="utf-8") if scope_yaml_path.is_file() else ""
        atomic_write(scope_yaml_path, merge_scope_into_yaml_text(existing, scope))
        merged_scope_yaml = True

    return {
        "platform": provider.platform,
        "handle": provider.handle,
        "scope_mode": scope.scope_mode,
        "usable": is_usable_scope(scope.to_dict(policy, len(hacktivity))),
        "in_scope_count": len(scope.in_scope),
        "out_of_scope_count": len(scope.out_of_scope),
        "hacktivity_count": len(hacktivity),
        "merged_scope_yaml": merged_scope_yaml,
        "program_scope_json": str(ps_path),
        "hacktivity_md": str(hv_path),
        "scope_yaml": str(scope_yaml_path),
        "placeholder_reason": scope.placeholder_reason or None,
    }


# --------------------------------------------------------------------------- helpers
def _dedup(items: List[str]) -> List[str]:
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def _yaml_list(items: List[str], indent: str) -> str:
    if not items:
        return " []"
    return "\n" + "\n".join(f'{indent}- "{s}"' for s in items)


def _unquote(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        return s[1:-1]
    return s


def _parse_inline_list(value: str) -> List[str]:
    v = value.strip()
    if not v or v == "[]":
        return []
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        if not inner:
            return []
        return [_unquote(p.strip()) for p in inner.split(",") if p.strip()]
    # a scalar on the key line (unusual for a list key) — treat as one item
    return [_unquote(v)]


def _split_value_comment(rest: str) -> tuple:
    """Split 'value  # comment' respecting quotes. Returns (value, '# comment' or '')."""
    q = None
    for i, ch in enumerate(rest):
        if q:
            if ch == q:
                q = None
        elif ch in ("'", '"'):
            q = ch
        elif ch == "#":
            return rest[:i].strip(), rest[i:].strip()
    return rest.strip(), ""


def _esc(s: str) -> str:
    return (s or "").replace("\\", "\\\\").replace('"', '\\"')


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _urllib_get(url: str) -> str:
    """Read-only GET (operator action). NOT invoked by tests (they inject http_get)."""
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:  # noqa: S310 - operator-supplied URL
        return resp.read().decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- CLI
def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="program_intel.py",
        description="Offline, read-only bug-bounty program-intel feeder "
                    "(scope/policy/dup-reference). No auto-submission.")
    p.add_argument("platform", help=f"program platform ({', '.join(sorted(PROVIDERS))})")
    p.add_argument("handle", help="program handle/identifier on that platform")
    p.add_argument("--engagement", required=True, help="engagement directory to write artifacts into")
    p.add_argument("--scope-url", help="(generic provider) JSON endpoint for the program scope")
    p.add_argument("--policy-url", help="(generic provider) JSON endpoint for the program policy")
    p.add_argument("--hacktivity-url", help="(generic provider) JSON endpoint for disclosed reports")
    p.add_argument("--no-merge", action="store_true", help="do NOT merge into scope.yaml (write intel only)")
    p.add_argument("--selftest", action="store_true", help="run the built-in self-test and exit")
    return p


def main(argv=None, provider_factory: Callable[..., Provider] = get_provider) -> int:
    """CLI entry point. `provider_factory` is injectable so tests drive a mocked provider."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--selftest" in argv:
        selftest()
        return 0
    args = build_argparser().parse_args(argv)
    try:
        provider = provider_factory(
            args.platform, args.handle,
            scope_url=args.scope_url, policy_url=args.policy_url, hacktivity_url=args.hacktivity_url)
    except ValueError as exc:
        print(f"program_intel: {exc}", file=sys.stderr)
        return 2

    result = run(provider, args.engagement, do_merge=not args.no_merge)

    print(f"program_intel: {result['platform']}:{result['handle']} -> {args.engagement}")
    print(f"  program_scope.json : scope_mode={result['scope_mode']} "
          f"in={result['in_scope_count']} out={result['out_of_scope_count']}")
    print(f"  hacktivity.md      : {result['hacktivity_count']} disclosed report(s)")
    if result["scope_mode"] == SCOPE_MODE_PLACEHOLDER:
        print("  scope.yaml         : NOT merged (fail-closed placeholder sentinel written)", file=sys.stderr)
        print(f"  FAIL-CLOSED: {result['placeholder_reason']}", file=sys.stderr)
        print("  A downstream scope check must REFUSE this placeholder (not read empty as 'nothing excluded').",
              file=sys.stderr)
        return 3
    print(f"  scope.yaml         : {'merged' if result['merged_scope_yaml'] else 'left unchanged (--no-merge)'}"
          " (authorized_by preserved)")
    return 0


# --------------------------------------------------------------------------- selftest
def selftest() -> None:
    # bucket classification
    assert _bucket_for("*.example.com", "") == "domains"
    assert _bucket_for("https://api.example.com", "") == "urls"
    assert _bucket_for("203.0.113.0/24", "") == "cidrs"
    assert _bucket_for("api.example.com", "api") == "urls"
    assert _bucket_for("x", "domain") == "domains"

    # fetched scope -> serializers + merge
    scope = ProgramScope(
        platform="generic", handle="acme", name="Acme",
        in_scope=[ScopeTarget("*.acme.com", "wildcard"), ScopeTarget("https://api.acme.com", "url")],
        out_of_scope=[ScopeTarget("blog.acme.com", "domain")])
    assert "fetched" in scope_to_yaml(scope)
    assert "api.acme.com" in scope_to_markdown(scope)

    base = (
        'engagement: "acme-2026"\n'
        'authorized_by: "ACME security team, auth ref #42"\n'
        "window:\n  start: 2026-01-01T00:00:00Z\n  end:   2026-02-01T00:00:00Z\n\n"
        "in_scope:\n  domains:\n    - \"existing.acme.com\"\n  cidrs: []\n  urls: []\n\n"
        "out_of_scope:          # excludes win\n  domains: []\n  cidrs: []\n")
    merged = merge_scope_into_yaml_text(base, scope)
    assert 'authorized_by: "ACME security team, auth ref #42"' in merged, "authorized_by must survive"
    assert "existing.acme.com" in merged and "*.acme.com" in merged, "in_scope union"
    assert "https://api.acme.com" in merged, "url bucket merged"
    assert "blog.acme.com" in merged, "out_of_scope merged"
    assert "# excludes win" in merged, "comment preserved"
    # idempotent: merging again adds nothing new
    assert merge_scope_into_yaml_text(merged, scope) == merged, "merge must be idempotent"

    # placeholder sentinel
    ph = ProgramScope.placeholder("generic", "acme", "boom")
    assert ph.is_placeholder and ph.scope_mode == SCOPE_MODE_PLACEHOLDER
    assert "placeholder" in scope_to_yaml(ph) and "boom" in scope_to_yaml(ph)
    try:
        merge_scope_into_yaml_text(base, ph)
        raise AssertionError("merging a placeholder must raise")
    except ValueError:
        pass
    assert is_usable_scope(scope.to_dict()) is True
    assert is_usable_scope(ph.to_dict()) is False

    # generic provider with injected (mocked) http_get — NO network
    fixtures = {
        "s": json.dumps({"name": "Acme", "in_scope": [{"identifier": "*.acme.com", "asset_type": "wildcard"}],
                         "out_of_scope": [{"identifier": "blog.acme.com", "asset_type": "domain"}]}),
        "p": json.dumps({"offers_bounties": True, "disallowed": ["no_dos"]}),
        "h": json.dumps({"entries": [{"title": "Stored XSS in profile", "severity": "high",
                                      "weakness": "XSS", "disclosed_at": "2025-01-01"}]}),
    }
    prov = GenericJsonProvider("generic", "acme", scope_url="s", policy_url="p", hacktivity_url="h",
                               http_get=lambda u: fixtures[u])
    sc, pol, hv = collect_program_intel(prov)
    assert not sc.is_placeholder and len(sc.in_scope) == 1 and len(sc.out_of_scope) == 1
    assert pol and pol.offers_bounties and pol.disallowed == ["no_dos"]
    assert len(hv) == 1 and "XSS" in hacktivity_to_markdown(hv, "generic", "acme")

    # failing scope fetch -> placeholder
    def _boom(_u):
        raise RuntimeError("network down")
    sc2, _, _ = collect_program_intel(GenericJsonProvider("generic", "x", scope_url="s", http_get=_boom))
    assert sc2.is_placeholder

    print("program_intel selftest: OK")


if __name__ == "__main__":
    sys.exit(main())
