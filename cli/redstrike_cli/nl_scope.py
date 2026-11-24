"""Natural-language → DRAFT scope.yaml seeder (a convenience, NEVER the authorization-of-record).

``redstrike scope --from-nl "only /api/* no /logout host x.com"`` parses a loose English scope
description into a DRAFT ``scope.yaml`` that a human then REVIEWS, fills ``authorized_by`` on, and
SIGNS. This is purely an input convenience to cut typing — the NL text is NOT, and can never be, the
authorization record. Two safeguards make that structural, not just documentation:

  * the draft's ``authorized_by`` is an explicit ``<UNSIGNED DRAFT …>`` placeholder, so
    ``scope.is_complete()`` (and therefore ``launch.gate``) REFUSES to launch until a human replaces
    it — the same ``<…>``-placeholder convention ``redstrike init`` uses for an un-filled field;
  * only the reviewed + signed ``scope.yaml`` is what ``redstrike run`` derives ``runtime/scope.json``
    from and feeds the PreToolUse scope gate. This draft feeds nothing by itself.

MAPPING (honest about what the host-level gate can enforce)
  * ``host/domain/site/target X``                → ``in_scope.domains`` (``*.x`` wildcards kept)
  * a bare ``http(s)://…`` URL                   → ``in_scope.urls``
  * a CIDR (``10.0.0.0/24``)                      → ``in_scope.cidrs``
  * ``no/exclude/skip <host-or-domain>``          → ``out_of_scope.domains``
  * ``only/allow/include <path>`` / ``no <path>`` → ADVISORY notes (the scope gate keys on HOST, not
    path — so path allow/exclude + ``ports`` are recorded for the reviewer/RoE, NOT gate-enforced; the
    draft says so plainly).

Stdlib only. The parser is a keyword-driven tokenizer (no cross-keyword greedy capture), so
``only /api/* no /logout`` never lets ``no /logout`` leak into the allow list.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import engagement, yamlio

# The un-signed authorization placeholder. Starts with '<' so scope.is_complete() flags it and
# launch.gate() refuses to launch until a human fills + signs it.
UNSIGNED = ("<UNSIGNED DRAFT — fill in the authorizing contact + written-auth reference, then "
            "REVIEW + SIGN this scope.yaml before any run>")

_ALLOW_KW = frozenset({"only", "allow", "include", "including", "just", "whitelist", "limited", "restrict"})
_EXCL_KW = frozenset({"no", "not", "exclude", "excluding", "skip", "without", "avoid", "deny",
                      "blacklist", "except"})
_HOST_KW = frozenset({"host", "hosts", "domain", "domains", "site", "sites", "target", "targets", "scope"})
_PORT_KW = frozenset({"port", "ports"})

_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
# A hostname/domain token: optional leading '*.' then dotted labels with a letter TLD.
_HOST_RE = re.compile(r"^\*?\.?(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]{1,}$", re.IGNORECASE)
# Final labels that mark a dotted token as a file, not a host (mirrors the scope gate's intent).
_FILE_EXTS = frozenset("json yaml yml txt md html htm js ts py sh csv xml log".split())


def _norm_host(tok: str) -> str:
    return tok.strip().lower().rstrip(".")


def _looks_like_host(tok: str) -> bool:
    if not _HOST_RE.match(tok):
        return False
    return tok.rsplit(".", 1)[-1].lower() not in _FILE_EXTS


def _dedup(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def parse_nl_scope(text: str) -> dict:
    """Parse an English scope description into structured intent. Keyword-driven: ``only/allow/…`` →
    allow mode, ``no/exclude/…`` → exclude mode, ``host/domain/…`` → host mode, ``port(s)`` → port
    mode; each subsequent token is classified against the CURRENT mode (so directives never bleed into
    each other). Unknown filler words keep the current mode and are ignored."""
    res = {
        "domains": [], "urls": [], "cidrs": [],
        "exclude_domains": [], "allow_paths": [], "exclude_paths": [], "ports": [],
    }
    text = (text or "").strip()
    if not text:
        return res

    mode = "host"  # default: a bare host at the start is in-scope
    for raw in re.findall(r"[^\s,]+", text):
        low = raw.lower().strip(".,;:!?")
        if low in _ALLOW_KW:
            mode = "allow"
            continue
        if low in _EXCL_KW:
            mode = "exclude"
            continue
        if low in _HOST_KW:
            mode = "host"
            continue
        if low in _PORT_KW:
            mode = "port"
            continue

        if mode == "port":
            for p in re.findall(r"\d+", raw):
                res["ports"].append(int(p))
            continue

        tok = raw.strip(",;")
        if tok.startswith("/"):
            (res["exclude_paths"] if mode == "exclude" else res["allow_paths"]).append(tok)
            continue
        if _CIDR_RE.match(tok):
            res["cidrs"].append(tok)
            continue
        if _URL_RE.match(tok):
            res["urls"].append(tok)
            continue
        if _looks_like_host(tok):
            host = _norm_host(tok)
            if mode == "exclude":
                res["exclude_domains"].append(host)
            else:
                res["domains"].append(host)
            continue
        # otherwise a filler word ("and", "the", "please") — keep the mode, ignore the token.

    for k in res:
        if k != "ports":
            res[k] = _dedup(res[k])
    res["ports"] = _dedup(res["ports"])
    return res


def _advisory_notes(parsed: dict, nl_text: str) -> str:
    """A SINGLE-LINE notes value (render_scope_yaml folds notes on one line) carrying the NL seed, the
    not-authorization disclaimer, and the path/port advisories the host-level gate cannot enforce."""
    bits = [
        "DRAFT seeded from a natural-language description — this is NOT an authorization record. "
        "A human must review it, fill authorized_by, and sign before any run."
    ]
    adv = []
    if parsed.get("allow_paths"):
        adv.append("allow-paths=" + ",".join(parsed["allow_paths"]))
    if parsed.get("exclude_paths"):
        adv.append("exclude-paths=" + ",".join(parsed["exclude_paths"]))
    if parsed.get("ports"):
        adv.append("ports=" + ",".join(str(p) for p in parsed["ports"]))
    if adv:
        bits.append("Advisory (NOT host-gate-enforced; the scope gate keys on host, not path — "
                    "enforce these in the RoE / manually): " + "; ".join(adv) + ".")
    seed = re.sub(r"\s+", " ", (nl_text or "").strip()).replace('"', "'")
    if seed:
        bits.append(f"NL seed: \"{seed}\".")
    return " ".join(bits)


def draft_fields(parsed: dict, *, client: str | None = None, nl_text: str = "",
                 window=None) -> dict:
    """Build ``engagement.build_fields``-shaped fields for the draft, with ``authorized_by`` left as
    the UNSIGNED placeholder and the path/port advisories folded into ``notes``."""
    client = client or (parsed["domains"][0] if parsed.get("domains") else
                        (parsed["cidrs"][0] if parsed.get("cidrs") else "draft"))
    return engagement.build_fields(
        client=client,
        authorized_by=UNSIGNED,
        domains=list(parsed.get("domains") or []),
        cidrs=list(parsed.get("cidrs") or []),
        urls=list(parsed.get("urls") or []),
        exclude_domains=list(parsed.get("exclude_domains") or []),
        window=window or engagement.default_window(),
        notes=_advisory_notes(parsed, nl_text),
    )


_DRAFT_HEADER = (
    "# ============================================================================\n"
    "# DRAFT scope.yaml — SEEDED FROM NATURAL LANGUAGE. NOT AN AUTHORIZATION RECORD.\n"
    "# The NL text is a convenience seed ONLY; it is NEVER the authorization-of-record.\n"
    "# A human MUST: review this draft, replace `authorized_by` with the real authorizing\n"
    "# contact + written-auth reference, verify in/out scope + the window, and SIGN it.\n"
    "# Only the reviewed + SIGNED scope.yaml feeds the PreToolUse scope gate; this draft\n"
    "# feeds nothing. Path/port lines are ADVISORY (the gate enforces hosts, not paths).\n"
    "# ============================================================================\n"
)


def render_draft(parsed: dict, *, client: str | None = None, nl_text: str = "") -> str:
    """Render the full DRAFT scope.yaml text (DRAFT banner + the rendered scope)."""
    fields = draft_fields(parsed, client=client, nl_text=nl_text)
    return _DRAFT_HEADER + yamlio.render_scope_yaml(fields)


def summary_lines(parsed: dict) -> list[str]:
    """Human-readable lines of what was parsed (for the CLI's pre-draft echo)."""
    def _j(xs):
        return ", ".join(str(x) for x in xs) if xs else "—"
    return [
        f"in-scope domains : {_j(parsed.get('domains'))}",
        f"in-scope urls    : {_j(parsed.get('urls'))}",
        f"in-scope cidrs   : {_j(parsed.get('cidrs'))}",
        f"excluded domains : {_j(parsed.get('exclude_domains'))}",
        f"allow paths (adv): {_j(parsed.get('allow_paths'))}",
        f"exclude paths(adv): {_j(parsed.get('exclude_paths'))}",
        f"ports (advisory) : {_j(parsed.get('ports'))}",
    ]
