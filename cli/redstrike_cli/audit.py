"""Audit-trail helpers: secret redaction + a tamper-evident run head.

The autonomous run tees Claude Code's raw stream-json to runtime/autorun.jsonl as the
engagement's audit trail. That stream can carry captured credential material (hashes, tokens,
Authorization headers, private keys) lifted from a target during a hunt, so it is redacted with
`redact_text` before anything is written to disk. Each run also stamps a `#`-prefixed head line
(`run_head`) carrying sha256(scope.yaml) + the authorizing reference, which (a) binds the trail to
the exact authorization record in force and (b) doubles as the console's run-boundary marker.

Stdlib-only; redaction is best-effort pattern matching, not a guarantee — it fingerprints the
obvious secret shapes so the trail stays reviewable without leaking the secret value itself.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import re
from pathlib import Path


def _fp(secret: str) -> str:
    """Stable short fingerprint of a secret — lets the same value be correlated across the trail
    without disclosing it."""
    return hashlib.sha256(secret.encode("utf-8", "replace")).hexdigest()[:12]


def _redact_group(m: "re.Match", label: str, group: int = 0) -> str:
    """Replace capture `group` of the match with a fingerprint token, keeping the rest verbatim."""
    full = m.group(0)
    secret = m.group(group)
    if not secret:
        return full
    token = f"[REDACTED:{label}:{_fp(secret)}]"
    start, end = m.start(group) - m.start(0), m.end(group) - m.start(0)
    return full[:start] + token + full[end:]


# --- patterns ---------------------------------------------------------------
# A PEM private-key block (real or \n-escaped inside a JSON string) → collapse the whole block.
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
# JSON Web Token (header.payload.signature).
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}")
# Cloud access-key id shape (provider-agnostic: 4 upper + 16 upper/digits).
_AKID_RE = re.compile(r"\b[A-Z]{4}[0-9A-Z]{16}\b")
# A pwdump / NetNTLM-style line: user:rid:lmhash:nthash:::  (redact the two 32-hex hashes).
_PWDUMP_RE = re.compile(r"\b([a-fA-F0-9]{32}):([a-fA-F0-9]{32})\b(?=:::)")
# crypt(3)/hashcat/john hash strings: $id$...  (bcrypt, sha-crypt, kerberos, NT, netntlm, …).
_CRYPT_RE = re.compile(
    r"\$(?:1|2[abxy]?|5|6|y|NT|LM|krb5\w*|sha1|md5|DCC2|mscash\w*|netntlm\w*|argon2\w*)\$[^\s\"':,}]+",
    re.IGNORECASE,
)
# Authorization: Bearer <token>  /  bare bearer token.
_BEARER_RE = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._\-+/=]{8,})")
# key = value / "key": "value" for credential-ish keys (redact the value only).
_KV_RE = re.compile(
    r"(?i)(\"?(?:password|passwd|pwd|secret|secret[_-]?key|token|access[_-]?token|refresh[_-]?token|"
    r"api[_-]?key|apikey|access[_-]?key|client[_-]?secret|private[_-]?key|session[_-]?key)\"?\s*[:=]\s*)"
    r"(\"?)([^\s\"',}&]{3,})"
)


def redact_text(text: str) -> str:
    """Redact credential material from a chunk of trail text, preserving structure (so a redacted
    JSONL line stays valid JSON). Idempotent on already-redacted text."""
    if not text:
        return text
    text = _PEM_RE.sub("[REDACTED-PRIVATE-KEY]", text)
    text = _JWT_RE.sub(lambda m: f"[REDACTED:jwt:{_fp(m.group(0))}]", text)
    text = _CRYPT_RE.sub(lambda m: f"[REDACTED:hash:{_fp(m.group(0))}]", text)
    text = _PWDUMP_RE.sub(lambda m: f"[REDACTED:ntlm:{_fp(m.group(1))}]:[REDACTED:ntlm:{_fp(m.group(2))}]", text)
    text = _AKID_RE.sub(lambda m: f"[REDACTED:akid:{_fp(m.group(0))}]", text)
    text = _BEARER_RE.sub(lambda m: f"Bearer [REDACTED:{_fp(m.group(1))}]", text)
    text = _KV_RE.sub(lambda m: m.group(1) + m.group(2) + f"[REDACTED:{_fp(m.group(3))}]", text)
    return text


# --- tamper-evident run head ------------------------------------------------
def scope_fingerprint(scope_yaml_path: str | Path) -> str:
    """sha256 of the canonical scope.yaml bytes (empty string if unreadable)."""
    try:
        return hashlib.sha256(Path(scope_yaml_path).read_bytes()).hexdigest()
    except Exception:
        return ""


def _clean(s: str) -> str:
    return str(s or "").replace("\n", " ").replace("\r", " ").strip()


def run_head(
    *,
    scope_yaml_path: str | Path,
    authorized_by: str,
    session_id: str,
    mode: str,
    now: _dt.datetime | None = None,
) -> str:
    """A `#`-prefixed audit head line (also the console's run-boundary marker) stamping the run
    with the time, mode, session, sha256(scope.yaml) and the authorizing reference."""
    ts = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat()
    sha = scope_fingerprint(scope_yaml_path) or "unavailable"
    return (
        f"# --- redstrike {_clean(mode)} run {ts} "
        f"· session={_clean(session_id)} "
        f"· scope.yaml#sha256={sha} "
        f"· authorized_by={_clean(authorized_by)} ---\n"
    )


def run_footer(mode: str, rc: int, now: _dt.datetime | None = None) -> str:
    """A `#`-prefixed footer closing a run with its outcome (used for interactive runs, which have
    no capturable event stream)."""
    ts = (now or _dt.datetime.now(_dt.timezone.utc)).isoformat()
    return f"# --- redstrike {_clean(mode)} run ended {ts} · exit={rc} ---\n"


def append_line(path: str | Path, line: str) -> None:
    """Best-effort append of a single (redacted) audit line; never raises."""
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line if line.endswith("\n") else line + "\n")
    except Exception:
        pass
