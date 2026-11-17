"""`redstrike accounts` — register test-account credentials for an engagement.

The split (see skills/_contract/notebook.md):
  • SECRET store  -> <engagement>/runtime/creds.json   — the raw identity + secret/session.
      runtime/ is gitignored (engagements/.gitignore = '*') and is NOT in any console-served
      file list (scripts/console.py WANTED / console_control.py routes). It must stay that way.
  • REDACTED view -> <engagement>/notebook.json test_accounts[] — id / tenant / role / REDACTED
      identity / auth METHOD / status / used_for. This is the console-served, report-safe
      projection (notebook.py validate() rejects an unredacted identity). creds.json is the
      source of truth; this list is always regenerated from it.

The running agents read their sessions from `auth.env`, which the orchestrator materializes from
creds.json at hunt start — that step is intentionally NOT done here (store + display only).

Stdlib only. Nothing here ever prints a raw secret; display is masked (last-4).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

CREDS_REL = Path("runtime") / "creds.json"
NB_NAME = "notebook.json"
STATUSES = ("active", "expired", "pending", "retired")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def creds_path(eng: Path) -> Path:
    return eng / CREDS_REL


# --------------------------------------------------------------------------- secret store
def load_creds(eng: Path) -> dict:
    data = _read_json(creds_path(eng))
    if not isinstance(data, dict):
        data = {"engagement": eng.name, "accounts": []}
    data.setdefault("engagement", eng.name)
    if not isinstance(data.get("accounts"), list):
        data["accounts"] = []
    return data


def save_creds(eng: Path, data: dict) -> Path:
    data["generated_at"] = _now()
    p = creds_path(eng)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)  # best-effort owner-only (largely a no-op on Windows ACLs)
    except Exception:
        pass
    return p


# --------------------------------------------------------------------------- redaction / masking
def redact_identity(raw: str) -> str:
    """A console/report-safe identity. Always contains a redaction marker so notebook.py
    validate() accepts it; keeps the domain of an email for operator legibility."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    if "@" in raw:
        _, _, domain = raw.partition("@")
        return f"‹redacted›@{domain}" if domain else "‹redacted›"
    return "‹redacted›"


def mask_secret(acct: dict) -> str:
    """A short, non-reversible display hint — never the secret itself."""
    secret = acct.get("secret") or {}
    for k in ("password", "token", "api_key"):
        v = secret.get(k)
        if isinstance(v, str) and v:
            return f"…{v[-4:]}" if len(v) >= 8 else "…"
    session = acct.get("session") or {}
    if session.get("cookie"):
        return "cookie set"
    if session.get("headers"):
        return "headers set"
    return "set"


def _infer_method(*, password=None, token=None, cookie=None, headers=None) -> str:
    if password:
        return "password"
    if token:
        return "bearer token"
    if cookie:
        return "cookie session"
    if headers:
        return "header auth"
    return "unspecified"


def build_account(*, id: str, role="", tenant="", identity="", auth="", status="active",
                  used_for="", password="", token="", cookie="", headers=None) -> dict:
    """Assemble one account record for the SECRET store (raw identity + secret/session)."""
    secret: dict = {}
    session: dict = {}
    if password:
        secret["password"] = password
    if token:
        secret["token"] = token
        session.setdefault("headers", {})["Authorization"] = f"Bearer {token}"
    if cookie:
        session["cookie"] = cookie
    for k, v in (headers or {}).items():
        if k:
            session.setdefault("headers", {})[k] = v
    acct = {
        "id": id,
        "tenant": tenant or "",
        "role": role or "",
        "identity": identity or "",  # RAW — creds.json only, never projected unredacted
        "auth_method": auth or _infer_method(password=password, token=token, cookie=cookie,
                                             headers=session.get("headers")),
        "status": status or "active",
        "used_for": used_for or "",
        "secret": secret,
        "session": session,
        "updated_at": _now(),
    }
    return {k: v for k, v in acct.items() if v not in ("", {}, None)}


def redacted_account(acct: dict) -> dict:
    """The notebook.test_accounts[] projection — no secret, identity redacted."""
    out: dict = {"id": acct.get("id")}
    if acct.get("tenant"):
        out["tenant"] = acct["tenant"]
    if acct.get("role"):
        out["role"] = acct["role"]
    ident = redact_identity(acct.get("identity", ""))
    if ident:
        out["identity"] = ident
    if acct.get("auth_method"):
        out["auth"] = acct["auth_method"]
    out["status"] = acct.get("status", "active")
    if acct.get("used_for"):
        out["used_for"] = acct["used_for"]
    return out


def _sync_notebook(eng: Path, accounts: list) -> None:
    """Regenerate notebook.test_accounts[] from the (authoritative) creds list, preserving
    every other notebook section. creds.json is the source of truth for accounts."""
    p = eng / NB_NAME
    nb = _read_json(p)
    if not isinstance(nb, dict):
        nb = {"engagement": eng.name}
    nb.setdefault("engagement", eng.name)
    nb["test_accounts"] = [redacted_account(a) for a in accounts]
    nb["generated_at"] = _now()
    p.write_text(json.dumps(nb, indent=2) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------- mutations
def upsert(eng: Path, acct: dict) -> None:
    data = load_creds(eng)
    accts = data["accounts"]
    for i, a in enumerate(accts):
        if a.get("id") == acct.get("id"):
            accts[i] = acct
            break
    else:
        accts.append(acct)
    save_creds(eng, data)
    _sync_notebook(eng, accts)


def remove(eng: Path, acct_id: str) -> bool:
    data = load_creds(eng)
    kept = [a for a in data["accounts"] if a.get("id") != acct_id]
    if len(kept) == len(data["accounts"]):
        return False
    data["accounts"] = kept
    save_creds(eng, data)
    _sync_notebook(eng, kept)
    return True


def summaries(eng: Path) -> list[dict]:
    """Display rows — masked, never the raw secret."""
    out = []
    for a in load_creds(eng).get("accounts", []):
        out.append({
            "id": a.get("id"),
            "role": a.get("role", ""),
            "tenant": a.get("tenant", ""),
            "identity": redact_identity(a.get("identity", "")),
            "auth": a.get("auth_method", ""),
            "status": a.get("status", ""),
            "used_for": a.get("used_for", ""),
            "secret": mask_secret(a),
        })
    return out
