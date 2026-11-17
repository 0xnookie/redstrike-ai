"""`redstrike accounts` — register test-account credentials for an engagement.

The split (see skills/_contract/notebook.md):
  • SECRET store  -> <engagement>/runtime/creds.json   — the raw identity + secret/session.
      runtime/ is gitignored (engagements/.gitignore = '*') and is NOT in any console-served
      file list (scripts/console.py WANTED / console_control.py routes). It must stay that way.
  • REDACTED view -> <engagement>/notebook.json test_accounts[] — id / tenant / role / REDACTED
      identity / auth METHOD / status / used_for. This is the console-served, report-safe
      projection (notebook.py validate() rejects an unredacted identity). creds.json is the
      source of truth; this list is always regenerated from it.

The running agents read their sessions from `auth.env`. `materialize()` (below) deterministically
writes `runtime/auth.env` from `creds.json` — one shell-sourceable block per identity — so a stored
2nd identity actually REACHES the executors (every reference to `auth.env` across the skills is a
READER; before this, nothing wrote it). It is auto-run at hunt start (the `redstrike run` launch
path) and after each `accounts add/rm`, and can be forced with `redstrike accounts materialize`.
`auth.env` lands under `runtime/` — gitignored (`.gitignore` + `engagements/.gitignore = '*'`) and NOT
in the console-served file list — so it is never committed or served.

Stdlib only. Nothing here ever prints a raw secret; display is masked (last-4); `auth.env` itself is
owner-only (0600 best-effort) and holds the secrets in the clear for the in-scope executors only.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

CREDS_REL = Path("runtime") / "creds.json"
AUTH_ENV_REL = Path("runtime") / "auth.env"
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


def auth_env_path(eng: Path) -> Path:
    return eng / AUTH_ENV_REL


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


def account_count(eng: Path) -> int:
    """How many well-formed identities are stored (ids only)."""
    return sum(1 for a in load_creds(eng).get("accounts", []) if isinstance(a, dict) and a.get("id"))


# --------------------------------------------------------------------------- auth.env materializer
def _ns(acct_id: str, taken: set) -> str:
    """A shell-identifier namespace for an account id (deterministic): uppercased, every run of
    non-alphanumerics → '_', a leading digit guarded, de-duplicated against `taken`."""
    base = re.sub(r"[^A-Za-z0-9]+", "_", (acct_id or "").strip()).strip("_").upper() or "ID"
    if base[0].isdigit():
        base = "ID_" + base
    ns, i = base, 2
    while ns in taken:
        ns, i = f"{base}_{i}", i + 1
    taken.add(ns)
    return ns


def _env_line(key: str, value) -> str:
    """One shell-sourceable ``KEY="VALUE"`` line. The value is double-quoted and every shell
    metacharacter escaped so ``source auth.env`` is safe and nothing (not even a newline) can break
    out of the value — each variable stays on a single line."""
    v = str(value)
    v = v.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    v = v.replace("\r", "").replace("\n", " ")
    return f'{key}="{v}"'


def _identity_pairs(acct: dict) -> list[tuple[str, str]]:
    """Ordered ``(SUFFIX, value)`` pairs for one identity — only the fields actually present.

    SUFFIXes: ID · ROLE · TENANT · BASE_URL · IDENTITY · PASSWORD · BEARER · API_KEY · COOKIE ·
    HEADERS (all session/auth headers as ``Name: Value`` pairs joined by a literal ``\\n`` so a
    consumer can split and pass each as a ``curl -H``). COOKIE/HEADERS mirror the tokens the
    recon/js-analysis skills document; BEARER is the bare token for ``-H "Authorization: Bearer …"``.
    """
    out: list[tuple[str, str]] = [("ID", acct.get("id", ""))]
    for suf, key in (("ROLE", "role"), ("TENANT", "tenant"), ("BASE_URL", "base_url"),
                     ("IDENTITY", "identity")):
        v = acct.get(key)
        if v:
            out.append((suf, v))
    secret = acct.get("secret") or {}
    session = acct.get("session") or {}
    if secret.get("password"):
        out.append(("PASSWORD", secret["password"]))
    if secret.get("token"):
        out.append(("BEARER", secret["token"]))
    if secret.get("api_key"):
        out.append(("API_KEY", secret["api_key"]))
    if session.get("cookie"):
        out.append(("COOKIE", session["cookie"]))
    headers = session.get("headers") or {}
    if headers:
        out.append(("HEADERS", "\\n".join(f"{k}: {v}" for k, v in headers.items())))
    return out


def materialize(eng: Path) -> Path | None:
    """Deterministically (re)write ``runtime/auth.env`` from ``runtime/creds.json`` so the executors'
    session material reaches them. One shell-sourceable block per identity, variables namespaced by
    the account id; the FIRST identity is ALSO exposed under the flat ``COOKIE=`` / ``HEADERS=`` /
    ``BASE_URL=`` names the recon/js-analysis skills document, so those readers work verbatim.

    stdlib-only · idempotent (same creds → identical bytes; no volatile timestamp) · never prints a
    secret · owner-only (0600 best-effort). Returns the path written, or None (a no-op) when
    ``creds.json`` is absent or holds no identities."""
    data = _read_json(creds_path(eng))
    accts = data.get("accounts") if isinstance(data, dict) else None
    if not isinstance(accts, list) or not accts:
        return None

    lines: list[str] = [
        "# runtime/auth.env — session material for the Redstrike executors.",
        "# AUTO-GENERATED from runtime/creds.json (via `redstrike accounts materialize` / at hunt",
        "# start). Do NOT hand-edit — regenerated each run. gitignored + never console-served; the",
        "# secrets live here in the clear for the in-scope executors ONLY. `source auth.env` to load.",
        "# One block per identity (vars namespaced by id); the primary identity is also aliased to the",
        "# flat COOKIE=/HEADERS=/BASE_URL= names recon + js-analysis read.",
        "",
    ]
    taken: set = set()
    primary: tuple[dict, list] | None = None
    for acct in accts:
        if not isinstance(acct, dict) or not acct.get("id"):
            continue
        ns = _ns(str(acct.get("id")), taken)
        pairs = _identity_pairs(acct)
        hdr = f"# identity: {acct.get('id')}"
        if acct.get("role"):
            hdr += f"  role={acct['role']}"
        if acct.get("tenant"):
            hdr += f"  tenant={acct['tenant']}"
        lines.append(hdr)
        lines += [_env_line(f"{ns}_{suf}", val) for suf, val in pairs]
        lines.append("")
        if primary is None:
            primary = (acct, pairs)

    if primary is None:
        return None
    a0, pairs0 = primary
    lines.append(f"# primary-identity aliases → {a0.get('id')} (flat names recon + js-analysis read)")
    lines += [_env_line(suf, val) for suf, val in pairs0 if suf != "ID"]

    content = "\n".join(lines).rstrip("\n") + "\n"
    p = auth_env_path(eng)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    try:
        os.chmod(p, 0o600)  # owner-only (best-effort; largely a no-op on Windows ACLs)
    except Exception:
        pass
    return p


def clear_auth_env(eng: Path) -> bool:
    """Remove a stale ``runtime/auth.env`` (e.g. after the last identity is removed). Returns True
    when a file was deleted. Best-effort; never raises."""
    p = auth_env_path(eng)
    try:
        if p.is_file():
            p.unlink()
            return True
    except Exception:
        pass
    return False
