"""Engagement bootstrap: scaffold engagements/<client>-<date>/ + scope.yaml.

This is the ONE human-gated input the launcher owns. `scaffold()` also records an
authorization.json (the operator's assertion that written authorization is on file),
which the RoE/skill treats as the §0 go-ahead — and which the agent is denied writing.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path

from . import __version__, yamlio


def slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.strip().lower()).strip("-")
    return s or "client"


def engagement_id(client: str, date: _dt.date | None = None) -> str:
    return f"{slugify(client)}-{(date or _dt.date.today()).isoformat()}"


def default_window(days: int = 14) -> tuple[str, str]:
    now = _dt.datetime.now(_dt.timezone.utc)
    start = _dt.datetime(now.year, now.month, now.day, tzinfo=_dt.timezone.utc)
    end = (start + _dt.timedelta(days=days)).replace(hour=23, minute=59, second=59)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return start.strftime(fmt), end.strftime(fmt)


def build_fields(
    *,
    client: str,
    authorized_by: str,
    domains: list[str],
    cidrs: list[str] | None = None,
    urls: list[str] | None = None,
    exclude_domains: list[str] | None = None,
    exclude_cidrs: list[str] | None = None,
    rate_limit: int = 20,
    oob: str = "",
    window: tuple[str, str] | None = None,
    notes: str | None = None,
    date: _dt.date | None = None,
) -> dict:
    return {
        "engagement": engagement_id(client, date),
        "authorized_by": authorized_by,
        "window": dict(zip(("start", "end"), window or default_window())),
        "in_scope": {"domains": domains, "cidrs": cidrs or [], "urls": urls or []},
        "out_of_scope": {"domains": exclude_domains or [], "cidrs": exclude_cidrs or []},
        "rules": {
            "no_dos": True,
            "no_destructive": True,
            "rate_limit_rps": rate_limit,
            "prod_touch_requires_approval": True,
            "approval_required_phases": ["exploitation", "post-exploitation"],
        },
        "oob": {"collaborator": oob or ""},
        "notes": notes or "Written authorization on file before the window opens.",
    }


def scaffold(repo_root: Path, fields: dict, *, operator: str, force: bool = False) -> Path:
    eid = fields["engagement"]
    eng_dir = repo_root / "engagements" / eid
    if (eng_dir / "scope.yaml").exists() and not force:
        raise FileExistsError(f"engagement already exists: {eng_dir} (use --force to overwrite scope)")
    for sub in ("", "runtime", "findings", "findings/evidence", "findings/poc", "reviews"):
        (eng_dir / sub).mkdir(parents=True, exist_ok=True)

    (eng_dir / "scope.yaml").write_text(yamlio.render_scope_yaml(fields), encoding="utf-8")

    auth = {
        "engagement": eid,
        "authorized_by": fields["authorized_by"],
        "operator_confirmed": True,
        "operator": operator,
        "confirmed_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "confirmation": "operator asserted written authorization is on file at launcher init",
        "cli_version": __version__,
    }
    (eng_dir / "runtime" / "authorization.json").write_text(
        json.dumps(auth, indent=2) + "\n", encoding="utf-8"
    )
    return eng_dir
