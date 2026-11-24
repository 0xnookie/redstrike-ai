"""Run-completion notifications for long autonomous engagements — with HARD evidence redaction.

A long autonomous run can take hours across many resumed legs. This module lets the operator
receive a short, REDACTED run summary at a GENERIC outbound webhook when a run finishes — so they
do not have to babysit the console. It is wired to three signals the post-run path already has:

  * ``runloop``'s ``emit`` callback — the loop's own status lines (collected via ``Collector``);
  * the ``runtime/diagnostics.json`` OUTCOME record (produced-findings / clean-tested /
    degraded-empty / failed, plus the degraded reason + cost + stop reason);
  * the engagement's ACCEPTED Critical/High findings (title + class only — never the evidence).

CONFIG is deliberately GENERIC and default-OFF:
  * a webhook URL + an optional JSON payload TEMPLATE (``${var}`` placeholders) — nothing else;
  * no webhook configured ⇒ this is a complete no-op (``notify_run`` returns skipped).
  Config source (first match wins): ``<engagement>/notify.json`` (operator-authored, gitignored
  under engagements/), else the ``REDSTRIKE_NOTIFY_WEBHOOK`` (+ ``REDSTRIKE_NOTIFY_TEMPLATE`` /
  ``REDSTRIKE_NOTIFY_MIN_SEVERITY``) environment variables. The template is a plain JSON object the
  operator shapes for whatever generic inbound webhook they run — there are NO vendor-named keys.

THE REDACTION GUARANTEE (why no secret can leave)
  ``redact_payload`` is a HARD pre-send filter run over the FULLY-RENDERED payload immediately
  before the POST — the single choke point every outbound byte passes through. It reuses the
  engagement audit redactor (``audit.redact_text``: PEM keys, JWTs, crypt/NTLM hashes, bearer
  tokens, credential-ish key=value pairs) AND a second evidence-shaped pass (token/session/api-key/
  password/secret/authorization assignments, Cookie / Set-Cookie headers, and any long base64-ish
  run). Because it runs on the final structure, a secret cannot leave even if a template, a finding
  title or a collected log line smuggled one in. A pentest tool must never exfiltrate a secret it
  captured, so redaction is non-optional and cannot be configured off.

Stdlib only (``urllib.request`` for the POST). The POST is injectable (``post=``) for tests, and
every failure is swallowed — a notification can never break or alter a run.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import audit as auditmod
from . import ui

# --- outcome / severity vocab (kept local so notifier has no import weight) ---
_ACCEPTED_STATUSES = frozenset({"verified", "accepted", "remediated"})
_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_DEFAULT_MIN_SEVERITY = "high"   # accepted Critical/High findings by default
_DEFAULT_TIMEOUT = 10

# A GENERIC default payload (plain JSON, no vendor-named keys). A `${var}` value that is the WHOLE
# string is substituted with the TYPED value (int/float/list), so counts stay numeric; a placeholder
# embedded in a longer string is interpolated as text.
DEFAULT_TEMPLATE = {
    "text": "Redstrike run ${engagement}: ${outcome} — ${findings_count} accepted finding(s), "
            "${critical_high_count} Critical/High",
    "engagement": "${engagement}",
    "outcome": "${outcome}",
    "reason": "${degraded_reason}",
    "findings_count": "${findings_count}",
    "critical_high_count": "${critical_high_count}",
    "critical_high": "${critical_high}",
    "invocations": "${invocations}",
    "cost_usd": "${cost_usd}",
    "stop_reason": "${stop_reason}",
    "generated_at": "${generated_at}",
}


# --- emit-callback collector (the runloop hook) ------------------------------
class Collector:
    """Tees ``runloop``'s ``emit`` callback: forwards each line to the real emit (so the console
    still sees it) AND keeps a bounded tail for the run summary. The captured lines are redacted
    only at send time (``build_summary`` → ``redact_payload``), never stored anywhere."""

    def __init__(self, maxlines: int = 200):
        self.lines: list[str] = []
        self._max = max(1, int(maxlines))

    def tee(self, downstream=None):
        def _emit(line):
            try:
                self.lines.append(str(line))
                if len(self.lines) > self._max:
                    del self.lines[0]
            except Exception:
                pass
            if downstream is not None:
                downstream(line)
        return _emit


# --- HARD pre-send redaction (the choke point) -------------------------------
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
# Evidence-shaped patterns layered OVER audit.redact_text, so an outbound payload is stripped of the
# obvious secret shapes even if they rode in via a template / finding title / collected log line.
_EXTRA_PATTERNS = [
    (re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-+/=]{6,}"), r"\1 **REDACTED**"),
    (re.compile(r"(?i)\b(token|session[_-]?id|api[_-]?key|apikey|password|passwd|pwd|secret|"
                r"authorization|auth[_-]?token|access[_-]?token|refresh[_-]?token)\b\s*[:=]\s*"
                r"[^\s,;}\"']+"), r"\1=**REDACTED**"),
    (re.compile(r"(?i)\b(set-cookie|cookie)\s*:\s*[^\s,;]+"), r"\1: **REDACTED**"),
    # Any long base64/token-ish run (catches opaque tokens the structured patterns miss).
    (re.compile(r"[A-Za-z0-9+/=_-]{40,}"), "**REDACTED**"),
]


def sanitize_text(text) -> str:
    """Redact credential/secret material from one string: the engagement audit redactor first, then
    the evidence-shaped passes above. Idempotent and never raises."""
    if text is None:
        return ""
    s = str(text)
    if not s:
        return s
    s = _ANSI_RE.sub("", s)
    try:
        s = auditmod.redact_text(s)
    except Exception:
        pass
    for pat, repl in _EXTRA_PATTERNS:
        s = pat.sub(repl, s)
    return s


def redact_payload(obj):
    """HARD pre-send filter: deep-copy ``obj`` with EVERY string value sanitized. Dict keys are left
    as-is (they are template-authored, not data); non-strings pass through unchanged. This is the
    final gate before any outbound POST."""
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, dict):
        return {k: redact_payload(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_payload(v) for v in obj]
    return obj


# --- config (default OFF) ----------------------------------------------------
def _valid_webhook(url: str) -> bool:
    return isinstance(url, str) and url.strip().lower().startswith(("http://", "https://"))


def _load_template_env(val: str):
    """REDSTRIKE_NOTIFY_TEMPLATE is either inline JSON or a path to a JSON file."""
    val = (val or "").strip()
    if not val:
        return None
    try:
        return json.loads(val)
    except Exception:
        pass
    try:
        return json.loads(Path(val).read_text(encoding="utf-8"))
    except Exception:
        return None


def load_config(eng_dir, env=None) -> dict | None:
    """Resolve the notifier config, or None when notifications are OFF (the default).

    Precedence: an explicit ``<engagement>/notify.json`` (operator-authored, richer) wins; otherwise
    the ``REDSTRIKE_NOTIFY_WEBHOOK`` env var (with optional ``REDSTRIKE_NOTIFY_TEMPLATE`` and
    ``REDSTRIKE_NOTIFY_MIN_SEVERITY``). Returns None unless a VALID http(s) webhook URL is present."""
    env = os.environ if env is None else env
    cfg: dict | None = None

    cfg_path = Path(eng_dir) / "notify.json"
    if cfg_path.is_file():
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg = loaded
        except Exception:
            cfg = None

    if cfg is None:
        url = (env.get("REDSTRIKE_NOTIFY_WEBHOOK") or "").strip()
        if not url:
            return None
        cfg = {"webhook_url": url}
        tmpl = _load_template_env(env.get("REDSTRIKE_NOTIFY_TEMPLATE", ""))
        if tmpl is not None:
            cfg["payload_template"] = tmpl
        minsev = (env.get("REDSTRIKE_NOTIFY_MIN_SEVERITY") or "").strip().lower()
        if minsev:
            cfg["min_severity"] = minsev

    url = str(cfg.get("webhook_url") or "").strip()
    if not _valid_webhook(url):
        return None
    out: dict = {"webhook_url": url}
    tmpl = cfg.get("payload_template")
    out["payload_template"] = tmpl if isinstance(tmpl, (dict, list, str)) and tmpl else None
    notify_on = cfg.get("notify_on")
    out["notify_on"] = [str(x) for x in notify_on] if isinstance(notify_on, list) and notify_on else None
    ms = str(cfg.get("min_severity") or _DEFAULT_MIN_SEVERITY).strip().lower()
    out["min_severity"] = ms if ms in _SEVERITY_ORDER else _DEFAULT_MIN_SEVERITY
    try:
        out["timeout"] = int(cfg.get("timeout") or _DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        out["timeout"] = _DEFAULT_TIMEOUT
    return out


# --- findings (accepted Critical/High) ---------------------------------------
def _read_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def _flat_findings(doc) -> list[dict]:
    if isinstance(doc, list):
        return [f for f in doc if isinstance(f, dict)]
    if isinstance(doc, dict):
        return [f for f in (list(doc.get("findings") or []) + list(doc.get("attack_chains") or []))
                if isinstance(f, dict)]
    return []


def load_findings(eng_dir) -> list[dict]:
    """The engagement's findings: the top-level findings.json when present, else the per-skill
    ``*/findings.json`` union (mirrors runloop's authoritative-findings discovery)."""
    eng = Path(eng_dir)
    root = _read_json(eng / "findings.json")
    if root is not None:
        return _flat_findings(root)
    acc: list[dict] = []
    for p in sorted(eng.glob("*/findings.json")):
        acc.extend(_flat_findings(_read_json(p)))
    return acc


def _severity_set(min_severity: str | None) -> frozenset:
    ms = (min_severity or _DEFAULT_MIN_SEVERITY).strip().lower()
    if ms not in _SEVERITY_ORDER:
        ms = _DEFAULT_MIN_SEVERITY
    i = _SEVERITY_ORDER.index(ms)
    return frozenset(_SEVERITY_ORDER[i:])


def accepted_findings_count(findings: list) -> int:
    return sum(1 for f in findings if isinstance(f, dict)
               and str(f.get("status", "")).lower() in _ACCEPTED_STATUSES)


def critical_high_lines(findings: list, min_severity: str | None = None) -> list[str]:
    """Redacted one-liners for accepted findings at/above ``min_severity`` (default High): severity
    + class + title ONLY. No evidence, request/response, URL or PoC — and each line is sanitized."""
    want = _severity_set(min_severity)
    out: list[str] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        if str(f.get("status", "")).lower() not in _ACCEPTED_STATUSES:
            continue
        sev = str(f.get("severity", "")).lower()
        if sev not in want:
            continue
        cls = str(f.get("class") or f.get("category") or f.get("type") or "?")
        title = str(f.get("title") or f.get("name") or "").strip()
        line = f"[{sev.upper()}] {cls}" + (f" — {title}" if title else "")
        out.append(sanitize_text(line))
    return out


# --- summary (built from the diagnostics record + loop + findings) -----------
def _loop_attr(loop, name, default=None):
    return getattr(loop, name, default) if loop is not None else default


def build_summary(eng_dir, record: dict, *, loop=None, run_log=None,
                  min_severity: str | None = None) -> dict:
    """Assemble the (pre-redaction) substitution variables from the diagnostics OUTCOME record, the
    loop result, and the accepted Critical/High findings. ``redact_payload`` is still applied to the
    rendered payload, so this is the single source of the summary but never the last redaction pass."""
    eng = Path(eng_dir)
    record = record or {}
    findings = load_findings(eng)
    ms = min_severity or record.get("_min_severity") or _DEFAULT_MIN_SEVERITY
    ch = critical_high_lines(findings, ms)
    fcount = int(record.get("findings_count", accepted_findings_count(findings)) or 0)

    cost = _loop_attr(loop, "cumulative_cost")
    stop = _loop_attr(loop, "reason") or record.get("outcome", "")
    invocations = _loop_attr(loop, "invocations")
    log_tail = ""
    if run_log:
        tail = [sanitize_text(ln) for ln in list(run_log)[-8:]]
        log_tail = "\n".join(t for t in tail if t.strip())

    return {
        "engagement": eng.name,
        "outcome": record.get("outcome", ""),
        "degraded_reason": record.get("degraded_reason") or "",
        "findings_count": fcount,
        "critical_high_count": len(ch),
        "critical_high": ch,
        "critical_high_summary": "; ".join(ch),
        "invocations": invocations,
        "cost_usd": (round(float(cost), 4) if cost is not None else None),
        "stop_reason": stop,
        "run_log_tail": log_tail,
        "generated_at": record.get("ended") or _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }


# --- payload rendering (${var} substitution) ---------------------------------
_PLACEHOLDER = re.compile(r"\$\{(\w+)\}")
_LONE = re.compile(r"^\s*\$\{(\w+)\}\s*$")


def _subst_string(s: str, summary: dict) -> str:
    return _PLACEHOLDER.sub(lambda m: "" if summary.get(m.group(1)) is None
                            else str(summary.get(m.group(1))), s)


def render_payload(template, summary: dict):
    """Render a template with ``${var}`` substitution. A value that is EXACTLY a single placeholder
    yields the TYPED value (int/float/list/str/None — counts stay numeric); a placeholder inside a
    longer string is interpolated as text. Recurses dict/list."""
    if isinstance(template, str):
        m = _LONE.match(template)
        if m:
            return summary.get(m.group(1))
        return _subst_string(template, summary)
    if isinstance(template, dict):
        return {k: render_payload(v, summary) for k, v in template.items()}
    if isinstance(template, (list, tuple)):
        return [render_payload(v, summary) for v in template]
    return template


# --- outbound POST (stdlib; injectable) --------------------------------------
def _mask_url(url: str) -> str:
    """Log-safe webhook URL: keep scheme + host, mask the path (webhook tokens often ride the path)."""
    try:
        from urllib.parse import urlsplit
        p = urlsplit(url)
        host = p.hostname or "?"
        return f"{p.scheme}://{host}/…" if p.path not in ("", "/") else f"{p.scheme}://{host}/"
    except Exception:
        return "the configured webhook"


def post_webhook(url: str, payload, *, timeout: int = _DEFAULT_TIMEOUT, post=None) -> tuple[bool, str]:
    """POST the JSON ``payload`` to ``url``. ``post`` (``(url, payload) -> (ok, detail)``) is a test
    seam; when None a stdlib ``urllib`` POST is made. Never raises — returns ``(ok, detail)``."""
    if post is not None:
        try:
            return post(url, payload)
        except Exception as e:  # a test/injected poster must never break the run either
            return False, f"{type(e).__name__}: {e}"
    if not _valid_webhook(url):
        return False, "invalid webhook URL (must be http/https)"
    import urllib.error
    import urllib.request
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "redstrike-notifier/1"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — operator-configured
            code = getattr(resp, "status", None) or getattr(resp, "code", "")
            return True, f"HTTP {code}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# --- result + orchestration --------------------------------------------------
@dataclass
class NotifyResult:
    sent: bool = False
    skipped: bool = False
    reason: str = ""
    status: str = ""
    payload: dict | None = field(default=None, repr=False)   # the REDACTED payload (for tests/inspection)


def notify_run(eng_dir, record: dict, *, loop=None, run_log=None, config=None,
               post=None, emit=None, env=None) -> NotifyResult:
    """Build, redact and send the run-completion notification.

    No-op (``skipped``) when no webhook is configured — notifications are OFF by default. Honors an
    optional ``notify_on`` outcome filter. The payload is ALWAYS passed through ``redact_payload``
    before the POST. Never raises; a POST failure is surfaced as one warning and the run is
    unaffected."""
    emit = emit or (lambda _line: None)
    try:
        cfg = config if config is not None else load_config(eng_dir, env=env)
    except Exception:
        cfg = None
    if not cfg:
        return NotifyResult(skipped=True, reason="notifications OFF (no webhook configured)")

    outcome = str((record or {}).get("outcome", ""))
    notify_on = cfg.get("notify_on")
    if notify_on and outcome not in notify_on:
        return NotifyResult(skipped=True,
                            reason=f"outcome '{outcome}' not in the configured notify_on filter")

    try:
        summary = build_summary(eng_dir, record, loop=loop, run_log=run_log,
                                min_severity=cfg.get("min_severity"))
        template = cfg.get("payload_template") or DEFAULT_TEMPLATE
        payload = render_payload(template, summary)
        payload = redact_payload(payload)   # HARD pre-send filter — the one choke point
    except Exception as e:
        emit(ui.warn(f"run notification not sent — could not build payload ({type(e).__name__}); "
                     f"the run is unaffected"))
        return NotifyResult(sent=False, reason=f"build-error: {type(e).__name__}: {e}")

    ok, detail = post_webhook(cfg["webhook_url"], payload, timeout=cfg.get("timeout", _DEFAULT_TIMEOUT),
                              post=post)
    if ok:
        emit(ui.ok(f"run notification sent → {_mask_url(cfg['webhook_url'])} ({detail}) · "
                   f"redacted summary, no secrets"))
        return NotifyResult(sent=True, reason="sent", status=detail, payload=payload)
    emit(ui.warn(f"run notification failed ({detail}) — continuing; the run is unaffected"))
    return NotifyResult(sent=False, reason=detail, status=detail, payload=payload)
