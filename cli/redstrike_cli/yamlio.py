"""Minimal YAML read + scope.yaml render, stdlib-only.

`load()` prefers PyYAML when installed and otherwise uses a small reader that
handles exactly the constructs Redstrike's scope.yaml uses (2-level maps, simple
sequences, scalars, inline `[]`, block `>`/`|`). The fallback is covered by a unit
test that diffs it against PyYAML on the real template, so it is proven, not assumed.
`render_scope_yaml()` writes scope.yaml from a template string — no YAML lib needed.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T")
_INT = re.compile(r"-?\d+$")
_FLOAT = re.compile(r"-?\d+\.\d+$")


def load(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
    except ImportError:
        return _mini_load(text)
    data = yaml.safe_load(text)
    return data or {}


# --- stdlib fallback reader ------------------------------------------------
def _strip_comment(s: str) -> str:
    out, q, esc = [], None, False
    for ch in s:
        if q:
            out.append(ch)
            if esc:
                esc = False                 # this char was escaped — consume it literally
            elif ch == "\\" and q == '"':
                esc = True                  # backslash escape inside a double-quoted scalar
            elif ch == q:
                q = None
        elif ch in ('"', "'"):
            q = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _unescape_double_quoted(s: str) -> str:
    """Decode the escapes a double-quoted YAML scalar carries (the ones `render_scope_yaml`'s `_q`
    emits, plus the common C-style ones): ``\\\\`` ``\\"`` ``\\n`` ``\\r`` ``\\t``. Keeps this
    stdlib fallback reader in step with PyYAML so an escaped value round-trips to the exact original
    (scope.yaml is re-parsed to drive the scope gate — a dropped escape would mangle an entry)."""
    if "\\" not in s:
        return s
    out: list[str] = []
    i, n = 0, len(s)
    _esc = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
    while i < n:
        ch = s[i]
        if ch == "\\" and i + 1 < n:
            out.append(_esc.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _scalar(v: str) -> Any:
    v = v.strip()
    if v in ("", "~") or v.lower() == "null":
        return None
    if v == "[]":
        return []
    if v == "{}":
        return {}
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return _unescape_double_quoted(v[1:-1])
    if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
        return v[1:-1]
    low = v.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if _TS.match(v):
        return v
    if _INT.match(v):
        return int(v)
    if _FLOAT.match(v):
        return float(v)
    return v


def _mini_load(text: str) -> dict:
    lines = text.split("\n")
    n = len(lines)

    def indent(i: int) -> int:
        return len(lines[i]) - len(lines[i].lstrip(" "))

    def skip(i: int) -> int:
        while i < n:
            s = lines[i].strip()
            if s == "" or s.startswith("#"):
                i += 1
            else:
                return i
        return i

    def parse_map(i: int, base: int) -> tuple[dict, int]:
        result: dict = {}
        while True:
            i = skip(i)
            if i >= n or indent(i) < base:
                break
            if indent(i) > base:  # defensive: unexpected deeper line
                i += 1
                continue
            line = _strip_comment(lines[i].strip())
            if line.startswith("- ") or line == "-":
                break
            if ":" not in line:
                i += 1
                continue
            key, _, rest = line.partition(":")
            key, rest = key.strip(), rest.strip()
            i += 1
            if rest in (">", "|"):
                body, blk = [], rest
                while i < n and (lines[i].strip() == "" or indent(i) > base):
                    body.append(lines[i].strip())
                    i += 1
                sep = " " if blk == ">" else "\n"
                result[key] = sep.join(b for b in body if b != "").strip()
            elif rest == "":
                j = skip(i)
                if j < n and indent(j) > base:
                    nxt = _strip_comment(lines[j].strip())
                    if nxt.startswith("- ") or nxt == "-":
                        result[key], i = parse_seq(j, indent(j))
                    else:
                        result[key], i = parse_map(j, indent(j))
                else:
                    result[key] = None
            else:
                result[key] = _scalar(rest)
        return result, i

    def parse_seq(i: int, base: int) -> tuple[list, int]:
        items: list = []
        while True:
            i = skip(i)
            if i >= n or indent(i) < base:
                break
            line = _strip_comment(lines[i].strip())
            if not (line.startswith("- ") or line == "-"):
                break
            val = line[1:].strip()
            i += 1
            items.append(_scalar(val) if val else None)
        return items, i

    data, _ = parse_map(skip(0), 0)
    return data


# --- scope.yaml render -----------------------------------------------------
def _q(value: Any) -> str:
    """Escape ``value`` into a VALID double-quoted YAML scalar: backslash, double-quote and the
    control chars (newline / carriage-return / tab). scope.yaml is the signed canonical authorization
    record that `load` re-parses to drive the scope gate, so an unescaped ``"`` / ``\\`` / newline in
    a free-text field (``authorized_by``, ``engagement``, ``notes``, a domain/URL, ``source.*`` …)
    would produce malformed YAML and silently drop or mangle an entry. Round-trips back via `load`."""
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return f'"{s}"'


def _yaml_list(items: list[str], indent: str) -> str:
    if not items:
        return " []"
    return "\n" + "\n".join(f"{indent}- {_q(s)}" for s in items)


def render_scope_yaml(fields: dict) -> str:
    """Produce a scope.yaml string from collected fields (stdlib, no YAML lib)."""
    ins = fields.get("in_scope", {})
    out = fields.get("out_of_scope", {})
    rules = fields.get("rules", {})
    phases = rules.get("approval_required_phases", ["exploitation", "post-exploitation"])
    phase_block = "\n".join(f"    - {p}" for p in phases)
    src = fields.get("source") or {}
    # White-box source audit: the shared `source:` block. Its PRESENCE marks the engagement
    # source-granted (the orchestrator runs the white-box pipeline). Emitted before `notes:` so
    # `notes:` stays last; absent for ordinary black-box engagements.
    source_block = ""
    if src:
        source_block = (
            "\nsource:                 # white-box: audit the cloned repo at this commit\n"
            f"  repo_url: {_q(src.get('repo_url', ''))}\n"
            f"  local_path: {_q(src.get('local_path', 'source/'))}\n"
            f"  commit: {_q(src.get('commit', ''))}\n"
            f"  branch: {_q(src.get('branch', ''))}\n"
        )
    return f"""# Per-engagement scope & rules of engagement. Authored by the `redstrike` CLI.
# The RoE gate (_contract/roe-gate.md) reads this before any ACTIVE action;
# out-of-scope / closed-window => HARD STOP. This file is the signed canonical
# authorization record; runtime/scope.json is a generated machine projection.

engagement: {_q(fields['engagement'])}
authorized_by: {_q(fields['authorized_by'])}
window:
  start: {fields['window']['start']}
  end:   {fields['window']['end']}

in_scope:
  domains:{_yaml_list(ins.get('domains', []), '    ')}
  cidrs:{_yaml_list(ins.get('cidrs', []), '    ')}
  urls:{_yaml_list(ins.get('urls', []), '    ')}

out_of_scope:          # explicit excludes always win over in_scope
  domains:{_yaml_list(out.get('domains', []), '    ')}
  cidrs:{_yaml_list(out.get('cidrs', []), '    ')}

rules:
  no_dos: {str(rules.get('no_dos', True)).lower()}
  no_destructive: {str(rules.get('no_destructive', True)).lower()}
  rate_limit_rps: {rules.get('rate_limit_rps', 20)}
  lockout_threshold: {rules.get('lockout_threshold', 5)}   # cap auth attempts/account under this to avoid lockout
  prod_touch_requires_approval: {str(rules.get('prod_touch_requires_approval', True)).lower()}
  approval_required_phases:
{phase_block}

oob:
  collaborator: {_q(fields.get('oob', {}).get('collaborator', ''))}
{source_block}
notes: {_q(fields.get('notes', 'Written authorization on file before the window opens.'))}
"""
