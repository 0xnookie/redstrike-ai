#!/usr/bin/env python3
"""structvalidate.py -- a tiny, stdlib-only STRUCTURAL validator for the _contract schemas.

The repo deliberately avoids a third-party JSON-Schema dependency (scripts/validate.py already
hand-rolls its structural checks). This module is the shared, reusable version of that style: it
walks a value against a `skills/_contract/*.schema.json` subset and returns a **non-throwing** list
of violations instead of raising. scripts/console.py uses it at serve time to attach a non-fatal
`_contract_violations[]` to each engagement artifact it serves, so a producer that drifts from a
schema (the js-analysis library->name / provider->provider_meta drift that broke the console) is
caught and surfaced instead of silently poisoning the payload.

Each violation is a plain dict (JSON-serializable, so it can ride along in the served payload):

    {"path": "sites[0].libraries[2].name", "expected": "<what the schema wanted>", "got": "<what was there>"}

Supported JSON-Schema keywords (a pragmatic subset — enough for the _contract schemas):
  type (incl. a list of types), enum, const, required, properties, additionalProperties
  (bool or subschema), patternProperties, items (single subschema), $ref (local "#/..." only),
  $defs/definitions, anyOf, allOf, oneOf, minimum, maximum, exclusiveMinimum, exclusiveMaximum,
  minItems, maxItems, minLength, maxLength, pattern. `format` is advisory and NOT enforced.

Two modes:
  * strict  (default) -- enforce `required`, `additionalProperties:false`, and `pattern`. Used for the
    js-analysis findings streams so the CANONICAL field names stay locked (a drifted alias key shows
    up as an unexpected-property violation; a missing identity key shows as a missing-required one).
  * lenient (lenient=True) -- skip `required`, `additionalProperties:false`, and `pattern`; only check
    the type / enum / const / numeric-range / length of the fields that ARE present. Used for schemas
    that are intentionally tolerant or are being extended concurrently (host_discovery, notebook,
    cve_intel, coverage_ledger, diagnostics): a benign extra key or a not-yet-written field never
    flags, but a genuinely wrong type/enum still does.

Nothing here raises on malformed input or a malformed schema: a bad schema node is reported as a
violation (or ignored) so the caller — a read-only console — can never be taken down by validation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_MAX_VIOLATIONS = 250  # hard cap so a pathologically-wrong payload can't produce an unbounded list


def _typename(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return type(v).__name__


def _matches_type(v, t: str) -> bool:
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if t == "string":
        return isinstance(v, str)
    if t == "boolean":
        return isinstance(v, bool)
    if t == "object":
        return isinstance(v, dict)
    if t == "array":
        return isinstance(v, list)
    if t == "null":
        return v is None
    return True  # unknown type token -> don't flag


def _short(v, limit: int = 60) -> str:
    try:
        s = v if isinstance(v, str) else json.dumps(v, default=str)
    except Exception:
        s = str(v)
    s = s.replace("\n", " ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


class _Validator:
    def __init__(self, root_schema: dict, lenient: bool):
        self.root = root_schema if isinstance(root_schema, dict) else {}
        self.lenient = lenient
        self.violations: list[dict] = []
        self._capped = False

    def _add(self, path: str, expected: str, got: str) -> None:
        if len(self.violations) >= _MAX_VIOLATIONS:
            if not self._capped:
                self._capped = True
                self.violations.append({
                    "path": path or "$",
                    "expected": f"<= {_MAX_VIOLATIONS} violations",
                    "got": "more violations (truncated)",
                })
            return
        self.violations.append({"path": path or "$", "expected": expected, "got": got})

    def _resolve(self, schema):
        """Follow local "#/..." $refs (bounded, cycle-safe)."""
        seen = 0
        while isinstance(schema, dict) and "$ref" in schema and seen < 32:
            ref = schema["$ref"]
            seen += 1
            if not isinstance(ref, str) or not ref.startswith("#"):
                return schema  # external refs unsupported -> treat as open
            node = self.root
            for part in ref.lstrip("#/").split("/"):
                if not part:
                    continue
                part = part.replace("~1", "/").replace("~0", "~")
                if isinstance(node, dict) and part in node:
                    node = node[part]
                else:
                    return {}  # dangling ref -> open (don't flag the data for a schema bug)
            schema = node
        return schema

    def check(self, value, schema, path: str) -> None:
        if self._capped:
            return
        schema = self._resolve(schema)
        if not isinstance(schema, dict) or schema is True:
            return
        if schema is False:
            self._add(path, "no value allowed here", _typename(value))
            return

        # combinators ---------------------------------------------------------
        if "anyOf" in schema and isinstance(schema["anyOf"], list):
            self._combinator(value, schema["anyOf"], path, need=1, label="anyOf")
        if "oneOf" in schema and isinstance(schema["oneOf"], list):
            self._combinator(value, schema["oneOf"], path, need=1, label="oneOf")
        if "allOf" in schema and isinstance(schema["allOf"], list):
            for sub in schema["allOf"]:
                self.check(value, sub, path)

        # type ----------------------------------------------------------------
        t = schema.get("type")
        if t is not None:
            types = t if isinstance(t, list) else [t]
            if not any(_matches_type(value, str(x)) for x in types):
                self._add(path, "type " + "|".join(str(x) for x in types), _typename(value))
                return  # a wrong base type makes deeper checks meaningless

        # enum / const --------------------------------------------------------
        if "enum" in schema and isinstance(schema["enum"], list):
            if value not in schema["enum"]:
                self._add(path, "one of " + _short(schema["enum"], 90), _short(value))
        if "const" in schema and value != schema["const"]:
            self._add(path, "const " + _short(schema["const"]), _short(value))

        # scalars -------------------------------------------------------------
        if isinstance(value, str):
            self._check_string(value, schema, path)
        elif isinstance(value, bool):
            pass
        elif isinstance(value, (int, float)):
            self._check_number(value, schema, path)
        elif isinstance(value, list):
            self._check_array(value, schema, path)
        elif isinstance(value, dict):
            self._check_object(value, schema, path)

    def _combinator(self, value, branches, path, need, label) -> None:
        best = None
        for sub in branches:
            probe = _Validator(self.root, self.lenient)
            probe.check(value, sub, path)
            if not probe.violations:
                return  # satisfied
            if best is None or len(probe.violations) < len(best):
                best = probe.violations
        # none matched -> surface the closest branch's violations (most actionable)
        if best is not None:
            for v in best:
                self._add(v["path"], v["expected"], v["got"])
        else:
            self._add(path, f"{label} match", _typename(value))

    def _check_string(self, value: str, schema: dict, path: str) -> None:
        mn, mx = schema.get("minLength"), schema.get("maxLength")
        if isinstance(mn, int) and len(value) < mn:
            self._add(path, f"minLength {mn}", f"length {len(value)}")
        if isinstance(mx, int) and len(value) > mx:
            self._add(path, f"maxLength {mx}", f"length {len(value)}")
        pat = schema.get("pattern")
        if pat and not self.lenient:
            try:
                if re.search(pat, value) is None:
                    self._add(path, f"match /{pat}/", _short(value))
            except re.error:
                pass  # bad pattern in schema -> don't blame the data

    def _check_number(self, value, schema: dict, path: str) -> None:
        mn, mx = schema.get("minimum"), schema.get("maximum")
        emn, emx = schema.get("exclusiveMinimum"), schema.get("exclusiveMaximum")
        if isinstance(mn, (int, float)) and value < mn:
            self._add(path, f">= {mn}", str(value))
        if isinstance(mx, (int, float)) and value > mx:
            self._add(path, f"<= {mx}", str(value))
        if isinstance(emn, (int, float)) and value <= emn:
            self._add(path, f"> {emn}", str(value))
        if isinstance(emx, (int, float)) and value >= emx:
            self._add(path, f"< {emx}", str(value))

    def _check_array(self, value: list, schema: dict, path: str) -> None:
        mn, mx = schema.get("minItems"), schema.get("maxItems")
        if isinstance(mn, int) and len(value) < mn:
            self._add(path, f"minItems {mn}", f"{len(value)} items")
        if isinstance(mx, int) and len(value) > mx:
            self._add(path, f"maxItems {mx}", f"{len(value)} items")
        items = schema.get("items")
        if isinstance(items, dict):
            for i, el in enumerate(value):
                if self._capped:
                    return
                self.check(el, items, f"{path}[{i}]")

    def _check_object(self, value: dict, schema: dict, path: str) -> None:
        props = schema.get("properties") or {}
        pattern_props = schema.get("patternProperties") or {}
        if not self.lenient:
            for req in schema.get("required", []) or []:
                if req not in value:
                    self._add(_join(path, req), "required property", "missing")
        addl = schema.get("additionalProperties", True)
        for key, val in value.items():
            kp = _join(path, key)
            if key in props:
                self.check(val, props[key], kp)
                continue
            matched = False
            for rx, subs in pattern_props.items():
                try:
                    if re.search(rx, key):
                        matched = True
                        self.check(val, subs, kp)
                except re.error:
                    pass
            if matched:
                continue
            if addl is False:
                if not self.lenient:
                    self._add(kp, "no additional property", f"unexpected key '{key}'")
            elif isinstance(addl, dict):
                self.check(val, addl, kp)


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def typename(v) -> str:
    """Public JSON type name for a value (object/array/string/integer/number/boolean/null)."""
    return _typename(v)


def validate(value, schema, *, lenient: bool = False) -> list[dict]:
    """Validate `value` against `schema`; return a list of {path, expected, got} dicts.

    Never raises. An empty list means clean. See the module docstring for the keyword subset and the
    strict-vs-lenient semantics."""
    try:
        v = _Validator(schema, lenient)
        v.check(value, schema, "")
        return v.violations
    except Exception as exc:  # noqa: BLE001 -- a validator must never take the caller down
        return [{"path": "$", "expected": "validatable value", "got": f"validator error: {exc}"}]


# --- schema loading (console.py imports this) -------------------------------
_SCHEMA_CACHE: dict[str, dict] = {}


def load_schema(contract_dir, filename: str):
    """Load and cache a `_contract/<filename>` schema; return the parsed dict or None."""
    key = str(filename)
    if key in _SCHEMA_CACHE:
        return _SCHEMA_CACHE[key]
    try:
        p = Path(contract_dir) / filename
        obj = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        obj = None
    _SCHEMA_CACHE[key] = obj if isinstance(obj, dict) else None
    return _SCHEMA_CACHE[key]


def selftest() -> None:
    """Deterministic self-check (wired into scripts/validate.py)."""
    # 1. clean object against a strict schema
    schema = {
        "type": "object",
        "required": ["name"],
        "additionalProperties": False,
        "properties": {
            "name": {"type": "string"},
            "line": {"type": "integer"},
            "severity": {"enum": ["info", "low", "high"]},
            "cves": {"type": "array", "items": {"type": "string"}},
        },
    }
    assert validate({"name": "next", "line": 0, "severity": "info"}, schema) == [], "clean should pass"

    # 2. the js-analysis drift: `library` instead of `name`, `note` not in the schema
    drift = validate({"library": "next", "note": "x"}, schema)
    paths = {v["path"] for v in drift}
    assert "name" in paths, "missing required `name` must be caught"
    assert any(p in paths for p in ("library", "note")), "drifted alias key must be caught"

    # 3. type / enum / range violations
    bad = validate({"name": 5, "line": "zero", "severity": "critical"}, schema)
    bp = {v["path"] for v in bad}
    assert {"name", "line", "severity"} <= bp, f"type/enum must be caught, got {bp}"

    # 4. lenient mode: tolerate missing-required + extra key, still catch a wrong type
    len_clean = validate({"extra": 1}, schema, lenient=True)
    assert len_clean == [], f"lenient should ignore required+additional, got {len_clean}"
    len_bad = validate({"line": "nope"}, schema, lenient=True)
    assert {v["path"] for v in len_bad} == {"line"}, "lenient still catches a present wrong type"

    # 5. numeric range (epss 0..1) + bool-is-not-integer
    rng = {"type": "object", "properties": {"epss": {"type": "number", "minimum": 0, "maximum": 1}}}
    assert validate({"epss": 0.85}, rng) == []
    assert validate({"epss": 1.5}, rng), "out-of-range must be caught"
    assert validate({"line": True}, {"properties": {"line": {"type": "integer"}}}), "bool != integer"

    # 6. $ref + anyOf
    refd = {
        "$defs": {"row": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}},
        "type": "array",
        "items": {"$ref": "#/$defs/row"},
    }
    assert validate([{"id": "a"}, {"id": "b"}], refd) == []
    assert validate([{"id": "a"}, {"nope": 1}], refd), "ref'd required must be caught"
    anyof = {"anyOf": [{"type": "array"}, {"type": "object", "required": ["findings"]}]}
    assert validate([1, 2], anyof) == []
    assert validate({"findings": []}, anyof) == []
    assert validate({"nope": 1}, anyof), "no anyOf branch should fail"

    print("structvalidate selftest: PASS")


if __name__ == "__main__":
    selftest()
