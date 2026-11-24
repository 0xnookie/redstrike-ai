#!/usr/bin/env python3
"""
bench_labgen.py -- CVE-KB-seeded LABELED-LAB generator (MVP).

Redstrike's one measured weakness: it has a benchmark SCORECARD (scripts/benchmark.py) but few/no
LABELLED targets to run it against. A twin reconstructed from a LIVE target has UNKNOWN ground truth
(unlabelled). A lab seeded from the cached CVE knowledge-base is instead SELF-LABELLING: stand up
`component@known-vulnerable-version` and THE CVE IS THE LABEL (the known answer). That turns the
cve_kb.jsonl redstrike already produces (skills/_contract/cve_kb.schema.json) into labelled benchmark
fixtures the harness can finally score for real recall/precision numbers.

This generator reads a cve_kb.jsonl (and/or a cve_intel.json) and, for each entry that is lab-able
(a valid CVE id + a component + a PINNABLE version + a weakness class), emits under benchmark/labs/<slug>/:

  * docker-compose.yml  -- a BEST-EFFORT scaffold standing up the vulnerable component@version (+ minimal
                           backing services when the component implies them). Deterministic from the metadata.
  * answer_key.json     -- the GROUND-TRUTH label (bench_label.schema.json): cve_id, component, version,
                           expected_class, expected_evidence (the SHAPE of proof, not a baked exploit), and
                           boot_status.
  * README.md           -- what the lab is, the label, and the boot/verify caveat.

HONESTY GUARD (non-negotiable): this generator can boot NOTHING, so every answer_key gets
`boot_status: "unverified"` and the generator NEVER emits "verified". The scorer (scripts/benchmark.py
--score-labs) counts ONLY verified labs toward any measured number, so an un-booted scaffold can never
fabricate a figure. Where the KB lacks enough to stand a lab, the entry is SKIPPED and recorded in the
report's `skipped[]` with a reason -- rather than emitting a broken/guessed lab.

Labelled labs are LOCAL + benign; the answer key is ground truth for SCORING, not an exploit.

Stdlib only. Examples:
  python scripts/bench_labgen.py --selftest
  python scripts/bench_labgen.py --kb engagements/<x>/cve-intelligence/cve_kb.jsonl
  python scripts/bench_labgen.py --intel engagements/<x>/cve-intelligence/cve_intel.json --out benchmark/labs
"""
import argparse
import datetime
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LABS = ROOT / "benchmark" / "labs"

CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]+$")
CWE_RE = re.compile(r"^CWE-[0-9]+$")
PLAIN_VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.\-+_]*$")
RANGE_CLAUSE_RE = re.compile(r"(>=|<=|==|=|<|>)\s*([0-9][0-9A-Za-z.\-+_]*)")

# Library ecosystems whose package is NOT a standalone container image: the scaffold uses a generic
# ecosystem runtime base image and installs the pinned package (a best-effort harness; the human adds any
# reachability app). (base_image, install_command_template{name,version}). Standard runtime images only.
_ECOSYSTEM_RUNTIME = {
    "npm":      ("node:lts",      "npm install {name}@{version}"),
    "pypi":     ("python:3-slim", "pip install '{name}=={version}'"),
    "gem":      ("ruby:3",        "gem install {name} --version {version}"),
    "composer": ("composer:2",    "composer require '{name}:{version}'"),
    "cargo":    ("rust:1",        "cargo install {name} --version {version}"),
    "go":       ("golang:1",      "go install {name}@v{version}"),
    "maven":    ("maven:3",       "mvn -q dependency:get -Dartifact={name}:{version}"),
}
# Ecosystems whose component IS a runnable application image: image = component:version.
_APP_ECOSYSTEMS = {"os", "generic", ""}

# Component (substring, lowercased) -> minimal backing service + the target env needed to reach it. Benign
# placeholder credentials for a LOCAL benign lab only. Keeps the scaffold "minimal backing services if the
# entry implies them".
_BACKING = {
    "wordpress": {
        "target_env": {"WORDPRESS_DB_HOST": "db", "WORDPRESS_DB_USER": "lab",
                       "WORDPRESS_DB_PASSWORD": "labpass", "WORDPRESS_DB_NAME": "app"},
        "service": {"name": "db", "image": "mariadb:11",
                    "environment": {"MARIADB_DATABASE": "app", "MARIADB_USER": "lab",
                                    "MARIADB_PASSWORD": "labpass", "MARIADB_ROOT_PASSWORD": "labrootpass"}},
    },
    "joomla": {
        "target_env": {"JOOMLA_DB_HOST": "db", "JOOMLA_DB_USER": "lab",
                       "JOOMLA_DB_PASSWORD": "labpass", "JOOMLA_DB_NAME": "app"},
        "service": {"name": "db", "image": "mysql:8",
                    "environment": {"MYSQL_DATABASE": "app", "MYSQL_USER": "lab",
                                    "MYSQL_PASSWORD": "labpass", "MYSQL_ROOT_PASSWORD": "labrootpass"}},
    },
    "drupal": {
        "target_env": {"POSTGRES_HOST": "db"},
        "service": {"name": "db", "image": "postgres:16",
                    "environment": {"POSTGRES_DB": "app", "POSTGRES_USER": "lab",
                                    "POSTGRES_PASSWORD": "labpass"}},
    },
    "ghost": {
        "target_env": {"database__client": "mysql", "database__connection__host": "db",
                       "database__connection__user": "lab", "database__connection__password": "labpass",
                       "database__connection__database": "app"},
        "service": {"name": "db", "image": "mysql:8",
                    "environment": {"MYSQL_DATABASE": "app", "MYSQL_USER": "lab",
                                    "MYSQL_PASSWORD": "labpass", "MYSQL_ROOT_PASSWORD": "labrootpass"}},
    },
    "nextcloud": {
        "target_env": {"MYSQL_HOST": "db", "MYSQL_USER": "lab",
                       "MYSQL_PASSWORD": "labpass", "MYSQL_DATABASE": "app"},
        "service": {"name": "db", "image": "mariadb:11",
                    "environment": {"MARIADB_DATABASE": "app", "MARIADB_USER": "lab",
                                    "MARIADB_PASSWORD": "labpass", "MARIADB_ROOT_PASSWORD": "labrootpass"}},
    },
}


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_jsonl(path: Path) -> list:
    """Read a cve_kb.jsonl (one JSON object per line); malformed/blank lines are skipped."""
    out = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        sys.exit(f"[!] cannot read KB jsonl {path}: {e}")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(o, dict):
            out.append(o)
    return out


def read_intel(path: Path) -> list:
    """Read a cve_intel.json and return its per-CVE entries (the canonical `cves` or the `entries` alias)."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"[!] cannot read cve_intel json {path}: {e}")
    if not isinstance(obj, dict):
        return []
    rows = obj.get("cves")
    if not isinstance(rows, list):
        rows = obj.get("entries") if isinstance(obj.get("entries"), list) else []
    return [r for r in rows if isinstance(r, dict)]


def _norm_cve(s) -> str:
    if not isinstance(s, str):
        return ""
    s = s.strip().upper()
    return s if CVE_RE.match(s) else ""


def _norm_cwe(s) -> str:
    """Normalize a CWE handle to 'CWE-<n>' or '' (so it is always schema-pattern-clean)."""
    if not isinstance(s, str):
        return ""
    s = s.strip().upper()
    if CWE_RE.match(s):
        return s
    if s.isdigit():
        return f"CWE-{s}"
    return ""


def pin_from_range(affected_range) -> str:
    """Derive ONE concrete known-vulnerable version from an affected-range constraint, deterministically.

    An exact clause (=/==) pins that version; else an inclusive lower bound (>=) IS a vulnerable version;
    else an inclusive upper bound (<=) IS one. A range with only strict </> bounds (or empty) cannot be
    pinned to a real published version offline -> '' (the caller skips it)."""
    if not isinstance(affected_range, str) or not affected_range.strip():
        return ""
    clauses = RANGE_CLAUSE_RE.findall(affected_range)
    exact = [v for op, v in clauses if op in ("=", "==")]
    if exact:
        return exact[0]
    ge = [v for op, v in clauses if op == ">="]
    if ge:
        return ge[0]
    le = [v for op, v in clauses if op == "<="]
    if le:
        return le[0]
    return ""


def pin_version(record: dict) -> str:
    """The concrete version to stand up: a plain version field verbatim, else derived from affected_range."""
    v = record.get("version")
    if isinstance(v, str) and PLAIN_VERSION_RE.match(v.strip()):
        return v.strip()
    return pin_from_range(record.get("affected_range"))


def normalize_kb_row(row: dict) -> dict:
    """A cve_kb.jsonl row -> the generator's internal record."""
    return {
        "_origin": "cve_kb",
        "cve_id": _norm_cve(row.get("cve_id")),
        "component": (row.get("component") or "").strip(),
        "version": row.get("version"),
        "affected_range": row.get("affected_range"),
        "ecosystem": (row.get("ecosystem") or "").strip().lower(),
        "fixed_version": row.get("fixed_version"),
        "cwe": _norm_cwe(row.get("cwe")),
        "owasp": "",
        "vuln_class": (row.get("technique_class") or "").strip(),
        "cvss": row.get("cvss"),
        "kev": row.get("kev"),
        "epss": row.get("epss"),
        "reachability": row.get("reachability_notes"),
        "source_refs": [s for s in (row.get("source_refs") or []) if isinstance(s, str)],
    }


def normalize_intel_entry(entry: dict) -> dict:
    """A cve_intel.json per-CVE entry -> the generator's internal record. The weakness class comes from the
    optional technique_seed (routed_class / cwe / owasp), the only class signal that row carries."""
    seed = entry.get("technique_seed") if isinstance(entry.get("technique_seed"), dict) else {}
    return {
        "_origin": "cve_intel",
        "cve_id": _norm_cve(entry.get("cve")),
        "component": (entry.get("component") or "").strip(),
        "version": entry.get("version"),
        "affected_range": None,
        "ecosystem": "",  # cve_intel carries no ecosystem -> app-image route (generic)
        "fixed_version": None,
        "cwe": _norm_cwe(seed.get("cwe")),
        "owasp": (seed.get("owasp") or "").strip(),
        "vuln_class": (seed.get("routed_class") or "").strip(),
        "cvss": entry.get("cvss"),
        "kev": entry.get("kev"),
        "epss": entry.get("epss"),
        "reachability": (entry.get("notes") or seed.get("injection_point") or ""),
        "source_refs": [s for s in (entry.get("source") or []) if isinstance(s, str)],
    }


def slugify(component: str, version: str, cve_id: str) -> str:
    raw = f"{component}-{version}-{cve_id}".lower()
    slug = re.sub(r"[^a-z0-9.]+", "-", raw)
    slug = re.sub(r"\.{2,}", ".", re.sub(r"-{2,}", "-", slug)).strip("-.")
    return slug or "lab"


def _class_title_regex(vuln_class: str) -> str:
    tokens = re.findall(r"[a-z0-9]+", vuln_class.lower())
    return r"[^a-z0-9]*".join(re.escape(t) for t in tokens) if tokens else ""


def build_matcher(record: dict) -> dict:
    """The benchmark matcher for the planted CVE (a single strong key, so a real finding matches reliably):
    CWE exact > OWASP prefix > a title_regex from the vuln class."""
    if record.get("cwe"):
        return {"cwe": record["cwe"]}
    if record.get("owasp"):
        return {"owasp": record["owasp"]}
    if record.get("vuln_class"):
        rx = _class_title_regex(record["vuln_class"])
        if rx:
            return {"title_regex": rx}
    return {}


def build_expected_class(record: dict) -> dict:
    ec = {}
    if record.get("cwe"):
        ec["cwe"] = record["cwe"]
    if record.get("owasp"):
        ec["owasp"] = record["owasp"]
    if record.get("vuln_class"):
        ec["vuln_class"] = record["vuln_class"]
    cvss = record.get("cvss")
    if isinstance(cvss, str) and cvss.strip():
        ec["cvss"] = cvss.strip()
    return ec


def _compose_services(record: dict, version: str):
    """Return (services, note) for the compose, or (None, skip_reason). A list of service dicts:
    {name, image, command?(list), environment?(dict), ports?(list), depends_on?(list)}."""
    comp = record["component"]
    eco = (record.get("ecosystem") or "").lower()
    note = ""
    if eco in _APP_ECOSYSTEMS:
        target = {"name": "target", "image": f"{comp}:{version}", "ports": ["8080:80"], "environment": {}}
        services = [target]
        for key, spec in _BACKING.items():
            if key in comp.lower():
                target["environment"].update(spec["target_env"])
                target["depends_on"] = [spec["service"]["name"]]
                services.append({"name": spec["service"]["name"], "image": spec["service"]["image"],
                                 "environment": dict(spec["service"]["environment"])})
                break
        note = ("application image component@version" if len(services) == 1
                else "application image component@version + a minimal backing database")
        return services, note
    if eco in _ECOSYSTEM_RUNTIME:
        base, install_tpl = _ECOSYSTEM_RUNTIME[eco]
        install = install_tpl.format(name=comp, version=version)
        cmd = ["sh", "-c", f"{install} && tail -f /dev/null"]
        note = (f"{eco} package installed at the pinned version on a {base} runtime "
                f"(best-effort harness; a human adds the reachability app)")
        return [{"name": "target", "image": base, "command": cmd}], note
    return None, f"unsupported-ecosystem:{eco or 'unknown'}"


def _yaml_scalar(v: str) -> str:
    """Quote a scalar only when a plain scalar would be mis-parsed. An image tag like `wordpress:6.4.2` is a
    valid plain scalar (the ':' is not followed by a space), so it stays unquoted; a ': ' / trailing ':' /
    leading indicator / reserved word is quoted."""
    s = str(v)
    if (s == "" or s != s.strip() or ": " in s or s.endswith(":")
            or s[0] in "!&*?@`%#|>-{}[]," or s.lower() in (
                "yes", "no", "true", "false", "null", "on", "off")):
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def render_compose(services: list, header_lines: list) -> str:
    """Render a minimal, deterministic docker-compose.yml for the bounded service shape we build."""
    out = list(header_lines)
    out.append("")
    out.append("services:")
    for svc in services:
        out.append(f"  {svc['name']}:")
        out.append(f"    image: {_yaml_scalar(svc['image'])}")
        if svc.get("command"):
            inner = ", ".join(json.dumps(c) for c in svc["command"])
            out.append(f"    command: [{inner}]")
        if svc.get("ports"):
            out.append("    ports:")
            for p in svc["ports"]:
                out.append(f'      - "{p}"')
        if svc.get("depends_on"):
            out.append("    depends_on:")
            for d in svc["depends_on"]:
                out.append(f"      - {d}")
        env = svc.get("environment") or {}
        if env:
            out.append("    environment:")
            for k in sorted(env):
                out.append(f"      - {k}={_yaml_scalar(env[k])}".rstrip())
    return "\n".join(out).rstrip() + "\n"


def build_answer_key(record: dict, slug: str, version: str, generated_at: str) -> dict:
    ak = {
        "schema_version": 1,
        "slug": slug,
        "cve_id": record["cve_id"],
        "component": record["component"],
        "version": version,
        "expected_class": build_expected_class(record),
        "expected_evidence": {},
        "boot_status": "unverified",  # the generator boots nothing; a human promotes this after confirming
        "generated_at": generated_at,
    }
    matcher = build_matcher(record)
    ev = {"match": matcher}
    reach = record.get("reachability")
    if isinstance(reach, str) and reach.strip():
        ev["reachability"] = reach.strip()
    mk = next(iter(matcher)) if matcher else "class"
    ev["proof_shape"] = (f"A reviewer-accepted finding whose {mk} matches {record['cve_id']}'s weakness "
                         f"class on {record['component']}@{version}.")
    ak["expected_evidence"] = ev
    eco = record.get("ecosystem")
    if isinstance(eco, str) and eco:
        ak["ecosystem"] = eco
    fv = record.get("fixed_version")
    if isinstance(fv, str) and fv.strip():
        ak["fixed_version"] = fv.strip()
    if isinstance(record.get("kev"), bool):
        ak["kev"] = record["kev"]
    if isinstance(record.get("epss"), (int, float)) and not isinstance(record["epss"], bool):
        ak["epss"] = float(record["epss"])
    if record.get("source_refs"):
        ak["source_refs"] = list(record["source_refs"])
    ak["notes"] = ("boot_status is 'unverified': this scaffold has not been booted. Confirm the lab stands "
                   "up the vulnerable component, then set boot_status to 'verified' before scoring.")
    return ak


def build_readme(ak: dict, compose_note: str) -> str:
    ec = ak.get("expected_class", {})
    cls = ec.get("cwe") or ec.get("owasp") or ec.get("vuln_class") or "(unclassified)"
    lines = [
        f"# Labeled lab: {ak['cve_id']} on {ak['component']}@{ak['version']}",
        "",
        "A **self-labeling** benchmark fixture: standing up this known-vulnerable component makes the CVE "
        "itself the ground-truth label, so `scripts/benchmark.py --score-labs` can measure real "
        "recall/precision against it.",
        "",
        "## Label (ground truth)",
        "",
        f"- **CVE:** {ak['cve_id']}",
        f"- **Component:** {ak['component']} @ {ak['version']}"
        + (f"  (fixed in {ak['fixed_version']})" if ak.get("fixed_version") else ""),
        f"- **Expected class:** {cls}",
        f"- **Match shape:** `{json.dumps(ak.get('expected_evidence', {}).get('match', {}))}`",
        "",
        "The full machine-readable label is in [`answer_key.json`](answer_key.json). It is ground truth for "
        "SCORING, not an exploit.",
        "",
        "## Boot / verify caveat (READ THIS)",
        "",
        f"- `docker-compose.yml` is a **best-effort scaffold** ({compose_note}), generated deterministically "
        "from CVE metadata. **Nobody has booted it.**",
        "- `answer_key.json` carries `boot_status: \"unverified\"`. The generator **never** marks a lab "
        "verified.",
        "- The scorer counts **only `verified`** labs toward any measured number, so this un-booted scaffold "
        "cannot fabricate a figure.",
        "",
        "## Promote to verified",
        "",
        "```bash",
        "docker compose up -d        # stand the lab up",
        "# confirm the vulnerable component is actually present and reachable at the pinned version,",
        "# then edit answer_key.json: set \"boot_status\": \"verified\"",
        "```",
        "",
        "Only then does `python scripts/benchmark.py --score-labs --engagement <run-dir>` count this lab.",
        "",
    ]
    return "\n".join(lines)


def labgen(records: list, out_dir: Path, *, generated_at: str = None, write: bool = True) -> dict:
    """Generate labeled labs from internal records. Returns a report {emitted[], skipped[], counts}.
    A non-lab-able record is SKIPPED with a reason rather than emitting a broken/guessed lab."""
    generated_at = generated_at or _now()
    emitted, skipped, seen_slugs = [], [], set()
    for rec in records:
        cve = rec.get("cve_id")
        comp = rec.get("component")
        tag = {"cve_id": cve or None, "component": comp or None}
        if not cve:
            skipped.append({**tag, "reason": "missing-or-invalid-cve-id"})
            continue
        if not comp:
            skipped.append({**tag, "reason": "missing-component"})
            continue
        version = pin_version(rec)
        if not version:
            skipped.append({**tag, "reason": "unpinnable-version"})
            continue
        if not (rec.get("cwe") or rec.get("owasp") or rec.get("vuln_class")):
            skipped.append({**tag, "reason": "no-weakness-class"})
            continue
        services, note = _compose_services(rec, version)
        if services is None:
            skipped.append({**tag, "reason": note})
            continue
        slug = slugify(comp, version, cve)
        if slug in seen_slugs:
            skipped.append({**tag, "reason": "duplicate-slug", "slug": slug})
            continue
        seen_slugs.add(slug)

        ak = build_answer_key(rec, slug, version, generated_at)
        header = [
            "# Redstrike labeled-lab scaffold (generated by scripts/bench_labgen.py) -- NOT yet booted.",
            f"# Label: {cve} on {comp}@{version} (ground truth: answer_key.json).",
            "# BEST-EFFORT scaffold from CVE metadata; answer_key.boot_status is 'unverified' until a human",
            "# confirms it stands up the vulnerable component. Bring it up, verify, then promote to score it.",
        ]
        compose = render_compose(services, header)
        readme = build_readme(ak, note)
        if write:
            lab_dir = out_dir / slug
            lab_dir.mkdir(parents=True, exist_ok=True)
            (lab_dir / "docker-compose.yml").write_text(compose, encoding="utf-8")
            (lab_dir / "answer_key.json").write_text(json.dumps(ak, indent=2) + "\n", encoding="utf-8")
            (lab_dir / "README.md").write_text(readme, encoding="utf-8")
        emitted.append({"slug": slug, "cve_id": cve, "component": comp, "version": version,
                        "ecosystem": rec.get("ecosystem") or "generic", "boot_status": "unverified"})
    return {
        "generated_at": generated_at,
        "out_dir": str(out_dir),
        "counts": {"seen": len(records), "emitted": len(emitted), "skipped": len(skipped)},
        "emitted": emitted,
        "skipped": skipped,
        "note": ("Every emitted lab is boot_status='unverified' -- this generator boots nothing. A human "
                 "must stand a lab up and confirm the vulnerable component before benchmark.py counts it."),
    }


def load_records(kb_path: str, intel_path: str) -> list:
    records = []
    if kb_path:
        records += [normalize_kb_row(r) for r in read_jsonl(Path(kb_path))]
    if intel_path:
        records += [normalize_intel_entry(e) for e in read_intel(Path(intel_path))]
    return records


def selftest() -> int:
    import tempfile
    # version pinning: exact, >= lower bound, <= upper bound, and the un-pinnable cases.
    assert pin_from_range("=1.4.1") == "1.4.1"
    assert pin_from_range(">=2.0.0 <2.6.3") == "2.0.0"
    assert pin_from_range("<=1.2.3") == "1.2.3"
    assert pin_from_range("<3.4.0") == "", "a bare upper-strict bound is not pinnable"
    assert pin_from_range("") == ""
    assert pin_version({"version": "6.4.2"}) == "6.4.2"
    assert pin_version({"version": "<3.4.0", "affected_range": "=9.9.9"}) == "9.9.9", "operator in version -> range"
    # cwe/cve normalization
    assert _norm_cwe("1321") == "CWE-1321" and _norm_cwe("CWE-79") == "CWE-79" and _norm_cwe("junk") == ""
    assert _norm_cve("cve-2024-1234") == "CVE-2024-1234" and _norm_cve("nope") == ""
    # matcher priority: cwe > owasp > vuln_class title_regex
    assert build_matcher({"cwe": "CWE-79"}) == {"cwe": "CWE-79"}
    assert build_matcher({"owasp": "A03"}) == {"owasp": "A03"}
    m = build_matcher({"vuln_class": "prototype-pollution"})
    assert "title_regex" in m and re.search(m["title_regex"], "Prototype Pollution in x", re.I)

    kb_rows = [
        # lab-able application component (generic ecosystem, implies a db) via exact range
        {"cve_id": "CVE-2024-11111", "component": "wordpress", "ecosystem": "generic",
         "affected_range": "=6.4.2", "fixed_version": "6.4.3", "cwe": "CWE-79",
         "technique_class": "xss", "kev": True, "epss": 0.4, "source_refs": ["osv", "nvd"],
         "reachability_notes": "comment field rendered unescaped"},
        # lab-able library (npm) via >= lower bound, class from technique_class only
        {"cve_id": "CVE-2023-22222", "component": "lodash", "ecosystem": "npm",
         "affected_range": ">=4.0.0 <4.17.21", "technique_class": "prototype-pollution",
         "cwe": "CWE-1321"},
        # NOT lab-able: unpinnable (<only) range
        {"cve_id": "CVE-2022-33333", "component": "jquery", "ecosystem": "npm",
         "affected_range": "<3.5.0", "cwe": "CWE-79"},
        # NOT lab-able: no weakness class
        {"cve_id": "CVE-2021-44444", "component": "openssl", "ecosystem": "os", "affected_range": "=1.1.1"},
        # NOT lab-able: unsupported ecosystem (nuget)
        {"cve_id": "CVE-2020-55555", "component": "Newtonsoft.Json", "ecosystem": "nuget",
         "affected_range": "=12.0.1", "cwe": "CWE-502"},
    ]
    intel_entries = [
        # lab-able: concrete detected version + class via technique_seed
        {"component": "drupal", "version": "9.3.0", "cve": "CVE-2022-66666",
         "technique_seed": {"routed_class": "deserialization", "cwe": "CWE-502",
                            "owasp": "A08:2021-Integrity Failures"}},
    ]
    records = [normalize_kb_row(r) for r in kb_rows] + [normalize_intel_entry(e) for e in intel_entries]

    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "labs"
        rep = labgen(records, out, generated_at="2026-01-01T00:00:00Z")
        assert rep["counts"]["emitted"] == 3, rep["counts"]
        assert rep["counts"]["skipped"] == 3, rep["counts"]
        reasons = sorted(s["reason"] for s in rep["skipped"])
        assert reasons == ["no-weakness-class", "unpinnable-version", "unsupported-ecosystem:nuget"], reasons
        slugs = sorted(e["slug"] for e in rep["emitted"])
        assert "wordpress-6.4.2-cve-2024-11111" in slugs, slugs
        # files landed + the honesty guard holds on every emitted answer key
        for e in rep["emitted"]:
            lab = out / e["slug"]
            assert (lab / "docker-compose.yml").is_file()
            assert (lab / "README.md").is_file()
            ak = json.loads((lab / "answer_key.json").read_text(encoding="utf-8"))
            assert ak["boot_status"] == "unverified", ak
            assert ak["schema_version"] == 1
            assert CVE_RE.match(ak["cve_id"])
            assert ak["expected_evidence"]["match"], "a lab must carry a non-empty matcher"
            assert ak["expected_class"], "a lab must carry at least one weakness class"
        # the wordpress lab stands up an app image + a backing db; version stays a target-descriptive fact
        wp = (out / "wordpress-6.4.2-cve-2024-11111" / "docker-compose.yml").read_text(encoding="utf-8")
        assert "image: wordpress:6.4.2" in wp and "mariadb:11" in wp and "depends_on" in wp, wp
        # the npm lab is a runtime+install harness, not a bogus `lodash:x` image
        lo = (out / "lodash-4.0.0-cve-2023-22222" / "docker-compose.yml").read_text(encoding="utf-8")
        assert "image: node:lts" in lo and "npm install lodash@4.0.0" in lo, lo
        # determinism: regenerating yields identical answer keys
        rep2 = labgen(records, Path(d) / "labs2", generated_at="2026-01-01T00:00:00Z")
        a1 = (out / "drupal-9.3.0-cve-2022-66666" / "answer_key.json").read_text(encoding="utf-8")
        a2 = (Path(d) / "labs2" / "drupal-9.3.0-cve-2022-66666" / "answer_key.json").read_text(encoding="utf-8")
        assert a1 == a2, "generation must be deterministic"

    print("bench_labgen.py selftest: OK (version-pinning + matcher + app/library scaffolds + "
          "skip reasons + boot_status=unverified honesty guard + determinism verified)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="CVE-KB-seeded labeled-lab generator (self-labeling benchmark fixtures).")
    ap.add_argument("--kb", help="path to a cve_kb.jsonl (skills/_contract/cve_kb.schema.json rows)")
    ap.add_argument("--intel", help="path to a cve_intel.json (skills/_contract/cve_intel.schema.json)")
    ap.add_argument("--out", default=str(LABS), help="output dir for labs (default: benchmark/labs)")
    ap.add_argument("--report", help="write the emitted[]/skipped[] report JSON here "
                                      "(default: <out>/labgen_report.json)")
    ap.add_argument("--dry-run", action="store_true", help="compute the report without writing any lab files")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json", help="print the full report JSON")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if not args.kb and not args.intel:
        ap.error("need --kb <cve_kb.jsonl> and/or --intel <cve_intel.json> (or --selftest)")

    records = load_records(args.kb, args.intel)
    if not records:
        sys.exit("[!] no usable records in the given KB/intel inputs")
    out_dir = Path(args.out)
    rep = labgen(records, out_dir, write=not args.dry_run)

    if not args.dry_run:
        report_path = Path(args.report) if args.report else (out_dir / "labgen_report.json")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")

    if args.as_json:
        print(json.dumps(rep, indent=2))
    else:
        c = rep["counts"]
        print(f"# bench_labgen -- {c['emitted']} lab(s) emitted, {c['skipped']} skipped (of {c['seen']} seen)")
        for e in rep["emitted"]:
            print(f"  + {e['slug']:<48} {e['cve_id']}  [boot_status=unverified]")
        if rep["skipped"]:
            print("  skipped:")
            for s in rep["skipped"][:40]:
                print(f"    - {str(s.get('component') or s.get('cve_id') or '?'):<28} {s['reason']}")
        if not args.dry_run:
            print(f"\nwrote {c['emitted']} lab(s) under {out_dir}  (all boot_status=unverified -- boot + "
                  f"confirm before scoring)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
