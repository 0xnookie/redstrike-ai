#!/usr/bin/env python3
"""
notebook.py -- the engagement notebook: leads + recon intel + evidence + RoE + test accounts.

See skills/_contract/notebook.md (schema: skills/_contract/notebook.schema.json). The notebook is
"what a hunt GATHERS that is not a finding (yet)" and the one artifact that makes a zero-finding hunt
legible: the recon it gathered and the leads it chased + killed still show even when nothing reached the
submission bar. It CROSS-LINKS the ledgers + findings (lead.surface_ref -> surface_ledger id;
lead.promoted_to -> finding.id) rather than duplicating them. Lives at <engagement>/notebook.json.

    python scripts/notebook.py --plan     --engagement engagements/<id>      # aggregate recon + seed leads
    python scripts/notebook.py --mark L-3 --status promoted --finding RS-2026-004 --engagement <dir>
    python scripts/notebook.py --mark L-5 --status dead --verdict "out-of-scope" --engagement <dir>
    python scripts/notebook.py --validate --engagement engagements/<id>       # shape + cross-ref
    python scripts/notebook.py --selftest

--plan is idempotent: it recomputes the derived recon_intel and MERGES leads (existing ids + their
status/verdict/promoted_to are preserved; new seeds are appended). roe/test_accounts are filled only when
absent, never clobbered. Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

NB_NAME = "notebook.json"
LEAD_STATUSES = {"open", "testing", "promoted", "dead"}
FINDING_RE = re.compile(r"^RS-[0-9]{4}-[0-9]{3,}$")
LEAD_ID_RE = re.compile(r"^L-[0-9]+$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(p: Path | None):
    if not p:
        return None
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return None


def _read_jsonl(p: Path | None) -> list:
    out: list = []
    if not p:
        return out
    try:
        for line in Path(p).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    except Exception:
        pass
    return out


def _first(eng: Path, *names: str) -> Path | None:
    """Shallowest existing file among candidate names (direct child first, then rglob)."""
    for n in names:
        direct = eng / n
        if direct.exists():
            return direct
        hits = sorted((h for h in eng.rglob(n) if h.is_file()), key=lambda x: len(x.parts))
        if hits:
            return hits[0]
    return None


# --------------------------------------------------------------------------- scope.yaml (subset)
def _yaml_load(path: Path):
    """PyYAML if available, else a minimal indentation parser for the scope.yaml subset
    (nested maps, `- ` lists, `key: value` scalars, `#` comments, `[a, b]` inline lists)."""
    text = ""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except Exception:
        return None
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text)
    except Exception:
        pass
    return _mini_yaml(text)


def _scalar(v: str):
    v = v.strip()
    if v == "" or v in ("~", "null"):
        return None
    if v in ("true", "True"):
        return True
    if v in ("false", "False"):
        return False
    if (v[0], v[-1]) in (('"', '"'), ("'", "'")) and len(v) >= 2:
        return v[1:-1]
    if v.startswith("[") and v.endswith("]"):
        inner = v[1:-1].strip()
        return [_scalar(x) for x in inner.split(",")] if inner else []
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v


def _mini_yaml(text: str):
    """Best-effort indentation parser for the scope.yaml subset. Returns nested dict/list.
    Frames are [indent, container|None, parent, key]; a None container is a pending key whose
    child (map or list) is created on the first nested line (list if it starts with '- ')."""
    root: dict = {}
    stack: list = [[-1, root, None, None]]
    fold_indent = None  # inside a `key: >` / `key: |` folded block -> skip deeper lines
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if fold_indent is not None:
            if indent > fold_indent:
                continue
            fold_indent = None
        line = raw.strip()
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        frame = stack[-1]

        def materialize(as_list: bool):
            if frame[1] is None:
                frame[1] = [] if as_list else {}
                frame[2][frame[3]] = frame[1]
            return frame[1]

        if line.startswith("- "):
            cont = materialize(True)
            if not isinstance(cont, list):
                continue
            item = line[2:].strip()
            if ":" in item and item[0] not in "\"'":
                k, _, v = item.partition(":")
                cont.append({k.strip(): _scalar(v)})
            else:
                cont.append(_scalar(item))
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            cont = materialize(False)
            if not isinstance(cont, dict):
                continue
            if v in (">", "|", ">-", "|-", ">+", "|+"):
                cont[k] = ""
                fold_indent = indent
            elif v == "":
                cont[k] = None
                stack.append([indent, None, cont, k])
            else:
                cont[k] = _scalar(v)
    return root


# --------------------------------------------------------------------------- load / save
def load(eng: Path) -> dict:
    nb = _read_json(eng / NB_NAME)
    if not isinstance(nb, dict):
        nb = {"engagement": eng.name}
    nb.setdefault("engagement", eng.name)
    nb.setdefault("leads", [])
    nb.setdefault("recon_intel", {})
    nb.setdefault("evidence", [])
    nb.setdefault("test_accounts", [])
    return nb


def save(eng: Path, nb: dict) -> Path:
    nb["generated_at"] = _now()
    p = eng / NB_NAME
    p.write_text(json.dumps(nb, indent=2) + "\n", encoding="utf-8")
    return p


def _next_lead_id(leads: list) -> int:
    mx = 0
    for l in leads:
        m = LEAD_ID_RE.match(str(l.get("id", "")))
        if m:
            mx = max(mx, int(l["id"][2:]))
    return mx + 1


# --------------------------------------------------------------------------- recon aggregation
def aggregate_recon(eng: Path) -> tuple[dict, list]:
    """Return (recon_intel, seed_leads) built from the feeder artifacts. Best-effort + tolerant."""
    subs, dns, net, content, defenses, osint = [], [], [], [], [], []
    sources: dict = {}
    seeds: list = []

    # osint
    oj = _first(eng, "osint.json")
    o = _read_json(oj)
    if isinstance(o, dict):
        sources["osint"] = str(oj)
        for s in o.get("subdomains", []) or []:
            host = s if isinstance(s, str) else (s.get("host") if isinstance(s, dict) else None)
            if host:
                subs.append({"host": host, "source": "osint", "scope": "other"})
        for d in o.get("dns", []) or []:
            if isinstance(d, dict):
                dns.append(d)

    # host-discovery
    hj = _first(eng, "host_discovery.json")
    h = _read_json(hj)
    if isinstance(h, dict):
        sources["host_discovery"] = str(hj)
        for lh in h.get("live_hosts", []) or []:
            if not isinstance(lh, dict):
                continue
            host = lh.get("host") or lh.get("ip")
            http = lh.get("http") or {}
            subs.append({
                "host": host, "source": "host-discovery", "resolves_to": lh.get("ip", ""),
                "http_status": http.get("status") if isinstance(http, dict) else None, "scope": "in",
                "note": (", ".join(http.get("tech", [])) if isinstance(http, dict) and http.get("tech") else ""),
            })
            ports = [str(p.get("port")) for p in (lh.get("ports") or []) if isinstance(p, dict) and p.get("port")]
            if ports:
                net.append({"range": lh.get("ip", host), "owner": "", "hosts": host, "ports": ports,
                            "note": "; ".join(f"{p.get('port')}/{p.get('service','')}".strip("/")
                                              for p in (lh.get("ports") or []) if isinstance(p, dict))})

    # dangling dns -> takeover leads + dns rows
    dd = _read_json(_first(eng, "dangling_dns.json"))
    for rec in (dd or []) if isinstance(dd, list) else (dd.get("dangling", []) if isinstance(dd, dict) else []):
        if isinstance(rec, dict) and rec.get("host"):
            dns.append({"type": "CNAME", "name": rec["host"], "value": rec.get("target", ""),
                        "note": "dangling", "severity": "high"})
            seeds.append({"status": "open", "priority": 1, "title": f"Possible subdomain takeover on {rec['host']}",
                          "host": rec["host"], "hypothesis": "Dangling DNS record pointing at a claimable resource.",
                          "discovered_by": "host-discovery", "scope_hint": "takeover"})

    # content-discovery
    cj = _first(eng, "content.json")
    c = _read_json(cj)
    if isinstance(c, dict):
        sources["content"] = str(cj)
        for r in c.get("routes", []) or []:
            if isinstance(r, dict) and r.get("path"):
                content.append({k: r[k] for k in ("path", "status", "type", "methods", "params", "note") if k in r})

    # js-analysis endpoints -> content (note js)
    je = _first(eng, "endpoints.jsonl")
    if je:
        sources["js_analysis"] = str(je.parent)
        seen = {x.get("path") for x in content}
        for row in _read_jsonl(je):
            url = row.get("url") or row.get("path")
            if url and url not in seen:
                content.append({"path": url, "note": "js-analysis", "methods": [row.get("method")] if row.get("method") else []})
                seen.add(url)

    # source-audit candidates -> open leads
    sc = _read_json(_first(eng, "source_context.json"))
    if isinstance(sc, dict):
        for cand in (sc.get("candidates", []) or []):
            if isinstance(cand, dict):
                seeds.append({"status": "open", "priority": 2,
                              "title": cand.get("note") or cand.get("route") or f"source-audit candidate {cand.get('id','')}",
                              "host": "", "path": cand.get("route", ""),
                              "hypothesis": cand.get("snippet", "source-audit taint candidate (static, unproven)."),
                              "discovered_by": "source-audit"})

    recon = {"subdomains": subs, "dns": dns, "network": net, "content": content,
             "defenses": defenses, "osint": osint, "sources": sources}
    recon = {k: v for k, v in recon.items() if v}  # drop empty buckets
    return recon, seeds


def build_roe(eng: Path) -> dict:
    sc = _yaml_load(eng / "scope.yaml") or {}
    if not isinstance(sc, dict):
        return {}
    ins = sc.get("in_scope", {}) or {}
    outs = sc.get("out_of_scope", {}) or {}
    rules_src = sc.get("rules", {}) or {}
    win = sc.get("window", {}) or {}
    roe: dict = {
        "authorization": sc.get("authorized_by", ""),
        "window": {"from": str(win.get("start", "") or ""), "to": str(win.get("end", "") or "")},
        "in_scope": list(ins.get("domains", []) or []) + list(ins.get("urls", []) or []) + list(ins.get("cidrs", []) or []),
        "out_of_scope": list(outs.get("domains", []) or []) + list(outs.get("paths", []) or []) + list(outs.get("cidrs", []) or []),
        "rate_limit": rules_src.get("rate_limit_rps"),
    }
    rules = []
    for key, allowed_if_false in (("no_dos", "No denial-of-service"), ("no_destructive", "No destructive actions"),
                                  ("no_social_engineering", "No social engineering")):
        if key in rules_src:
            rules.append({"allowed": not bool(rules_src.get(key)), "text": allowed_if_false})
    if rules:
        roe["rules"] = rules
    return {k: v for k, v in roe.items() if v not in (None, [], {}, "")}


# --------------------------------------------------------------------------- commands
def cmd_plan(eng: Path, fresh: bool) -> dict:
    nb = {"engagement": eng.name} if fresh else load(eng)
    nb.setdefault("engagement", eng.name)
    nb.setdefault("leads", [])
    recon, seeds = aggregate_recon(eng)
    nb["recon_intel"] = recon  # derived -> always recomputed
    # merge seed leads (dedupe by (title, host))
    have = {(l.get("title"), l.get("host")) for l in nb["leads"]}
    nid = _next_lead_id(nb["leads"])
    for s in seeds:
        key = (s.get("title"), s.get("host"))
        if key in have:
            continue
        s.pop("scope_hint", None)
        s["id"] = f"L-{nid}"
        s["updated_at"] = _now()
        nb["leads"].append(s)
        have.add(key)
        nid += 1
    # fill roe / test_accounts only if absent
    if not nb.get("roe"):
        roe = build_roe(eng)
        if roe:
            nb["roe"] = roe
    nb.setdefault("test_accounts", [])
    nb.setdefault("evidence", [])
    if "target" not in nb:
        roe = nb.get("roe", {})
        dom = (roe.get("in_scope") or [None])[0]
        if dom:
            nb["target"] = dom
    return nb


def cmd_mark(nb: dict, lead_id: str, status: str, finding: str, verdict: str) -> list:
    msgs = []
    lead = next((l for l in nb.get("leads", []) if l.get("id") == lead_id), None)
    if not lead:
        return [f"no lead {lead_id}"]
    lead["status"] = status
    lead["updated_at"] = _now()
    if status == "promoted":
        if finding:
            lead["promoted_to"] = finding
        if not lead.get("promoted_to"):
            msgs.append(f"{lead_id}: promoted without --finding (promoted_to is required)")
    if status == "dead":
        if verdict:
            lead["verdict"] = verdict
        if not lead.get("verdict"):
            msgs.append(f"{lead_id}: dead without --verdict")
    return msgs


def validate(nb: dict, finding_ids: set[str] | None = None) -> tuple[bool, list]:
    msgs: list = []
    if not nb.get("engagement"):
        msgs.append("missing engagement")
    for l in nb.get("leads", []):
        lid = l.get("id", "?")
        if not LEAD_ID_RE.match(str(lid)):
            msgs.append(f"lead {lid}: id must match ^L-[0-9]+$")
        st = l.get("status")
        if st not in LEAD_STATUSES:
            msgs.append(f"lead {lid}: bad status {st!r}")
        if st == "promoted":
            pt = l.get("promoted_to", "")
            if not FINDING_RE.match(str(pt)):
                msgs.append(f"lead {lid}: promoted needs promoted_to ^RS-YYYY-NNN (got {pt!r})")
            elif finding_ids is not None and pt not in finding_ids:
                msgs.append(f"lead {lid}: promoted_to {pt} not in consolidated findings")
        if st == "dead" and not str(l.get("verdict", "")).strip():
            msgs.append(f"lead {lid}: dead needs a verdict")
    for a in nb.get("test_accounts", []):
        ident = str(a.get("identity", ""))
        if ident and "@" in ident and "redact" not in ident.lower() and "‹" not in ident:
            msgs.append(f"test account {a.get('id','?')}: identity looks unredacted ({ident!r})")
    return (len(msgs) == 0, msgs)


def _finding_ids(eng: Path) -> set[str]:
    ids: set[str] = set()
    cons = _read_json(_first(eng, "findings_consolidated.json"))
    rows = cons.get("findings", []) if isinstance(cons, dict) else (cons if isinstance(cons, list) else [])
    for f in rows or []:
        if isinstance(f, dict) and f.get("id"):
            ids.add(f["id"])
    return ids


# --------------------------------------------------------------------------- selftest
def _selftest() -> int:
    # yaml subset
    y = _mini_yaml("in_scope:\n  domains:\n    - a.com\n    - b.com\nrules:\n  no_dos: true\n  rate_limit_rps: 1\n")
    assert y["in_scope"]["domains"] == ["a.com", "b.com"], y
    assert y["rules"]["no_dos"] is True and y["rules"]["rate_limit_rps"] == 1, y
    # mark + validate
    nb = {"engagement": "t", "leads": [
        {"id": "L-1", "status": "open", "title": "x"},
        {"id": "L-2", "status": "dead", "title": "y", "verdict": "out-of-scope"},
    ]}
    assert validate(nb)[0], validate(nb)
    cmd_mark(nb, "L-1", "promoted", "RS-2026-001", "")
    ok, msgs = validate(nb, {"RS-2026-001"})
    assert ok, msgs
    ok2, msgs2 = validate(nb, set())  # finding missing from consolidated
    assert not ok2 and any("not in consolidated" in m for m in msgs2), msgs2
    bad = {"engagement": "t", "leads": [{"id": "L-3", "status": "promoted", "title": "z"}]}
    assert not validate(bad)[0]
    print("notebook.py selftest: OK")
    return 0


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike engagement notebook.")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--validate", action="store_true")
    ap.add_argument("--mark")
    ap.add_argument("--status", choices=sorted(LEAD_STATUSES))
    ap.add_argument("--finding", default="")
    ap.add_argument("--verdict", default="")
    ap.add_argument("--engagement")
    ap.add_argument("--fresh", action="store_true", help="--plan: rebuild instead of idempotent merge")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()

    if args.plan:
        if not args.engagement:
            ap.error("--plan needs --engagement")
        eng = Path(args.engagement)
        nb = cmd_plan(eng, args.fresh)
        p = save(eng, nb)
        print(f"[+] {p} · {len(nb.get('leads', []))} leads · "
              f"{sum(len(v) for k, v in nb.get('recon_intel', {}).items() if isinstance(v, list))} recon rows")
        return 0

    if args.mark:
        if not (args.engagement and args.status):
            ap.error("--mark needs --engagement and --status")
        eng = Path(args.engagement)
        nb = load(eng)
        msgs = cmd_mark(nb, args.mark, args.status, args.finding, args.verdict)
        save(eng, nb)
        for m in msgs:
            print(f"[!] {m}")
        print(f"[+] {args.mark} -> {args.status}")
        return 1 if (msgs and args.strict) else 0

    if args.validate:
        if not args.engagement:
            ap.error("--validate needs --engagement")
        eng = Path(args.engagement)
        if not (eng / NB_NAME).exists():
            print(json.dumps({"pass": True, "messages": [f"no {NB_NAME} (soft)"]}))
            return 0
        nb = load(eng)
        ok, msgs = validate(nb, _finding_ids(eng))
        print(json.dumps({"pass": ok, "messages": msgs}, indent=2))
        return 0 if (ok or not args.strict) else 1

    ap.error("choose one of --plan / --validate / --mark / --selftest")
    return 2


if __name__ == "__main__":
    sys.exit(main())
