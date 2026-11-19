"""Per-engagement reasoning-provenance trace — persisted, entity-keyed lineage of HOW findings came to be.

The live run stream (``runtime/autorun.jsonl``) is ephemeral, free-text, and keyed to no stable
entity, so it can never drive a persisted provenance graph. This module closes that gap. It emits a
durable ``runtime/reasoning_trace.json`` whose nodes are the reasoning steps of the engagement and
whose edges are the relations between them:

    goal     a top-level objective of the engagement (derived from scope).
    intent   a HYPOTHESIS formed under a goal — "is <class> present on <target>?" (one per routed
             vulnerability category).
    fact     EVIDENCE gathered while testing a hypothesis — a positive observation that produced a
             finding, or the negative/ruled-out observation that closed the hypothesis.
    finding  a produced finding, CROSS-REFERENCED by its stable finding id (``finding_id``) so a
             consumer can link the trace back to the finding it explains.

Edges (``source`` → ``target``, upstream → downstream):

    spawns        goal → intent        (the goal spawned this line of inquiry)
    yields        intent → fact        (testing the hypothesis yielded this evidence)
    proves        fact → finding       (the evidence proves this finding)
    derived_from  fact → intent        (a prior fact motivated a deeper hypothesis) — reserved for
                  inline emission; not auto-derived from artifacts here.

DESIGN / HONESTY
  * STRICTLY ADDITIVE + CRASH-SAFE. The trace is an overlay: an absent, partial, or malformed trace
    must never break a run or the console graph. Every read is best-effort; the one write is atomic
    and its failure is SURFACED (never silently swallowed — no-silent-no-op discipline), it just does
    not abort the run.
  * DERIVED, not fabricated. Every node is grounded in an artifact the pipeline already produced
    (scope.yaml, coverage_ledger.json, the per-skill/consolidated findings). Finding nodes reuse the
    EXISTING finding ids; intents reuse coverage category ids; facts key off finding ids. No node
    invents a reasoning step that the artifacts don't evidence.

The pure pieces (``build_trace`` and the small extractors) take parsed data and are unit-tested
directly; ``assemble`` is the thin glue that reads the engagement's files and ``write`` persists it.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

# --- schema version ----------------------------------------------------------
TRACE_SCHEMA_VERSION = 1

# --- node kinds / edge relations ---------------------------------------------
GOAL = "goal"
INTENT = "intent"
FACT = "fact"
FINDING = "finding"

SPAWNS = "spawns"
YIELDS = "yields"
PROVES = "proves"
DERIVED_FROM = "derived_from"

# Finding statuses that count as a delivered finding (mirrors diagnostics.ACCEPTED_STATUSES).
ACCEPTED_STATUSES = frozenset({"verified", "accepted", "remediated"})
# Coverage statuses whose hypothesis is worth recording (it was actually explored or decided).
_EXPLORED_STATUSES = frozenset({"attempted", "blocked", "skipped", "pipeline"})
_ROOT_GOAL_ID = "goal:root"
_MAX_LABEL = 160


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def _clip(s, limit: int = _MAX_LABEL) -> str:
    s = (" ".join(str(s or "").split())).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


# --- producer-slug extraction (pure) -----------------------------------------
def producer_of(finding: dict) -> str | None:
    """The executor skill behind a finding (its reviewer is ``<skill>-verify``)."""
    if not isinstance(finding, dict):
        return None
    reviewer = ((finding.get("review") or {}).get("reviewer") if isinstance(finding.get("review"), dict) else None)
    if not isinstance(reviewer, str) or not reviewer:
        return None
    slug = reviewer.strip()
    if slug.endswith("-verify"):
        slug = slug[: -len("-verify")]
    if slug.startswith("redstrike-"):
        slug = slug[len("redstrike-"):]
    return slug or None


def _category_index(coverage_ledger: dict | None):
    """Return (categories, slug->category_id). ``categories`` is the raw list; the map lets a
    finding's producer slug resolve to the category (intent) it belongs to."""
    cats = []
    slug_to_cat: dict[str, str] = {}
    if isinstance(coverage_ledger, dict) and isinstance(coverage_ledger.get("categories"), list):
        for c in coverage_ledger["categories"]:
            if not isinstance(c, dict):
                continue
            cid = str(c.get("id") or c.get("name") or "").strip()
            if not cid:
                continue
            cats.append(c)
            for sk in (c.get("skills") or []):
                if isinstance(sk, str) and sk:
                    slug_to_cat.setdefault(sk, cid)
    return cats, slug_to_cat


def _fact_label(finding: dict) -> str:
    """A one-line summary of the evidence that produced a finding — prefer the first reproduction
    step, else the first evidence ref, else the impact. Honest provenance, not a verdict."""
    repro = finding.get("reproduction")
    if isinstance(repro, list):
        for step in repro:
            if isinstance(step, str) and step.strip():
                return _clip(step)
    ev = finding.get("evidence")
    if isinstance(ev, list):
        for e in ev:
            if isinstance(e, dict) and e.get("ref"):
                return _clip(f"evidence: {e.get('type', 'artifact')} — {e['ref']}")
    if isinstance(finding.get("impact"), str) and finding["impact"].strip():
        return _clip(finding["impact"])
    return "evidence gathered"


def _first_evidence_ref(finding: dict) -> str | None:
    ev = finding.get("evidence")
    if isinstance(ev, list):
        for e in ev:
            if isinstance(e, dict) and isinstance(e.get("ref"), str) and e["ref"]:
                return e["ref"]
    return None


def _is_accepted(finding: dict) -> bool:
    status = str(finding.get("status", "")).lower()
    verdict = ""
    if isinstance(finding.get("review"), dict):
        verdict = str(finding["review"].get("verdict", "")).lower()
    return status in ACCEPTED_STATUSES or verdict in ("accepted", "blocked")


# --- the pure builder --------------------------------------------------------
def build_trace(scope: dict | None, coverage_ledger: dict | None,
                findings: list | None, chains: list | None = None) -> dict:
    """Compose the full trace document (``version``/``nodes``/``edges``) from already-parsed inputs.

    Deterministic and pure. Every node carries a stable id; finding nodes cross-reference the
    EXISTING finding ids (``finding_id``). Shapes that can't be used are skipped, never fatal.
    """
    scope = scope if isinstance(scope, dict) else {}
    findings = [f for f in (findings or []) if isinstance(f, dict) and f.get("id")]
    cats, slug_to_cat = _category_index(coverage_ledger)

    nodes: list[dict] = []
    edges: list[dict] = []
    seen_nodes: set[str] = set()
    seen_edges: set[str] = set()

    def add_node(node: dict) -> bool:
        nid = node.get("id")
        if not nid or nid in seen_nodes:
            return False
        seen_nodes.add(nid)
        nodes.append(node)
        return True

    def add_edge(source: str, target: str, rel: str) -> None:
        if not source or not target or source not in seen_nodes or target not in seen_nodes:
            return
        eid = f"{source}->{target}:{rel}"
        if eid in seen_edges:
            return
        seen_edges.add(eid)
        edges.append({"id": eid, "source": source, "target": target, "rel": rel})

    # --- root goal (from scope) ---
    target = str(scope.get("target") or "").strip()
    if not target and isinstance(scope.get("in_scope"), dict):
        domains = scope["in_scope"].get("domains")
        if isinstance(domains, list) and domains:
            target = str(domains[0] or "").lstrip("*.").strip()
    target = target or str(scope.get("engagement") or "the target").strip()
    goal_label = _clip(scope.get("notes") or f"Assess {target} for vulnerabilities")
    add_node({"id": _ROOT_GOAL_ID, "kind": GOAL, "label": goal_label,
              "parent": None, "producer": "orchestrator", "meta": {"target": target}})

    # --- an intent (hypothesis) per routed category ---
    def intent_id(cid: str) -> str:
        return f"intent:{cid}"

    def ensure_intent(cid: str, name: str | None = None, producer: str | None = None) -> str:
        iid = intent_id(cid)
        if iid not in seen_nodes:
            label = _clip(f"Is {name or cid} present on {target}?")
            add_node({"id": iid, "kind": INTENT, "label": label, "parent": _ROOT_GOAL_ID,
                      "category": cid, "producer": producer, "meta": {"category": cid}})
            add_edge(_ROOT_GOAL_ID, iid, SPAWNS)
        return iid

    for c in cats:
        cid = str(c.get("id") or c.get("name") or "").strip()
        if not cid:
            continue
        status = str(c.get("status", "")).lower()
        has_findings = int(c.get("findings_count", 0) or 0) > 0
        if status not in _EXPLORED_STATUSES and not has_findings:
            continue
        producer = (c.get("skills") or [None])
        ensure_intent(cid, c.get("name"), producer[0] if isinstance(producer, list) and producer else None)
        # Ruled-out hypothesis: attempted/decided with zero findings and a recorded reason → a
        # negative fact closes the intent (honest "tested, nothing found because <reason>").
        reason = c.get("reason")
        if not has_findings and isinstance(reason, str) and reason.strip():
            fid = f"fact:ruledout:{cid}"
            if add_node({"id": fid, "kind": FACT, "label": _clip(reason), "parent": intent_id(cid),
                         "category": cid, "producer": producer[0] if isinstance(producer, list) and producer else None,
                         "meta": {"ruled_out": True}}):
                add_edge(intent_id(cid), fid, YIELDS)

    # --- a fact + finding node per produced finding ---
    synthetic = {c.get("id") for c in cats}
    for f in findings:
        fid_val = str(f["id"])
        slug = producer_of(f)
        cid = slug_to_cat.get(slug) if slug else None
        if not cid:
            # No category match (recon-only or a producer outside the ledger) → a synthetic intent
            # keyed on the producer slug so the finding still has an upstream hypothesis.
            cid = slug or "uncategorized"
            if cid not in synthetic:
                ensure_intent(cid, slug, slug)
                synthetic.add(cid)
        iid = ensure_intent(cid)

        fact_id = f"fact:{fid_val}"
        add_node({"id": fact_id, "kind": FACT, "label": _fact_label(f), "parent": iid,
                  "category": cid, "producer": slug, "evidence_ref": _first_evidence_ref(f),
                  "finding_id": fid_val, "meta": {"ruled_out": False}})
        add_edge(iid, fact_id, YIELDS)

        find_node_id = f"finding:{fid_val}"
        add_node({"id": find_node_id, "kind": FINDING, "label": _clip(f.get("title") or fid_val),
                  "parent": fact_id, "finding_id": fid_val, "producer": slug,
                  "severity": f.get("severity"), "status": f.get("status"),
                  "accepted": _is_accepted(f),
                  "meta": {"verdict": (f.get("review") or {}).get("verdict") if isinstance(f.get("review"), dict) else None}})
        add_edge(fact_id, find_node_id, PROVES)

    return {"version": TRACE_SCHEMA_VERSION, "nodes": nodes, "edges": edges}


# --- assembly (impure glue) --------------------------------------------------
def _load_json(path: Path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def _findings_list(obj):
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and isinstance(obj.get("findings"), list):
        return obj["findings"]
    return None


def discover_findings(eng_dir: Path) -> list:
    """The engagement's findings across the layouts the pipeline produces (mirrors the console's
    serve-side discovery): the consolidated report if present, else a root findings.json, else the
    UNION of per-skill ``<eng>/<skill>/findings.json`` — so the trace cross-references the SAME ids
    the console shows, even before ``reporting`` consolidates."""
    eng_dir = Path(eng_dir)
    for rel in ("report/findings_consolidated.json", "findings_consolidated.json"):
        lst = _findings_list(_load_json(eng_dir / rel))
        if lst is not None:
            return lst
    lst = _findings_list(_load_json(eng_dir / "findings.json"))
    if lst is not None:
        return lst
    union: list = []
    for p in sorted(eng_dir.glob("*/findings.json")):
        part = _findings_list(_load_json(p))
        if part:
            union.extend(part)
    return union


def _scope(eng_dir: Path) -> dict | None:
    """Scope from the generated machine projection (runtime/scope.json) if present, else None.
    The trace only needs target + notes, so a missing scope just yields a generic goal label."""
    for rel in ("runtime/scope.json", "scope.json"):
        s = _load_json(eng_dir / rel)
        if isinstance(s, dict):
            return s
    return None


def assemble(eng_dir) -> dict:
    """Read the engagement's artifacts (scope / coverage ledger / findings) and compose the full
    trace document, stamped with engagement + generated_at. Best-effort: a missing/malformed file is
    treated as absent, never fatal."""
    eng_dir = Path(eng_dir)
    scope = _scope(eng_dir)
    coverage = _load_json(eng_dir / "coverage_ledger.json")
    findings = discover_findings(eng_dir)
    chains = _load_json(eng_dir / "attack_chains.json")
    doc = build_trace(scope, coverage, findings, chains)
    doc["engagement"] = (scope.get("engagement") if isinstance(scope, dict) else None) or eng_dir.name
    doc["generated_at"] = _now_iso()
    return doc


# --- persistence (crash-safe, error-surfacing) -------------------------------
def write(eng_dir, trace: dict) -> Path:
    """Persist the trace to ``runtime/reasoning_trace.json`` (whole-document replace — the trace is
    re-derived in full each run, not appended). Atomic via a temp file + replace so a crash mid-write
    never leaves a half-written document. Returns the path. Raises on I/O error so the caller can
    SURFACE it (never a silent no-op); the caller guards the call so a failure degrades, not aborts."""
    eng_dir = Path(eng_dir)
    runtime = eng_dir / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    path = runtime / "reasoning_trace.json"
    tmp = runtime / "reasoning_trace.json.tmp"
    tmp.write_text(json.dumps(trace, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path
