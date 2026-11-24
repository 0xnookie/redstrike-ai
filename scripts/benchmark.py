#!/usr/bin/env python3
"""
benchmark.py -- Redstrike benchmark SCORECARD: recall + precision + cost + reproducibility.

Redstrike's architecture is at the field frontier, but it can PROVE nothing without a measured,
reproducible scorecard. This harness scores four axes against labelled targets and flags regressions:

  * RECALL        -- "what did we MISS?" -- solved / total known vulns (overall + per category + difficulty).
  * PRECISION     -- "is what we report REAL?" -- reported findings vs the target's TRUTH set. A reported
                     finding not in the truth set is an FP *candidate* (real-but-unlabelled findings exist),
                     NOT an automatic FP -- it is marked for adjudication, never auto-failed.
  * COST / TIME   -- mean cost per verified finding + time-to-first-finding + totals, from the engagement's
                     runtime telemetry (diagnostics.json + autorun.jsonl).
  * REPRODUCIBILITY-- recall/precision variance across K>=3 epochs (the Cybench convention); a variance
                     blowout is itself a regression.

Two answer-key kinds:
  * http-json     -- a live app whose ground truth is enumerable (OWASP Juice Shop: 116 challenges, each
                     machine-checkable via GET /api/Challenges with a boolean `solved`). recall = solved/total.
  * findings-match-- target-agnostic: an `expected` vuln manifest matched against an engagement's REPORTED
                     findings (accepted/blocked, non-composite). No live solved-API needed, so ANY labelled
                     app can be scored from a run's output. Guards against Juice-Shop overfitting. An optional
                     `truth` / `not_expected` set drives precision (see benchmark/README.md).

Positioning (TWO-SPEED): the live score RUN needs a live target + a real engagement, so it is an OPERATOR
workflow (see benchmark/RUNBOOK.md), NOT a push-CI job. What CI runs is `--selftest` (deterministic, no
network) via scripts/validate.py, so the harness + target specs + category maps can't rot.

  --score      Score recall (+ precision + cost when an --engagement is given) from a live --base-url, a
               captured --answer-key dump, or (findings-match) an --engagement dir. Optionally --out JSON.
  --repro      Score K epochs (repeat --engagement/--answer-key) and report recall/precision VARIANCE.
  --baseline   Score, then record it as benchmark/baselines/<target>.json (the floor to beat).
  --check      Score, compare to the recorded baseline, EXIT 2 on recall/precision regression > --tolerance
               or a reproducibility variance blowout > --max-variance.
  --scoreboard Regenerate benchmark/SCOREBOARD.md (the committed, public scorecard) from the baselines.
  --map        Print the target's native-category -> Redstrike routing-map-category mapping (validated).
  --selftest   Validate every target spec + the scoring/precision/cost/repro logic. No network. (CI runs this.)

Stdlib only. Examples:
  python scripts/benchmark.py --selftest
  python scripts/benchmark.py --score --target juice-shop --base-url http://localhost:3000
  python scripts/benchmark.py --score --target generic-web --engagement engagements/<client>-<date>
  python scripts/benchmark.py --repro --target generic-web --engagement run1 --engagement run2 --engagement run3
  python scripts/benchmark.py --check --target juice-shop --answer-key challenges.json --tolerance 0.02
  python scripts/benchmark.py --scoreboard
"""
import argparse
import datetime
import json
import re
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "benchmark"
TARGETS = BENCH / "targets"
BASELINES = BENCH / "baselines"
RESULTS = BENCH / "results"
LABS = BENCH / "labs"
MAP_PATH = ROOT / "skills" / "_contract" / "routing-map.json"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_target(name: str) -> dict:
    p = TARGETS / f"{name}.json"
    if not p.is_file():
        avail = ", ".join(sorted(t.stem for t in TARGETS.glob("*.json"))) or "(none)"
        sys.exit(f"[!] unknown target '{name}'. Available: {avail}")
    t = _read_json(p)
    if t is None:
        sys.exit(f"[!] target '{name}' invalid JSON")
    return t


def _dig(obj, path: str):
    for key in (path.split(".") if path else []):
        obj = obj[key]
    return obj


def fetch_answer_key(target: dict, base_url: str = None, answer_key_file: str = None) -> list:
    """Return [{id, category, solved, difficulty}] from the live endpoint or a captured dump.
    A dump is either the raw /api/Challenges JSON, {'data': [...]}, or a bare list of challenges."""
    ak = target["answer_key"]
    if answer_key_file:
        raw = _read_json(Path(answer_key_file))
        if raw is None:
            sys.exit(f"[!] answer-key dump unreadable: {answer_key_file}")
    else:
        if not base_url:
            sys.exit("[!] need --base-url (live) or --answer-key (captured dump)")
        import urllib.request
        url = base_url.rstrip("/") + ak["endpoint"]
        try:
            with urllib.request.urlopen(url, timeout=20) as r:  # noqa: S310 — operator-supplied target
                raw = json.loads(r.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001
            sys.exit(f"[!] could not fetch answer key from {url}: {e}")
    rows = raw if isinstance(raw, list) else _dig(raw, ak.get("data_path", "data"))
    out = []
    for r in rows:
        out.append({
            "id": r.get(ak["id_field"]),
            "category": r.get(ak["category_field"], "(uncategorized)"),
            "solved": bool(r.get(ak["solved_field"])),
            "difficulty": r.get(ak.get("difficulty_field", "difficulty")),
        })
    if not out:
        sys.exit("[!] answer key is empty -- is the target seeded and reachable?")
    return out


# --- engagement findings discovery (mirrors verify_completion/console: multi-layout + reportable) ----
def _findings_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return list(data.get("findings") or [])
    return []


def _discover_findings(eng: Path):
    """All findings across the layouts the pipeline produces, else None if the dir holds no findings file:
    the consolidated report, else a root findings.json, else the UNION of per-skill <eng>/*/findings.json."""
    cons = eng / "report" / "findings_consolidated.json"
    if cons.is_file():
        return _findings_list(_read_json(cons))
    root = eng / "findings.json"
    if root.is_file():
        return _findings_list(_read_json(root))
    per = sorted(eng.glob("*/findings.json"))
    if per:
        union = []
        for p in per:
            union.extend(_findings_list(_read_json(p)))
        return union
    return None


def _verdict(f: dict) -> str:
    # `review.verdict` is the AUTHORITATIVE axis; `status` is derived from it (verify-base.md:
    # accepted/blocked->verified, rejected->rejected, needs-evidence->open). Falling back to status
    # when the inline review block is absent is lossy (blocked reads back as accepted) but
    # _reportable treats both the same. Mirrors scripts/console.py._verdict.
    r = f.get("review") or {}
    if r.get("verdict"):
        return r["verdict"]
    st = f.get("status")
    return "rejected" if st == "rejected" else "accepted" if st == "verified" else ""


def _reportable(f: dict) -> bool:
    composite = bool(f.get("composite") or f.get("_composite"))
    return (not composite) and _verdict(f) in ("accepted", "blocked")


def _load_findings(eng: Path) -> list:
    """REPORTED findings (accepted/blocked, non-composite) from an engagement, normalized for matching.
    Works with every findings layout a real run produces, so recall credits what actually got reported."""
    if not eng.is_dir():
        sys.exit(f"[!] engagement dir not found: {eng}")
    findings = _discover_findings(eng)
    if findings is None:
        sys.exit(f"[!] no findings.json under {eng} (root, per-skill, or report/findings_consolidated.json)")
    out = []
    for f in findings:
        if isinstance(f, dict) and _reportable(f):
            cat = f.get("category") or {}
            out.append({"owasp": str(cat.get("owasp", "")), "cwe": str(cat.get("cwe", "")),
                        "wstg": str(cat.get("wstg", "")), "title": str(f.get("title", ""))})
    return out


def _match_expected(m: dict, f: dict) -> bool:
    """A finding f satisfies an expected matcher m when EVERY declared key matches."""
    if m.get("owasp") and not f["owasp"].upper().startswith(m["owasp"].upper()):
        return False
    if m.get("cwe") and f["cwe"].upper() != m["cwe"].upper():
        return False
    if m.get("wstg") and m["wstg"].upper() not in f["wstg"].upper():
        return False
    if m.get("title_regex") and not re.search(m["title_regex"], f["title"], re.I):
        return False
    return bool(m)  # an empty matcher never matches (avoids a free pass)


def _expected_challenges(target: dict, findings: list) -> list:
    """Turn an expected-vuln manifest + the run's findings into score()-compatible pseudo-rows,
    so the scorer / baseline / check all work unchanged for findings-match targets."""
    rows = []
    for e in target.get("expected", []):
        found = any(_match_expected(e.get("match") or {}, f) for f in findings)
        rows.append({"id": e.get("name", e.get("id")), "category": e.get("group", "expected"),
                     "solved": found, "difficulty": e.get("severity", "-")})
    if not rows:
        sys.exit("[!] findings-match target has no 'expected' manifest")
    return rows


def _recall(solved: int, total: int) -> float:
    return round(solved / total, 4) if total else 0.0


def score(challenges: list, target: dict, want_unsolved: bool = True) -> dict:
    total = len(challenges)
    solved = sum(1 for c in challenges if c["solved"])
    by_cat, by_diff, unsolved = {}, {}, {}
    for c in challenges:
        cat = c["category"]
        d = by_cat.setdefault(cat, {"solved": 0, "total": 0})
        d["total"] += 1
        d["solved"] += 1 if c["solved"] else 0
        if not c["solved"]:
            unsolved.setdefault(cat, []).append(c["id"])
        diff = str(c.get("difficulty"))
        dd = by_diff.setdefault(diff, {"solved": 0, "total": 0})
        dd["total"] += 1
        dd["solved"] += 1 if c["solved"] else 0
    for d in list(by_cat.values()) + list(by_diff.values()):
        d["recall"] = _recall(d["solved"], d["total"])
    res = {
        "target": target["target"],
        "scored_at": _now(),
        "overall": {"solved": solved, "total": total, "recall": _recall(solved, total)},
        "by_category": dict(sorted(by_cat.items(), key=lambda kv: kv[0])),
        "by_difficulty": {k: by_diff[k] for k in sorted(by_diff)},
    }
    if want_unsolved:
        res["unsolved"] = {k: sorted(v) for k, v in sorted(unsolved.items())}
    return res


def to_baseline(res: dict, provenance: str) -> dict:
    bl = {
        "target": res["target"],
        "recorded_at": _now(),
        "provenance": provenance,
        "overall": res["overall"],
        "by_category": {k: {kk: v[kk] for kk in ("solved", "total", "recall")}
                        for k, v in res["by_category"].items()},
    }
    # precision / cost / reproducibility are carried into the baseline ONLY when the score produced them,
    # so a recall-only baseline (e.g. the shipped Juice-Shop floor) stays backward-compatible.
    if isinstance(res.get("precision"), dict):
        p = res["precision"]
        bl["precision"] = {k: p[k] for k in (
            "reported", "true_positives", "confirmed_fp", "fp_candidates",
            "precision_upper", "precision_lower", "fp_rate_confirmed") if k in p}
    if isinstance(res.get("cost"), dict):
        c = res["cost"]
        bl["cost"] = {k: c.get(k) for k in (
            "verified_findings", "total_cost_usd", "mean_cost_per_finding_usd",
            "total_tokens", "total_wallclock_s", "time_to_first_finding_s", "total_steps")}
    if isinstance(res.get("reproducibility"), dict):
        r = res["reproducibility"]
        bl["reproducibility"] = {"epochs": r.get("epochs"), "enough_epochs": r.get("enough_epochs"),
                                 "recall": r.get("recall"), "precision": r.get("precision")}
    return bl


def load_baseline(name: str) -> dict:
    p = BASELINES / f"{name}.json"
    if not p.is_file():
        sys.exit(f"[!] no baseline for '{name}' -- record one first: "
                 f"benchmark.py --baseline --target {name} --base-url <url>")
    return _read_json(p)


def check(res: dict, base: dict, tolerance: float, max_variance: float = None) -> dict:
    regress, improve, missing = [], [], []
    bo, co = base["overall"]["recall"], res["overall"]["recall"]
    if co < bo - tolerance:
        regress.append(("overall", bo, co))
    elif co > bo + 1e-9:
        improve.append(("overall", bo, co))
    cur = res["by_category"]
    for cat, b in base.get("by_category", {}).items():
        if cat not in cur:
            missing.append(cat)
            continue
        cr = cur[cat]["recall"]
        if cr < b["recall"] - tolerance:
            regress.append((cat, b["recall"], cr))
        elif cr > b["recall"] + 1e-9:
            improve.append((cat, b["recall"], cr))
    new_cats = [c for c in cur if c not in base.get("by_category", {})]

    # --- precision regression (only when BOTH sides carry precision) ---------------------------------
    bp, cp = base.get("precision"), res.get("precision")
    if isinstance(bp, dict) and isinstance(cp, dict):
        bu, cu = float(bp.get("precision_upper", 1.0)), float(cp.get("precision_upper", 1.0))
        if cu < bu - tolerance:
            regress.append(("precision", bu, cu))
        elif cu > bu + 1e-9:
            improve.append(("precision", bu, cu))
        # a rising CONFIRMED false-positive rate is a regression too (candidates never auto-fail).
        bf, cf = float(bp.get("fp_rate_confirmed", 0.0)), float(cp.get("fp_rate_confirmed", 0.0))
        if cf > bf + tolerance:
            regress.append(("fp-rate", bf, cf))

    # --- reproducibility variance blowout -----------------------------------------------------------
    var_flags = []
    repro = res.get("reproducibility")
    if max_variance is not None and isinstance(repro, dict):
        for axis in ("recall", "precision"):
            st = repro.get(axis) or {}
            sd = st.get("stdev")
            if sd is not None and float(sd) > max_variance:
                var_flags.append((axis, float(sd), max_variance))
                regress.append((f"{axis}-variance", max_variance, float(sd)))

    return {"ok": not regress and not missing, "regressions": regress,
            "improvements": improve, "missing_categories": missing, "new_categories": new_cats,
            "variance_blowouts": var_flags}


# =================================================================================================
# PRECISION / FALSE-POSITIVE scoring
# =================================================================================================
def _truth_matchers(target: dict) -> list:
    """Matchers for KNOWN-TRUE vulnerabilities. Defaults to the `expected` set (every expected vuln is a
    known-true), plus any extra `truth[]` entries declared for true vulns that aren't scored for recall."""
    out = [e["match"] for e in target.get("expected", []) if isinstance(e, dict) and e.get("match")]
    out += [t["match"] for t in target.get("truth", []) if isinstance(t, dict) and t.get("match")]
    return out


def _not_expected_matchers(target: dict) -> list:
    """Matchers for KNOWN-FALSE claims (a reported finding matching one is a CONFIRMED false positive)."""
    return [n["match"] for n in target.get("not_expected", []) if isinstance(n, dict) and n.get("match")]


def precision(findings: list, target: dict) -> dict:
    """Score PRECISION of an engagement's REPORTED findings against the target's truth set.

    Each reported finding is classed:
      * TRUE POSITIVE   -- matches a truth matcher (`expected`/`truth`).
      * CONFIRMED FP    -- matches a `not_expected` matcher (labelled-false).
      * FP CANDIDATE    -- matches neither: UNLABELLED. Real-but-unlabelled findings exist, so a candidate
                           is flagged for ADJUDICATION, never auto-counted as a false positive.

    Reported as a RANGE so no honesty is lost:
      precision_upper = TP / (TP + confirmed_FP)        -- candidates adjudicated out (optimistic floor-free)
      precision_lower = TP / (TP + confirmed_FP + cand) -- every candidate is an FP (pessimistic worst-case)
      fp_rate_confirmed = confirmed_FP / reported        -- CONFIRMED only; candidates listed separately.
    """
    truth = _truth_matchers(target)
    not_exp = _not_expected_matchers(target)
    tp, cfp, cand = [], [], []
    for f in findings:
        if truth and any(_match_expected(m, f) for m in truth):
            tp.append(f)
        elif not_exp and any(_match_expected(m, f) for m in not_exp):
            cfp.append(f)
        else:
            cand.append(f)
    n_tp, n_cfp, n_cand = len(tp), len(cfp), len(cand)
    reported = n_tp + n_cfp + n_cand
    labelled = n_tp + n_cfp
    p_upper = round(n_tp / labelled, 4) if labelled else (1.0 if reported == 0 else 0.0)
    p_lower = round(n_tp / reported, 4) if reported else 1.0
    return {
        "reported": reported,
        "true_positives": n_tp,
        "confirmed_fp": n_cfp,
        "fp_candidates": n_cand,
        "precision_upper": p_upper,
        "precision_lower": p_lower,
        "fp_rate_confirmed": round(n_cfp / reported, 4) if reported else 0.0,
        "truth_matchers": len(truth),
        "not_expected_matchers": len(not_exp),
        "candidates_for_adjudication": sorted({(f.get("title") or "(untitled)") for f in cand}),
        "confirmed_fp_titles": sorted({(f.get("title") or "(untitled)") for f in cfp}),
        "note": ("precision_upper adjudicates candidates OUT; precision_lower counts them all as FP. "
                 "FP candidates are UNLABELLED reported findings -- adjudicate before treating as FPs."),
    }


# =================================================================================================
# COST / TIME telemetry (read from runtime/diagnostics.json [+ autorun.jsonl for cost/tokens])
# =================================================================================================
def _parse_iso(ts):
    if not ts or not isinstance(ts, str):
        return None
    try:
        return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def _duration_s(started, ended) -> float:
    a, b = _parse_iso(started), _parse_iso(ended)
    if a is None or b is None:
        return 0.0
    return max(0.0, (b - a).total_seconds())


def _run_cost_tokens(run: dict):
    """Cost/tokens from the diagnostics run RECORD itself, if a future diagnostics schema carries them
    (preferred, authoritative). Returns (cost_usd|None, tokens|None). diagnostics.py owns that schema; this
    reads several plausible keys so the metric lights up the moment they are added -- without touching it."""
    if not isinstance(run, dict):
        return None, None
    cost = None
    for k in ("cost_usd", "total_cost_usd", "cost"):
        v = run.get(k)
        if isinstance(v, (int, float)):
            cost = float(v)
            break
    usage = run.get("usage") if isinstance(run.get("usage"), dict) else {}
    tokens = None
    for k in ("total_tokens", "tokens"):
        v = run.get(k) if run.get(k) is not None else usage.get(k)
        if isinstance(v, (int, float)):
            tokens = int(v)
            break
    if tokens is None and usage:
        it, ot = usage.get("input_tokens"), usage.get("output_tokens")
        if isinstance(it, (int, float)) or isinstance(ot, (int, float)):
            tokens = int(it or 0) + int(ot or 0)
    return cost, tokens


def _autorun_session_telemetry(eng: Path) -> dict:
    """Parse runtime/autorun.jsonl -> {session_id: {cost_usd, tokens, turns}} from its `result` events.

    IMPORTANT (measured from real runs): `total_cost_usd` is CUMULATIVE within a session -- every result
    event of the same session repeats the running total -- so per session we take the MAX (never sum, which
    would multiply-count). `usage` tokens and `num_turns`, by contrast, are PER-LEG, so they are SUMMED.
    """
    path = eng / "runtime" / "autorun.jsonl"
    if not path.is_file():
        return {}
    sess: dict = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(o, dict) or o.get("type") != "result":
            continue
        sid = o.get("session_id") or ""
        s = sess.setdefault(sid, {"cost_usd": 0.0, "tokens": 0, "turns": 0})
        cost = o.get("total_cost_usd")
        if isinstance(cost, (int, float)):
            s["cost_usd"] = max(s["cost_usd"], float(cost))   # cumulative-per-session -> MAX
        u = o.get("usage") if isinstance(o.get("usage"), dict) else {}
        s["tokens"] += int(u.get("input_tokens") or 0) + int(u.get("output_tokens") or 0)  # per-leg -> SUM
        t = o.get("num_turns")
        if isinstance(t, (int, float)):
            s["turns"] += int(t)
    return sess


def telemetry(eng: Path, verified_findings: int) -> dict:
    """Cost/time scorecard for an engagement, from runtime/diagnostics.json (+ autorun.jsonl for $/tokens).

    Headline metrics:
      * mean_cost_per_finding_usd = total_cost / verified_findings  (the differentiator: efficiency, not just
        capability). None when cost is unavailable or there are no verified findings.
      * time_to_first_finding_s   = summed engine-run durations UP TO the first finding-bearing leg. Findings
        carry no per-item timestamp, so this is a leg-granularity proxy over ENGINE WORK TIME (idle gaps
        between legs are excluded, so an interactive close hours later does not inflate it).
      * total_wallclock_s         = summed per-leg engine durations (ended-started), not calendar span.
      * total_cost_usd / total_tokens / total_steps / runs.

    Returns {} when there is no diagnostics.json (telemetry is best-effort; absence never fails a score).
    """
    diag = _read_json(eng / "runtime" / "diagnostics.json")
    runs = (diag or {}).get("runs") if isinstance(diag, dict) else None
    if not isinstance(runs, list) or not runs:
        return {}
    runs = [r for r in runs if isinstance(r, dict)]
    runs.sort(key=lambda r: _parse_iso(r.get("started")) or datetime.datetime.min.replace(
        tzinfo=datetime.timezone.utc))

    autorun = _autorun_session_telemetry(eng)
    total_cost = 0.0
    total_tokens = 0
    cost_seen = tokens_seen = False
    counted_sessions = set()
    total_wall = 0.0
    total_steps = 0
    ttff = None
    cum_dur = 0.0

    for r in runs:
        dur = _duration_s(r.get("started"), r.get("ended"))
        total_wall += dur
        cum_dur += dur
        total_steps += len(r.get("phase_tally") or [])
        # first finding-bearing leg (findings_count is a cumulative snapshot per leg).
        if ttff is None and int(r.get("findings_count", 0) or 0) > 0:
            ttff = round(cum_dur, 3)
        # cost/tokens: prefer the run record; else the matching autorun session (max/sum rules applied).
        rc, rt = _run_cost_tokens(r)
        sid = r.get("session") or ""
        if rc is None and sid and sid in autorun:
            rc = autorun[sid]["cost_usd"]
        if rt is None and sid and sid in autorun:
            rt = autorun[sid]["tokens"]
        if rc is not None:
            total_cost += rc
            cost_seen = True
        if rt is not None:
            total_tokens += rt
            tokens_seen = True
        if sid:
            counted_sessions.add(sid)

    # autorun sessions with no diagnostics run to attribute them to (e.g. an interactive close whose leg
    # recorded an empty session) still represent real spend -- fold them into the totals once.
    for sid, s in autorun.items():
        if sid and sid not in counted_sessions:
            total_cost += s["cost_usd"]
            total_tokens += s["tokens"]
            cost_seen = cost_seen or s["cost_usd"] > 0
            tokens_seen = tokens_seen or s["tokens"] > 0

    vf = int(verified_findings or 0)
    mean_cpf = round(total_cost / vf, 4) if (cost_seen and vf > 0) else None
    src = "diagnostics.json"
    if autorun:
        src += "+autorun.jsonl"
    return {
        "verified_findings": vf,
        "runs": len(runs),
        "total_cost_usd": round(total_cost, 4) if cost_seen else None,
        "mean_cost_per_finding_usd": mean_cpf,
        "total_tokens": total_tokens if tokens_seen else None,
        "total_wallclock_s": round(total_wall, 3),
        "time_to_first_finding_s": ttff,
        "total_steps": total_steps,
        "source": src,
        "note": ("cost is cumulative-per-session in autorun.jsonl (MAX per session); time-to-first-finding "
                 "is a leg-granularity proxy over engine work time (findings have no per-item timestamp)."),
    }


# =================================================================================================
# REPRODUCIBILITY -- K-epoch variance (Cybench convention: K>=3)
# =================================================================================================
def _dist(xs: list) -> dict:
    xs = [float(x) for x in xs if x is not None]
    if not xs:
        return {"n": 0, "mean": None, "stdev": None, "min": None, "max": None, "spread": None}
    return {
        "n": len(xs),
        "mean": round(statistics.fmean(xs), 4),
        "stdev": round(statistics.pstdev(xs), 4),   # population stdev: deterministic, defined for n==1 (0.0)
        "min": round(min(xs), 4),
        "max": round(max(xs), 4),
        "spread": round(max(xs) - min(xs), 4),
    }


def reproducibility(results: list, min_epochs: int = 3) -> dict:
    """Aggregate K per-epoch score() results into recall/precision variance (stdev/spread).

    K>=3 is the Cybench convention; fewer epochs still compute but set `enough_epochs=False` so a reader
    (and --check) knows the variance estimate is under-powered."""
    recalls = [r.get("overall", {}).get("recall") for r in results]
    precs = [r["precision"]["precision_upper"] for r in results
             if isinstance(r.get("precision"), dict)]
    per = []
    for i, r in enumerate(results):
        row = {"epoch": i + 1, "recall": r.get("overall", {}).get("recall")}
        if isinstance(r.get("precision"), dict):
            row["precision"] = r["precision"]["precision_upper"]
        if isinstance(r.get("cost"), dict):
            row["mean_cost_per_finding_usd"] = r["cost"].get("mean_cost_per_finding_usd")
        per.append(row)
    return {
        "epochs": len(results),
        "min_epochs": min_epochs,
        "enough_epochs": len(results) >= min_epochs,
        "recall": _dist(recalls),
        "precision": _dist(precs) if precs else None,
        "per_epoch": per,
    }


# =================================================================================================
# LABELED-LAB scoring -- CVE-KB-seeded SELF-LABELING benchmark (see scripts/bench_labgen.py)
# =================================================================================================
# A lab generated by bench_labgen.py stands up component@known-vulnerable-version, so the planted CVE IS
# the ground-truth label. This scorer matches a run's REPORTED findings against those labels to produce the
# measured recall/precision the harness otherwise lacks a labelled target for.
#
# HONESTY GUARD: the generator can boot nothing, so it only ever writes boot_status='unverified'. ONLY labs
# a human has promoted to 'verified' (confirmed the vulnerable component actually stands up) count toward any
# measured number. 'unverified'/'failed' labs are EXCLUDED and listed, so an un-booted scaffold can never
# fabricate a figure. This folds into the existing score() shape (overall + by_category + precision), so the
# baseline / scoreboard / check machinery all work unchanged.
def _load_labs(labs_dir: Path = None) -> list:
    """Load every generated answer_key.json under <labs_dir>/<slug>/ (default benchmark/labs)."""
    labs_dir = labs_dir or LABS
    out = []
    if not labs_dir.is_dir():
        return out
    for ak in sorted(labs_dir.glob("*/answer_key.json")):
        d = _read_json(ak)
        if isinstance(d, dict):
            d.setdefault("slug", ak.parent.name)
            out.append(d)
    return out


def _lab_matcher(lab: dict) -> dict:
    """The benchmark matcher for a lab's planted CVE: expected_evidence.match, else derived from
    expected_class (cwe > owasp). Empty when the label carries no usable key (then it can't score)."""
    m = (lab.get("expected_evidence") or {}).get("match") or {}
    if m:
        return m
    ec = lab.get("expected_class") or {}
    if ec.get("cwe"):
        return {"cwe": ec["cwe"]}
    if ec.get("owasp"):
        return {"owasp": ec["owasp"]}
    return {}


def score_labs(labs: list, findings: list) -> dict:
    """Score generated labeled labs against an engagement's REPORTED findings, in the score() shape.

    A planted CVE whose label matcher matches a reported finding is a TRUE POSITIVE (recall); per-lab
    pass/fail is carried in a `labs` block. Precision runs over the verified labs' matchers as the truth set
    (an unplanted/unmatched finding stays an FP *candidate* -- never auto-failed, consistent with the rest of
    the harness). Only boot_status=='verified' labs are scored; the rest are excluded + listed (honesty guard).
    """
    verified, excluded = [], []
    for lab in labs:
        if lab.get("boot_status") == "verified":
            verified.append(lab)
        else:
            excluded.append({"slug": lab.get("slug"), "cve_id": lab.get("cve_id"),
                             "boot_status": lab.get("boot_status", "unverified")})
    challenges, truth_entries, per_lab = [], [], []
    for lab in verified:
        m = _lab_matcher(lab)
        found = bool(m) and any(_match_expected(m, f) for f in findings)
        ec = lab.get("expected_class") or {}
        cat = ec.get("vuln_class") or ec.get("owasp") or ec.get("cwe") or "labeled-lab"
        cid = lab.get("cve_id") or lab.get("slug") or "?"
        challenges.append({"id": cid, "category": cat, "solved": found, "difficulty": ec.get("cvss", "-")})
        per_lab.append({"cve_id": cid, "slug": lab.get("slug"), "component": lab.get("component"),
                        "version": lab.get("version"), "category": cat, "found": found,
                        "matcher": m, "pass": found})
        if m:
            truth_entries.append({"id": cid, "match": m})

    if challenges:
        res = score(challenges, {"target": "labeled-labs"})
    else:
        # no verified labs yet -> an honest empty score; the labs block explains why numbers are withheld.
        res = {"target": "labeled-labs", "scored_at": _now(),
               "overall": {"solved": 0, "total": 0, "recall": 0.0},
               "by_category": {}, "by_difficulty": {}, "unsolved": {}}
    if findings:
        res["precision"] = precision(findings, {"target": "labeled-labs", "truth": truth_entries})
    res["labs"] = {
        "total": len(labs),
        "scored": len(verified),
        "excluded_unverified": excluded,
        "per_lab": per_lab,
        "note": ("Only boot_status=='verified' labs are scored; bench_labgen.py never emits 'verified' "
                 "(a human confirms boot first), so un-booted scaffolds cannot fabricate a measured number. "
                 + ("" if verified else "No verified labs -> recall/precision are WITHHELD (0 scored).")),
    }
    return res


def _print_labs(labs: dict):
    if not isinstance(labs, dict):
        return
    print(f"\n# Labeled labs  ({labs['scored']} verified / {labs['total']} total)")
    if not labs["scored"]:
        print("  no VERIFIED labs -> recall/precision WITHHELD (boot + promote a lab first; "
              "the generator never marks a lab verified).")
    for r in labs.get("per_lab", []):
        mark = "PASS" if r.get("pass") else "MISS"
        print(f"  [{mark}] {str(r.get('cve_id')):<18} {str(r.get('category')):<20} "
              f"{r.get('component')}@{r.get('version')}")
    exc = labs.get("excluded_unverified") or []
    if exc:
        print(f"  excluded (unverified/failed, not scored): {len(exc)}")
        for e in exc[:10]:
            print(f"    - {str(e.get('cve_id') or e.get('slug')):<24} boot_status={e.get('boot_status')}")


def _print_score(res: dict):
    o = res["overall"]
    print(f"# Recall -- {res['target']}  (scored {res['scored_at']})")
    print(f"overall: {o['solved']}/{o['total']} = {o['recall']:.1%}\n")
    print(f"{'category':<28} {'recall':>8}  solved/total")
    for cat, d in res["by_category"].items():
        print(f"{cat:<28} {d['recall']:>7.1%}  {d['solved']}/{d['total']}")
    if res.get("by_difficulty"):
        print("\nby difficulty:  " + " ".join(
            f"{k}*={v['solved']}/{v['total']}" for k, v in res["by_difficulty"].items()))
    _print_precision(res.get("precision"))
    _print_cost(res.get("cost"))
    _print_repro(res.get("reproducibility"))
    _print_labs(res.get("labs"))


def _print_precision(p: dict):
    if not isinstance(p, dict):
        return
    print(f"\n# Precision  ({p['reported']} reported)")
    print(f"  precision: {p['precision_upper']:.1%} (adjudicated) .. {p['precision_lower']:.1%} (worst-case)")
    print(f"  TP={p['true_positives']}  confirmed-FP={p['confirmed_fp']} "
          f"(rate {p['fp_rate_confirmed']:.1%})  FP-candidates={p['fp_candidates']}")
    if p.get("confirmed_fp_titles"):
        print("  confirmed false positives:")
        for t in p["confirmed_fp_titles"][:10]:
            print(f"    x {t}")
    if p.get("candidates_for_adjudication"):
        print("  FP candidates (ADJUDICATE -- unlabelled, may be real):")
        for t in p["candidates_for_adjudication"][:10]:
            print(f"    ? {t}")


def _fmt_s(v):
    return "n/a" if v is None else f"{v:.1f}s"


def _print_cost(c: dict):
    if not isinstance(c, dict):
        return
    print(f"\n# Cost / time  ({c['runs']} run leg(s), {c['verified_findings']} verified finding(s))")
    tc = c.get("total_cost_usd")
    mcpf = c.get("mean_cost_per_finding_usd")
    print(f"  total cost: {'n/a' if tc is None else f'${tc:.4f}'}   "
          f"mean $/finding: {'n/a' if mcpf is None else f'${mcpf:.4f}'}")
    print(f"  time-to-first-finding: {_fmt_s(c.get('time_to_first_finding_s'))}   "
          f"total engine time: {_fmt_s(c.get('total_wallclock_s'))}   steps: {c.get('total_steps')}")
    if c.get("total_tokens") is not None:
        print(f"  total tokens: {c['total_tokens']:,}")


def _print_repro(r: dict):
    if not isinstance(r, dict):
        return
    tag = "" if r.get("enough_epochs") else f"  (under-powered: <{r.get('min_epochs')} epochs)"
    print(f"\n# Reproducibility  ({r['epochs']} epoch(s)){tag}")
    rc = r.get("recall") or {}
    print(f"  recall:    mean {rc.get('mean')}  stdev {rc.get('stdev')}  "
          f"spread {rc.get('spread')}  [{rc.get('min')}..{rc.get('max')}]")
    pr = r.get("precision")
    if pr:
        print(f"  precision: mean {pr.get('mean')}  stdev {pr.get('stdev')}  "
              f"spread {pr.get('spread')}  [{pr.get('min')}..{pr.get('max')}]")


# =================================================================================================
# SCOREBOARD -- the committed, public, versioned scorecard (generated from the baselines)
# =================================================================================================
def _pct(v):
    return "—" if v is None else f"{float(v) * 100:.1f}%"


def _usd(v):
    return "—" if v is None else f"${float(v):.3f}"


def _num(v):
    return "—" if v is None else f"{v}"


def render_scoreboard(baselines: list) -> str:
    """Render SCOREBOARD.md from a list of baseline dicts (one per target). Deterministic: the committed
    scorecard is regenerated, never hand-edited. Missing axes render as '—' so a recall-only baseline is
    still listed honestly."""
    lines = []
    lines.append("# Redstrike benchmark scorecard")
    lines.append("")
    lines.append("<!-- GENERATED by `python scripts/benchmark.py --scoreboard` from benchmark/baselines/*.json."
                 " Do not hand-edit. -->")
    lines.append("")
    lines.append("The public, versioned, reproducible scorecard: recall (what we catch), precision (whether "
                 "what we report is real), cost efficiency (mean $ per verified finding), and reproducibility "
                 "(variance across epochs). Capability without a measured precision + cost + reproducibility "
                 "number proves nothing; this is that number.")
    lines.append("")
    lines.append("Baselines are committed deliberately (the floor to beat); `benchmark/results/` is gitignored "
                 "scratch. A live score is an operator workflow (see `RUNBOOK.md`); CI only runs `--selftest`.")
    lines.append("")
    lines.append("| Target | Recall | Precision (adj.) | Confirmed FP-rate | Mean $/finding | Recall σ | "
                 "Epochs | Recorded |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for bl in baselines:
        if not isinstance(bl, dict):
            continue
        tgt = bl.get("target", "?")
        recall = _pct((bl.get("overall") or {}).get("recall"))
        p = bl.get("precision") or {}
        prec = _pct(p.get("precision_upper")) if p else "—"
        fpr = _pct(p.get("fp_rate_confirmed")) if p else "—"
        c = bl.get("cost") or {}
        mcpf = _usd(c.get("mean_cost_per_finding_usd")) if c else "—"
        rep = bl.get("reproducibility") or {}
        rsd = (rep.get("recall") or {}).get("stdev") if rep else None
        rsd_s = _num(rsd)
        epochs = _num(rep.get("epochs")) if rep else "—"
        rec_at = bl.get("recorded_at", "—")
        lines.append(f"| {tgt} | {recall} | {prec} | {fpr} | {mcpf} | {rsd_s} | {epochs} | {rec_at} |")
    lines.append("")
    lines.append("## Per-target detail")
    lines.append("")
    for bl in baselines:
        if not isinstance(bl, dict):
            continue
        lines.append(f"### {bl.get('target', '?')}")
        lines.append("")
        if bl.get("provenance"):
            lines.append(f"*Provenance:* {bl['provenance']}")
            lines.append("")
        o = bl.get("overall") or {}
        lines.append(f"- **Recall:** {_pct(o.get('recall'))} ({o.get('solved')}/{o.get('total')})")
        p = bl.get("precision")
        if p:
            lines.append(f"- **Precision:** {_pct(p.get('precision_upper'))} adjudicated .. "
                         f"{_pct(p.get('precision_lower'))} worst-case "
                         f"(TP={p.get('true_positives')}, confirmed-FP={p.get('confirmed_fp')}, "
                         f"FP-candidates={p.get('fp_candidates')})")
        c = bl.get("cost")
        if c:
            lines.append(f"- **Cost:** mean {_usd(c.get('mean_cost_per_finding_usd'))}/finding, "
                         f"total {_usd(c.get('total_cost_usd'))} over "
                         f"{_num(c.get('verified_findings'))} verified finding(s); "
                         f"time-to-first-finding {_num(c.get('time_to_first_finding_s'))}s")
        rep = bl.get("reproducibility")
        if rep:
            rc = rep.get("recall") or {}
            lines.append(f"- **Reproducibility:** {rep.get('epochs')} epochs, recall σ={rc.get('stdev')} "
                         f"(spread {rc.get('spread')}){'' if rep.get('enough_epochs') else ' — UNDER-POWERED (<3)'}")
        by_cat = bl.get("by_category") or {}
        if by_cat:
            lines.append("")
            lines.append("<details><summary>Per-category recall</summary>")
            lines.append("")
            lines.append("| Category | Recall | solved/total |")
            lines.append("|---|---|---|")
            for cat, d in by_cat.items():
                lines.append(f"| {cat} | {_pct(d.get('recall'))} | {d.get('solved')}/{d.get('total')} |")
            lines.append("")
            lines.append("</details>")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def generate_scoreboard() -> int:
    bls = []
    for p in sorted(BASELINES.glob("*.json")):
        bl = _read_json(p)
        if isinstance(bl, dict):
            bls.append(bl)
    if not bls:
        sys.exit("[!] no baselines under benchmark/baselines/ -- record one first (--baseline)")
    out = BENCH / "SCOREBOARD.md"
    out.write_text(render_scoreboard(bls), encoding="utf-8")
    print(f"wrote scorecard ({len(bls)} target(s)) -> benchmark/SCOREBOARD.md")
    return 0


def _validate_map(target: dict):
    """Return (errors, known_ids) for the target's category_map against the routing map."""
    rmap = _read_json(MAP_PATH)
    if not isinstance(rmap, dict):
        return [f"cannot read routing map: {MAP_PATH}"], set()
    known = {c["id"] for c in rmap["categories"]}
    errors = []
    for jscat, ids in target.get("category_map", {}).items():
        for cid in ids:
            if cid not in known:
                errors.append(f"category_map['{jscat}'] -> '{cid}' is not a routing-map category id")
    return errors, known


def selftest() -> int:
    specs = sorted(TARGETS.glob("*.json"))
    assert specs, "no target specs under benchmark/targets/"
    for p in specs:
        t = _read_json(p)
        assert isinstance(t, dict), f"{p.name} is not a JSON object"
        for k in ("target", "answer_key"):
            assert k in t, f"{p.name} missing '{k}'"
        ak_type = (t.get("answer_key") or {}).get("type", "http-json")
        if ak_type == "findings-match":
            exp = t.get("expected")
            assert isinstance(exp, list) and exp, f"{p.name} findings-match target needs a non-empty 'expected'"
            for e in exp:
                assert e.get("match"), f"{p.name} expected item '{e.get('id')}' has no 'match'"
            # OPTIONAL precision sets: `truth` (extra known-true) + `not_expected` (known-false). Same
            # matcher shape as `expected`, so a precision-aware spec stays consistent with the routing map.
            for key in ("truth", "not_expected"):
                items = t.get(key)
                if items is not None:
                    assert isinstance(items, list), f"{p.name} '{key}' must be a list"
                    for e in items:
                        assert isinstance(e, dict) and e.get("match"), \
                            f"{p.name} {key} item '{(e or {}).get('id')}' has no 'match'"
        else:
            assert "category_map" in t, f"{p.name} (http-json) missing 'category_map'"
            for k in ("endpoint", "id_field", "category_field", "solved_field"):
                assert k in t["answer_key"], f"{p.name} answer_key missing '{k}'"
            errs, _ = _validate_map(t)
            assert not errs, f"{p.name}: " + "; ".join(errs)
    # scoring logic on a tiny synthetic key
    fake = [{"id": "a", "category": "X", "solved": True, "difficulty": 1},
            {"id": "b", "category": "X", "solved": False, "difficulty": 2},
            {"id": "c", "category": "Y", "solved": True, "difficulty": 1}]
    res = score(fake, {"target": "t"})
    assert res["overall"] == {"solved": 2, "total": 3, "recall": 0.6667}, res["overall"]
    assert res["by_category"]["X"]["recall"] == 0.5
    base = to_baseline(res, "selftest")
    # a drop in Y is a regression; an overall rise is an improvement
    worse = score([{"id": "c", "category": "Y", "solved": False, "difficulty": 1},
                   {"id": "a", "category": "X", "solved": True, "difficulty": 1},
                   {"id": "b", "category": "X", "solved": True, "difficulty": 2}], {"target": "t"})
    chk = check(worse, base, 0.0)
    assert any(r[0] == "Y" for r in chk["regressions"]), "Y regression not caught"
    assert not chk["ok"]
    # findings-match path (target-agnostic): expected manifest matched against a run's findings
    tgt = {"target": "t", "expected": [
        {"id": "sqli", "name": "SQLi", "group": "injection", "match": {"cwe": "CWE-89"}},
        {"id": "xss", "name": "XSS", "group": "injection", "match": {"cwe": "CWE-79"}},
        {"id": "ssrf", "name": "SSRF", "group": "ssrf", "match": {"cwe": "CWE-918"}}]}
    fnd = [{"owasp": "A03:2021-Injection", "cwe": "CWE-89", "wstg": "", "title": "SQLi in login"}]
    fm = score(_expected_challenges(tgt, fnd), tgt)
    assert fm["overall"] == {"solved": 1, "total": 3, "recall": 0.3333}, fm["overall"]
    assert not _match_expected({}, fnd[0]), "empty matcher must not match"

    # --- PRECISION / FP (TP + confirmed-FP + candidate, with truth + not_expected) -------------------
    ptgt = {"target": "t",
            "expected": [{"id": "sqli", "match": {"cwe": "CWE-89"}},
                         {"id": "xss", "match": {"cwe": "CWE-79"}}],
            "not_expected": [{"id": "fake-rce", "match": {"cwe": "CWE-77"}}]}
    pfnd = [{"owasp": "A03", "cwe": "CWE-89", "wstg": "", "title": "SQLi"},        # TP (truth=expected)
            {"owasp": "A03", "cwe": "CWE-77", "wstg": "", "title": "bogus RCE"},   # confirmed FP
            {"owasp": "A05", "cwe": "CWE-16", "wstg": "", "title": "odd header"}]  # UNLABELLED -> candidate
    pr = precision(pfnd, ptgt)
    assert (pr["true_positives"], pr["confirmed_fp"], pr["fp_candidates"]) == (1, 1, 1), pr
    assert pr["precision_upper"] == 0.5, pr          # TP / (TP+confirmed_FP) = 1/2
    assert pr["precision_lower"] == 0.3333, pr       # TP / reported            = 1/3
    assert pr["fp_rate_confirmed"] == 0.3333, pr     # candidate NOT counted as FP
    assert pr["candidates_for_adjudication"] == ["odd header"], pr

    # --- COST / TIME telemetry (synthetic diagnostics.json; cost carried IN the run record) ----------
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        eng = Path(d)
        (eng / "runtime").mkdir(parents=True)
        (eng / "runtime" / "diagnostics.json").write_text(json.dumps({"version": 2, "runs": [
            {"session": "s1", "started": "2026-01-01T00:00:00+00:00", "ended": "2026-01-01T00:00:40+00:00",
             "findings_count": 0, "phase_tally": [{"class": "sqli"}, {"class": "xss"}], "cost_usd": 1.0},
            {"session": "s2", "started": "2026-01-01T00:01:00+00:00", "ended": "2026-01-01T00:01:20+00:00",
             "findings_count": 2, "phase_tally": [{"class": "idor"}], "cost_usd": 3.0,
             "usage": {"input_tokens": 100, "output_tokens": 50}},
        ]}), encoding="utf-8")
        tel = telemetry(eng, verified_findings=2)
        assert tel["total_cost_usd"] == 4.0, tel                      # 1.0 + 3.0
        assert tel["mean_cost_per_finding_usd"] == 2.0, tel           # 4.0 / 2
        assert tel["total_wallclock_s"] == 60.0, tel                  # 40 + 20
        assert tel["time_to_first_finding_s"] == 60.0, tel           # legs up to the finding-bearing leg
        assert tel["total_steps"] == 3, tel                           # 2 + 1 phase-tally entries
        assert tel["total_tokens"] == 150, tel
        # cost cumulative-per-session rule via autorun.jsonl (same session repeats the running total).
        with tempfile.TemporaryDirectory() as d2:
            eng2 = Path(d2)
            (eng2 / "runtime").mkdir(parents=True)
            (eng2 / "runtime" / "diagnostics.json").write_text(json.dumps({"runs": [
                {"session": "AA", "started": "2026-01-01T00:00:00+00:00",
                 "ended": "2026-01-01T00:00:10+00:00", "findings_count": 1, "phase_tally": []}]}),
                encoding="utf-8")
            (eng2 / "runtime" / "autorun.jsonl").write_text(
                json.dumps({"type": "result", "session_id": "AA", "total_cost_usd": 5.0, "num_turns": 10,
                            "usage": {"input_tokens": 10, "output_tokens": 5}}) + "\n" +
                json.dumps({"type": "result", "session_id": "AA", "total_cost_usd": 9.0, "num_turns": 1,
                            "usage": {"input_tokens": 2, "output_tokens": 1}}) + "\n",
                encoding="utf-8")
            tel2 = telemetry(eng2, verified_findings=1)
            assert tel2["total_cost_usd"] == 9.0, tel2    # MAX per session (9), never 5+9=14
            assert tel2["total_tokens"] == 18, tel2       # tokens SUMMED per-leg: 15 + 3

    # --- REPRODUCIBILITY (variance across epochs) + check() blowout ----------------------------------
    e1 = {"overall": {"recall": 0.60}, "precision": {"precision_upper": 0.90}}
    e2 = {"overall": {"recall": 0.62}, "precision": {"precision_upper": 0.88}}
    e3 = {"overall": {"recall": 0.61}, "precision": {"precision_upper": 0.91}}
    rep = reproducibility([e1, e2, e3])
    assert rep["epochs"] == 3 and rep["enough_epochs"], rep
    assert rep["recall"]["mean"] == 0.61, rep
    assert rep["recall"]["spread"] == 0.02, rep
    noisy = {"target": "t", "overall": {"solved": 0, "total": 1, "recall": 0.0}, "by_category": {},
             "reproducibility": reproducibility(
                 [{"overall": {"recall": 0.2}}, {"overall": {"recall": 0.9}}, {"overall": {"recall": 0.5}}])}
    vchk = check(noisy, {"overall": {"recall": 0.0}, "by_category": {}}, 0.0, max_variance=0.1)
    assert not vchk["ok"] and any(r[0] == "recall-variance" for r in vchk["regressions"]), vchk
    # precision regression is caught too
    pbase = {"overall": {"recall": 0.0}, "by_category": {}, "precision": {"precision_upper": 0.9,
             "fp_rate_confirmed": 0.0}}
    pcur = {"target": "t", "overall": {"solved": 0, "total": 1, "recall": 0.0}, "by_category": {},
            "precision": {"precision_upper": 0.7, "fp_rate_confirmed": 0.0}}
    pchk = check(pcur, pbase, 0.05)
    assert not pchk["ok"] and any(r[0] == "precision" for r in pchk["regressions"]), pchk

    # --- SCOREBOARD renders from baselines (recall-only + full) --------------------------------------
    full_bl = to_baseline({"target": "demo", "overall": {"solved": 1, "total": 2, "recall": 0.5},
                           "by_category": {}, "precision": pr, "cost": tel,
                           "reproducibility": rep}, "selftest")
    sb = render_scoreboard([full_bl, load_baseline("juice-shop") if (BASELINES / "juice-shop.json").is_file()
                            else {"target": "x", "overall": {"recall": 0.3}}])
    assert sb.startswith("# Redstrike benchmark scorecard"), sb[:60]
    assert "demo" in sb and "Mean $/finding" in sb, "scoreboard missing columns"

    # --- LABELED-LAB scoring (CVE-KB-seeded self-labeling labs) + the boot_status=unverified honesty guard -
    labs = [
        {"slug": "wordpress-6.4.2-cve-2024-11111", "cve_id": "CVE-2024-11111", "component": "wordpress",
         "version": "6.4.2", "boot_status": "verified", "expected_class": {"cwe": "CWE-79", "vuln_class": "xss"},
         "expected_evidence": {"match": {"cwe": "CWE-79"}}},
        {"slug": "drupal-9.3.0-cve-2022-66666", "cve_id": "CVE-2022-66666", "component": "drupal",
         "version": "9.3.0", "boot_status": "verified", "expected_class": {"cwe": "CWE-502",
         "vuln_class": "deserialization"}, "expected_evidence": {"match": {"cwe": "CWE-502"}}},
        {"slug": "lodash-4.0.0-cve-2023-22222", "cve_id": "CVE-2023-22222", "component": "lodash",
         "version": "4.0.0", "boot_status": "unverified", "expected_class": {"cwe": "CWE-1321"},
         "expected_evidence": {"match": {"cwe": "CWE-1321"}}},
    ]
    lab_fnd = [{"owasp": "A03:2021-Injection", "cwe": "CWE-79", "wstg": "", "title": "Stored XSS in comments"},
               {"owasp": "A05", "cwe": "CWE-16", "wstg": "", "title": "unlabelled extra"}]
    lr = score_labs(labs, lab_fnd)
    # only the 2 VERIFIED labs score; the unverified lodash lab is excluded (honesty guard).
    assert lr["labs"]["scored"] == 2 and lr["labs"]["total"] == 3, lr["labs"]
    assert lr["labs"]["excluded_unverified"][0]["cve_id"] == "CVE-2023-22222", lr["labs"]
    # wordpress CVE (CWE-79) planted + found = TP; drupal CVE (CWE-502) planted but NOT found = miss.
    assert lr["overall"] == {"solved": 1, "total": 2, "recall": 0.5}, lr["overall"]
    per = {r["cve_id"]: r["pass"] for r in lr["labs"]["per_lab"]}
    assert per == {"CVE-2024-11111": True, "CVE-2022-66666": False}, per
    # precision: the matched finding is a TP vs the planted truth set; the extra is an UNLABELLED candidate.
    assert lr["precision"]["true_positives"] == 1 and lr["precision"]["fp_candidates"] == 1, lr["precision"]
    # ALL-unverified -> an honest empty score (numbers WITHHELD), never a fabricated figure.
    none_verified = score_labs([dict(labs[2])], lab_fnd)
    assert none_verified["overall"]["total"] == 0 and none_verified["labs"]["scored"] == 0, none_verified["labs"]
    assert "WITHHELD" in none_verified["labs"]["note"], none_verified["labs"]["note"]

    print(f"benchmark.py selftest: OK ({len(specs)} target spec(s); recall + precision/FP + cost/time + "
          f"reproducibility + scoreboard + labeled-labs verified)")
    return 0


def _score_one(target: dict, *, base_url=None, answer_key=None, engagement=None):
    """Score ONE epoch and attach precision + cost telemetry whenever an engagement dir is available.

    findings-match -> requires an engagement (its reported findings ARE the data). http-json -> scores the
    solved-API; if an engagement dir is ALSO supplied, precision + cost are attached from it too."""
    ak_type = (target.get("answer_key") or {}).get("type", "http-json")
    findings = None
    if ak_type == "findings-match":
        if not engagement:
            sys.exit("[!] a findings-match target needs --engagement <dir> (the run's output)")
        findings = _load_findings(Path(engagement))
        res = score(_expected_challenges(target, findings), target)
    else:
        res = score(fetch_answer_key(target, base_url, answer_key), target)
        if engagement:
            findings = _load_findings(Path(engagement))
    if findings is not None:
        res["precision"] = precision(findings, target)
    if engagement:
        tel = telemetry(Path(engagement), verified_findings=len(findings or []))
        if tel:
            res["cost"] = tel
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description="Redstrike benchmark scorecard (recall + precision + cost + repro).")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--score-labs", action="store_true", dest="score_labs",
                    help="score the generated CVE-KB-seeded labeled labs (benchmark/labs) against an "
                         "--engagement's reported findings (only boot_status=='verified' labs count)")
    ap.add_argument("--labs-dir", dest="labs_dir",
                    help="dir of generated labeled labs (default: benchmark/labs)")
    ap.add_argument("--repro", action="store_true",
                    help="score K epochs (repeat --engagement/--answer-key) and report recall/precision variance")
    ap.add_argument("--baseline", action="store_true", help="record the current score as the baseline")
    ap.add_argument("--check", action="store_true", help="compare to baseline; exit 2 on regression")
    ap.add_argument("--scoreboard", action="store_true", help="regenerate benchmark/SCOREBOARD.md from baselines")
    ap.add_argument("--map", action="store_true", dest="show_map")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--target", help="target name under benchmark/targets/")
    ap.add_argument("--base-url", help="live base URL of the running target")
    ap.add_argument("--answer-key", action="append",
                    help="captured answer-key JSON dump (instead of --base-url; repeatable for --repro)")
    ap.add_argument("--engagement", action="append",
                    help="engagement dir (findings-match scores its findings; repeatable for --repro)")
    ap.add_argument("--tolerance", type=float, default=0.0, help="allowed recall/precision drop before it's a regression")
    ap.add_argument("--epochs", type=int, default=3, help="--repro: minimum epochs for a sound variance estimate (default 3)")
    ap.add_argument("--max-variance", type=float, default=None,
                    help="--check: fail if reproducibility recall/precision stdev exceeds this (variance blowout)")
    ap.add_argument("--out", help="write the full result JSON here")
    ap.add_argument("--provenance", default="", help="note stored with a --baseline (how it was produced)")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.scoreboard:
        return generate_scoreboard()

    # --- labeled-lab scoring: self-labeling CVE-KB-seeded labs, no --target needed (they ARE the labels) ---
    if args.score_labs:
        engagements = args.engagement or []
        if not engagements:
            ap.error("--score-labs needs --engagement <dir> (the redstrike run to score against the labs)")
        labs = _load_labs(Path(args.labs_dir) if args.labs_dir else None)
        if not labs:
            ldir = args.labs_dir or str(LABS)
            sys.exit(f"[!] no labeled labs under {ldir} -- generate some first: "
                     f"python scripts/bench_labgen.py --kb <cve_kb.jsonl>")
        findings = _load_findings(Path(engagements[0]))
        res = score_labs(labs, findings)
        tel = telemetry(Path(engagements[0]), verified_findings=len(findings))
        if tel:
            res["cost"] = tel
        if args.out:
            op = Path(args.out)
            op.parent.mkdir(parents=True, exist_ok=True)
            op.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        if args.baseline:
            if res["overall"]["total"] == 0:
                sys.exit("[!] refusing to record a labeled-lab baseline with 0 VERIFIED labs -- boot + "
                         "promote at least one lab to boot_status='verified' first (no fabricated numbers).")
            BASELINES.mkdir(parents=True, exist_ok=True)
            prov = args.provenance or f"labeled-labs ({res['labs']['scored']} verified), {res['scored_at']}"
            (BASELINES / "labeled-labs.json").write_text(
                json.dumps(to_baseline(res, prov), indent=2) + "\n", encoding="utf-8")
            _print_score(res)
            print("\nwrote baseline -> benchmark/baselines/labeled-labs.json")
            return 0
        if args.as_json:
            print(json.dumps(res, indent=2))
        else:
            _print_score(res)
        return 0

    if not args.target:
        ap.error("need --target (or --selftest / --scoreboard / --score-labs)")
    target = load_target(args.target)
    engagements = args.engagement or []
    answer_keys = args.answer_key or []

    if args.show_map:
        errs, _ = _validate_map(target)
        print(f"# {target.get('name', target['target'])} category map -> Redstrike routing-map categories")
        for jscat, ids in target.get("category_map", {}).items():
            print(f"  {jscat:<28} -> {', '.join(ids)}")
        if errs:
            print("\nERRORS:")
            for e in errs:
                print(f"  - {e}")
            return 2
        print("\nall mapped ids exist in routing-map.json.")
        return 0

    # --- reproducibility: score K epochs, aggregate variance -----------------------------------------
    if args.repro:
        sources = [{"engagement": e} for e in engagements] + [{"answer_key": a} for a in answer_keys]
        if len(sources) < 2:
            ap.error("--repro needs >=2 epochs: repeat --engagement/--answer-key (K>=3 recommended)")
        epochs = [_score_one(target, base_url=args.base_url, **src) for src in sources]
        rep = reproducibility(epochs, min_epochs=args.epochs)
        res = dict(epochs[-1])                      # carry the last epoch's headline score + attach variance
        res["reproducibility"] = rep
        if args.out:
            op = Path(args.out)
            op.parent.mkdir(parents=True, exist_ok=True)
            op.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")
        if args.baseline:
            BASELINES.mkdir(parents=True, exist_ok=True)
            prov = args.provenance or f"{rep['epochs']}-epoch repro, {res['scored_at']}"
            (BASELINES / f"{args.target}.json").write_text(
                json.dumps(to_baseline(res, prov), indent=2) + "\n", encoding="utf-8")
            _print_score(res)
            print(f"\nwrote baseline -> benchmark/baselines/{args.target}.json")
            return 0
        if args.as_json:
            print(json.dumps(res, indent=2))
        else:
            _print_score(res)
        if not rep["enough_epochs"]:
            print(f"\n[!] only {rep['epochs']} epoch(s) (<{args.epochs}) -- variance estimate is under-powered.")
        return 0

    # --- single score (one source) -------------------------------------------------------------------
    res = _score_one(target, base_url=args.base_url,
                     answer_key=answer_keys[0] if answer_keys else None,
                     engagement=engagements[0] if engagements else None)
    if args.out:
        op = Path(args.out)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8")

    if args.baseline:
        BASELINES.mkdir(parents=True, exist_ok=True)
        src = (answer_keys[0] if answer_keys else None) or args.base_url or (engagements[0] if engagements else None)
        prov = args.provenance or f"scored {res['scored_at']} from {src}"
        bl = to_baseline(res, prov)
        (BASELINES / f"{args.target}.json").write_text(json.dumps(bl, indent=2) + "\n", encoding="utf-8")
        _print_score(res)
        print(f"\nwrote baseline -> benchmark/baselines/{args.target}.json")
        return 0

    if args.check:
        base = load_baseline(args.target)
        chk = check(res, base, args.tolerance, max_variance=args.max_variance)
        if args.as_json:
            print(json.dumps({"result": res["overall"], "precision": res.get("precision"),
                              "cost": res.get("cost"), "check": chk}, indent=2))
        else:
            _print_score(res)
            print(f"\n# Regression check vs baseline ({base['recorded_at']}, tol {args.tolerance:.0%})")
            for cat, bv, cv in chk["regressions"]:
                print(f"  REGRESS  {cat:<26} {bv:.3f} -> {cv:.3f}")
            for cat in chk["missing_categories"]:
                print(f"  MISSING  {cat:<26} (in baseline, absent now)")
            for cat, bv, cv in chk["improvements"]:
                print(f"  up       {cat:<26} {bv:.3f} -> {cv:.3f}")
            if chk["new_categories"]:
                print(f"  new categories (not in baseline): {', '.join(chk['new_categories'])}")
            print(f"\n{'PASS' if chk['ok'] else 'FAIL'}: "
                  + ("no regression." if chk["ok"] else "regression detected (see above)."))
        return 0 if chk["ok"] else 2

    if args.score:
        if args.as_json:
            print(json.dumps(res, indent=2))
        else:
            _print_score(res)
        return 0

    ap.error("choose one of --score / --score-labs / --repro / --baseline / --check / --scoreboard / "
             "--map / --selftest")


if __name__ == "__main__":
    sys.exit(main())
