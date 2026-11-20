# Redstrike benchmark scorecard

Redstrike's architecture is at the field frontier — but it can **prove** nothing without a measured,
reproducible scorecard. This benchmark is that scorecard. It scores four axes against labelled targets and
flags regressions against a committed floor:

- **Recall** — *what did we miss?* — solved / total known vulns (overall, per vulnerability class, per difficulty).
- **Precision** — *is what we report real?* — reported findings vs the target's **truth** set, with honest
  handling of unlabelled findings (see below).
- **Cost / time** — **mean cost per verified finding**, **time-to-first-finding**, and totals, from the
  engagement's runtime telemetry.
- **Reproducibility** — recall/precision **variance across K≥3 epochs** (the Cybench convention); a variance
  blowout is itself a regression.

Why it matters: every other improvement (better routing, deeper recon, broader payloads) is *unverifiable*
without these numbers. Capability alone proves nothing; **measured precision + cost + reproducibility** is the
single highest-leverage differentiator. The committed, public scorecard lives in
[`SCOREBOARD.md`](SCOREBOARD.md) (regenerate it with `python scripts/benchmark.py --scoreboard`).

## What runs where (two-speed)

A **score** needs a live labelled target **and/or** a real engagement — so measuring the scorecard is an
**operator workflow** (see `RUNBOOK.md`), not a push-CI job. (The old live-engagement-in-CI run was removed
for exactly this reason.) What **CI** runs is `scripts/benchmark.py --selftest` (via `scripts/validate.py`):
deterministic, no network — it validates every target spec, keeps each `category_map` in sync with
`skills/_contract/routing-map.json`, and exercises the recall + precision + cost + reproducibility logic with
synthetic fixtures, so the harness can't rot. **CI never depends on a live target.**

## How it works

1. **Answer key.** A target spec (`targets/<name>.json`) declares how to read ground truth. Two kinds:
   - **`http-json`** — a live app with an enumerable answer key. OWASP Juice Shop is first: 116 challenges,
     each machine-checkable via `GET /api/Challenges` (boolean `solved`). `recall = solved / total`.
   - **`findings-match`** — target-agnostic: an `expected` vuln manifest matched against an engagement's
     **reported** findings (accepted/blocked, non-composite). No live solved-API needed, so *any* labelled
     app scores from a run's output. This is how recall generalizes beyond Juice-Shop-style apps (and guards
     against overfitting to one target).
2. **Score.** `--score` computes recall overall + per category + per difficulty. When an `--engagement` dir is
   given it **also** attaches **precision** (from the target's truth set) and **cost/time** telemetry.
3. **Baseline.** `--baseline` records the current score as `baselines/<name>.json` — the floor to beat. It
   carries whichever axes the score produced (recall always; precision/cost/repro when measured).
4. **Check.** `--check` scores again and **exits non-zero** on a recall **or** precision regression (beyond
   `--tolerance`), a rising confirmed-FP rate, or a reproducibility **variance blowout** (beyond
   `--max-variance`). Run it at your own cadence against a fresh engagement.
5. **Scoreboard.** `--scoreboard` regenerates `SCOREBOARD.md` from all committed baselines — the public,
   versioned, reproducible scorecard. Never hand-edit it.

```bash
python scripts/benchmark.py --selftest                         # CI runs this — specs + logic, no network

# http-json (Juice Shop): score a live app, or a captured /api/Challenges dump
python scripts/benchmark.py --score    --target juice-shop --base-url http://localhost:3000
curl -s http://localhost:3000/api/Challenges > challenges.json
python scripts/benchmark.py --check    --target juice-shop --answer-key challenges.json --tolerance 0.02

# findings-match: score ANY engagement's output — recall + precision + cost in one pass
python scripts/benchmark.py --score    --target generic-web --engagement engagements/<client>-<date>

# reproducibility: K>=3 epochs of the SAME target -> recall/precision variance
python scripts/benchmark.py --repro    --target generic-web \
    --engagement run1 --engagement run2 --engagement run3 --epochs 3

python scripts/benchmark.py --scoreboard                       # regenerate SCOREBOARD.md from baselines
python scripts/benchmark.py --map      --target juice-shop     # native-category -> Redstrike category
python scripts/benchmark.py --baseline --target generic-web --engagement engagements/<client>-<date>
```

## Precision (truth set + false positives)

A `findings-match` target carries the truth set that drives precision. Every reported finding is classed:

- **True positive** — matches a matcher in `expected` (which doubles as the truth set) or an extra `truth[]`
  entry.
- **Confirmed false positive** — matches a `not_expected[]` matcher (a vuln *known to be absent* on this
  target). These count toward the confirmed FP-rate.
- **FP candidate** — matches *neither*. Because **real-but-unlabelled findings exist**, a candidate is
  **flagged for adjudication, never auto-counted as an FP and never auto-failed**.

Precision is reported as a **range** so no honesty is lost: `precision_upper = TP / (TP + confirmed_FP)`
(candidates adjudicated out) down to `precision_lower = TP / all_reported` (every candidate treated as an FP,
worst case). `--check` only regresses on the *confirmed* FP-rate and on `precision_upper` — candidates alone
never fail the gate.

## Cost / time telemetry

With `--engagement`, the scorer reads `runtime/diagnostics.json` (+ `runtime/autorun.jsonl` for $/tokens) and
reports **mean cost per verified finding** (the efficiency differentiator), **time-to-first-finding**, total
cost, total engine time, tokens and steps. Two honest caveats baked in: `total_cost_usd` is
*cumulative-per-session* in the engine stream, so cost is taken as the **max per session** (never summed);
and since findings carry no per-item timestamp, time-to-first-finding is a **leg-granularity proxy over engine
work time** (idle gaps between resume legs are excluded). If no diagnostics exist, cost is simply omitted — it
never fails a score.

## Reproducibility

`--repro` scores **K≥3 epochs** (repeat `--engagement`/`--answer-key`) of the same target and reports the
mean / population-stdev / spread of recall and precision across runs. K≥3 is the Cybench convention; fewer
epochs still compute but are flagged under-powered. A `--check --max-variance <σ>` run fails if the recall or
precision stdev exceeds the threshold — a reproducibility **blowout** is a regression even when the mean held.

## Current baseline

`baselines/juice-shop.json` — **40/116 = 34.5%** recall (assisted session: the first autonomous pass reached
~18/116; a dedicated follow-up reached 40/116). A *provisional, recall-only* floor — the precision/cost/repro
columns in `SCOREBOARD.md` populate once a baseline is recorded with `--engagement` / `--repro`. Replace it
with a clean autonomous-run score (`--baseline`) once you have one. Lowering a baseline is a deliberate,
reviewed act.

## Adding a target

Clone `targets/generic-web.json`, rename it, and trim `expected` to the app's known vulnerabilities (a
matcher fires when **every** declared key matches: `cwe` exact, `owasp` prefix, `wstg` substring,
`title_regex`). Optionally add `not_expected[]` (same `{id, name, match}` shape) for vulns known to be absent —
these make precision's confirmed-FP detection sharper — and `truth[]` for known-true vulns you don't want
scored for recall. That's it — `--selftest` validates it (shape + routing-map sync) and
`--score --engagement` scores recall + precision + cost. WebGoat / DVWA / crAPI are natural next targets.
