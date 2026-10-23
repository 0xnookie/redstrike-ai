# Redstrike recall benchmark

Redstrike's precision is strong — every reported finding is independently verified. **Recall** — *what did
we miss?* — is the unmeasured axis. This benchmark fixes that: it scores recall against a labelled target,
per vulnerability class, and flags regressions against a recorded floor.

Why it matters: every other improvement (better routing, deeper recon, broader payloads) is *unverifiable*
without a recall number. See the research doc *Redstrike Recall: Not Missing Vulns & CVEs* for the argument.

## What runs where

A recall **score** needs a live labelled target **and** a real engagement — so measuring recall is an
**operator workflow** (see `RUNBOOK.md`), not a push-CI job. (The old live-engagement-in-CI run was removed
for exactly this reason.) What **CI** runs is `scripts/benchmark.py --selftest` (via `scripts/validate.py`):
deterministic, no network — it validates every target spec, keeps each `category_map` in sync with
`skills/_contract/routing-map.json`, and exercises the scoring + regression logic, so the harness can't rot.

## How it works

1. **Answer key.** A target spec (`targets/<name>.json`) declares how to read ground truth. Two kinds:
   - **`http-json`** — a live app with an enumerable answer key. OWASP Juice Shop is first: 116 challenges,
     each machine-checkable via `GET /api/Challenges` (boolean `solved`). `recall = solved / total`.
   - **`findings-match`** — target-agnostic: an `expected` vuln manifest matched against an engagement's
     **reported** findings (accepted/blocked, non-composite). No live solved-API needed, so *any* labelled
     app scores from a run's output. This is how recall generalizes beyond Juice-Shop-style apps (and guards
     against overfitting to one target).
2. **Score.** `--score` computes recall overall + per native category + per difficulty.
3. **Baseline.** `--baseline` records the current score as `baselines/<name>.json` — the floor to beat.
4. **Check.** `--check` scores again and **exits non-zero** if overall or any category recall dropped below
   the baseline (beyond `--tolerance`). Run this at your own cadence against a fresh engagement.

```bash
python scripts/benchmark.py --selftest                         # CI runs this — specs + logic, no network

# http-json (Juice Shop): score a live app, or a captured /api/Challenges dump
python scripts/benchmark.py --score    --target juice-shop --base-url http://localhost:3000
curl -s http://localhost:3000/api/Challenges > challenges.json
python scripts/benchmark.py --check    --target juice-shop --answer-key challenges.json --tolerance 0.02

# findings-match: score ANY engagement's output against an expected-vuln manifest
python scripts/benchmark.py --score    --target generic-web --engagement engagements/<client>-<date>

python scripts/benchmark.py --map      --target juice-shop   # native-category -> Redstrike category
python scripts/benchmark.py --baseline --target juice-shop --base-url http://localhost:3000
```

## Current baseline

`baselines/juice-shop.json` — **40/116 = 34.5%** (assisted session: the first autonomous pass reached
~18/116; a dedicated follow-up reached 40/116). A *provisional* floor — replace it with a clean
autonomous-run score (`--baseline`) once you have one. Lowering a baseline is a deliberate, reviewed act.

## Adding a target

Clone `targets/generic-web.json`, rename it, and trim `expected` to the app's known vulnerabilities (a
matcher fires when **every** declared key matches: `cwe` exact, `owasp` prefix, `wstg` substring,
`title_regex`). That's it — `--selftest` will validate it and `--score --engagement` will score it.
WebGoat / DVWA / crAPI are natural next targets.
