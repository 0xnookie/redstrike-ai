# Redstrike recall benchmark (Phase 2)

Redstrike's precision is strong — every reported finding is independently verified. **Recall** — *what did
we miss?* — was unmeasured. This benchmark fixes that: it runs Redstrike against a target with an enumerable
answer key, scores recall per vulnerability class, and **fails CI when recall regresses**.

Why this is the highest-leverage change: every other improvement (better routing, deeper recon, broader
payloads) is unverifiable without a recall number. See the research doc *Redstrike Recall: Not Missing Vulns
& CVEs* for the full argument.

## How it works

1. **Answer key.** A target spec (`targets/<name>.json`) declares how to read ground truth. OWASP Juice Shop
   is first: 116 labelled challenges, each machine-checkable via `GET /api/Challenges` (boolean `solved`).
2. **Score.** `scripts/benchmark.py --score` computes `recall = solved / total`, overall and per native
   category and per difficulty.
3. **Baseline.** `--baseline` records the current score as `baselines/<name>.json` — the floor to beat.
4. **Gate.** `--check` scores again and **exits non-zero** if overall or any category recall dropped below
   the baseline (beyond `--tolerance`).

```bash
# one-off, against a running Juice Shop
python scripts/benchmark.py --score    --target juice-shop --base-url http://localhost:3000
python scripts/benchmark.py --baseline --target juice-shop --base-url http://localhost:3000
python scripts/benchmark.py --check    --target juice-shop --base-url http://localhost:3000

# score from a captured dump instead of a live fetch (for CI after an engagement run)
curl -s http://localhost:3000/api/Challenges > challenges.json
python scripts/benchmark.py --check --target juice-shop --answer-key challenges.json

python scripts/benchmark.py --map --target juice-shop   # challenge-category -> Redstrike category
python scripts/benchmark.py --selftest                  # validate specs + scoring logic (no network)
```

## Current baseline

`baselines/juice-shop.json` — recorded 2026-10-21 at **40/116 = 34.5%** (assisted session: the first
autonomous pass reached ~18/116; a dedicated follow-up reached 40/116). This is a provisional floor; replace
it with a **clean autonomous-run** score once the engagement run is wired into CI (below).

## CI

- `validate.yml` runs `benchmark.py --selftest` on every push — keeps the target specs valid and the
  category map in sync with `routing-map.json` (no network).
- `recall-benchmark.yml` (`workflow_dispatch`) runs the **full loop**: spin up Juice Shop → install the
  Redstrike CLI + Claude Code → `redstrike init` an engagement scoped to the service and pre-approve benign
  exploitation (drops `exploitation` from `approval_required_phases`, leaving host-level post-exploitation
  gated) → `redstrike run --autonomous` (budget/turn-capped, deny-by-default + scope gate, `--allow Bash`,
  benign-PoC prompt) → capture `/api/Challenges` → score + gate. Needs a repo secret **`ANTHROPIC_API_KEY`**
  (or `CLAUDE_CODE_OAUTH_TOKEN`); without it the engagement run and gate are skipped and only the tooling is
  validated.

  **Record the autonomous baseline first.** The committed baseline (40/116) is an *assisted* ceiling, so a
  `mode=check` run would fail honestly. Dispatch once with **`mode=baseline`** to record the true autonomous
  floor (it's uploaded as an artifact — commit it to `benchmark/baselines/juice-shop.json`). Then `mode=check`
  gates future runs within `tolerance` (default 0.05, to absorb run-to-run LLM variance). Tune `max_turns` /
  `max_budget_usd` to trade cost for depth.

  **One-time setup (secret → baseline → check), with exact commands: [`RUNBOOK.md`](RUNBOOK.md).**

## Two answer-key types (how targets stay general, not Juice-Shop-overfit)

A `targets/<name>.json` declares one of:

- **`http-json`** — a live solved-API (Juice Shop: `GET /api/Challenges`, boolean `solved`). Score with
  `--base-url` (live) or `--answer-key <dump>`.
- **`findings-match`** — a **static expected-vuln manifest**; recall is scored by matching the run's
  `findings.json` (accepted/verified findings) against `expected[]`. Needs **no solved-API**, so **any**
  labelled target works. Score with `--engagement <dir>`:
  ```bash
  python scripts/benchmark.py --score --target generic-web --engagement engagements/<client>-<date>
  ```
  A matcher fires when EVERY declared key matches: `cwe` (exact), `owasp` (prefix), `wstg` (substring),
  `title_regex`. `targets/generic-web.json` is a ready OWASP-Top-10 template — clone it per target and trim
  `expected` to that app's known vulnerabilities.

The scorer, baseline, and regression gate are **target-agnostic** — they work the same for both types.

## Targets roadmap

Juice Shop is the live-API reference. Add shape-diverse targets to avoid overfitting: **WebGoat** / **DVWA**
(classic web), **VAmPI** / **crAPI** (API-centric, for BOLA/BFLA). Apps without a solved-API use
`findings-match` with a curated `expected[]` manifest.

## Files

- `targets/<name>.json` — target spec (answer-key adapter + category map). **Tracked.**
- `baselines/<name>.json` — recorded recall floor. **Tracked.**
- `results/` — per-run score dumps. **Gitignored** (transient).
