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
- `recall-benchmark.yml` (`workflow_dispatch`) spins up Juice Shop, **runs the Redstrike engagement**, then
  runs `--check`. The engagement-run step is the open piece: it needs the agent runtime + credentials and is
  marked as pluggable in the workflow. Until it's wired, trigger the workflow after a local/manual run that
  populated the target, or run `--check` locally.

## Targets roadmap

Juice Shop first (breadth across the OWASP Top 10). Add shape-diverse targets to avoid overfitting:
**WebGoat** / **DVWA** (classic web), **VAmPI** / **crAPI** (API-centric, for BOLA/BFLA). Each is a new
`targets/<name>.json` with its own answer-key adapter; the scorer and gate are target-agnostic.

## Files

- `targets/<name>.json` — target spec (answer-key adapter + category map). **Tracked.**
- `baselines/<name>.json` — recorded recall floor. **Tracked.**
- `results/` — per-run score dumps. **Gitignored** (transient).
