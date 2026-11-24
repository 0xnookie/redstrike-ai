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

## Labeled labs — CVE-KB-seeded, self-labeling (`scripts/bench_labgen.py`)

The hardest part of a scorecard is getting **labelled** targets. A twin reconstructed from a *live* target
has **unknown ground truth** (unlabelled). A lab seeded from the cached CVE knowledge-base is instead
**self-labelling**: stand up `component@known-vulnerable-version` and **the CVE *is* the label** (the
known answer). That turns the `cve_kb.jsonl` redstrike already produces into labelled fixtures the harness
can finally score for real recall/precision numbers.

**Generate.** `scripts/bench_labgen.py` reads a `cve_kb.jsonl` (and/or a `cve_intel.json`) and, for each
entry that is *lab-able* (a valid CVE id + a component + a **pinnable** version + a weakness class), emits
under `benchmark/labs/<slug>/`:

- `docker-compose.yml` — a **best-effort** scaffold standing up the vulnerable `component@version` (+ a
  minimal backing database when the component implies one), deterministic from the KB metadata. Application
  components become an image (`image: wordpress:6.4.2` — a target-descriptive fact from the CVE data);
  library packages become a runtime base image + a pinned install (not a non-existent package-as-image).
- `answer_key.json` — the **ground-truth label** (`skills/_contract/bench_label.schema.json`): `cve_id`,
  `component`, `version`, `expected_class`, and `expected_evidence` (the *shape* of proof — a matcher — not
  a baked exploit). It is ground truth for **scoring**, not an exploit.
- `README.md` — what the lab is, the label, and the boot/verify caveat.

Where the KB lacks enough to stand a lab (an un-pinnable range, no weakness class, an ecosystem with no
deterministic scaffold), the entry is **skipped** and recorded in the run's `skipped[]` report with a
reason — rather than emitting a broken/guessed lab.

**The honesty guard (why fabricated numbers can't leak).** The generator can boot nothing, so every
`answer_key.json` is written `boot_status: "unverified"` and the generator **never** emits `verified`. The
scorer counts **only `verified`** labs toward any measured number; `unverified`/`failed` labs are excluded
and listed. So an un-booted scaffold cannot produce a figure, and `--score-labs --baseline` **refuses** to
record a baseline with zero verified labs. A human promotes a lab by booting it, confirming the vulnerable
component is actually present and reachable, then editing `boot_status` to `verified`.

**Score.** `--score-labs` matches a run's **reported** findings against the labs' labels and folds into the
existing scorecard shape (recall + per-category + precision + the per-lab pass/fail `labs` block): a planted
CVE whose matcher matches a reported finding is a true positive (recall); an unmatched reported finding stays
an **FP candidate** (unlabelled — flagged, never auto-failed), consistent with the rest of the harness.

```bash
# 1) generate labelled labs from a cached CVE KB (labs land in benchmark/labs/, gitignored scratch)
python scripts/bench_labgen.py --kb engagements/<x>/cve-intelligence/cve_kb.jsonl
python scripts/bench_labgen.py --selftest              # deterministic; no Docker needed

# 2) a human boots a lab, confirms it, and sets answer_key.json boot_status -> "verified"
cd benchmark/labs/<slug> && docker compose up -d       # then verify the component is really vulnerable

# 3) run redstrike against the booted lab, then score the run against the labels
python scripts/benchmark.py --score-labs --engagement engagements/<run-dir>
python scripts/benchmark.py --score-labs --engagement engagements/<run-dir> --baseline   # needs >=1 verified
```
