# Benchmark scorecard — operator runbook

Measuring the scorecard (recall + precision + cost + reproducibility) is a deliberate, hands-on run: it needs
a live labelled target and/or a real Redstrike engagement against it. It is **not** a push-CI job (CI only
runs `--selftest`). Here is the end-to-end loop.

## A. Juice Shop (`http-json`, live solved-API)

Juice Shop tracks which of its 116 challenges you've solved and exposes that at `GET /api/Challenges`.
Solve challenges *during the engagement*, then read recall straight off the app.

```bash
# 1. bring the target up (pin a version so the answer key is stable)
docker run --rm -d -p 3000:3000 --name juice bkimminich/juice-shop:v20.3.0

# 2. run a Redstrike engagement against http://localhost:3000 (see the main README / redstrike skill).
#    Authorize it in scope.yaml as a local, you-own-it target.

# 3. score recall off the live solved state
python scripts/benchmark.py --score --target juice-shop --base-url http://localhost:3000

#    …or capture the answer key once and score offline (reproducible):
curl -s http://localhost:3000/api/Challenges > challenges.json
python scripts/benchmark.py --score --target juice-shop --answer-key challenges.json --out benchmark/results/juice-$(date -u +%F).json

# 4. compare against the recorded floor; exit 2 on a regression beyond the tolerance
python scripts/benchmark.py --check --target juice-shop --answer-key challenges.json --tolerance 0.02

docker rm -f juice
```

Recording a new floor (only when you have a clean autonomous-run score, and intend it as the number to
beat):

```bash
python scripts/benchmark.py --baseline --target juice-shop --answer-key challenges.json \
  --provenance "clean autonomous run, redstrike <sha>, $(date -u +%F)"
```

## B. Any labelled app (`findings-match`, target-agnostic)

No live solved-API required — score the engagement's **reported** findings against an expected-vuln
manifest. Clone `targets/generic-web.json`, trim `expected` to that app's known issues, then:

```bash
python scripts/benchmark.py --score --target <your-target> --engagement engagements/<client>-<date>
```

`_load_findings` reads whichever findings layout the run produced (consolidated report, a root
`findings.json`, or the union of per-skill `*/findings.json`) and counts only accepted/blocked,
non-composite findings — i.e. recall credits what actually got **reported**. The same `--score --engagement`
pass **also** reports precision (vs the target's truth set) and cost/time (from `runtime/diagnostics.json` +
`runtime/autorun.jsonl`) — no extra step.

## C. Reproducibility (K≥3 epochs)

Run the SAME target K≥3 times (separate engagement dirs), then aggregate the variance:

```bash
python scripts/benchmark.py --repro --target <your-target> \
  --engagement engagements/<t>-run1 --engagement engagements/<t>-run2 --engagement engagements/<t>-run3 \
  --epochs 3 --out benchmark/results/<t>-repro.json

# gate a change on variance (fail if recall/precision stdev blows out):
python scripts/benchmark.py --check --target <your-target> --max-variance 0.10 \
  --engagement engagements/<t>-rerun
```

Record a repro result as the baseline (`--repro --baseline`) to publish the variance on the scoreboard.

## D. Scoreboard (the committed, public scorecard)

```bash
python scripts/benchmark.py --scoreboard      # regenerate benchmark/SCOREBOARD.md from all baselines
```

`SCOREBOARD.md` is generated — never hand-edit it. Regenerate it whenever you record/replace a baseline, and
commit the regenerated file alongside the baseline change.

## Interpreting it

- **Overall recall** is the headline: solved / total known vulns. **Per-category** recall shows *where* recall
  is weak — that is where to aim routing/payload/recon work.
- **Precision** is a range: `precision_upper` (candidates adjudicated out) .. `precision_lower` (worst case).
  **FP candidates are unlabelled, not failures** — triage them: a genuine new bug becomes a `truth[]`/`expected`
  entry, a genuine false alarm becomes a `not_expected[]` entry (then it counts toward the confirmed FP-rate).
- **Mean $/finding** and **time-to-first-finding** are the efficiency axes — a capability gain that doubles cost
  is not a free win.
- A `--check` regression (recall, precision, confirmed-FP rate, or a variance blowout) means a change made
  Redstrike worse: investigate before merging. Improvements are printed too (consider re-recording the baseline).
- `benchmark/results/` is git-ignored scratch; commit a baseline (and the regenerated `SCOREBOARD.md`)
  deliberately, not every score.
