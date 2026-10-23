# Recall benchmark — operator runbook

Measuring recall is a deliberate, hands-on run: it needs a live labelled target and a real Redstrike
engagement against it. It is **not** a push-CI job (CI only runs `--selftest`). Here is the end-to-end loop.

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
non-composite findings — i.e. recall credits what actually got **reported**.

## Interpreting it

- **Overall recall** is the headline: solved / total known vulns.
- **Per-category** recall shows *where* recall is weak — that is where to aim routing/payload/recon work.
- A `--check` regression means a change made Redstrike miss something it used to catch: investigate before
  merging. An improvement is printed too (consider re-recording the baseline up).
- `benchmark/results/` is git-ignored scratch; commit a baseline deliberately, not every score.
