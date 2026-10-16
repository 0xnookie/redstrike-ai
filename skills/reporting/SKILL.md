# Reporting

> TERMINAL skill — the engagement aggregator. Consumes every skill's `findings.json`, keeps only
> `review.verdict == accepted` findings, de-dupes across agents, and assembles the client report.
> Emits NO new findings → `review.md` only, no `verify.md` (findings were verified upstream).
> Standardized reporting: CVSS + evidence + executive summary.

## Interview
- **STEPS:** collect all findings → filter to accepted → de-dupe cross-agent → normalize severity/CVSS → order by risk → write executive summary + per-finding writeups → emit report + consolidated JSON → review.
- **TOOLS:** `jq` over the engagement dirs, `refs/report_template.md`.
- **GOAL:** Produce a client-ready report of verified findings — executive summary, risk-ordered findings with evidence + reproduction + remediation, and a consolidated machine-readable file. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `findings_consolidated.json`, `report.md`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = every `<engagement>/<skill>/findings.json` + `scope.yaml`. `refs/` = `report_template.md`. Chains FROM all findings-producing skills; terminal (chains to the human).
- **DECOMPOSITION:** n/a (terminal aggregator).

## Goal
Assemble the engagement report from ACCEPTED findings only.
DONE = `checklist.md` all `- [x]` · `review.md` PASS (report + consolidated JSON exist, non-empty; CVSS present on each finding).

## What do we want
- Every `accepted` finding, de-duped (e.g. the same bug found by `idor` and `bola-bfla` = one entry)
- Risk-ordered list (Critical→Info) with CVSS, affected asset, evidence refs, reproduction, impact, remediation, CWE/WSTG/ATT&CK
- An executive summary (scope, dates, risk posture, headline findings) for non-technical readers

## Steps  (action · tool · output)
1. Collect all `<engagement>/*/findings.json` · `jq` · (in memory)
2. Keep only `review.verdict == "accepted"` (status `verified`) · `jq` filter · (in memory)
3. De-dupe across agents (same asset+class+root cause → merge, keep strongest evidence) · synth · `findings_consolidated.json`
4. Normalize severity/CVSS; order Critical→Info · `refs/report_template.md` · `findings_consolidated.json`
5. Write per-finding sections (template) + executive summary · synth · `report.md`
6. Emit a short stats summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- `jq` over engagement dirs, `refs/report_template.md`

## Inputs
- every `<engagement>/<skill>/findings.json` (+ their `poc/`/evidence refs)
- `scope.yaml` (engagement metadata: client, dates, scope)
- `refs/report_template.md`

## Outputs
`findings_consolidated.json` · `report.md` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** collect + filter-to-accepted + de-dupe.
- **Phase 2 (target-specific):** CVSS normalization + writeups + executive summary.

## Safety
Report only `accepted` findings — never include `rejected`/`needs-evidence` items as confirmed. Keep
redacted secrets redacted. The report + evidence stay in the engagement dir (git-ignored); deliver to
the client through the agreed channel only.
