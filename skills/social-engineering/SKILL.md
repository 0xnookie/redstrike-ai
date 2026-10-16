# Social Engineering Agent

> ATOMIC agent — AUTHORIZED phishing + pretext simulation (email/vishing/smishing) measuring human-layer controls; findings are process/control gaps + aggregate metrics, never named-person blame.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** + **explicit written authorization naming the target population**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** confirm written authorization + the authorized target population → design a pretext + campaign (sender, landing/harvest page, tracking) → choose a delivery (link / attachment / OAuth-consent) → run the approved, time-boxed simulation → measure click/submit/report rates + identify the control gaps → rate → emit (aggregate) → review → verify.
- **TOOLS:** `gophish` (campaign/sender/landing page/tracking), OSINT feeders for scoped targeting, `refs/se_methodology.md`.
- **GOAL:** Measure the human-layer control posture of an AUTHORIZED, pre-named target population via a simulated campaign — surfacing process/control gaps (reporting path, link/attachment handling, MFA/consent hygiene, filtering) and aggregate susceptibility metrics — with benign test-credential submissions only. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `se_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = signed written authorization naming the target population + `scope.yaml` (authorized sender domains, target group, window) + scoped OSINT. `refs/` = `se_methodology.md`. Chains FROM `osint` (scoped); chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic; phishing/vishing/smishing variants in refs).

## Goal
Measure human-layer controls on an authorized, named population and surface control gaps — aggregate, benign. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The authorized target population (named/consented group) + the pretext + the control being tested (reporting, link/attachment handling, MFA/OAuth-consent hygiene, email filtering)
- The delivery vector + what it measures (click rate, credential-submit rate, report rate, consent-grant rate)
- A benign proof: an APPROVED simulated campaign captured benign test-credential submissions / click + report metrics — NO real malware, NO real credentials stored, NO individual named for blame

## Steps  (action · tool · output)
1. Confirm signed written authorization + the authorized population + sender domains + window · RoE · (into tests)
2. Design the pretext + campaign (sender, landing/credential-harvest page, tracking pixels/links) · `gophish` · `se_tests.jsonl`
3. Choose delivery: tracked link / benign attachment / OAuth-consent prompt (approved option) · `gophish` · `se_tests.jsonl`
4. Scoped OSINT targeting (only the authorized population; no out-of-scope individuals) · `osint` · `se_tests.jsonl`
5. Run the approved, time-boxed simulation; collect click/submit/report events · `gophish` · `poc/<id>/`
6. (If in scope) vishing/smishing methodology against the authorized group with a benign pretext · `refs` · `se_tests.jsonl`
7. Aggregate metrics + identify control gaps + rate (CVSS, process-level) · synth · `findings.json`
8. Emit report (aggregate, no named blame) · synth · `report.md` · 9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- `gophish` (sender/landing/tracking), scoped `osint`, `refs/se_methodology.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- Signed written authorization naming the target population, authorized sender domains + window, scoped OSINT, `scope.yaml`

## Outputs
`se_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** authorization confirmation + pretext/campaign design.
- **Phase 2 (target-specific):** approved time-boxed simulation + aggregate metrics + control-gap rating (approval-gated).

## Safety
**Heaviest authorization gate.** Proceed ONLY with explicit **written authorization that names the target
population**; never target individuals outside that scope; never a real third party, customer, or a
non-consenting person. Benign simulation only — **no real malware**, no real exploit payloads; a
credential-harvest page captures benign test submissions and **never stores real passwords** (hash+discard /
accept-and-redirect). Findings are **process/control gaps + aggregate metrics**, not a list shaming named
people. Time-boxed; authorized sender domains only; teardown the campaign + harvest page after; handle any
captured data as sensitive and redact. Audit-log every send.
