# Engagement Docs

> DOCUMENTATION skill — writes the full client-ready deliverable suite for an engagement:
> **Rules of Engagement (RoE)** (pre-engagement) and the formal **pentest report** + **attestation** +
> **retest template** (post-engagement). Consumes `scope.yaml` + the ACCEPTED findings (from `reporting`).
> Emits documents, not findings → `review.md` only, no `verify.md`.

## Interview
- **STEPS:** determine mode (pre/post) → gather engagement metadata from scope.yaml → [pre] write RoE + scope + authorization → [post] ingest accepted findings → write executive summary → detailed findings → risk summary + remediation roadmap → appendices → attestation + retest template → review.
- **TOOLS:** `jq` over the engagement dirs, `refs/doc_templates.md`.
- **GOAL:** Produce the professional engagement documents — a RoE that scopes and authorizes the test, and a full report (exec summary → detailed findings → remediation → appendices) plus an attestation letter and a retest template — client-ready, factual, accepted-findings-only. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `RoE.md`, `report.md`, `attestation.md`, `retest.md`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `scope.yaml` (client, dates, scope, contacts, RoE) + `<engagement>/report/findings_consolidated.json` (accepted findings from `reporting`). `refs/` = `doc_templates.md`. Chains FROM `scope.yaml` (pre) + `reporting` (post); terminal (to the human).
- **DECOMPOSITION:** n/a (documentation skill).

## Goal
Produce the engagement deliverable suite (RoE + report + attestation + retest).
DONE = `checklist.md` all `- [x]` · `review.md` PASS (all docs exist, non-zero; report reflects only accepted findings).

## What do we want
- **RoE** — engagement overview, authorization, in/out scope, testing windows, contacts + escalation, emergency/kill-switch procedures, restrictions (no DoS, data handling), deliverables, sign-off block
- **Report** — title page; executive summary (non-technical: scope, dates, risk posture, severity counts, headline findings); the **Assurance & Coverage** clause (below); methodology (PTES / OWASP WSTG / MITRE ATT&CK); detailed findings (per finding: severity + CVSS + CWE/OWASP/ATT&CK + asset + description + reproduction + evidence refs + impact + remediation + references); risk summary; prioritized remediation roadmap; appendices (tools, scope, out-of-scope notes)
- **Attestation** — a short letter: what was tested, when, by whom, overall posture (for compliance/third parties) — **grounded in the Assurance & Coverage clause** (the posture line must match measured coverage, never overstate it)
- **Assurance & Coverage (MACHINE-FILLED — required in the report + attestation)** — a factual coverage statement sourced ONLY from the engagement's own machine artifacts, never narrated: pull from `coverage_ledger.json`, `reviews/recall_audit.verdict.json`, and `runtime/diagnostics.json`. It states:
  - **Surface tested / total** — tested vs discovered surfaces (from `surface_ledger.json` when present; else the coverage ledger's attempted vs routed categories).
  - **Categories run / accepted / blocked / skipped** — counts by `coverage_ledger.json` category `status` (attempted, blocked, skipped, n/a, pending), with each skip's stated reason.
  - **Open-proof-gap count** — findings carried as `rejection_class: open-proof-gap` + any recall gaps the recall-audit verdict left `BLOCKED`/open — real-looking but undemonstrated here, reported as caveats, never silently dropped.
  - **Run outcome** — `runtime/diagnostics.json` latest run `outcome` (`produced-findings` / `clean-tested` / `degraded-empty` / `failed`) + its `degraded_reason` when degraded.
  - **Hard rule (enforced by `verify_completion.py --engagement`, R4):** a deliverable must NOT assert a clean/hardened/secure posture ("hardened", "held the line", "no vulnerabilities/findings", "secure posture", …) while the recall-audit verdict has UNADJUDICATED gaps OR the run outcome is `degraded-empty`/`failed`. An incomplete or degraded run is reported AS SUCH in this clause — it is not a clean bill of health. The deliverable-consistency gate HARD-fails that contradiction once a report exists.
- **Retest** — a template to record remediation verification per finding

## Steps  (action · tool · output)
1. Determine mode (pre-engagement = RoE; post = full suite) + gather metadata from `scope.yaml` · read · (context)
2. **[pre]** Write the RoE (scope + authorization + RoE restrictions + contacts + windows) · `refs/doc_templates.md` · `RoE.md`
3. **[post]** Ingest accepted findings (`findings_consolidated.json`; `review.verdict == accepted` only) · `jq` · (in memory)
4. Write the executive summary (non-technical + severity counts + headline findings) · synth · `report.md`
4b. **Fill the Assurance & Coverage clause** (surfaces tested/total · categories run/accepted/blocked/skipped · open-proof-gap count · run outcome) — read `coverage_ledger.json` + `surface_ledger.json` + `reviews/recall_audit.verdict.json` + `runtime/diagnostics.json`; NEVER assert a clean/hardened posture over an unadjudicated recall gap or a degraded/failed run · `jq` · `report.md`
5. Write detailed findings (per-finding template, risk-ordered) + risk summary + remediation roadmap + appendices · `refs` · `report.md`
6. Write the attestation letter (posture line grounded in the Assurance & Coverage clause) + the retest template · `refs` · `attestation.md`, `retest.md`
7. Emit a short index/summary of produced docs · synth · `summary.md`
8. /REVIEW SKILL · `review.md`

## Tools
- `jq` over the engagement dirs, `refs/doc_templates.md`

## Inputs
- `scope.yaml` (client, dates, scope, contacts, RoE); `<engagement>/report/findings_consolidated.json` (post)
- **Assurance & Coverage sources:** `coverage_ledger.json`, `surface_ledger.json`, `reviews/recall_audit.verdict.json`, `runtime/diagnostics.json`
- `refs/doc_templates.md`

## Outputs
`RoE.md` · `report.md` · `attestation.md` · `retest.md` · `summary.md` · `logs/`

## Phases
- **Phase 1 (pre-engagement):** RoE + scope + authorization.
- **Phase 2 (post-engagement):** full report + attestation + retest from accepted findings.

## Safety
Factual + accepted-only: the report includes ONLY `accepted` findings (never `rejected`/`needs-evidence`),
and states only what the engagement actually tested/found. Keep redacted secrets redacted. The RoE encodes
AUTHORIZATION from `scope.yaml`/the client — do NOT fabricate authorization; if scope/authorization is
missing, flag it, don't invent it. Deliverables are DRAFTS for the human to finalize + sign; the engagement
dir is the audit trail. Never overstate severity or impact beyond the evidence.
**Posture must match measured recall (R4):** the Assurance & Coverage clause is machine-filled from the
engagement's own artifacts, and a clean/hardened/secure posture claim is forbidden while the recall-audit
verdict has unadjudicated gaps or the run was `degraded-empty`/`failed`. An incomplete/degraded run is
reported as such — `verify_completion.py --engagement` HARD-fails the deliverable that narrates "hardened"
over a contradicting coverage signal once a report exists (empty/degraded ≠ clean).
