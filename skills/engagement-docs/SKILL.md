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
- **Report** — title page; executive summary (non-technical: scope, dates, risk posture, severity counts, headline findings); methodology (PTES / OWASP WSTG / MITRE ATT&CK); detailed findings (per finding: severity + CVSS + CWE/OWASP/ATT&CK + asset + description + reproduction + evidence refs + impact + remediation + references); risk summary; prioritized remediation roadmap; appendices (tools, scope, out-of-scope notes)
- **Attestation** — a short letter: what was tested, when, by whom, overall posture (for compliance/third parties)
- **Retest** — a template to record remediation verification per finding

## Steps  (action · tool · output)
1. Determine mode (pre-engagement = RoE; post = full suite) + gather metadata from `scope.yaml` · read · (context)
2. **[pre]** Write the RoE (scope + authorization + RoE restrictions + contacts + windows) · `refs/doc_templates.md` · `RoE.md`
3. **[post]** Ingest accepted findings (`findings_consolidated.json`; `review.verdict == accepted` only) · `jq` · (in memory)
4. Write the executive summary (non-technical + severity counts + headline findings) · synth · `report.md`
5. Write detailed findings (per-finding template, risk-ordered) + risk summary + remediation roadmap + appendices · `refs` · `report.md`
6. Write the attestation letter + the retest template · `refs` · `attestation.md`, `retest.md`
7. Emit a short index/summary of produced docs · synth · `summary.md`
8. /REVIEW SKILL · `review.md`

## Tools
- `jq` over the engagement dirs, `refs/doc_templates.md`

## Inputs
- `scope.yaml` (client, dates, scope, contacts, RoE); `<engagement>/report/findings_consolidated.json` (post)
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
