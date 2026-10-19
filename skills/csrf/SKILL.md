# CSRF Agent

> ATOMIC single agent (no feeder) — one confirmation method: a state-changing request executes
> from an attacker origin using the victim's ambient credentials.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`; carries `review.md` + `verify.md`.

## Interview
- **STEPS:** enumerate state-changing requests → map anti-CSRF defenses per request → classify gaps → craft cross-origin PoC → confirm execution with victim creds → assess impact → rate → emit → review → verify.
- **TOOLS:** `jq` over `js-analysis/` endpoints + forms; interceptor (Caido/mitmproxy) for token replay/removal; `puppeteer` for cross-origin PoC in a real logged-in session; ladder fetch.
- **GOAL:** Confirm CSRF — a security-relevant state change triggered cross-origin without a valid anti-CSRF token, with a working PoC. Done = checklist all `- [x]`, review passes, every finding accepted.
- **OUTPUT:** `state_changing_requests.json`, `defense_matrix.json`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/endpoints.jsonl` + forms, `auth.env` (a logged-in session), `scope.yaml`. `refs/` = `poc_templates.md`. Chains FROM `js-analysis`; chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic). Note: overlaps CORS (credentialed cross-origin reads) and clickjacking (UI-driven CSRF) — de-dupe.

## Goal
Find requests that change security-relevant state and lack effective CSRF protection, and prove a
cross-origin PoC fires them with the victim's cookies. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding `review.verdict = accepted`.

## What do we want
- Every state-changing request (method + endpoint + params + content-type)
- Per request: token present? validated? SameSite cookie? custom-header/origin/referer check?
- A cross-origin PoC that executes the change using ambient cookies
- Impact of the change + CVSS

## Steps  (action · tool · output)
1. Enumerate state-changing requests (POST/PUT/PATCH/DELETE; sensitive GETs) · `jq` endpoints + forms + interceptor · `state_changing_requests.json`
2. Map defenses per request (token, SameSite, custom header, origin/referer) · interceptor + replay · `defense_matrix.json`
3. Classify gaps (no token / unvalidated token / SameSite=None / cookie-auth) · synth · (into findings)
4. Craft cross-origin PoC (auto-submit form / `fetch` with credentials) · `refs/poc_templates.md` · `poc/<id>/poc.html`
5. Confirm the change fires cross-origin with victim creds · `puppeteer` (logged-in profile) · `poc/<id>/` evidence
6. Assess impact + rate (CVSS) + write finding · synth · `findings.json`
7. Emit report · synth · `report.md`
8. /REVIEW SKILL · `review.md` → `verify_completion.py`
9. /VERIFY · `verify.md` (subagent)

## Tools
- **Enumerate/defense:** `jq`, interceptor (Caido / mitmproxy), token removal/replay
- **PoC/confirm:** `puppeteer`/`playwright` (victim session), `refs/poc_templates.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/findings/endpoints.jsonl` (state=live), forms/routes
- `auth.env`: a valid victim session (cookies)
- `scope.yaml` (RoE)
- `refs/poc_templates.md`

## Outputs
`state_changing_requests.json` · `defense_matrix.json` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** enumerate state-changing requests + defense matrix.
- **Phase 2 (target-specific):** PoC + cross-origin confirmation + impact + rating.

## Safety
Active — a confirmed PoC performs a real state change with the victim's creds. Use a **test account**;
keep changes reversible/benign; scope-gate; rate-limit; audit-log. No destructive change on a real
account without approval (RoE `no_destructive`).
