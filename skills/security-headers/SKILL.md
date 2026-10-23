# Security Headers Agent

> ATOMIC single agent (no feeder) — assess missing/weak security headers and report with ACCURATE,
> de-inflated severity. Most header gaps are Info/Low unless they enable a concrete attack in context.
> Read-only (non-destructive) but ACTIVE over the network — httpx/curl header fetches + `nuclei` — so it
> honors `_contract/roe-gate.md`: scope + rate-limit on every fetch, and run `nuclei` DETECTION-ONLY
> (`-etags rce,intrusive,dos,oast`; never `-tags <product>`). findings-producing → carries `review.md` +
> `verify.md` (the verify guards against the #1 failure mode here: severity inflation / best-practice noise).

## Interview
- **STEPS:** collect response headers across key pages → evaluate against a matrix → assess real exploitability in context → rate honestly → emit → review → verify.
- **TOOLS:** `httpx`/`curl -I`, `nuclei -t http/misconfiguration`, cookie inspector; `jq`.
- **GOAL:** Produce an accurate security-header assessment where each reported item has a real, contextual impact (not "missing header = vuln"). Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `headers.json`, `assessment.json`, `findings.json`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/findings/endpoints.jsonl` (key pages), `scope.yaml`. Chains FROM `js-analysis`; cross-refs `clickjacking` (XFO), `cors` (ACAO), `xss-*` (CSP). Chains TO `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Assess security headers and report only items with contextual impact, correctly rated. Emit
`findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- Header set per key page: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, COOP/COEP/CORP, cookie flags (Secure/HttpOnly/SameSite)
- Per gap: does it enable a REAL attack given this app? (don't report best-practice noise)

## Steps  (action · tool · output)
1. Collect headers across key pages (authed + unauthed) · `httpx -include` / `curl -I` · `headers.json`
2. Evaluate each against the matrix + cookie flags · synth · `assessment.json`
3. Assess contextual exploitability (missing CSP + reflected input? HSTS + no redirect? etc.) · synth · (into findings)
4. Rate honestly (most → Info/Low; elevate only with a concrete path) · synth · `findings.json`
5. Emit report · synth · `report.md`
6. /REVIEW · `review.md` · 7. /VERIFY · `verify.md`

## Tools
- **Collect/eval:** `httpx -include`, `curl -I`, `nuclei -t http/misconfiguration/http-missing-security-headers`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `endpoints_*.txt`, optional `auth.env`
- `scope.yaml`

## Outputs
`headers.json` · `assessment.json` · `findings.json` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** collect headers + matrix evaluation.
- **Phase 2 (target-specific):** contextual exploitability assessment + honest rating.

## Safety
Read-only. The real risk here is REPORTING quality, not blast radius: do not flood the report with
best-practice "missing header" noise rated as vulns. Cross-reference the dedicated agents
(clickjacking/cors/xss) rather than double-reporting.
