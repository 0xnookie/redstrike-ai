# HTTP Request Smuggling Agent

> ATOMIC single agent (no feeder) — one confirmation: a front-end/back-end desync lets a request
> prefix influence the NEXT request on the connection.
> ACTIVE, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval gate** (near
> exploitation: desync can poison other users' traffic / cause outages). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** fingerprint the front-end/back-end chain → probe CL.TE / TE.CL / TE.TE / CL.CL + H2 downgrade → confirm desync SAFELY (timing + self-canary) → assess impact → rate → emit → cleanup → review → verify.
- **TOOLS:** Burp Repeater (disable auto content-length), `smuggler.py`, `h2csmuggler`, turbo-intruder; timing-based detection.
- **GOAL:** Confirm an HTTP desync with a SAFE, self-contained PoC (timing differential + a canary that poisons only your own follow-up request) — never by poisoning real users. Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `chain_fingerprint.json`, `desync_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `cleanup.md`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/out/<site>/analysis/site-summary.md` (front-end/CDN fingerprint), target endpoints, `scope.yaml`. `refs/` = `smuggling_techniques.md`. Chains TO `cache-poisoning` (desync→cache) + `reporting`.
- **DECOMPOSITION:** n/a (atomic).

## Goal
Find a request-smuggling desync and prove it with a SAFE confirmation; assess impact (cache poisoning,
auth bypass, credential capture) without harming real traffic. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted · **approval obtained**.

## What do we want
- The proxy chain (front-end/CDN + back-end) and how each parses `Content-Length` vs `Transfer-Encoding`
- A confirmed desync class (CL.TE / TE.CL / TE.TE / CL.CL / H2.CL / H2.TE)
- A SAFE PoC (timing + self-canary), plus the impact path — WITHOUT poisoning real users

## Steps  (action · tool · output)
1. Fingerprint the chain (front-end/CDN, back-end) · `js-analysis/out/<site>/analysis/site-summary.md` + `httpx` · `chain_fingerprint.json`
2. Probe desync classes with timing detection (safe: no victim capture) · `smuggler.py` / Burp · `desync_tests.jsonl`
3. Confirm the desync with a SELF-canary (your own next request on the socket) · Burp/turbo-intruder · `poc/<id>/`
4. Assess impact path (cache, auth, cred capture) — describe, do NOT weaponize against users · synth · (into findings)
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Record anything that must be reset + confirm no persistent poison left · synth · `cleanup.md`
7. Emit report · synth · `report.md`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- **Detect/confirm:** `smuggler.py`, Burp Repeater (manual CL/TE), `h2csmuggler`, turbo-intruder; timing-differential detection
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/out/<site>/analysis/site-summary.md` (front-end/CDN), endpoints
- `scope.yaml` (RoE — **approval gate** before confirmation)
- `refs/smuggling_techniques.md`

## Outputs
`chain_fingerprint.json` · `desync_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `cleanup.md` · `logs/`

## Phases
- **Phase 1 (generic):** chain fingerprint + timing-based desync detection (no victim capture).
- **Phase 2 (target-specific):** safe self-canary confirmation + impact assessment + rating (approval-gated).

## Safety
HIGH blast radius — a desync can corrupt OTHER users' requests and cause outages. Therefore:
confirm ONLY via timing + a self-poisoning canary (your own follow-up request); **never** capture a
real user's request or inject into shared state; get **human approval** before confirmation (RoE);
rate-limit hard; verify no persistent desync/queue poisoning remains (`cleanup.md`); honor the kill switch.
