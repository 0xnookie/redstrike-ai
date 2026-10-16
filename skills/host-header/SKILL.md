# Host Header Injection Agent

> ATOMIC single agent (no feeder) — one confirmation: attacker-controlled Host / X-Forwarded-Host
> reaches a security-relevant sink (password-reset link, absolute redirect, cache key, SSRF routing).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md`; carries `review.md` + `verify.md`.

## Interview
- **STEPS:** identify host-reflecting behaviors → test Host / X-Forwarded-Host / X-Host overrides → observe reflection into links/redirects/cache → confirm impact → rate → emit → review → verify.
- **TOOLS:** `curl`/interceptor (override Host + forwarding headers), password-reset flow driver, `jq`. Headers to try: `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, duplicate `Host`, absolute-URI request line.
- **GOAL:** Confirm host header injection — the app uses an attacker-controlled host in a security-relevant sink (most impactfully a password-reset link that then points to the attacker). Done = checklist `- [x]`, review passes, findings accepted.
- **OUTPUT:** `host_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `js-analysis/endpoints_*.txt` (password-reset, email, redirect flows), `scope.yaml`, `oob.collaborator` (routing/SSRF checks). `refs/` = `host_header_payloads.md` (override headers + sinks). Chains FROM `js-analysis`; chains TO `reporting` (and SSRF/cache-poisoning agents).
- **DECOMPOSITION:** n/a (atomic). Overlaps `cache-poisoning` (host as cache key) and `ssrf` (routing).

## Goal
Find security-relevant sinks fed by an attacker-controlled Host/forwarding header; confirm + rate
(password-reset poisoning is the headline). Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` all `- [x]` · `review.md` PASS · every finding accepted.

## What do we want
- Behaviors that reflect Host: password-reset links, absolute URLs in responses/emails, redirects, cache keys
- Which header the app trusts (`Host`, `X-Forwarded-Host`, `X-Host`, …)
- Confirmed impact: poisoned reset link → attacker host, cache poisoning, or routing

## Steps  (action · tool · output)
1. Identify host-reflecting behaviors (reset flow, absolute URLs, redirects) · crawl + `jq` · (into tests)
2. Test Host + forwarding-header overrides per behavior · `curl`/interceptor · `host_tests.jsonl`
3. Drive the password-reset flow with an injected host; inspect the resulting link · reset driver · `poc/<id>/`
4. Confirm impact (reset link host = attacker / cache poisoned / routing) · synth · (into findings)
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report + curl · synth · `report.md`, `curl_commands.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- **Probe:** `curl`/interceptor with overridden `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, duplicate `Host`, absolute-URI request line
- **Confirm:** password-reset flow driver; `oob.collaborator` for routing/SSRF; `refs/host_header_payloads.md` (override-header matrix + sinks)
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `js-analysis/`: `endpoints_*.txt` (reset/email/redirect flows)
- `scope.yaml` (+ `oob.collaborator`)

## Outputs
`host_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** find host-reflecting behaviors + header-override matrix.
- **Phase 2 (target-specific):** password-reset / redirect / cache impact confirmation + rating.

## Safety
Driving a real password-reset flow touches account state and email — use a **test account**, don't
trigger resets for real users, scope-gate, audit-log. Routing/SSRF checks use your OOB host only.
