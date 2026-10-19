# WAF / Filter Bypass Agent

> CAPABILITY / SERVICE skill (no findings of its own) — when a target is behind a WAF/CDN/anti-bot and a
> vuln agent's payloads are being blocked, this profiles the filter and returns a TUNED evasion ladder the
> calling agent re-runs ITS payloads through. Emits NO findings → `review.md` only (no `verify.md`).
> ACTIVE (sends probes) → imports `_contract/roe-gate.md`.

## Interview
- **STEPS:** confirm a block (baseline vs blocked) → fingerprint the WAF/CDN → climb the evasion ladder (encoding/case/comment per vuln-class · HTTP manipulation · TLS/JA3 · HTTP/2-3 · origin discovery) → record which transforms pass a benign canary → emit a WAF profile + tuned bypass notes for the calling agent.
- **TOOLS:** `wafw00f`/`identYwaf`, interceptor, `curl --http2/--http3`, `openssl s_client`, `refs/waf_bypass.md`.
- **GOAL:** Turn "blocked" into a working delivery path: identify the WAF and the specific transforms that let a BENIGN canary through, so the vuln agent (sqli/xss/ssrf/…) can confirm its bug. Produces guidance, not a finding. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `waf_profile.json`, `bypass_notes.md`, `logs/`.
- **DATA / RAG:** inputs = the blocked request/agent + `js-analysis/out/<site>/analysis/site-summary.md` (stack/WAF) + `scope.yaml`. `refs/` = `waf_bypass.md`. Called BY any vuln agent / the orchestrator when a WAF blocks; feeds the tuned payloads back.
- **DECOMPOSITION:** n/a (capability).

## Goal
Profile the WAF and find the benign-canary bypass path. Emit `waf_profile.json` + `bypass_notes.md`.
DONE = `checklist.md` `- [x]` · `review.md` PASS. (No findings.json — the real finding belongs to the vuln agent.)

## What do we want
- The WAF/CDN identity (Cloudflare/Akamai/Imperva/AWS/Sucuri/F5/…) from headers, cookies, challenge pages
- The minimal transform(s) that pass a BENIGN canary the WAF currently blocks (so no payload strength is wasted)
- A profile the calling agent consumes to re-tune its own payloads

## Steps  (action · tool · output)
1. Confirm a block: benign request 200 vs the agent's payload 403/429/challenge · interceptor · `logs/`
2. Fingerprint the WAF/CDN (headers `Server`/`X-*`, cookies `__cf_bm`/`AWSALB`, challenge JS, routes) · `wafw00f` · `waf_profile.json`
3. Climb the ladder with a BENIGN canary (e.g. a harmless marker, not a live exploit): encoding/case/comment → HTTP header/HPP/chunk → TLS/JA3 align → HTTP/2-3 → origin discovery · `refs/waf_bypass.md` · `waf_profile.json`
4. Record which transforms pass + residual limits · synth · `bypass_notes.md`
5. Hand the tuned transform set back to the calling vuln agent · synth · `bypass_notes.md`
6. /REVIEW · `review.md`

## Tools
- `wafw00f`/`identYwaf`, interceptor, `curl --http2/--http3`, `openssl s_client -servername`, `refs/waf_bypass.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- the blocked request / calling agent, `js-analysis/out/<site>/analysis/site-summary.md`, `scope.yaml`

## Outputs
`waf_profile.json` · `bypass_notes.md` · `logs/`

## Phases
- **Phase 1 (generic):** confirm block + fingerprint.
- **Phase 2 (target-specific):** find the benign-canary bypass + hand tuned transforms back.

## Safety
Evasion is for AUTHORIZED testing of the in-scope app — **never** to attack the WAF vendor or another
tenant, and **not a DoS**: techniques like Rapid Reset / CONTINUATION flood / connection exhaustion are
catalogued for awareness but NOT fired. Probe with benign canaries; stay in scope; respect the RoE and the
anti-automation ladder; audit-log. If origin discovery finds a real IP, confirm it is in scope before using it.
