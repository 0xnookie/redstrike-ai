# WAF / Filter Bypass Agent

> CAPABILITY / SERVICE skill (no findings of its own) — when a target is behind a WAF/CDN/anti-bot and a
> vuln agent's payloads are being blocked, this profiles the filter and returns a TUNED evasion ladder the
> calling agent re-runs ITS payloads through. Emits NO findings → `review.md` only (no `verify.md`).
> ACTIVE (sends probes) → imports `_contract/roe-gate.md`.
>
> **Two distinct jobs, never conflated:** (1) **operational WAF hygiene** — ALWAYS-ON, every engagement behind
> a WAF: don't get your egress IP banned while testing (benign canaries, NOT signature-blasting). This is NOT a
> "bypass" and needs no evasion authorization — it is how you stay reachable. (2) **authorized evasion-to-exploit**
> — RoE-GATED: deliberately defeat a *content filter* to prove a SPECIFIC benign canary (hence a specific bug) is
> reachable past it. Spoofing a client identity/fingerprint to slip a scripted client past a gateway during
> ordinary testing is NEITHER — it stays barred by `_contract/roe-gate.md` + `_contract/anti-automation-ladder.md`.

## Interview
- **STEPS:** **fingerprint FIRST** (you can't be WAF-safe or evade what you haven't identified) → baseline egress health on a known-good public path → confirm a block (benign baseline vs blocked) → **tell an egress ban from a per-request filter** (estate-wide recon-200→now-403/429 drift = YOUR egress is banned → HALT, don't evade) → climb the evasion ladder (encoding/case/comment per vuln-class · HTTP manipulation · TLS/JA3 · HTTP/2-3 · origin discovery) ONLY when the RoE authorizes evasion → record which transforms pass a benign canary → emit a WAF profile + tuned bypass notes for the calling agent.
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
1. **Fingerprint FIRST** — WAF/CDN id + block-shell signature (headers `Server`/`X-*`, cookies `__cf_bm`/`AWSALB`, challenge JS, routes). Record the WAF product/vendor + its block signature in `waf_profile.json` AND the engagement — you can't be WAF-safe or evade what you haven't identified · `wafw00f`/`identYwaf` · `waf_profile.json`
2. **Baseline egress health** — a benign request to a known-good public path (`/robots.txt`, `/`) returns the recon-expected status; snapshot it so you can see drift later · interceptor · `logs/egress_health.log`
3. Confirm a block: benign request 200 vs the agent's payload 403/429/challenge — a per-request CONTENT filter on this sink · interceptor · `logs/`
4. **Ban check (always-on, not a bypass)** — if hosts/paths recon just saw as 200 now return the block-shell/429 ESTATE-WIDE (or a normally-public path like `/robots.txt` 403s), YOUR egress is banned (not a per-host policy deny) → **HALT; do NOT evade, re-encode, or disguise the client** (`_contract/anti-automation-ladder.md` block-vs-deny rule); recover per **Safety** · interceptor · `logs/egress_health.log`
5. Climb the ladder with a BENIGN canary (RoE-authorized evasion only — a harmless marker, not a live exploit): encoding/case/comment → HTTP header/HPP/chunk → TLS/JA3 align → HTTP/2-3 → origin discovery · `refs/waf_bypass.md` · `waf_profile.json`
6. Record which transforms pass + residual limits · synth · `bypass_notes.md`
7. Hand the tuned transform set back to the calling vuln agent · synth · `bypass_notes.md`
8. /REVIEW · `review.md`

## Tools
- `wafw00f`/`identYwaf`, interceptor, `curl --http2/--http3`, `openssl s_client -servername`, `refs/waf_bypass.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- the blocked request / calling agent, `js-analysis/out/<site>/analysis/site-summary.md`, `scope.yaml`

## Outputs
`waf_profile.json` · `bypass_notes.md` · `logs/`

## Phases
- **Phase 1 (generic):** fingerprint FIRST + baseline egress health + confirm block (and tell a block from an egress ban). Always-on hygiene — runs with or without evasion authorization.
- **Phase 2 (target-specific, RoE-gated):** find the benign-canary bypass past the content filter + hand tuned transforms back. Runs ONLY when the RoE authorizes evasion.

## Safety
Evasion is for AUTHORIZED testing of the in-scope app — **never** to attack the WAF vendor or another
tenant, and **not a DoS**: techniques like Rapid Reset / CONTINUATION flood / connection exhaustion are
catalogued for awareness but NOT fired. Probe with benign canaries; stay in scope; respect the RoE and the
anti-automation ladder; audit-log. If origin discovery finds a real IP, confirm it is in scope before using it.

- **Operational WAF hygiene (ALWAYS-ON — not a "bypass", needs no evasion authorization).** Every engagement
  behind a WAF keeps *detection* WAF-safe: benign/low-signal canaries, encoded over raw, rate-capped
  (`_contract/roe-gate.md` `rate_limit_rps`). **Never broadcast raw attack-signatures** (`/etc/passwd`,
  `{{7*7}}`, `' OR '1'='1`, `../../`) across many hosts in broad probes — that is exactly what a WAF's
  IP-reputation engine scores on, and it gets your *egress* banned estate-wide. A signature string belongs in a
  single, targeted canary against ONE identified sink — never sprayed. (**Field lesson — city-of-vienna:** a
  prior session blasted raw `/etc/passwd` / `{{7*7}}` / SQL-tautology payloads in broad probes against a
  government estate behind "MA 01 - Wien Digital" (`server: Magistrat der Stadt Wien - Web Gateway`); the
  gateway's IP-reputation engine banned the egress IP ESTATE-WIDE — every in-scope host recon had seen as 200
  then returned the 403 block-shell from that IP, burning the whole engagement's egress. Only one app on
  unrelated infra still answered.)
- **An egress ban is engagement-wide, not one host — detect it early, then HALT.** A **403 on one host/path** is
  usually a per-host *policy deny* (skip it, keep going). The ban tell is different: a **sudden 403/429
  block-shell across hosts/paths that recon just saw as 200**, or a 403 on a normally-public path (`/robots.txt`)
  — the WAF denying your *client* wholesale (`_contract/anti-automation-ladder.md` block-vs-deny rule). Baseline
  a known-good public path up front (step 2) and watch for recon-200→now-403 **drift**. On a real ban: **stop —
  do NOT escalate rungs, re-encode, or disguise the client to get back in** (beating a reputation gate that way
  is evasion, barred by `_contract/roe-gate.md`).
- **Egress recovery (authorized egress only).** An IP-reputation ban is categorically different from a
  per-request content filter: it keys on the *client IP's* recent history, so **no payload transform un-bans
  it**. Recover by (a) **pausing** until the reputation ban lapses (minutes–hours, vendor-dependent), then
  resuming GENTLY + WAF-safe; or (b) **rotating to a fresh, AUTHORIZED egress** (a source IP the RoE/`scope.yaml`
  permits), resuming slow and benign. **Never** try to "un-ban" by spoofing the client identity/fingerprint to
  disguise the banned client — `_contract/roe-gate.md` bars that. Record the ban + the recovery choice in
  `bypass_notes.md`.
- **Authorized evasion-to-exploit is RoE-gated and content-filter-scoped.** The evasion ladder (Phase 2) runs
  ONLY when the RoE authorizes evasion, and ONLY to prove a *specific* benign canary (hence a specific bug) is
  reachable past a **content filter** — encoding ladders, normalization/parser-differential tricks, chunking,
  casing, alternate content-types. It is NOT a license to **brute the WAF**, nor to **spoof a browser
  fingerprint / JA3 to slip a scripted client past a gateway** during ordinary testing — that disguise stays
  barred by `_contract/roe-gate.md` + `_contract/anti-automation-ladder.md`. Record the evasion authorization
  (`_contract/roe-gate.md` §2) BEFORE climbing the ladder.
