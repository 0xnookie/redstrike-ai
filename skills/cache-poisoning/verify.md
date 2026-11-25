# Web Cache Poisoning — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the cache-poisoning gauntlet. Confirmed = a shared cache serves one request's
content to a DIFFERENT request, by EITHER mode: (a) an unkeyed input reflected into a cached response, or
(b) a cache-key COLLISION (cache key injection — keyed fragments manipulated so two different requests
resolve to one key). The cache HIT on the second, differently-shaped request is the proof.

## Cache-poisoning false-positive gauntlet (base check #3)
- [ ] **Cross-request cache HIT.** Evidence shows a SECOND request (classic mode: clean, no attacker
      header/param; CKI mode: the same key reached via a DIFFERENT byte-split) receiving the primed
      response from cache (`X-Cache: hit` / `Age` > 0) — not just per-request reflection. Reflection
      without a cache hit is a different (or no) bug.
- [ ] **The confirmation mode is sound.**
      - *Classic poisoning:* the input is genuinely UNKEYED — changing it doesn't change the cached
        variant — otherwise each attacker only poisons their own key.
      - *Cache key injection:* the two requests are genuinely DIFFERENT (distinct uri/header/scheme bytes)
        yet share ONE cache entry because the key is built by delimiter-less concatenation — the collision
        is the bug, so "the input is keyed" is NOT a rejection here. Reject only if the "collision" is two
        identical requests, or the HIT came from the attacker's own normal key (no real cross-request serve).
- [ ] **Impact is real.** The cached payload does something (executes XSS, redirects, breaks the page
      for DoS, or — deception — caches a private/authenticated page for anonymous users).
- [ ] **Hygiene.** Payload benign; poison scoped to a buster you control or short-TTL; recorded in
      `cleanup.md`; approval obtained for a shared/production cache.
- [ ] **In scope.**

## CVSS integrity
Impact scales with blast radius (persistent cached XSS to all visitors → High/Critical). Cache
deception of private data → per sensitivity. Justify from the confirmed hit + payload effect.

Run `scripts/cvss.py "<CVSS vector>"` for any **Medium+** finding to compute the base score (do not hand-assert it); the gate recomputes and flags drift.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|blocked|rejected|needs-evidence", "reviewer": "cache-poisoning-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["X-Forwarded-Host unkeyed; clean request got cached redirect (X-Cache:hit, Age:40); buster-scoped; approved"],
  "scope_ok": true, "notes": "poison limited to /?cb=rs7f3q; purged after confirm" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
