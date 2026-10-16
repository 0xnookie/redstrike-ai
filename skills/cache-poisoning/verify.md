# Web Cache Poisoning — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the cache-poisoning gauntlet. Confirmed = an unkeyed input lands in a CACHED
response served to a DIFFERENT request. The cache HIT is the proof — re-fetch without the buster.

## Cache-poisoning false-positive gauntlet (base check #3)
- [ ] **Cross-user cache HIT.** Evidence shows a second, clean request (no attacker header/param)
      receiving the poisoned response from cache (`X-Cache: hit` / `Age` > 0) — not just per-request
      reflection. Reflection without a cache hit is a different (or no) bug.
- [ ] **Input is genuinely UNKEYED.** The poisoning input is not part of the cache key (changing it
      doesn't change the cached variant) — otherwise each attacker only poisons their own key.
- [ ] **Impact is real.** The cached payload does something (executes XSS, redirects, breaks the page
      for DoS, or — deception — caches a private/authenticated page for anonymous users).
- [ ] **Hygiene.** Payload benign; poison scoped to a buster you control or short-TTL; recorded in
      `cleanup.md`; approval obtained for a shared/production cache.
- [ ] **In scope.**

## CVSS integrity
Impact scales with blast radius (persistent cached XSS to all visitors → High/Critical). Cache
deception of private data → per sensitivity. Justify from the confirmed hit + payload effect.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "cache-poisoning-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["X-Forwarded-Host unkeyed; clean request got cached redirect (X-Cache:hit, Age:40); buster-scoped; approved"],
  "scope_ok": true, "notes": "poison limited to /?cb=rs7f3q; purged after confirm" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
