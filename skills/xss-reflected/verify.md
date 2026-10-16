# Reflected XSS — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. Runs as a SUBAGENT with its own fresh context.
# Precondition: review.md (mechanical) already PASSED.
# Input: findings.json + poc/ + contexts.json. Output: each finding's review{} block
# (schema: _contract/finding.schema.json) + an overall verdict.

Run the 7 base checks (verify-base.md) on EVERY finding, plus the reflected-XSS
false-positive gauntlet below. Re-execute the PoC in a headless browser whenever feasible.

## Reflected-XSS false-positive gauntlet (base check #3)

For each finding, you MUST rule out every item or the finding is NOT confirmed:

- [ ] **Reflection ≠ execution.** The payload must have *executed* (captured `alert`/`print`/DOM-mutation/callback in `poc/<id>/`), not merely appeared in the response body. Reflection-only ⇒ `needs-evidence` (or downgrade to info).
- [ ] **Context match.** The executing context matches `contexts.json`. A payload "reflected" inside a `<textarea>`, `<script>`-as-text, an HTML comment, or an already-encoded position does not execute — reject if the PoC relies on that.
- [ ] **Encoding not neutralized.** The working payload is the *actual* bytes that executed. If the app HTML-entity/JS/URL-encoded the breakout character, the PoC must show the bypass that defeats it — not a payload the server would have encoded.
- [ ] **CSP reality check.** If a CSP (or Trusted Types) would block execution, the browser evidence must show it executed *anyway*. If CSP blocks it, downgrade to low/info ("reflected, non-executing under current CSP") and note it — do not rate it as a working XSS.
- [ ] **Delivery is realistic.** Reflected XSS delivery = victim opens an attacker-crafted URL. That is valid. But a payload that needs the victim to paste into the DOM, or that only fires for the tester's own session, is self-XSS → reject/park.
- [ ] **Right variant.** The sink is reached via the *request reflection*, not via a client-side source (`location.hash` etc. = `xss-dom`) or persisted server state (= `xss-stored`). Reclassify/dedupe across sibling agents instead of double-reporting.
- [ ] **In scope.** `asset` ∈ `scope.yaml`; payload was sent within the RoE window and rate limits.

## CVSS integrity (base check #4)
Recompute the vector from evidence. Reflected XSS is typically `AV:N/AC:L/PR:N/UI:R/S:*/C:L/I:L/A:N` (Medium) — raise `S:C`/impact only with evidence (e.g. token theft, account action demonstrated). Reject inflation to High/Critical without that evidence.

## Verdict (write into each finding's review{} block)
```json
"review": {
  "verdict": "accepted | rejected | needs-evidence",
  "reviewer": "xss-reflected-verify",
  "reviewed_at": "<ISO-8601>",
  "rubric": { "evidence": "pass", "reproducibility": "pass", "fp_gauntlet": "pass",
              "cvss": "pass", "coverage": "pass", "scope": "pass" },
  "false_positive_checks": ["context=attr-unquoted confirmed exec; CSP absent; not self-XSS"],
  "scope_ok": true,
  "notes": "re-executed PoC headless; alert fired in attribute-unquoted context"
}
```
- `accepted` → finding `status: verified`; flows to reporting.
- `rejected` / `needs-evidence` → bounce to executor; re-run the failed step; do NOT report.
