# Stored XSS — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. Runs as a SUBAGENT with its own fresh context.
# Precondition: review.md (mechanical) already PASSED.
# Input: findings.json + poc/ + render_map.json. Output: each finding's review{} block
# (schema: _contract/finding.schema.json) + an overall verdict.

Run the 7 base checks (verify-base.md) on EVERY finding, plus the stored-XSS gauntlet
below. Stored XSS is confirmed by the CROSS-USER render, not the store — weight accordingly.
Re-execute: store as attacker, then load the render surface as the victim session.

## Stored-XSS false-positive gauntlet (base check #3)

For each finding you MUST rule out every item or it is NOT confirmed:

- [ ] **Both ends evidenced.** `poc/<id>/` has the store request AND the render-surface
      execution, and a tracer/marker correlates them (the thing that executed is the thing
      that was stored). Store-only or render-only ⇒ `needs-evidence`.
- [ ] **Cross-user execution (the whole point).** It executed for a **different** user/session
      than the one that stored it (other user / admin / anonymous viewer per `render_map.json`).
      If it only fires when the *same* session that submitted it views its own input, it is
      effectively self-XSS/reflected — downgrade and reclassify, do not report as stored.
- [ ] **Survived OUTPUT sanitization.** Stored XSS is usually filtered on output, not input.
      The PoC payload must be what executed *after* the render-side encoder/sanitizer — not a
      payload the surface would have neutralized. (Watch for DOMPurify/HTML-sanitizer + mXSS.)
- [ ] **Durable, not session/DOM state.** Fires on a fresh page load / new session, from
      server-persisted state — not from the tester's live client state (that is `xss-dom`) and
      not from the request reflection (that is `xss-reflected`). Reclassify/de-dupe across siblings.
- [ ] **CSP reality check.** If CSP/Trusted Types would block it, the browser evidence must show
      it executed anyway; otherwise downgrade to "stored, non-executing under CSP" (low/info).
- [ ] **Scope + blast radius + hygiene.** `asset` ∈ `scope.yaml`; payload was benign; the stored
      artifact is recorded in `cleanup.md`; if the render surface is viewed by real users/admins,
      approval was obtained (RoE). Flag any payload left live without a cleanup entry.

## CVSS integrity (base check #4)
Stored typically outranks reflected: it often drops `UI:R` (fires on normal view) and may be
`S:C` (executes in a victim/admin context). A cross-user, no-interaction stored XSS in an
authenticated app is commonly `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`-ish — but **justify every
elevation with the cross-user evidence**. Same-session-only ⇒ do not rate as stored.

## Verdict (write into each finding's review{} block)
```json
"review": {
  "verdict": "accepted | rejected | needs-evidence",
  "reviewer": "xss-stored-verify",
  "reviewed_at": "<ISO-8601>",
  "rubric": { "evidence": "pass", "reproducibility": "pass", "fp_gauntlet": "pass",
              "cvss": "pass", "coverage": "pass", "scope": "pass" },
  "false_positive_checks": ["stored as attacker A, fired in admin session B; survived output sanitizer; durable across fresh login"],
  "scope_ok": true,
  "notes": "re-executed cross-session; cleanup.md records the comment id to remove"
}
```
- `accepted` → finding `status: verified`; flows to reporting.
- `rejected` / `needs-evidence` → bounce to executor; re-run the failed step; do NOT report.
