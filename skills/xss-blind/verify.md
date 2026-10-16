# Blind XSS — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. Runs as a SUBAGENT with its own fresh context.
# Precondition: review.md (mechanical) already PASSED.
# Input: findings.json + callbacks.jsonl + injections.jsonl. Output: each finding's review{} block.
# Blind XSS is confirmed by an ATTRIBUTABLE OOB CALLBACK that proves JS execution — nothing else.

Run the 7 base checks (verify-base.md) on EVERY finding, plus the blind-XSS gauntlet below.
No callback ⇒ no finding (do not report an injection as a vuln without a fire).

## Blind-XSS false-positive gauntlet (base check #3)

For each finding you MUST rule out every item or it is NOT confirmed:

- [ ] **Callback proves EXECUTION, not just a lookup.** The OOB interaction is an HTTP beacon
      carrying JS-derived data (`document.domain`, URL, DOM snippet) — i.e. script actually ran.
      A bare DNS hit or a plain URL fetch can be a parser/SSRF/preview, NOT XSS → `needs-evidence`.
- [ ] **Attributable.** The callback's unique token maps to exactly ONE injection in
      `injections.jsonl`. If several payloads share a token or the mapping is ambiguous, you cannot
      attribute the fire — reject/re-inject with distinct tokens.
- [ ] **Not a scanner / mail-AV / link-preview.** Rule out automated link-following: check the
      beacon's own signals (did JS run and report `document.domain`? headless/AV user-agent?
      timing vs a human workflow?). A callback from a security scanner opening the link is not XSS.
- [ ] **Fired context is real + privileged value noted.** Record where it executed (admin console,
      ticket viewer, log UI, email/PDF client) and which viewer — this is the impact.
- [ ] **Distinct from stored/reflected/dom.** Blind = the tester could not observe the render and
      confirmation is OOB. If the render was actually visible, it belongs to `xss-stored`. De-dupe.
- [ ] **Scope + hygiene.** `asset`/surface ∈ `scope.yaml`; beacon was benign; injected artifact is
      in `cleanup.md`; staff-facing injection had approval per RoE.

## CVSS integrity (base check #4)
Blind XSS commonly fires in a privileged, no-interaction context: often
`AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N`-ish (e.g. executes in an admin's session). Justify the
elevation with the callback's fired-context evidence. No callback ⇒ not a finding at all.

## Verdict (write into each finding's review{} block)
```json
"review": {
  "verdict": "accepted | rejected | needs-evidence",
  "reviewer": "xss-blind-verify",
  "reviewed_at": "<ISO-8601>",
  "rubric": { "evidence": "pass", "reproducibility": "pass", "fp_gauntlet": "pass",
              "cvss": "pass", "coverage": "pass", "scope": "pass" },
  "false_positive_checks": ["beacon ran JS, reported document.domain=admin.internal; token maps to support-ticket body; not an AV UA"],
  "scope_ok": true,
  "notes": "fired 4h after injection in the agent console; cleanup.md records the ticket id"
}
```
- `accepted` → finding `status: verified`; flows to reporting.
- `rejected` / `needs-evidence` → bounce to executor; re-inject with distinct tokens / wait; do NOT report.
