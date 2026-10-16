# Blind SSRF — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the blind-SSRF gauntlet. Confirmed = an attributable OOB callback FROM THE
TARGET EGRESS proving a server-side fetch. No callback ⇒ no finding.

## Blind-SSRF false-positive gauntlet (base check #3)
- [ ] **Attributable callback from the server.** The OOB interaction's token maps to exactly one
      probe/sink, and the source is the TARGET's egress IP — not the tester's browser, a scanner, or a
      URL-unfurling preview bot. `callbacks.jsonl` + `poc/<id>/` show it.
- [ ] **Server-side, not client.** Confirm the fetch is server-initiated (egress IP / server UA),
      distinguishing from a client that merely rendered the URL.
- [ ] **Internal reach (if claimed) evidenced.** Any claim of reaching internal hosts rests on timing
      differentials or protocol behavior — reproducible, not a single anomaly. Without it, keep impact
      to "confirmed blind SSRF (external fetch)".
- [ ] **Honest severity.** Blind SSRF with only external OOB confirmation is typically Medium; elevate
      only with evidence of internal interaction (and hand cloud-metadata reach to `ssrf-cloud`).
- [ ] **In scope.**

## CVSS integrity
External-only blind SSRF ~Medium. Internal interaction (timing-proven) → High. Don't rate Critical
without demonstrated internal impact.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ssrf-blind-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["token t1 maps to import-url sink; HTTP callback from target egress 203.0.113.9; not a preview bot UA"],
  "scope_ok": true, "notes": "external fetch confirmed; internal reach not demonstrated -> Medium" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
