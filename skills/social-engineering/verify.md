# Social Engineering — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the social-engineering gauntlet. Confirmed = an APPROVED simulated campaign against
the authorized, named population measured a real human-layer control gap (benign test-credential submissions /
click + report metrics), reported in aggregate with no real malware and no named-person blame.

## Social-engineering false-positive gauntlet (base check #3)
- [ ] **Authorization is explicit + written + population-scoped.** The campaign targeted ONLY the named,
      authorized population from the written authorization — no out-of-scope individuals, third parties, or
      non-consenting people; authorized sender domains + window only.
- [ ] **The finding is a real control gap, evidenced by metrics.** Aggregate click/submit/report/consent
      rates show a concrete gap (slow/absent reporting path, high credential-submit rate, OAuth-consent
      granted, weak filtering) — not an anecdote about one person.
- [ ] **Benign + privacy-safe.** No real malware or working exploit; the harvest page did NOT store real
      passwords (hash+discard / accept-and-redirect); captured data is aggregate + redacted; the campaign
      and harvest page were torn down.
- [ ] **Framing is process-level, not shaming.** Findings name the control/process gap and aggregate
      metrics, NOT individuals for blame. Reject any finding that singles out a named person.
- [ ] **In scope** (population, domains, window) + approval.

## CVSS integrity
Rate the organizational/control exposure the gap represents (e.g. credential-harvest success enabling
account takeover, absent reporting path delaying response), from aggregate metrics — not from a single
click. Keep it process-level.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "social-engineering-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["approved campaign to the named population (written auth on file); 28% submitted to the benign harvest page, 4% reported; no passwords stored; aggregate only; no individual named"],
  "scope_ok": true, "notes": "written authorization naming the population; no real malware; aggregate metrics; campaign torn down; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
