# CORS — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the CORS gauntlet. Confirmed = a cross-origin read of sensitive data —
re-execute the fetch from an attacker origin in a victim session.

## CORS false-positive gauntlet (base check #3)
- [ ] **Reflects attacker origin AND `ACAC:true`** on a credentialed endpoint — the combination that
      lets a cross-origin page read authenticated responses. Reflection with `ACAC:false` is only a
      finding if the endpoint exposes sensitive data to ANY origin without creds.
- [ ] **Data is actually sensitive.** The readable response contains private/authenticated data
      (PII, tokens, user data). A public endpoint reflecting origin is not a vuln.
- [ ] **Browser-enforceable.** `ACAO` is a single origin (reflected) or `null` with `ACAC:true` — NOT
      `*` with credentials (browsers reject that combo, so it's not exploitable as described).
- [ ] **Bypass is realistic.** `null` (sandbox/data-URL iframe), or a substring/regex gap reachable by
      a registrable attacker domain (`target.com.evil.com`, `eviltarget.com`) — not a trusted origin
      the attacker can't control.
- [ ] **PoC reads cross-origin** (evidence in `poc/<id>/`): attacker page fetched + read the data.
- [ ] **In scope.**

## CVSS integrity
Impact = sensitivity of the readable data (session tokens / PII → high). Justify from what the PoC read.

## Verdict
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "cors-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["ACAO reflects evil.example + ACAC:true; /api/me returns email+token; read cross-origin"],
  "scope_ok": true, "notes": "test account; data read not retained" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
