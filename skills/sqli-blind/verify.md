# Blind SQLi — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the blind SQLi gauntlet. Confirmed = a reproducible boolean/time differential
(or OOB) controlled by an injected condition — not timing noise. Re-run and reproduce the differential.

## Blind SQLi false-positive gauntlet (base check #3)
- [ ] **Condition-controlled differential.** Response (boolean) or latency (time) flips with the
      injected truth value: `1=1` → one state, `1=2` → the other, reproducibly across trials
      (evidence in `inferences.jsonl`/`poc/`). A one-off slow response is NOT proof.
- [ ] **Time payloads isolated.** The delay tracks the conditional SLEEP (baseline vs injected),
      controlled for network jitter (multiple samples), not general server slowness.
- [ ] **OOB (if used) attributable.** The DNS/HTTP interaction's token maps to the injection and
      exfiltrates a DB-derived value (version char), proving extraction.
- [ ] **Extraction demonstrated, minimally.** At least one benign fact inferred (proves it's
      extractable) — without dumping PII.
- [ ] **Scope + approval; no destructive/stacked payloads.**

## CVSS integrity
Blind SQLi is still High (data is extractable, just slowly). Justify from the proven inference; don't
down-rate to Low just because it's blind, nor claim write/RCE without evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "sqli-blind-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["boolean diff reproduced x5 (1=1 -> 200 len 812, 1=2 -> 200 len 340); SLEEP(5) tracked; inferred version starts '8'"],
  "scope_ok": true, "notes": "no PII; approved; SLEEP<=5s rate-limited" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
