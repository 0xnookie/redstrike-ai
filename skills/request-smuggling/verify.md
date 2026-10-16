# HTTP Request Smuggling — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the smuggling gauntlet. Confirmed = a reproducible desync proven SAFELY.
This is high-risk; the reviewer also guards that confirmation did not harm real traffic.

## Smuggling false-positive gauntlet (base check #3)
- [ ] **Reproducible desync, not timing noise.** The timing differential / self-canary result is
      repeatable across trials (evidence in `poc/<id>/`), with the specific class named (CL.TE, etc.).
      A single slow response is not proof.
- [ ] **Confirmed via SELF-canary, not victim capture.** Evidence shows the operator's OWN follow-up
      request was affected — NOT a captured real-user request. If confirmation relied on capturing
      other traffic, that's an RoE violation → reject + flag, regardless of the technical result.
- [ ] **Class + chain coherent.** The named desync class matches the fingerprinted front-end/back-end
      parsing behavior.
- [ ] **Impact assessed, not weaponized.** Impact (cache poisoning / auth bypass / cred capture) is
      described and plausible from the desync — the executor did not actually harvest users.
- [ ] **No persistent poison left** (`cleanup.md`); **approval was obtained** (RoE); in scope.

## CVSS integrity
Request smuggling is typically High/Critical (`S:C`, affects other users / infra). Justify from the
confirmed class + plausible impact; don't rate a non-reproducible timing blip.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "request-smuggling-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["CL.TE repeatable x5; self-canary prefixed operator's own next request; no user traffic captured; approved"],
  "scope_ok": true, "notes": "no persistent desync left; kill switch tested" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
