# In-Band SSRF — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the in-band SSRF gauntlet. Confirmed = the server fetched an attacker-chosen
internal/unauthorized target with in-band proof. Re-run the request and inspect the reflected content.

## In-band SSRF false-positive gauntlet (base check #3)
- [ ] **Server-side fetch, not client-side.** The fetch originates from the TARGET's egress (evidence:
      reflected internal content / egress IP), not the tester's browser.
- [ ] **Attacker-chosen INTERNAL/unauthorized target.** The sink reached something it shouldn't
      (internal host, loopback, another tenant) — not just any external URL a URL-preview feature is
      meant to fetch. A feature fetching arbitrary public URLs by design is only SSRF if it reaches
      internal/unauthorized resources.
- [ ] **In-band evidence is real.** The reflected body / status / length differential actually
      corresponds to the internal target (not an error page that looks similar). `poc/<id>/` shows it.
- [ ] **Bypass (if claimed) genuine.** The allowlist/redirect/protocol bypass is the real reason it
      reached internal, reproducibly.
- [ ] **Cross-skill dup (flag, don't merge).** If this SSRF reaches cloud metadata
      (`169.254.169.254` / metadata host), it is also `ssrf-cloud`'s territory. You can't see sibling
      findings, so DON'T drop it — note a suspected dup in `review.notes` (e.g. "likely the same SSRF as an
      ssrf-cloud finding on <param>") for reporting to merge.
- [ ] **Scope + safety.** Target ∈ in-scope internal ranges; read-only; approved.

## CVSS integrity
Internal read / service interaction is typically High (`S:C`); full read of sensitive internal data
or protocol-smuggling to an internal service → Critical. Justify from what was actually reached/read.

Run `scripts/cvss.py "<CVSS vector>"` for any **Medium+** finding to compute the base score (do not hand-assert it); the gate recomputes and flags drift.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|blocked|rejected|needs-evidence", "reviewer": "ssrf-inband-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["webhook param fetched http://169.254... blocked; reached http://10.0.0.5/ (in scope); internal title reflected; egress IP = target"],
  "scope_ok": true, "notes": "read-only; approved; no internal pivot" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
