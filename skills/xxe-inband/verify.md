# In-Band XXE — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the in-band XXE gauntlet. Confirmed = an EXTERNAL entity was resolved and its
content reflected. Re-run the benign payload and confirm the file/internal content.

## In-band XXE false-positive gauntlet (base check #3)
- [ ] **External entity resolved, content reflected.** The PoC shows file content (`file://`) or an
      internal fetch result reflected in the response/error — not just a benign INTERNAL entity echoed
      (that only proves entity parsing, not external resolution). Evidence in `poc/<id>/`.
- [ ] **Content is genuinely external.** The reflected data matches the requested file / internal URL
      (e.g. the host's actual hostname), not attacker-supplied text.
- [ ] **SSRF-via-XXE classified.** If the entity reached an internal URL, note it; hand cloud-metadata
      reach to `ssrf-cloud`.
- [ ] **Benign + scope.** A non-sensitive file was used for proof; no DoS; in scope; approved.

## CVSS integrity
Local file read → High (`C:H`); SSRF-via-XXE to internal/metadata → High/Critical. Justify from what
was actually read/reached.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "xxe-inband-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["SYSTEM file:///etc/hostname entity -> response contained the real hostname 'web-01'; not an echoed internal entity"],
  "scope_ok": true, "notes": "benign file only; no DoS; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
