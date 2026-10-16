# Upload-to-RCE — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the upload-RCE gauntlet. Confirmed = an uploaded file EXECUTED server-side.
Re-request the stored file and confirm the marker / OOB.

## Upload-RCE false-positive gauntlet (base check #3)
- [ ] **Execution, not just upload.** The PoC shows the uploaded file EXECUTING — the stored URL
      returns the benign marker (`RS7F3Q`) rendered by the server, or the webshell called OOB — not
      merely that an upload succeeded or the file is downloadable as-is.
- [ ] **Stored path web-reachable + executable.** The file landed where the server will execute it
      (php/jsp/aspx handler), evidenced by the marker being executed (not echoed as source).
- [ ] **Validation bypass genuine.** The ext/magic/content-type bypass is the reason it executed,
      reproducibly.
- [ ] **Benign + cleaned up.** Only a marker-webshell was used (no real shell/backdoor); the uploaded
      artifact is in `cleanup.md` and was removed. Flag any real webshell.
- [ ] **Scope + approval.**

## CVSS integrity
Upload-to-RCE → Critical (`S:C`, code execution). Justify from the execution evidence; a stored-but-
non-executing upload is not RCE (maybe stored-XSS/other — reclassify).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "upload-rce-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["shell.php.jpg bypass; stored /uploads/shell.php; GET returned 'RS7F3Q' executed (not source); removed after"],
  "scope_ok": true, "notes": "benign marker-webshell only; cleanup.md records removal; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
