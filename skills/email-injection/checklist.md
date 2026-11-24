# Email Injection (SMTP / email header injection) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Email-sending flows + the user fields that reach each mail ingested from flow_context.json + recon
- [ ] Carrier + high-value payload mapped per flow (reset link/token, invite, invoice, magic-link)
- [ ] Approval obtained (RoE — a probe sends a real outbound email) + a tester-owned recipient confirmed

## Inject (scope-gated, benign, tester-owned recipient only)
- [ ] Bcc/Cc exfil probe (LF-only → CRLF → raw `\r\n`) into a user field
- [ ] Reply-To redirect probe
- [ ] Subject / arbitrary header override probe
- [ ] Content-Type / MIME body-and-structure break probe
- [ ] The injected header ACTUALLY took effect (copy to tester mailbox / reply redirected / header present in the delivered message) — not a bare 200/accepted
- [ ] Any carried secret redacted to a fingerprint
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (payload + the took-effect evidence: tester-mailbox copy / redirected reply / delivered headers)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
