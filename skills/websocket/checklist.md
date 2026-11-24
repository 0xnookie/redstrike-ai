# WebSocket (CSWSH / message-layer / socket authz) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] `ws(s)://` / `new WebSocket(...)` endpoints ingested from js-analysis (endpoints.jsonl)
- [ ] Handshake auth model ingested from auth-context (cookie vs token; Origin-validation posture)
- [ ] Frame protocol mapped per endpoint (read vs state-changing frames)
- [ ] Approval obtained (RoE — active socket; state-changing frames perform real actions) + ≥2 tester identities confirmed for frame-authz

## Probe (scope-gated, benign, tester sessions only)
- [ ] CSWSH: cross-origin handshake from a tester-controlled page carrying the tester's ambient cookie + a benign READ frame
- [ ] Message-layer injection over frames (XSS / SQLi / cmd / JSON role-tamper) — reply + downstream effect observed
- [ ] Authz / IDOR over frames (second identity → cross-identity read/change by before/after state)
- [ ] Missing auth: unauthenticated connection + a privileged read/action frame
- [ ] `ws://` cleartext check (sensitive data over an unencrypted socket)
- [ ] A REAL break proven benignly — accepted cross-origin read / before-after state differential / privileged unauth frame / cleartext capture — not a bare 101 upgrade
- [ ] Any downstream-detonating payload (XSS/SQLi/cmd) routed to its owning class, not double-claimed
- [ ] Any carried secret redacted to a fingerprint; any test record reverted
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (the handshake/frames + the break evidence: cross-origin read / before-after state / OOB)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
