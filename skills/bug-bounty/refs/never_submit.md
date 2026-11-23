# Never-submit → chain-anchor table (bug-bounty discipline)
# Reference for the never-submit gate (cli/redstrike_cli/hooks/never_submit_gate.py) and for anyone drafting
# a submission. These classes are routinely CLOSED / NOT-APPLICABLE on bug-bounty programs when reported
# ALONE: a triager rejects "no impact" and the report burns reputation. Each is only worth submitting once
# CHAINED to demonstrated impact. This table names the anchor to pursue for each — aligned with
# `skills/attack-chain-discovery/refs/chain_anchors.md`. A draft that shows the chain (impact demonstrated)
# passes; one that reports the bare signal does not.

## The rule
A submission draft that contains a never-submit SIGNAL must also contain CHAIN LANGUAGE — the demonstrated
escalation to impact (a chain/kill-chain, "leads to", "→ account takeover", "combined with", a referenced
`chain-NNN` composite, or a concrete attacker outcome). The signal alone is a non-finding: pursue the
anchor, confirm the escalated leg (its own `*-verify` reviewer accepts it), THEN submit the chain. Never
submit the raw signal.

## The table — signal → why-alone-is-nothing → chain anchor to pursue
| Never-submit signal | Alone it is | Chain anchor to pursue (→ executor) |
|---|---|---|
| **missing-headers-alone** (XFO / CSP / HSTS absent, no PoC) | best-practice note | if XFO/`frame-ancestors` is the gap → a framed, sensitive, state-changing action (clickjacking PoC); if HSTS → an MITM/downgrade scenario (auth-bypass) |
| **self-XSS** (payload only fires in your own session) | no victim | a delivery vector that makes another user execute it: CSRF-to-set the value, a login-CSRF, or a stored sink rendered to an admin (csrf → xss-stored / auth-bypass) |
| **open-redirect-alone** (external redirect, nothing stolen) | low/none | OAuth/OIDC `redirect_uri` reflection → auth `code` to attacker domain → ATO; token/`code` in the redirected URL (oauth) |
| **CORS-wildcard-no-impact** (`ACAO:*` or reflected origin, no creds) | cosmetic | a credentialed endpoint with `ACAC:true` reflecting the attacker origin that reads sensitive data cross-origin (cors → bola-bfla/idor) |
| **blind/DNS-only SSRF** (OOB DNS ping, no data) | unproven reach | HTTP reach to cloud metadata → IAM creds, or an internal admin/API the server can hit (ssrf-cloud / ssrf-inband) |
| **clickjacking-no-impact** (frameable, but the framed action is trivial) | no loss | frame a SENSITIVE state-changing action (email/password/role/payment change) and drive it via UI redress (clickjacking + the state-change class) |
| **version-disclosure** (banner / software version leaked) | recon aid | a version-matched, reachable CVE on THAT exact version → the matching Tier-2 exploit path (cve-intelligence → the component executor) |

## Notes
- This gate fires ONLY for a BUG-BOUNTY engagement (program scope / mission marker present). A redstrike
  pentest report legitimately carries informational findings (missing headers, version disclosure, …) for
  the client's defence-in-depth — the gate NO-OPs there and never touches a pentest report.
- "Chain language present" is the escape hatch: the moment the draft demonstrates the escalation, it is a
  real submission and the gate passes. The gate is backpressure toward impact, not a ban on a class.
- De-dupe + scope still apply (see `refs/report_quality.md`): only `accepted`, in-scope, non-duplicate
  findings — chained to impact — ever become submissions.
