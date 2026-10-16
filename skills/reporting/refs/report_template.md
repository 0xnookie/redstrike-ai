# Report template + standards (adapted from Claude-Red offensive-reporting)
# CVSS scoring, evidence standards, severity table, executive-summary + per-finding structure.

## Severity (CVSS 3.1 base → rating)
| Rating | CVSS | Meaning |
|---|---|---|
| Critical | 9.0–10.0 | immediate, severe (RCE, auth bypass, full data compromise) |
| High | 7.0–8.9 | significant (SQLi, SSRF-internal, account takeover) |
| Medium | 4.0–6.9 | moderate (reflected XSS, CSRF, info leak) |
| Low | 0.1–3.9 | limited (missing header with a path, open redirect) |
| Info | 0.0 | best-practice / hardening |

Every finding carries a CVSS vector (the reviewer recomputed it). Do not invent scores.

## Executive summary (non-technical)
- Engagement scope + dates + methodology (PTES / OWASP WSTG).
- Overall risk posture (1–2 sentences) + a count table by severity.
- Headline findings (top 3–5, business impact in plain language).

## Per-finding structure
```
### [SEVERITY] <Title>   (RS-YYYY-NNN)
- CVSS: <vector> (<score>)   | CWE: <id>  | WSTG: <id>  | ATT&CK: <ids>
- Affected: <asset/endpoint>
- Summary: <one paragraph, what + why it matters>
- Reproduction:
  1. ...
- Evidence: <refs into the vault — request/response, screenshot, PoC>
- Impact: <business impact>
- Remediation: <specific, actionable fix + references>
```

## Rules
- Accepted findings only (`review.verdict == accepted`). No rejected/tentative items as confirmed.
- De-dupe: one root cause = one finding (note all agents/paths that found it).
- Order Critical → Info.
- Keep redacted secrets redacted; reference evidence, don't paste raw secrets.
- Remediation is specific and testable (not "sanitize input").
