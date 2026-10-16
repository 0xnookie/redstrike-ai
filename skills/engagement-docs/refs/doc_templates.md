# Engagement document templates
# Fill <PLACEHOLDERS> from scope.yaml + findings_consolidated.json. Accepted findings ONLY.
# These are DRAFTS a human finalizes + signs. Be factual; never fabricate authorization or inflate severity.

================================================================================
## 1. Rules of Engagement  (→ RoE.md)   — pre-engagement
================================================================================
```markdown
# Rules of Engagement — <CLIENT> Penetration Test

**Engagement:** <ENGAGEMENT_ID>   **Prepared:** <DATE>   **Tester:** <TESTER/FIRM>

## 1. Overview & Objective
<1–2 sentences: a <TYPE: web/internal/AD/LLM> penetration test of <TARGET> to identify and
validate security weaknesses, per PTES / OWASP WSTG.>

## 2. Authorization
This testing is authorized by **<AUTHORIZED_BY>** (from scope.yaml). The tester is permitted to perform
the activities in this document against the in-scope assets ONLY, during the stated window. Written
authorization is on file. *(If authorization is not established, STOP — do not test.)*

## 3. Scope
**In scope:** <in_scope.domains / cidrs / urls>
**Out of scope (never touch):** <out_of_scope.*>
**Assets / accounts provided:** <test accounts, foothold, OOB collaborator>

## 4. Testing window & rate
- Window: <window.start> → <window.end>  (timezone <TZ>)
- Rate limit: <rate_limit_rps> req/s ; off-hours only: <yes/no>

## 5. Restrictions (RoE)
- ❌ No Denial of Service / resource exhaustion (`no_dos`)
- ❌ No destructive actions, data modification/deletion, or exfiltration of real user/PII data
- ❌ No social engineering / phishing unless explicitly authorized
- ⚠️ Exploitation, post-exploitation, and RCE-class tests require per-phase approval
- Data handling: findings/evidence stored encrypted, deleted <N> days after report delivery

## 6. Contacts & escalation
| Role | Name | Contact | When |
|---|---|---|---|
| Tester lead | <...> | <...> | primary |
| Client POC | <...> | <...> | scope/approval |
| Emergency (outage/incident) | <...> | <24/7 contact> | STOP + call immediately |

**Kill switch:** on any sign of disruption or an out-of-scope touch, testing halts immediately and the
client emergency contact is notified.

## 7. Deliverables
- This RoE (signed) · the penetration test report · an attestation letter · a retest (on request).

## 8. Sign-off
Client (authorized signatory): __________________  Date: ______
Tester: __________________  Date: ______
```

================================================================================
## 2. Penetration Test Report  (→ report.md)   — post-engagement
================================================================================
```markdown
# Penetration Test Report — <CLIENT>

**Engagement:** <ENGAGEMENT_ID> · **Dates:** <start>–<end> · **Tester:** <TESTER/FIRM> · **Classification:** CONFIDENTIAL

## Executive Summary
<Plain-language: what was tested (<TARGET>, <TYPE>), the window, and the overall risk posture in 2–3
sentences.> During the engagement, **<N>** issues were confirmed:

| Severity | Count |
|---|---|
| Critical | <n> |
| High | <n> |
| Medium | <n> |
| Low | <n> |
| Info | <n> |

**Headline findings:** <top 3–5 in business terms, e.g. "An unauthenticated attacker could take over any
user account via …">. **Overall posture:** <one line>.

## Scope & Methodology
- **Scope:** <in-scope assets> (out of scope: <...>).
- **Methodology:** PTES engagement lifecycle · OWASP WSTG / Top 10 (+ OWASP LLM Top 10 / MITRE ATT&CK as
  applicable). Recon → vulnerability analysis → exploitation (approval-gated) → reporting. Every finding was
  independently verified against evidence before inclusion.
- **Tools:** <from appendices>.

## Findings
<For EACH accepted finding, risk-ordered Critical→Info:>

### [<SEVERITY>] <Title>   (<RS-YYYY-NNN>)
- **CVSS:** <vector> (<score>) | **CWE:** <id> | **OWASP:** <WSTG/Top10/LLM id> | **ATT&CK:** <Txxxx>
- **Affected:** <asset / endpoint>
- **Description:** <what it is + why it matters, one paragraph>
- **Reproduction:**
  1. <step>
- **Evidence:** <refs into the evidence vault — request/response, screenshot, PoC>
- **Impact:** <business impact>
- **Remediation:** <specific, testable fix + references>

## Risk Summary
<A short table or heat view: finding × severity × likelihood. Note any chains (attack-chain-discovery).>

## Remediation Roadmap (prioritized)
1. **Immediate (Critical/High):** <...>
2. **Short-term (Medium):** <...>
3. **Hardening (Low/Info):** <...>

## Appendices
- **A. Tools used:** <nmap, ffuf, sqlmap, BloodHound, certipy, …>
- **B. Scope detail & out-of-scope:** <...>
- **C. Methodology references:** PTES, OWASP WSTG/Top 10/LLM Top 10, MITRE ATT&CK.
- **D. Evidence index:** <paths in the engagement dir>
```

================================================================================
## 3. Attestation Letter  (→ attestation.md)
================================================================================
```markdown
# Letter of Attestation

<DATE>

To whom it may concern,

<TESTER/FIRM> conducted an independent penetration test of <CLIENT>'s <TARGET> (<TYPE>) between
<start> and <end>, following the PTES methodology and OWASP testing guides. The assessment identified
**<n> Critical, <n> High, <n> Medium, <n> Low** findings, detailed in the accompanying report
(<ENGAGEMENT_ID>). <One line on overall posture / whether criticals were remediated at retest.>

This letter attests that the testing was performed as described; it is not a certification or a guarantee
of security.

<TESTER NAME / SIGNATURE>, <TITLE>, <FIRM>
```

================================================================================
## 4. Retest Template  (→ retest.md)
================================================================================
```markdown
# Retest — <CLIENT> (<ENGAGEMENT_ID>)   Retest date: <DATE>

| Finding | Severity | Status | Evidence | Notes |
|---|---|---|---|---|
| <RS-YYYY-NNN> <title> | <sev> | ☐ Fixed ☐ Partially ☐ Not fixed | <retest evidence> | <...> |

**Summary:** <N> of <M> findings remediated; <k> Critical/High outstanding.
```

================================================================================
## Severity → CVSS (shared with reporting)
================================================================================
| Rating | CVSS 3.1 | Meaning |
|---|---|---|
| Critical | 9.0–10.0 | RCE, auth bypass, full data/domain compromise |
| High | 7.0–8.9 | SQLi, SSRF-internal, account takeover, privesc |
| Medium | 4.0–6.9 | reflected XSS, CSRF, info leak |
| Low | 0.1–3.9 | missing header with a path, open redirect |
| Info | 0.0 | best-practice / hardening |

Use the CVSS vector the finding's reviewer recomputed. Do not invent scores. One root cause = one finding.
