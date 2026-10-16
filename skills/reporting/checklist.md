# Reporting — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Collect
- [ ] All <engagement>/*/findings.json collected
- [ ] Filtered to review.verdict == accepted ONLY
- [ ] De-duped across agents (same root cause merged)

## Build
- [ ] Severity/CVSS normalized; ordered Critical→Info
- [ ] Per-finding writeups (CVSS, asset, evidence refs, reproduction, impact, remediation, CWE/WSTG/ATT&CK)
- [ ] Executive summary (scope, dates, risk posture, headline findings)
- [ ] Redacted secrets kept redacted

## Emit
- [ ] findings_consolidated.json
- [ ] report.md
- [ ] summary.md
- [ ] /REVIEW SKILL passes
