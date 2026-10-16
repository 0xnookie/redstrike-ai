# Bug Bounty — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Scope
- [ ] Program scope + rules parsed → program_scope.json + scope.yaml
  - [ ] in-scope assets
  - [ ] exclusions (DoS / social-eng / disallowed automation)
  - [ ] rate limits + allowed vuln classes

## Hunt (orchestrated, gated)
- [ ] Recon run (js-analysis + discovery)
- [ ] Prioritized hunt plan (cve-intelligence + program focus)
- [ ] Matching vuln agents run — each mechanical-gated + reviewer-accepted
- [ ] Attack chains composed (attack-chain-discovery)
- [ ] Triage/de-dupe (program known issues + internal dupes)

## Package
- [ ] Only accepted, in-scope, non-duplicate findings kept
- [ ] reporting run; per-finding submission drafts in submissions/
- [ ] summary.md
- [ ] /REVIEW SKILL passes  (submissions are DRAFTS — a human sends them)
