# XSS Hunter — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.
# Thin single-class mission wrapper — inherits _contract/hunter-base.md.

## Scope (XSS-pinned)
- [ ] Program scope + rules parsed → program_scope.json + scope.yaml
  - [ ] in-scope assets
  - [ ] exclusions (DoS / social-eng / disallowed automation)
  - [ ] rate limits (XSS is the only class in play)

## Hunt (orchestrated, gated, depth-first)
- [ ] XSS-scoped recon run (js-analysis DOM sinks + param/stored-surface discovery)
- [ ] xss-context feeder run → xss_context.json (candidate points + context + CSP + DOM flows + routing)
- [ ] Prioritized hunt plan (targeting per xss-context/refs/hunt_flow.md)
- [ ] The four variants run — each mechanical-gated + reviewer-accepted
  - [ ] xss-reflected
  - [ ] xss-stored
  - [ ] xss-dom
  - [ ] xss-blind
- [ ] Escalation/chains composed (hunt_flow.md catalog + attack-chain-discovery)
- [ ] Triage/de-dupe (program known issues + internal dupes)

## Package
- [ ] Only accepted, in-scope, non-duplicate XSS findings kept
- [ ] reporting run; per-finding submission drafts in submissions/
  - [ ] each submission meets the report-quality bar (bug-bounty/refs/report_quality.md)
- [ ] summary.md
- [ ] /REVIEW SKILL passes  (submissions are DRAFTS — a human sends them)
