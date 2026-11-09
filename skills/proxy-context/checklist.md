# Proxy Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Connect
- [ ] Proxy connected + health-checked (or a SKIP recorded when none is connected)
- [ ] Scope filter applied (in-scope hosts only, per scope.yaml)

## Export
- [ ] Captured History pulled (agent + human-driven browsing)
- [ ] Each exchange normalized (method · path · status · mime · params · headers · body · timing)
- [ ] Secrets / cookies / PII redacted → ‹redacted›

## Emit
- [ ] http_history.json (valid JSON; `exchanges[]` with req/res — see SKILL.md shape)
- [ ] summary.md
- [ ] /REVIEW SKILL passes
