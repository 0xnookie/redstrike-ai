# Proxy Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Connect
- [ ] Operator asked whether Burp/Caido is running + on what host:port (`_contract/proxy.md` §0); on yes `HTTP_PROXY`/`HTTPS_PROXY`/`RS_PROXY` exported + egress verified to flow through it (`_contract/proxy.md` §8)
- [ ] Proxy connected + health-checked (or a SKIP recorded when none is connected)
- [ ] Scope filter applied (in-scope hosts only, per scope.yaml)

## Export
- [ ] Captured History pulled (agent + human-driven browsing)
- [ ] Each exchange normalized (method · path · status · mime · params · headers · body · timing)
- [ ] Secrets / cookies / PII redacted → ‹redacted›
- [ ] RSC / server-action writes kept replay-faithful (full headers incl. `Next-Action`; multipart body preserved verbatim; redaction swaps secret values only) — `_contract/proxy.md` §4a

## Emit
- [ ] http_history.json (valid JSON; `exchanges[]` with req/res — see SKILL.md shape)
- [ ] summary.md
- [ ] /REVIEW SKILL passes
