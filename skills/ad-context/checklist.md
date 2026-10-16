# AD Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] Authorized foothold confirmed (creds/shell in scope)

## Enumerate
- [ ] Domain enumerated (users/groups/computers/GPOs/trusts)
- [ ] BloodHound data collected

## Map
- [ ] Principals flagged (kerberoastable / asrep / delegation / high-priv / adminCount)
- [ ] Interesting ACL edges mapped
- [ ] ADCS templates enumerated (ESC1-8)
- [ ] Attack paths computed (foothold → DA/high-value)

## Emit
- [ ] ad_context.json validates against _contract/ad_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
