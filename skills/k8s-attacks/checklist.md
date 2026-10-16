# Kubernetes Attacks — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Foothold
- [ ] Access source identified (SA token / exposed API / kubelet) + in-scope cluster
- [ ] Approval obtained (RoE — post-exploitation)

## Enumerate
- [ ] SA token + namespace read
- [ ] kubectl auth can-i --list (permission map)
- [ ] Exposed API server / kubelet (:10250) checked

## Abuse (scope-gated, benign)
- [ ] Over-permissioned path identified (exec / create pod / read secrets / privileged pod→node)
- [ ] Confirmed benignly (can-i + one benign read/list; host marker if node reached)
- [ ] Test pod / artifacts removed (cleanup.md)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid, tokens redacted)
- [ ] poc/ per finding
- [ ] cleanup.md
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
