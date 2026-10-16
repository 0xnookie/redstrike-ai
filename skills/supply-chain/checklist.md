# Supply-Chain Attack — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Dependency surface mapped (manifests, lockfiles, internal names, registry/CI config)
- [ ] Approval obtained (RoE — staging packages / install hooks) + in-scope namespaces/registries confirmed

## Test (scope-gated, benign)
- [ ] Sink classified (dependency confusion / typosquat / install hook / pipeline poisoning / lockfile-hash bypass)
- [ ] TEST package/namespace staged (tester-owned, benign marker hook; lab/private index where needed)
- [ ] Benign proof — resolver prefers attacker name/version in a lab, OR OOB callback from the test hook
- [ ] No real payload; no usable internal name published to a public index; no prod pipeline touched
- [ ] Staged artifacts unpublished/reverted (cleanup)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
