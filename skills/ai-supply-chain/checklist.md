# AI/ML Supply-Chain (LLM03) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] Model supply chain mapped (formats, hubs/registries, load/deserialize sinks)
- [ ] Approval obtained (RoE — loading/scanning model artifacts) + in-scope model sources confirmed

## Test (scope-gated, benign, sandboxed)
- [ ] Risk classified (pickle/.pt RCE / Keras Lambda / unsafe deserializer / hub confusion-typosquat)
- [ ] Suspect artifact scanned (picklescan/ModelScan/Fickling) AND/OR TEST model crafted (tester-owned)
- [ ] Benign proof — OOB callback on load IN A SANDBOX, or scanner flags the opcode/Lambda
- [ ] No real payload; no untrusted real model loaded outside the sandbox; no deceptive hub name published
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
