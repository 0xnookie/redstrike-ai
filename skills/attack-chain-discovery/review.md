# Attack Chain Discovery — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/attack-chain-discovery --out <out_dir>
# Liveness only. Empty chains/findings (no composable chains) is a PASS.

- [ ] A — Primitives
  - [ ] A.1 `primitives.json` valid JSON
- [ ] B — Chains
  - [ ] B.1 `chains.json` valid JSON (empty array → PASS)
- [ ] C — Findings
  - [ ] C.1 `findings.json` valid JSON (empty array → PASS)
- [ ] D — PoC (verify.md enforces for demonstrated chains)
  - [ ] D.1 `poc/` (optional)
- [ ] E — Report
  - [ ] E.1 `report.md` non-zero
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "attack-chain-discovery",
  "artifacts": [
    { "id": "A.1", "path": "primitives.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "chains.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/attack_chain.schema.json" },
    { "id": "C.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "poc", "type": "dir", "required": false },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
