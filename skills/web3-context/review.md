# Web3 Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/web3-context --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — Contracts
  - [ ] A.1 `contracts.jsonl` ≥1 record, each line valid JSON
- [ ] B — Context
  - [ ] B.1 `web3_context.json` valid JSON, non-empty
- [ ] C — Summary
  - [ ] C.1 `summary.md` non-zero
- [ ] D — Source (optional — absent when target is unverified)
  - [ ] D.1 `contracts/` (optional)
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "web3-context",
  "artifacts": [
    { "id": "A.1", "path": "contracts.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "B.1", "path": "web3_context.json", "type": "json" },
    { "id": "C.1", "path": "summary.md", "type": "text" },
    { "id": "D.1", "path": "contracts", "type": "dir", "required": false },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
