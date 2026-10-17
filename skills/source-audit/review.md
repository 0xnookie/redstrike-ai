# Source Audit — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/source-audit --out <out_dir>
# White-box recon feeder → liveness only, no verify.md (candidates are proven by the routed executors).

- [ ] A — Candidates
  - [ ] A.1 `source_findings.jsonl` each line valid JSON (may be empty when the source is clean)
- [ ] B — Context
  - [ ] B.1 `source_context.json` valid JSON, non-empty
- [ ] C — Summary
  - [ ] C.1 `summary.md` non-zero
- [ ] D — Logs
  - [ ] D.1 `logs/` populated
- [ ] E — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "source-audit",
  "artifacts": [
    { "id": "A.1", "path": "source_findings.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "B.1", "path": "source_context.json", "type": "json" },
    { "id": "C.1", "path": "summary.md", "type": "text" },
    { "id": "D.1", "path": "logs", "type": "dir" }
  ]
}
```
