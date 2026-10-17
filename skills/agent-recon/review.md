# Agent-Protocol Recon — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/agent-recon --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — Discovery
  - [ ] A.1 `discovery.json` valid JSON, non-empty
- [ ] B — Enumeration / posture
  - [ ] B.1 `enumeration.jsonl` each line valid JSON (may be empty for discovery-only targets)
- [ ] C — Context
  - [ ] C.1 `agent_context.json` valid JSON, non-empty
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "agent-recon",
  "artifacts": [
    { "id": "A.1", "path": "discovery.json", "type": "json" },
    { "id": "B.1", "path": "enumeration.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "C.1", "path": "agent_context.json", "type": "json" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
