# SSRF Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/ssrf-context --out <out_dir>
# Recon feeder → liveness only, no verify.md. Empty fetch_sinks is a valid PASS (ran, none found),
# but the probe itself must have run (behavior_probes.jsonl non-empty).

- [ ] A — Fetch sinks
  - [ ] A.1 `fetch_sinks.json` valid JSON
- [ ] B — Behavior probes
  - [ ] B.1 `behavior_probes.jsonl` ≥1 record, each line valid JSON
- [ ] C — Context
  - [ ] C.1 `ssrf_context.json` valid JSON, non-empty
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "ssrf-context",
  "artifacts": [
    { "id": "A.1", "path": "fetch_sinks.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "behavior_probes.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "ssrf_context.json", "type": "json" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
