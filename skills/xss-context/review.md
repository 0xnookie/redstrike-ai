# XSS Context — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xss-context --out <out_dir>
# Recon feeder → liveness only, no verify.md. An empty injection_points array is a valid
# PASS (ran, nothing reflected) — but the probe itself MUST have run (reflections.jsonl non-empty).

- [ ] A — Ingest surface
  - [ ] A.1 `candidate_points.json` valid JSON, non-empty
- [ ] B — Marker probe
  - [ ] B.1 `reflections.jsonl` ≥1 record, each line valid JSON
- [ ] C — CSP / headers
  - [ ] C.1 `csp.json` valid JSON
- [ ] D — DOM flows
  - [ ] D.1 `dom_flows.json` valid JSON
- [ ] E — Consolidated context
  - [ ] E.1 `xss_context.json` valid JSON, non-empty (validate vs schema in step 8)
- [ ] F — Summary
  - [ ] F.1 `summary.md` non-zero
- [ ] G — Logs
  - [ ] G.1 `logs/` populated
- [ ] H — /REVIEW SKILL → any unchecked ⇒ re-run that step

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xss-context",
  "artifacts": [
    { "id": "A.1", "path": "candidate_points.json", "type": "json" },
    { "id": "B.1", "path": "reflections.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "csp.json", "type": "json" },
    { "id": "D.1", "path": "dom_flows.json", "type": "json" },
    { "id": "E.1", "path": "xss_context.json", "type": "json", "schema": "skills/_contract/xss_context.schema.json" },
    { "id": "F.1", "path": "summary.md", "type": "text" },
    { "id": "G.1", "path": "logs", "type": "dir" }
  ]
}
```
