# Next.js Agent — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/nextjs --out <out_dir>
# Liveness only. Empty cve_map/findings (patched Next, no exposed surface) is a PASS.

- [ ] A — Fingerprint
  - [ ] A.1 `framework.json` valid JSON
- [ ] B — Surface
  - [ ] B.1 `surface.json` valid JSON
- [ ] C — CVE map
  - [ ] C.1 `cve_map.json` valid JSON (empty array → PASS)
- [ ] D — Findings
  - [ ] D.1 `findings.json` valid JSON (empty array → PASS)
- [ ] E — Report
  - [ ] E.1 `report.md` non-zero
- [ ] F — Logs
  - [ ] F.1 `logs/` populated
- [ ] G — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "nextjs",
  "artifacts": [
    { "id": "A.1", "path": "framework.json", "type": "json" },
    { "id": "B.1", "path": "surface.json", "type": "json" },
    { "id": "C.1", "path": "cve_map.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "E.1", "path": "report.md", "type": "text" },
    { "id": "F.1", "path": "logs", "type": "dir" }
  ]
}
```
