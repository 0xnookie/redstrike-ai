# Code Audit — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/code-audit --out <out_dir>
# Liveness only. Empty findings.json (repo audited, nothing confirmed) is a PASS. verify.md judges whether findings are TRUE.

- [ ] A — App model
  - [ ] A.1 `app_model.json` valid, non-empty JSON object (entry points / boundaries / auth / data / privileged ops)
- [ ] S — Surface inventory (completeness)
  - [ ] S.1 engagement-level `../surface_ledger.json` present + schema-valid (the white-box surface was enumerated). Closure (every element tested/reasoned-skipped) is the `--routed-to code-audit --strict` gate verify.md enforces.
- [ ] B — Analysis
  - [ ] B.1 `analysis.jsonl` each line valid JSON (MAY be empty when the repo has no candidates to trace)
- [ ] C — Chains
  - [ ] C.1 `chains.jsonl` valid JSONL (MAY be empty — needs ≥2 confirmed legs)
- [ ] D — Fuzz targets
  - [ ] D.1 `fuzz_targets.jsonl` valid JSONL (MAY be empty — no fuzzable native entry point surfaced)
- [ ] E — Findings
  - [ ] E.1 `findings.json` valid JSON (empty array → PASS)
- [ ] F — PoC (verify.md enforces when findings non-empty)
  - [ ] F.1 `poc/` (optional)
- [ ] G — Report
  - [ ] G.1 `report.md` non-zero
- [ ] H — Logs
  - [ ] H.1 `logs/` populated
- [ ] I — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "code-audit",
  "artifacts": [
    { "id": "A.1", "path": "app_model.json", "type": "json" },
    { "id": "S.1", "path": "../surface_ledger.json", "type": "json", "schema": "skills/_contract/surface_ledger.schema.json" },
    { "id": "B.1", "path": "analysis.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "C.1", "path": "chains.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "D.1", "path": "fuzz_targets.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "E.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "F.1", "path": "poc", "type": "dir", "required": false },
    { "id": "G.1", "path": "report.md", "type": "text" },
    { "id": "H.1", "path": "logs", "type": "dir" }
  ]
}
```
