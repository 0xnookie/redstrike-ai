# JS Analysis — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/js-analysis --out <out_dir>
#
# Layout is per-site: one out/<site>/ tree per in-scope site (e.g. out/app.target.com/).
# The JSON manifest globs across sites (an existence + non-zero floor); the lettered checks
# below must hold for EVERY out/<site>/ produced. Mechanical globs can't prove 1:1 parity,
# per-line JSONL validity, or a runnable curl — the reviewer confirms those by reading.

- [ ] A — Tree matches the mandated layout for out/<site>/ exactly (SKILL.md §Outputs)
  - [ ] A.1 `raw/external/` (+ `raw/inline/` where present) populated; filename rules applied
  - [ ] A.2 `logs/` has one log per tool/action
- [ ] B — raw↔beautified filename parity holds (every raw file has a beautified twin, same stem)
- [ ] C — Every external file has BOTH `ast/external/{name}.ast.json` AND `analysis/external/{name}.md`
  - [ ] C.1 `ast/symbols.json` present (globals, exports, definition file+line)
  - [ ] C.2 per-file note for every inline block (`analysis/inline/`), when inline scripts exist
- [ ] D — `ast/symbols.json` + every `findings/*.jsonl` are VALID (each line parses as JSON)
      — endpoints, params, apis, secrets, gadgets, libraries; an empty-but-valid file is a pass
- [ ] E — `analysis/site-summary.md` + `report.md` + `curl_commands.sh` non-zero; curl file runnable
      — curl covers every `endpoints.jsonl` row with state `live`|`unauthed`
- [ ] F — /REVIEW SKILL → review ALL above; any unchecked ⇒ re-run that step

Pass = layout exact · all artifacts non-zero · all JSON/JSONL valid · parity holds.

<!-- machine-readable manifest for verify_completion.py (globs across every out/<site>/) -->
```json
{
  "manifest_version": 1,
  "skill": "js-analysis",
  "artifacts": [
    { "id": "A.1", "path": "out/*/raw/external/*",           "type": "glob", "min_matches": 1 },
    { "id": "A.2", "path": "out/*/logs/*",                   "type": "glob", "min_matches": 1 },
    { "id": "B.1", "path": "out/*/beautified/external/*",    "type": "glob", "min_matches": 1 },
    { "id": "C.1", "path": "out/*/ast/external/*.ast.json",  "type": "glob", "min_matches": 1 },
    { "id": "C.2", "path": "out/*/ast/symbols.json",         "type": "glob", "min_matches": 1 },
    { "id": "C.3", "path": "out/*/analysis/external/*.md",   "type": "glob", "min_matches": 1 },
    { "id": "C.4", "path": "out/*/analysis/inline/*.md",     "type": "glob", "min_matches": 1, "required": false },
    { "id": "D.1", "path": "out/*/findings/*.jsonl",         "type": "glob", "min_matches": 1, "required": false },
    { "id": "E.1", "path": "out/*/analysis/site-summary.md", "type": "glob", "min_matches": 1 },
    { "id": "E.2", "path": "out/*/report.md",                "type": "glob", "min_matches": 1 },
    { "id": "E.3", "path": "out/*/curl_commands.sh",         "type": "glob", "min_matches": 1 }
  ]
}
```
