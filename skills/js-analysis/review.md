# JS Analysis — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/js-analysis --out <out_dir>

- [ ] A — Enumerate sources
  - [ ] A.1 `js_sources.txt` non-zero
- [ ] B — Fetch JS
  - [ ] B.1 `js/raw/` populated, non-zero; `logs/fetch.log` present
- [ ] C — Deobfuscate
  - [ ] C.1 `js/beautified/` non-zero
- [ ] D — Endpoints
  - [ ] D.1 `endpoints_{live,historical,unauthed}.txt` present + non-zero
- [ ] E — Params / routes
  - [ ] E.1 `params.txt`, `routes.md` non-zero
- [ ] F — APIs
  - [ ] F.1 `apis.json` valid JSON, non-empty
- [ ] G — Secrets
  - [ ] G.1 `secrets.json` valid JSON (may be empty array → still a pass)
- [ ] H — Gadgets
  - [ ] H.1 `gadgets.md` non-zero
- [ ] I — Libraries + tech
  - [ ] I.1 `libraries.json` + `tech.md` non-zero
- [ ] J — Report
  - [ ] J.1 `report.md` + `curl_commands.sh` non-zero; curl file is runnable
- [ ] K — /REVIEW SKILL → review ALL above; any unchecked ⇒ re-run that step

Pass = every tool has a log/output · all artifacts non-zero · format & size plausible.

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "js-analysis",
  "artifacts": [
    { "id": "A.1", "path": "js_sources.txt", "type": "text" },
    { "id": "B.1", "path": "js/raw", "type": "dir", "min_children": 1 },
    { "id": "B.2", "path": "logs/fetch.log", "type": "text" },
    { "id": "C.1", "path": "js/beautified", "type": "dir", "min_children": 1 },
    { "id": "D.1", "path": "endpoints_live.txt", "type": "text" },
    { "id": "D.2", "path": "endpoints_historical.txt", "type": "text" },
    { "id": "D.3", "path": "endpoints_unauthed.txt", "type": "text" },
    { "id": "E.1", "path": "params.txt", "type": "text" },
    { "id": "E.2", "path": "routes.md", "type": "text" },
    { "id": "F.1", "path": "apis.json", "type": "json" },
    { "id": "G.1", "path": "secrets.json", "type": "json", "allow_empty_array": true },
    { "id": "H.1", "path": "gadgets.md", "type": "text" },
    { "id": "I.1", "path": "libraries.json", "type": "json", "allow_empty_array": true },
    { "id": "I.2", "path": "tech.md", "type": "text" },
    { "id": "J.1", "path": "report.md", "type": "text" },
    { "id": "J.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" }
  ]
}
```
