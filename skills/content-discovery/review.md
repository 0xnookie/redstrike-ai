# Content Discovery — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/content-discovery --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — Crawl
  - [ ] A.1 `crawl.txt` non-zero
- [ ] B — Endpoints
  - [ ] B.1 `endpoints.txt` non-zero
- [ ] C — Params
  - [ ] C.1 `params.txt` non-zero
- [ ] D — Custom wordlist
  - [ ] D.1 `custom_wordlist.txt` non-zero
- [ ] E — Consolidated
  - [ ] E.1 `content.json` valid JSON
- [ ] F — Summary
  - [ ] F.1 `summary.md` non-zero
- [ ] G — Logs
  - [ ] G.1 `logs/` populated
- [ ] H — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "content-discovery",
  "artifacts": [
    { "id": "A.1", "path": "crawl.txt", "type": "text" },
    { "id": "B.1", "path": "endpoints.txt", "type": "text" },
    { "id": "C.1", "path": "params.txt", "type": "text" },
    { "id": "D.1", "path": "custom_wordlist.txt", "type": "text" },
    { "id": "E.1", "path": "content.json", "type": "json" },
    { "id": "F.1", "path": "summary.md", "type": "text" },
    { "id": "G.1", "path": "logs", "type": "dir" }
  ]
}
```
