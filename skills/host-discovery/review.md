# Host Discovery — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/host-discovery --out <out_dir>
# Recon feeder → liveness only, no verify.md.

- [ ] A — Subdomains
  - [ ] A.1 `subdomains.txt` non-zero
- [ ] B — Hosts
  - [ ] B.1 `hosts.json` valid JSON, non-empty
- [ ] C — Consolidated
  - [ ] C.1 `host_discovery.json` valid JSON, non-empty
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "host-discovery",
  "artifacts": [
    { "id": "A.1", "path": "subdomains.txt", "type": "text" },
    { "id": "B.1", "path": "hosts.json", "type": "json" },
    { "id": "C.1", "path": "host_discovery.json", "type": "json" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
