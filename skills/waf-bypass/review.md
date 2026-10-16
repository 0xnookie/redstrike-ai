# WAF / Filter Bypass — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/waf-bypass --out <out_dir>
# Service/capability skill — review.md ONLY (emits no findings.json → no verify.md).

- [ ] A — WAF profile
  - [ ] A.1 `waf_profile.json` valid JSON, non-empty (WAF id + transform results)
- [ ] B — Bypass notes
  - [ ] B.1 `bypass_notes.md` non-zero (tuned ladder for the calling agent)
- [ ] C — Logs
  - [ ] C.1 `logs/` populated
- [ ] D — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "waf-bypass",
  "artifacts": [
    { "id": "A.1", "path": "waf_profile.json", "type": "json" },
    { "id": "B.1", "path": "bypass_notes.md", "type": "text" },
    { "id": "C.1", "path": "logs", "type": "dir" }
  ]
}
```
