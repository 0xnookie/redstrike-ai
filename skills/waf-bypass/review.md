# WAF / Filter Bypass — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/waf-bypass --out <out_dir>
# Service/capability skill — review.md ONLY (emits no findings.json → no verify.md).

- [ ] A — WAF profile (fingerprint FIRST)
  - [ ] A.1 `waf_profile.json` valid JSON, non-empty, records the WAF id/vendor + block-shell signature (fingerprint precedes any transform)
- [ ] B — Bypass notes
  - [ ] B.1 `bypass_notes.md` non-zero (tuned ladder for the calling agent)
  - [ ] B.2 If any evasion transform was used: `bypass_notes.md` records the RoE evasion authorization and that proofs used BENIGN canaries (content-filter evasion for a specific bug — NOT WAF-brute, NOT client-fingerprint disguise). If an egress ban occurred: the halt + recovery choice is recorded.
- [ ] C — Logs (incl. egress hygiene)
  - [ ] C.1 `logs/` populated
  - [ ] C.2 Egress-health baseline / ban-watch recorded (`logs/egress_health.log`) — known-good public path baselined, recon-200→now-403 drift watched
- [ ] D — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "waf-bypass",
  "artifacts": [
    { "id": "A.1", "path": "waf_profile.json", "type": "json", "must_contain": "waf" },
    { "id": "B.1", "path": "bypass_notes.md", "type": "text" },
    { "id": "C.1", "path": "logs", "type": "dir" },
    { "id": "C.2", "path": "logs/egress_health.log", "type": "text", "required": false }
  ]
}
```
