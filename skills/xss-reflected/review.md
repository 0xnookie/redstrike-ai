# Reflected XSS — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xss-reflected --out <out_dir>
# Liveness only: "did every step run and emit well-formed output?" Whether a finding is
# REAL is verify.md's job. An empty findings.json (ran, found nothing) is a PASS here.

- [ ] A — Injection points
  - [ ] A.1 `injection_points.txt` non-zero
- [ ] B — Reflection probe
  - [ ] B.1 `reflections.txt` non-zero
- [ ] C — Context classification
  - [ ] C.1 `contexts.json` valid JSON
- [ ] D — Payload/WAF probing
  - [ ] D.1 `payloads_tried.jsonl` ≥1 record, each line valid JSON
- [ ] E — Findings
  - [ ] E.1 `findings.json` valid JSON (empty array = ran, nothing found → still a PASS)
- [ ] F — PoC (present when findings non-empty — enforced semantically by verify.md)
  - [ ] F.1 `poc/` directory (optional at this altitude)
- [ ] G — Report
  - [ ] G.1 `report.md` non-zero; `curl_commands.sh` runnable
- [ ] H — Logs
  - [ ] H.1 `logs/` populated
- [ ] I — /REVIEW SKILL → any unchecked ⇒ re-run that step

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xss-reflected",
  "artifacts": [
    { "id": "A.1", "path": "injection_points.txt", "type": "text" },
    { "id": "B.1", "path": "reflections.txt", "type": "text" },
    { "id": "C.1", "path": "contexts.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "payloads_tried.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "E.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "F.1", "path": "poc", "type": "dir", "required": false },
    { "id": "G.1", "path": "report.md", "type": "text" },
    { "id": "G.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" },
    { "id": "H.1", "path": "logs", "type": "dir" }
  ]
}
```
