# DOM XSS — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xss-dom --out <out_dir>
# Liveness only. Empty findings.json (ran, no exploitable flow) is a PASS; whether a flow is
# REAL and client-side-only is verify.md's job.

- [ ] A — Candidates
  - [ ] A.1 `dom_candidates.json` valid JSON
- [ ] B — Gadgets
  - [ ] B.1 `gadgets.md` non-zero (gadget gathering ran)
- [ ] C — Taint flows
  - [ ] C.1 `taint_flows.json` valid JSON
- [ ] D — Payload probing
  - [ ] D.1 `payloads_tried.jsonl` ≥1 record, each line valid JSON
- [ ] E — Findings
  - [ ] E.1 `findings.json` valid JSON (empty array = ran, nothing found → PASS)
- [ ] F — PoC (present when findings non-empty — enforced semantically by verify.md)
  - [ ] F.1 `poc/` directory (optional at this altitude)
  - [ ] F.2 `poc_urls.txt` (optional at this altitude)
- [ ] G — Report
  - [ ] G.1 `report.md` non-zero
- [ ] H — Logs
  - [ ] H.1 `logs/` populated
- [ ] I — /REVIEW SKILL → any unchecked ⇒ re-run that step

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xss-dom",
  "artifacts": [
    { "id": "A.1", "path": "dom_candidates.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "gadgets.md", "type": "text" },
    { "id": "C.1", "path": "taint_flows.json", "type": "json", "allow_empty_array": true },
    { "id": "D.1", "path": "payloads_tried.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "E.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "F.1", "path": "poc", "type": "dir", "required": false },
    { "id": "F.2", "path": "poc_urls.txt", "type": "text", "required": false },
    { "id": "G.1", "path": "report.md", "type": "text" },
    { "id": "H.1", "path": "logs", "type": "dir" }
  ]
}
```
