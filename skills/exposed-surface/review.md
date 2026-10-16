# Exposed Surface — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/exposed-surface --out <out_dir>
# Liveness only. Empty confirmed.jsonl / findings.json (ran, nothing exposed) is a PASS.

- [ ] A — Targets
  - [ ] A.1 `targets.txt` non-zero
- [ ] B — Fingerprint
  - [ ] B.1 `fingerprint.json` valid JSON
- [ ] C — Fuzz
  - [ ] C.1 `fuzz_raw.jsonl` well-formed (empty → PASS)
- [ ] D — Templated scan
  - [ ] D.1 `nuclei.jsonl` well-formed (empty → PASS)
- [ ] E — Params
  - [ ] E.1 `params_found.txt` (optional)
- [ ] F — Confirmed
  - [ ] F.1 `confirmed.jsonl` well-formed (empty → PASS)
- [ ] G — Findings
  - [ ] G.1 `findings.json` valid JSON (empty array → PASS)
- [ ] H — Evidence (verify.md enforces when findings non-empty)
  - [ ] H.1 `evidence/` (optional)
- [ ] I — Report
  - [ ] I.1 `report.md` non-zero
- [ ] J — Logs
  - [ ] J.1 `logs/` populated
- [ ] K — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "exposed-surface",
  "artifacts": [
    { "id": "A.1", "path": "targets.txt", "type": "text" },
    { "id": "B.1", "path": "fingerprint.json", "type": "json", "allow_empty_object": true },
    { "id": "C.1", "path": "fuzz_raw.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "D.1", "path": "nuclei.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "E.1", "path": "params_found.txt", "type": "text", "required": false },
    { "id": "F.1", "path": "confirmed.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "G.1", "path": "findings.json", "type": "json", "allow_empty_array": true },
    { "id": "H.1", "path": "evidence", "type": "dir", "required": false },
    { "id": "I.1", "path": "report.md", "type": "text" },
    { "id": "J.1", "path": "logs", "type": "dir" }
  ]
}
```
