# Blind XSS — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/xss-blind --out <out_dir>
# ASYNC skill: liveness = "did the listener come up and did we inject with a token map?"
# callbacks.jsonl MAY be empty at review time (fires land later) -> still a PASS.
# findings.json MAY be empty (no callback yet) -> still a PASS. A FINDING needs a callback (verify.md).

- [ ] A — Candidates
  - [ ] A.1 `blind_candidates.json` valid JSON
- [ ] B — OOB listener
  - [ ] B.1 `oob_config.json` valid JSON (collaborator host + token scheme)
- [ ] C — Injections
  - [ ] C.1 `injections.jsonl` ≥1 record, each line valid JSON (token → point)
- [ ] D — Callbacks
  - [ ] D.1 `callbacks.jsonl` valid JSONL (MAY be empty — async)
- [ ] E — Findings
  - [ ] E.1 `findings.json` valid JSON (empty array = no callback yet → PASS)
- [ ] F — PoC (present when findings non-empty — enforced semantically by verify.md)
  - [ ] F.1 `poc/` directory (optional at this altitude)
- [ ] G — Cleanup
  - [ ] G.1 `cleanup.md` non-zero (injected artifacts + removal)
- [ ] H — Report
  - [ ] H.1 `report.md` non-zero; `curl_commands.sh` runnable
- [ ] I — Logs
  - [ ] I.1 `logs/` populated
- [ ] J — /REVIEW SKILL → any unchecked ⇒ re-run that step

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "xss-blind",
  "artifacts": [
    { "id": "A.1", "path": "blind_candidates.json", "type": "json", "allow_empty_array": true },
    { "id": "B.1", "path": "oob_config.json", "type": "json" },
    { "id": "C.1", "path": "injections.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "D.1", "path": "callbacks.jsonl", "type": "jsonl", "allow_empty": true },
    { "id": "E.1", "path": "findings.json", "type": "json", "allow_empty_array": true, "schema": "skills/_contract/finding.schema.json" },
    { "id": "F.1", "path": "poc", "type": "dir", "required": false },
    { "id": "G.1", "path": "cleanup.md", "type": "text" },
    { "id": "H.1", "path": "report.md", "type": "text" },
    { "id": "H.2", "path": "curl_commands.sh", "type": "text", "must_contain": "curl" },
    { "id": "I.1", "path": "logs", "type": "dir" }
  ]
}
```
