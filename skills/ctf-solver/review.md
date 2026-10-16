# CTF Solver — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/ctf-solver --out <out_dir>
# Mission orchestrator → liveness only, no verify.md. flag.txt is optional (not every challenge solved);
# but the attempt + reasoning MUST be recorded.

- [ ] A — Analysis
  - [ ] A.1 `challenge_analysis.md` non-zero
- [ ] B — Attempts
  - [ ] B.1 `attempts.jsonl` ≥1 record, each line valid JSON
- [ ] C — Flag
  - [ ] C.1 `flag.txt` (optional — present only if captured)
- [ ] D — Writeup
  - [ ] D.1 `writeup.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "ctf-solver",
  "artifacts": [
    { "id": "A.1", "path": "challenge_analysis.md", "type": "text" },
    { "id": "B.1", "path": "attempts.jsonl", "type": "jsonl", "min_items": 1 },
    { "id": "C.1", "path": "flag.txt", "type": "text", "required": false },
    { "id": "D.1", "path": "writeup.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
