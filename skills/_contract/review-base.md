# review-base — the mechanical completion gate (inherited by every `review.md`)

`review.md` answers ONE question: **did every step run and emit well-formed output?**
It makes **no** judgment about whether a finding is true — that is `verify.md`'s job.

## Pass criteria (whole skill)

- Every tool/action has a log file or output artifact.
- All declared output is **non-zero bytes**.
- Output matches the expected **format** (valid JSON parses; `.jsonl` lines parse) and a **plausible size**.
- Structured files are well-formed. An **empty-but-valid** collection is a PASS when the step legitimately found nothing (declare `allow_empty_array` / `allow_empty` on that artifact).

## Shape of every `review.md`

1. A human-readable per-step ledger (`- [ ] A — <step>` → `- [ ] A.1 <artifact> non-zero`).
2. A fenced ```json **manifest** the verifier consumes:

```json
{
  "manifest_version": 1,
  "skill": "<skill-name>",
  "artifacts": [
    { "id": "A.1", "path": "out_file.txt",      "type": "text" },
    { "id": "B.1", "path": "raw/",              "type": "dir",  "min_children": 1 },
    { "id": "C.1", "path": "logs/run.log",      "type": "text", "must_contain": "done" },
    { "id": "D.1", "path": "data.json",         "type": "json" },
    { "id": "E.1", "path": "maybe_empty.json",  "type": "json", "allow_empty_array": true },
    { "id": "F.1", "path": "records.jsonl",     "type": "jsonl", "min_items": 1 },
    { "id": "G.1", "path": "js/raw/*.js",       "type": "glob", "min_matches": 1 },
    { "id": "H.1", "path": "poc/",              "type": "dir",  "required": false }
  ]
}
```

### Artifact fields

| field | applies to | meaning |
|---|---|---|
| `type` | all | `text` · `json` · `jsonl` · `dir` · `glob` |
| `min_bytes` | text/json/jsonl | default 1 |
| `allow_empty_array` / `allow_empty_object` | json | empty structure still passes |
| `min_items` / `allow_empty` | jsonl | record count floor |
| `min_children` | dir | child count floor (default 1) |
| `min_matches` | glob | non-empty match floor (default 1) |
| `must_contain` | text/json/jsonl | required substring (e.g. `curl` in a runnable file) |
| `required` | all | `false` = optional; failure won't fail the gate |

## Final checklist item (always last)

```
- [ ] /REVIEW SKILL → review ALL of the above for completion.
      Any unchecked box ⇒ re-run that step.
```

Run it: `python skills/_contract/verify_completion.py --skill <skill-dir> --out <engagement_out_dir>` (exit 0 = PASS, 2 = re-run the failed steps).
