# Lab Reconstruct — completion review (MECHANICAL gate)
# Inherits _contract/review-base.md. Run: python skills/_contract/verify_completion.py --skill skills/lab-reconstruct --out <out_dir>
# Tier-3 capability, review-only → liveness only, NO verify.md (the skill makes no security claim; it
# emits a benign local lab bench, not findings). The lab is NEVER an oracle — see SKILL.md ## Safety +
# the lab/lab_manifest.json honesty layer + the additive guardrail in _contract/verify-base.md.

- [ ] A — Lab topology
  - [ ] A.1 `lab/docker-compose.yml` present + non-empty (app service + backing services)
  - [ ] A.2 `lab/Dockerfile` present + non-empty (app built from the cloned source/)
- [ ] B — Honesty layer
  - [ ] B.1 `lab/lab_manifest.json` valid JSON, non-empty, validates vs `_contract/lab_manifest.schema.json`
        (per service → recon field + confidence + `mode` + `fidelity_tier`; `never_an_oracle: true`)
- [ ] C — README
  - [ ] C.1 `lab/README.md` non-zero (real-vs-stub + the IRON GUARDRAIL + DEV/REPRO-bench framing)
- [ ] D — Summary
  - [ ] D.1 `summary.md` non-zero
- [ ] E — Logs
  - [ ] E.1 `logs/` populated
- [ ] F — /REVIEW SKILL → any unchecked ⇒ re-run

<!-- machine-readable manifest for verify_completion.py -->
```json
{
  "manifest_version": 1,
  "skill": "lab-reconstruct",
  "artifacts": [
    { "id": "A.1", "path": "lab/docker-compose.yml", "type": "text" },
    { "id": "A.2", "path": "lab/Dockerfile", "type": "text" },
    { "id": "B.1", "path": "lab/lab_manifest.json", "type": "json", "schema": "skills/_contract/lab_manifest.schema.json" },
    { "id": "C.1", "path": "lab/README.md", "type": "text" },
    { "id": "D.1", "path": "summary.md", "type": "text" },
    { "id": "E.1", "path": "logs", "type": "dir" }
  ]
}
```
