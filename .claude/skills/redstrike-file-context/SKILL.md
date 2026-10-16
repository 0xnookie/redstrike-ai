---
name: redstrike-file-context
description: Run the Redstrike file/path context feeder — map file-read/include params + upload endpoints (type checks, stored path, executability) into file_context.json for path-traversal-lfi/upload-rce. Recon feeder (review.md only). Benign probes.
---

Run the Redstrike **file-context** feeder (canonical spec: `skills/file-context/`).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Benign probes — read a NON-sensitive marker; characterize uploads WITHOUT uploading an executable (that's `upload-rce`).
2. **Execute:** follow `skills/file-context/SKILL.md`; consume `skills/js-analysis/` params/endpoints; work `skills/file-context/checklist.md`; use `skills/file-context/refs/`. Write outputs to `<engagement>/file-context/` — key artifact `file_context.json` (validate against `skills/_contract/file_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/file-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/file-context --out <engagement>/file-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `file_context.json` feeds `redstrike-path-traversal-lfi | upload-rce`.
