---
name: redstrike-path-traversal-lfi
description: Run the Redstrike path-traversal/LFI hunt (executor) — read a file outside the base dir (benign marker), assess LFI-RCE — then gate and hand off to the path-traversal-lfi-verify reviewer agent.
---

Run the Redstrike **path-traversal-lfi** methodology (canonical spec: `skills/path-traversal-lfi/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval**; benign marker files for proof (prefer `/etc/hostname`); LFI-to-RCE proven BENIGNLY (OOB/marker); no destructive reads.
2. **Execute:** follow `skills/path-traversal-lfi/SKILL.md`; consume `<engagement>/file-context/file_context.json` (read/include sinks); work `skills/path-traversal-lfi/checklist.md`; use `skills/file-context/refs/`. Write outputs to `<engagement>/path-traversal-lfi/`.
3. **Coverage:** copy your filled checklist into `<engagement>/path-traversal-lfi/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/path-traversal-lfi --out <engagement>/path-traversal-lfi` → fix + re-run until exit 0.
5. **Reviewer:** launch the `path-traversal-lfi-verify` subagent on `<engagement>/path-traversal-lfi`. Only `accepted` findings go to reporting.
