---
name: redstrike-upload-rce
description: Run the Redstrike upload-to-RCE hunt (executor) — benign marker-webshell stored at a web-reachable executable path EXECUTES — then gate and hand off to the upload-rce-verify reviewer agent.
---

Run the Redstrike **upload-rce** methodology (canonical spec: `skills/upload-rce/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. RCE-class — **get approval**; upload ONLY a BENIGN marker-webshell (echo a marker / OOB) — **never** a real shell/backdoor/persistence; record uploaded artifacts in `cleanup.md` and REMOVE them; honor the kill switch.
2. **Execute:** follow `skills/upload-rce/SKILL.md`; consume `<engagement>/file-context/file_context.json` (upload sinks, stored_path, executes_hint); work `skills/upload-rce/checklist.md`; use `skills/file-context/refs/`. Write outputs to `<engagement>/upload-rce/` (incl. `cleanup.md`). (SVG/XML uploads → XXE: hand to `redstrike-xxe-*`.)
3. **Coverage:** copy your filled checklist into `<engagement>/upload-rce/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/upload-rce --out <engagement>/upload-rce` → fix + re-run until exit 0.
5. **Reviewer:** launch the `upload-rce-verify` subagent on `<engagement>/upload-rce`. Only `accepted` findings go to reporting.
