---
name: redstrike-command-injection
description: Run the Redstrike command-injection hunt (executor) — RCE-class, confirmed BENIGNLY via OOB/timing — then gate and hand off to the command-injection-verify reviewer agent.
---

Run the Redstrike **command-injection** methodology (canonical spec: `skills/command-injection/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. RCE = max blast radius — **get approval**; confirm with BENIGN commands only (`sleep`, a curl to YOUR OOB host, `whoami` exfil'd to OOB) — **never** destructive, no reverse shells, no file/process tampering; honor the kill switch.
2. **Execute:** follow `skills/command-injection/SKILL.md`; consume `<engagement>/injection-context/injection_context.json` (command sinks); work `skills/command-injection/checklist.md`; use `skills/injection-context/refs/`. Write outputs to `<engagement>/command-injection/`.
3. **Coverage:** copy your filled checklist into `<engagement>/command-injection/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/command-injection --out <engagement>/command-injection` → fix + re-run until exit 0. (Empty `callbacks.jsonl` is a valid pass — timing-only.)
5. **Reviewer:** launch the `command-injection-verify` subagent on `<engagement>/command-injection`. Only `accepted` findings go to reporting.
