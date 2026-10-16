---
name: redstrike-ssti
description: Run the Redstrike SSTI hunt (executor) — server-side template expression evaluation, benign RCE proof — then gate and hand off to the ssti-verify reviewer agent.
---

Run the Redstrike **ssti** methodology (canonical spec: `skills/ssti/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Confirm with arithmetic/object reads; RCE escalation is **approval-gated** and proven BENIGNLY (OOB/sleep) — never a destructive command.
2. **Execute:** follow `skills/ssti/SKILL.md`; consume `<engagement>/injection-context/injection_context.json` (template sinks); work `skills/ssti/checklist.md`; use `skills/injection-context/refs/`. Write outputs to `<engagement>/ssti/`.
3. **Coverage:** copy your filled checklist into `<engagement>/ssti/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ssti --out <engagement>/ssti` → fix + re-run until exit 0.
5. **Reviewer:** launch the `ssti-verify` subagent on `<engagement>/ssti`. Only `accepted` findings go to reporting.
