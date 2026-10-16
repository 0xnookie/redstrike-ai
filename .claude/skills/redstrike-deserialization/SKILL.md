---
name: redstrike-deserialization
description: Run the Redstrike insecure-deserialization hunt (executor) — benign URLDNS/OOB gadget proves the sink deserializes attacker data — then gate and hand off to the deserialization-verify reviewer agent.
---

Run the Redstrike **deserialization** methodology (canonical spec: `skills/deserialization/`).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. Use **URLDNS / DNS-only benign gadgets** to confirm; real RCE gadgets are **approval-gated** and proven BENIGNLY (OOB only) — never write files, spawn shells, or persist; honor the kill switch.
2. **Execute:** follow `skills/deserialization/SKILL.md`; consume `<engagement>/injection-context/injection_context.json` (deserialize sinks) + `skills/js-analysis/libraries.json` (gadget libs); work `skills/deserialization/checklist.md`; use `skills/injection-context/refs/`. Write outputs to `<engagement>/deserialization/`.
3. **Coverage:** copy your filled checklist into `<engagement>/deserialization/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/deserialization --out <engagement>/deserialization` → fix + re-run until exit 0.
5. **Reviewer:** launch the `deserialization-verify` subagent on `<engagement>/deserialization`. Only `accepted` findings go to reporting.
