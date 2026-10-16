---
name: redstrike-linux-privesc
description: Run the Redstrike Linux privilege-escalation hunt (post-exploitation) — enumerate + confirm a vector to root BENIGNLY on an in-scope host — then gate and hand off to the linux-privesc-verify reviewer agent. High-risk, approval-gated.
---

Run the Redstrike **linux-privesc** methodology (canonical spec: `skills/linux-privesc/`). Post-exploitation.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Escalate BENIGNLY (prove `id=root`, a benign command) — **no** persistence/backdoors/destruction/data-theft; prefer the lowest-risk vector; a crash-risky kernel exploit = report feasibility, don't run. Revert anything created (`cleanup.md`). In-scope host only.
2. **Execute:** follow `skills/linux-privesc/SKILL.md` on the foothold host — enumerate with **`linpeas.sh -a`** (spine) + `pspy` + manual per `skills/linux-privesc/refs/enumeration.md`, then turn a confirmed vector into benign root per `skills/linux-privesc/refs/linux_privesc_playbook.md`; work `skills/linux-privesc/checklist.md`. Write outputs to `<engagement>/linux-privesc/` (keep raw `enum.txt` as evidence).
3. **Coverage:** copy your filled checklist into `<engagement>/linux-privesc/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/linux-privesc --out <engagement>/linux-privesc` → fix + re-run until exit 0.
5. **Reviewer:** launch the `linux-privesc-verify` subagent on `<engagement>/linux-privesc`. Only `accepted` findings go to reporting.
