---
name: redstrike-windows-privesc
description: Run the Redstrike Windows privilege-escalation hunt (post-exploitation) — enumerate + confirm a vector to SYSTEM/admin BENIGNLY on an in-scope host — then gate and hand off to the windows-privesc-verify reviewer agent. High-risk, approval-gated.
---

Run the Redstrike **windows-privesc** methodology (canonical spec: `skills/windows-privesc/`). Post-exploitation.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Escalate BENIGNLY (prove `whoami`=SYSTEM, a benign command) — **no** persistence/backdoors/destruction/bulk-cred-dumping; prefer the lowest-risk vector; crash-risky exploits = report feasibility. Revert anything created/changed (services/binaries/registry/tasks) — back up files you replace (`cleanup.md`). In-scope host only.
2. **Execute:** follow `skills/windows-privesc/SKILL.md` on the foothold host — `whoami /all` first, then enumerate with **winPEAS** (`log=enum.txt`) + PowerUp/Seatbelt + WES-NG + manual per `skills/windows-privesc/refs/enumeration.md`, then turn a confirmed vector into benign SYSTEM per `skills/windows-privesc/refs/windows_privesc_playbook.md`; work `skills/windows-privesc/checklist.md`. Write outputs to `<engagement>/windows-privesc/` (keep raw `enum.txt` as evidence). If domain-joined → coordinate with `redstrike-ad-*`.
3. **Coverage:** copy your filled checklist into `<engagement>/windows-privesc/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/windows-privesc --out <engagement>/windows-privesc` → fix + re-run until exit 0.
5. **Reviewer:** launch the `windows-privesc-verify` subagent on `<engagement>/windows-privesc`. Only `accepted` findings go to reporting.
