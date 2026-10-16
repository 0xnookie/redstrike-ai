---
name: redstrike-container-escape
description: Run the Redstrike container-escape hunt (post-exploitation) — enumerate escape vectors (privileged/release_agent, mounted docker.sock, hostPath, cap_sys_admin, exposed devices) and break out to the host BENIGNLY (prove a host-only read / host-namespace id), then gate and hand off to the container-escape-verify reviewer agent. High-risk, approval-gated.
---

Run the Redstrike **container-escape** methodology (canonical spec: `skills/container-escape/`). Post-exploitation.

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Get approval** + kill switch. Escape BENIGNLY (prove host access with a read/`id`) — **no** persistence/destruction/other-tenant impact; crash-risky kernel escapes = report feasibility. Revert anything created (`cleanup.md`). In-scope host only.
2. **Execute:** follow `skills/container-escape/SKILL.md` on the container foothold; work `skills/container-escape/checklist.md`; use `skills/container-escape/refs/`. Write outputs to `<engagement>/container-escape/`. Hand the host foothold to `redstrike-linux-privesc`.
3. **Coverage:** copy your filled checklist into `<engagement>/container-escape/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/container-escape --out <engagement>/container-escape` → fix + re-run until exit 0.
5. **Reviewer:** launch the `container-escape-verify` subagent on `<engagement>/container-escape`. Only `accepted` findings go to reporting.
