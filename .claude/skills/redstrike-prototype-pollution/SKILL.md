---
name: redstrike-prototype-pollution
description: Run the Redstrike prototype pollution hunt (executor) — client-side and server-side __proto__/constructor.prototype pollution via merge/clone sinks, confirmed on a fresh object, with gadget-to-impact (XSS/RCE/DoS) where present — then gate and hand off to the prototype-pollution-verify reviewer agent.
---

Run the Redstrike **prototype-pollution** methodology (canonical spec: `skills/prototype-pollution/`).

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`; approval required; marker-only payloads; pollution is global for the process/page — on a shared/server target scope tightly and avoid persistent keys.
2. **Execute:** follow `skills/prototype-pollution/SKILL.md`; consume `skills/js-analysis/` params + sources/sinks (merge/clone/assign) + `content-discovery` (JSON APIs); work `skills/prototype-pollution/checklist.md`; use `skills/prototype-pollution/refs/`. Write outputs to `<engagement>/prototype-pollution/`.
3. **Coverage:** copy your filled checklist into `<engagement>/prototype-pollution/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/prototype-pollution --out <engagement>/prototype-pollution` → fix + re-run until exit 0.
5. **Reviewer:** launch the `prototype-pollution-verify` subagent on `<engagement>/prototype-pollution`. Only `accepted` findings go to reporting (pollution-only rated at its true severity; a gadget needs its own benign proof).
