---
name: redstrike-waf-bypass
description: Run the Redstrike WAF/filter-bypass capability — when a WAF/CDN/anti-bot blocks a vuln agent's payloads, fingerprint the filter and return a tuned evasion ladder (encoding/HTTP/TLS/HTTP2-3/origin) that lets a benign canary through, so the calling agent can confirm its bug. Capability skill — emits guidance, not findings.
---

Run the Redstrike **waf-bypass** methodology (canonical spec: `skills/waf-bypass/`). Capability / service skill.

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. In-scope app only; probe with BENIGN canaries; never attack the WAF vendor/another tenant; do NOT fire DoS techniques; scope-check any discovered origin IP before use.
2. **Execute:** follow `skills/waf-bypass/SKILL.md` for the blocked request/agent; work `skills/waf-bypass/checklist.md`; use `skills/waf-bypass/refs/`. Write outputs to `<engagement>/waf-bypass/`.
3. **Coverage:** copy your filled checklist into `<engagement>/waf-bypass/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/waf-bypass --out <engagement>/waf-bypass` → fix + re-run until exit 0.
5. **Hand-back:** return `waf_profile.json` + `bypass_notes.md` to the calling vuln agent, which re-tunes its payloads and owns verification of the actual bug. (No reviewer subagent — this capability emits no findings.)
