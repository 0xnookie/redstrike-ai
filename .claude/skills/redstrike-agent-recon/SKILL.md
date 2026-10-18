---
name: redstrike-agent-recon
description: Run the Redstrike agent-recon feeder — black-box discovery + read-only enumeration of AI agent protocols (MCP/A2A/OpenAPI) + auth/transport posture mapped to the OWASP Agentic Top 10 (ASI01-10), into agent_context.json for the LLM executors. Recon feeder (review.md only). READ-NEVER-INVOKE, scope-gated.
---

Run the Redstrike **agent-recon** feeder (canonical spec: `skills/agent-recon/`). TIER-2 (AI/LLM).

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Authorized agent endpoints ONLY (hard stop on out-of-scope). **READ-NEVER-INVOKE** — enumerate the capability surface, never call a discovered tool / fetch a resource body / trigger a prompt. Benign read-only protocol requests; rate-limit; honor `no_dos`.
2. **Execute:** follow `skills/agent-recon/SKILL.md`; consume `<engagement>/host-discovery/host_discovery.json` + `js-analysis` endpoints; work `skills/agent-recon/checklist.md`; use `skills/agent-recon/refs/agent_protocol_recon.md`. Write outputs to `<engagement>/agent-recon/` — key artifact `agent_context.json` (validate against `skills/_contract/agent_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/agent-recon/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/agent-recon --out <engagement>/agent-recon` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. `agent_context.json` feeds `redstrike-excessive-agency | prompt-injection | sensitive-disclosure | llm-output-handling`; relates to `redstrike-llm-context`. Generic TLS/CORS/plaintext/rate-limit exposures → `tls-attacks | cors | security-headers | exposed-surface`.
