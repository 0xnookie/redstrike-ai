---
name: redstrike-agent-tool-abuse
description: Run the Redstrike agent-tool-abuse hunt (executor, OWASP Agentic ASI02 + ASI05) — gated exploitation of the agent tools agent-recon enumerated — multi-step tool-chain abuse, MCP/A2A/OpenAPI protocol-level tools/call exploitation of an enumerated tool (ASI02), and executing a malicious/confused tool definition (ASI05) — confirmed benignly by an attributable OOB callback or a benign marker effect — then gate and hand off to the agent-tool-abuse-verify reviewer agent. Approval-gated.
---

Run the Redstrike **agent-tool-abuse** methodology (canonical spec: `skills/agent-tool-abuse/`). OWASP Agentic ASI02 (Tool Misuse & Exploitation) + ASI05 (Unexpected Code Execution).

1. **Scope + approval:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. **Approval required** — this executor performs REAL tool calls and loads a tool definition (the actions `agent-recon` is forbidden from taking) + kill switch. Confirm with BENIGN effects ONLY — an attributable OOB callback or a no-op/marker action read back; **never** destructive (no real emails/payments/data changes, no production state mutated). Load any malicious/confused tool DEFINITION ONLY in a sandboxed, egress-restricted VM/container; SSRF via a tool stays in scope (metadata → `ssrf-cloud`). Redact secrets + session-IDs; label + remove every injected definition / test artifact afterward.
2. **Execute:** follow `skills/agent-tool-abuse/SKILL.md`; consume `<engagement>/agent-recon/agent_context.json` (`tool_targets`, `endpoints`, `protocol`, `transport`, `capability`, `exposures`, `asi_refs`); work `skills/agent-tool-abuse/checklist.md`; use `skills/agent-tool-abuse/refs/`. Write outputs to `<engagement>/agent-tool-abuse/`. **De-dup:** a single over-permissioned tool call → `excessive-agency`; a classic web-sink RCE → `command-injection`/`deserialization`; downstream tool-arg sinks → hand to `ssrf-*`/`sqli-*`/`command-injection`/`deserialization`.
3. **Coverage:** copy your filled checklist into `<engagement>/agent-tool-abuse/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/agent-tool-abuse --out <engagement>/agent-tool-abuse` → fix + re-run until exit 0.
5. **Reviewer:** launch the `agent-tool-abuse-verify` subagent on `<engagement>/agent-tool-abuse`. Only `accepted` findings go to reporting.
