# Agent Tool Abuse Agent  (OWASP Agentic ASI02 + ASI05)

> Variant of the AI/agent family (siblings: `excessive-agency`, `prompt-injection`, `sensitive-disclosure`, `llm-output-handling`).
> GATED EXPLOITATION of the agent tools the `agent-recon` feeder enumerates but nothing exploits.
> Covers **ASI02 Tool Misuse & Exploitation** (multi-step misuse/chaining of already-granted tools; MCP/A2A/OpenAPI
> protocol-level `tools/call` abuse of an enumerated tool) and **ASI05 Unexpected Code Execution** (a malicious /
> confused MCP tool *definition* → RCE).
> ACTIVE, performs REAL tool calls / loads a tool definition, findings-producing → imports `_contract/roe-gate.md`
> + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest `agent_context.json` (`tool_targets`[+`capability`], `endpoints`[`protocol`/`transport`], `exposures`[`asi_refs`]) → pick a protocol-level `tools/call` target or a multi-step tool chain → **ASI02**: drive an enumerated tool over its protocol (MCP `tools/call` / A2A / OpenAPI) with benign markers, and chain one tool's output/injection into an action in another tool → **ASI05**: register/load a malicious or *confused* TEST tool DEFINITION in a sandbox so its handler executes → confirm the unauthorized action actually EXECUTED (attributable OOB callback / benign marker effect) → cleanup → rate → emit → review → verify.
- **TOOLS:** a generic JSON-RPC / MCP client (`tools/call`), interceptor, OOB (`interactsh-client`), a sandboxed egress-restricted VM/container (ASI05 definition load), `refs/agent_tool_abuse.md`; hand downstream web sinks to the web vuln agents.
- **GOAL:** Prove tool misuse/exploitation — an enumerated agent tool (or a chain of them) was driven to perform an UNAUTHORIZED action, or a malicious/confused tool *definition* executed code — demonstrated BENIGNLY (OOB callback / benign marker), approval-gated. "A tool named `exec_shell` exists" is recon (agent-recon), NOT a finding. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `abuse_tests.jsonl`, `callbacks.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = `agent_context.json` (`tool_targets`, `endpoints`, `protocol`, `transport`, `capability`, `exposures`, `asi_refs`) from `agent-recon` + `scope.yaml` (`oob.collaborator`). `refs/` = `agent_tool_abuse.md`. Chains FROM `agent-recon` (enumerated surface); chains TO `reporting` + `ssrf-*`/`sqli-*`/`command-injection`/`deserialization` (downstream sinks reached via a tool arg).
- **DECOMPOSITION:** this IS the ASI02/ASI05 variant (two phases in refs: tool-chain/protocol abuse, and malicious tool-definition execution).

## Goal
Prove tool misuse/exploitation (ASI02) or unexpected code execution via a tool definition (ASI05), benignly.
Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The enumerated tool(s) + their `capability` + protocol/transport (from `agent_context.json`) that are actually callable
- A driven, UNAUTHORIZED action proven benignly, one of:
  - **ASI02 multi-step chain** — tool A's output (or an injection carried through it) drives a privileged action in tool B
  - **ASI02 protocol-level `tools/call`** — a direct MCP/A2A/OpenAPI call of an enumerated tool performs an action the caller should not be allowed (SSRF via a fetch tool, an injected tool-arg reaching a backend sink, a filesystem/network reach beyond the declared contract)
  - **ASI05 tool-definition RCE** — a malicious or *confused* TEST tool definition whose handler executes code when registered/loaded/invoked in a sandbox
- Benign, attributable proof the tool/chain actually EXECUTED (OOB callback with a unique token, or a benign marker effect read back) — NOT the model merely saying it would, NOT the mere existence of a dangerous tool name

## De-dup boundary  (stated here + in `verify.md`)
- A single-shot "the LLM was induced to call ONE over-permissioned tool" stays `excessive-agency` (LLM06).
- Classic RCE at a WEB sink (shell/eval/unsafe-deserialization of a request param) stays `command-injection` / `deserialization`.
- **THIS skill owns:** MULTI-STEP tool-chain abuse; MCP/A2A/OpenAPI **protocol-level `tools/call`** exploitation of an enumerated tool; and executing a malicious/confused **tool definition** (ASI05). A downstream SQLi/SSRF/RCE reached *through* a tool arg is hooked here but its web-sink proof is handed to that class's agent (we own the tool-abuse leg, they own the sink leg).

## Steps  (action · tool · output)
1. Ingest `agent_context.json` (`tool_targets`+`capability`, `endpoints`+`protocol`/`transport`, `exposures`+`asi_refs`) + scope · `jq` · (into tests)
2. Select targets: a protocol-level `tools/call` tool + a multi-step chain (A→B) · refs · `abuse_tests.jsonl`
3. **ASI02** protocol `tools/call`: invoke an enumerated tool over MCP/A2A/OpenAPI with BENIGN markers (SSRF via a fetch tool → OOB; injected tool-arg → backend sink) · MCP client + interceptor + OOB · `abuse_tests.jsonl` / `callbacks.jsonl`
4. **ASI02** chain: drive tool A's output / a carried injection into a privileged action in tool B (benign) · MCP client + refs · `abuse_tests.jsonl`
5. **ASI05** tool-definition RCE: register/load a malicious or confused TEST tool definition in a SANDBOX; show the handler executes (OOB on register/invoke) · sandbox + OOB · `abuse_tests.jsonl` / `callbacks.jsonl`
6. Confirm the unauthorized action EXECUTED (attributable OOB / benign marker effect) + record cleanup · synth · `poc/<id>/`
7. Rate (CVSS) + write finding (de-duped per the boundary above) · synth · `findings.json`
8. Emit report · synth · `report.md`
9. /REVIEW · `review.md` · 10. /VERIFY · `verify.md`

## Tools
- a generic JSON-RPC / MCP client (`tools/call`, session-bound), interceptor, OOB (`interactsh-client`), a sandboxed egress-restricted VM/container (ASI05 definition load), `refs/agent_tool_abuse.md`; hand downstream sinks to `ssrf-*`/`sqli-*`/`command-injection`/`deserialization`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `agent_context.json` (`tool_targets`, `endpoints`, `protocol`, `transport`, `capability`, `exposures`, `asi_refs`) from `agent-recon`
- `scope.yaml` (`oob.collaborator`, in-scope agent endpoints), `refs/agent_tool_abuse.md`

## Outputs
`abuse_tests.jsonl` · `callbacks.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** target selection from `agent_context.json` + protocol-level `tools/call` of an enumerated tool (SSRF-via-tool / benign marker).
- **Phase 2 (target-specific):** multi-step tool chaining + ASI05 malicious/confused tool-definition execution in a sandbox + benign-action confirmation + cleanup + rating (approval-gated).

## Safety
Approval-gated — this executor performs REAL tool calls and loads a tool DEFINITION (the actions `agent-recon`
is forbidden from taking). Confirm with BENIGN effects ONLY (an attributable OOB callback, a no-op/marker
action read back) — **never** destructive, no real emails/payments/data changes, no production state mutated.
Load any malicious/confused tool DEFINITION ONLY inside a sandboxed, egress-restricted VM/container; never
register a deceptive tool on a shared/live agent server. SSRF via a tool stays in scope (cloud-metadata reach →
hand to `ssrf-cloud`). Redact secrets + session-ID values to fingerprints. **Label + remove** every injected
definition / test artifact afterward (cleanup). Kill switch; scope allowlist; audit-log; honor `no_dos`.
