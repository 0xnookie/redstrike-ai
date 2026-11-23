# Agent Tool Abuse (ASI02 + ASI05) — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest
- [ ] `agent_context.json` ingested (tool_targets+capability, endpoints+protocol/transport, exposures+asi_refs)
- [ ] Approval obtained (RoE — real tool calls + loading a tool definition) + in-scope agent endpoints confirmed

## Abuse (scope-gated, benign, approval-gated)
- [ ] Targets selected: a protocol-level `tools/call` tool + a multi-step chain (A→B)
- [ ] ASI02 protocol `tools/call` — enumerated tool driven over MCP/A2A/OpenAPI with BENIGN markers
- [ ] ASI02 tool chaining — tool A's output / carried injection drives a privileged action in tool B
- [ ] ASI05 tool-definition RCE — malicious/confused TEST definition loaded in a SANDBOX; handler executes
- [ ] Unauthorized action CONFIRMED EXECUTED (attributable OOB callback / benign marker effect)
- [ ] De-duped vs excessive-agency (single over-permissioned tool) / command-injection / deserialization
- [ ] No production state changed; secrets + session-IDs redacted to fingerprints
- [ ] Injected definitions / test artifacts labelled + removed (cleanup)
- [ ] CVSS rated

## Emit
- [ ] findings.json (schema-valid)
- [ ] poc/ per finding (call/chain + tool action + OOB/marker evidence)
- [ ] report.md

## Gates
- [ ] /REVIEW SKILL (mechanical) passes  [empty callbacks.jsonl is a valid liveness PASS]
- [ ] /VERIFY (semantic) — every finding accepted or rejected with reason
