# Agent-Protocol Recon — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Discovery + identification
- [ ] Agent endpoints discovered (host-discovery HTTP services + well-known paths)
- [ ] Protocol identified per target (MCP / A2A / OpenAPI / unknown) + transport + confidence
- [ ] Unconfirmed targets flagged + capped low (no clean verdict on an unreached target)

## Enumeration (read-only, MCP)
- [ ] Capability surface enumerated (tools/list, resources/list, prompts/list; paginated)
- [ ] Dynamic-dispatch hint checked (hidden surface > listing)
- [ ] Handshake `instructions` leak checked (operator-prompt material)
- [ ] NO tool invoked / resource fetched / prompt triggered (read-never-invoke held)

## Posture
- [ ] Auth/session posture (open vs gated, OAuth+PKCE, bearer challenge, redirect-URI, session entropy, Host validation)
- [ ] Transport posture (plaintext, TLS cert/cipher, CORS preflight, rate-limit, downgrade)
- [ ] Secrets + session-ID values redacted to fingerprints

## Route + emit
- [ ] ASI exposures mapped (OWASP Agentic Top 10) + coverage accounting (complete/incomplete)
- [ ] tool_targets (→ excessive-agency) + injection_points + variant_hint (→ the 4 LLM executors)
- [ ] agent_context.json validates against _contract/agent_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
