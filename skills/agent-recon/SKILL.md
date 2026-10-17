# Agent-Protocol Recon (shared feeder)

> RECON / enumeration feeder for the AI/LLM family. Black-box discovery + enumeration of AI AGENT
> PROTOCOLS — MCP, A2A agent cards, OpenAPI tool surfaces — plus their auth + transport posture, mapped to
> the OWASP Top 10 for Agentic Applications (ASI01–ASI10, 2026). READ-NEVER-INVOKE: enumerate the exposed
> capability surface, NEVER call a discovered tool. Lightly active (benign, read-only protocol requests) →
> honors `_contract/roe-gate.md`. Emits NO findings → `review.md` only.
> Output: `agent_context.json` (schema `_contract/agent_context.schema.json`).

## Interview
- **STEPS:** discover agent endpoints → identify protocol + transport (confidence-scored) → complete the protocol handshake → enumerate the capability surface read-only (tools/resources/prompts) → assess auth + session posture → assess transport/TLS/CORS posture → map ASI exposures → route to the LLM executors → emit → review.
- **TOOLS:** `curl`/`httpx` + a generic JSON-RPC client (MCP `initialize` / `*/list`, read-only), `openssl`/`nmap` (TLS + `host:port` sweep), `jq`; consumes `host-discovery`. Tool-first — `_contract/tooling.md`.
- **GOAL:** Map the agent-protocol surface — endpoints, protocol/transport, capability inventory, auth + transport posture, ASI-tagged exposures — into `agent_context.json`, so the AI/LLM executors fan out. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `discovery.json`, `enumeration.jsonl`, `agent_context.json`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `host-discovery/host_discovery.json` (live `host:port` + HTTP services) + `js-analysis` endpoints + `scope.yaml` (`oob.collaborator`). `refs/` = `agent_protocol_recon.md`. Chains FROM `host-discovery`/`osint`; chains TO `excessive-agency` | `prompt-injection` | `sensitive-disclosure` | `llm-output-handling`; relates to `llm-context`.
- **DECOMPOSITION:** n/a (feeder).

## Goal
Produce the shared agent-protocol context (endpoints + protocol/transport + capability surface + auth/transport
posture + ASI exposures + routing). DONE = `checklist.md` `- [x]` · `review.md` PASS (`agent_context.json`
validates against the schema).

## What do we want
- **Endpoints** — agent endpoints reachable black-box (from `host-discovery` HTTP services + well-known paths)
- **Identification** — protocol (MCP / A2A / OpenAPI / unknown), transport (streamable-HTTP / HTTP+SSE / WebSocket / HTTPS), and a **confidence** per target; an unconfirmed target is capped low, never rendered clean
- **Capability surface (MCP)** — tools / resources / prompts the endpoint reveals to the caller (read-only `*/list`), dynamic-dispatch hints (a hidden surface larger than the listing), and any handshake `instructions` leaking operator-prompt material
- **Auth + session posture** — enumeration open vs auth-gated; OAuth metadata + PKCE; bearer challenge; redirect-URI laxity; session-ID entropy (value never recorded); Host-header validation (DNS rebinding)
- **Transport posture** — plaintext, TLS cert/cipher health, CORS (real preflight; wildcard + credentials), rate-limit headers, cleartext downgrade
- **Routing** — `tool_targets` (→ excessive-agency), `injection_points` + `variant_hint` (→ the 4 LLM executors)

## Steps  (action · tool · output)
1. Ingest live HTTP services + scope · `jq host_discovery.json` + `scope.yaml` · (seed)
2. Discover agent endpoints (well-known paths: `/mcp`, `/sse`, `/.well-known/agent.json`, `/openapi.json`, …) · `curl`/`httpx` · `discovery.json`
3. Identify protocol + transport + confidence (handshake / agent-card / OpenAPI doc) · JSON-RPC client + `curl` · `discovery.json`
4. Enumerate the MCP capability surface READ-ONLY (`tools/list`, `resources/list`, `prompts/list`, paginated) + dynamic-dispatch + `instructions` leak · JSON-RPC client · `enumeration.jsonl`
5. Assess auth + session posture (open/gated, OAuth+PKCE, bearer challenge, redirect-URI, session entropy, Host validation) · `curl` · `enumeration.jsonl`
6. Assess transport posture (plaintext, TLS, CORS preflight, rate-limit, downgrade) · `openssl`/`curl` · `enumeration.jsonl`
7. Map ASI exposures + coverage accounting (matched/clean/skipped/could-not-run) · synth · (into context)
8. Route (`tool_targets`, `injection_points` + `variant_hint`) + consolidate + validate vs schema · synth · `agent_context.json`
9. Emit summary · synth · `summary.md`
10. /REVIEW SKILL · `review.md`

## Tools
- `curl`/`httpx` + a generic JSON-RPC client (read-only MCP requests), `openssl` (TLS), `nmap`/`naabu` (`host:port` sweep), `jq`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `host-discovery/host_discovery.json` (live hosts + HTTP services), `js-analysis/` endpoints
- `scope.yaml` (`oob.collaborator`), `refs/agent_protocol_recon.md`

## Outputs
`discovery.json` · `enumeration.jsonl` · `agent_context.json` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** endpoint discovery + protocol/transport identification + transport posture (runs against any endpoint, even one with no enumeration support).
- **Phase 2 (target-specific):** MCP handshake + capability enumeration + auth/session posture + ASI mapping + routing.

## Safety
**READ-NEVER-INVOKE** — enumerate the capability surface (`*/list`), **never** call a discovered tool
(`tools/call`), fetch a resource body, or trigger a prompt. All requests are benign + read-only. An endpoint
that does not complete a real protocol handshake is **UNCONFIRMED** — cap every observation at info/low and
say so; never render a target the scan could not reach as "clean" (coverage accounting: matched / clean /
skipped / could-not-run → `complete` | `incomplete`). Redact secrets + session-ID **values** to fingerprints
(record entropy, never the value). Generic TLS/CORS/plaintext/rate-limit exposures are handed to
`tls-attacks`/`cors`/`security-headers`/`exposed-surface` (de-dupe). Scope to authorized agent endpoints;
rate-limit; audit-log; honor `no_dos`.
