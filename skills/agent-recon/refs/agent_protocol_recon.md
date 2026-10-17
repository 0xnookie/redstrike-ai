# Agent-protocol recon & enumeration — methodology

Black-box reconnaissance of AI agent endpoints: identify the protocol, enumerate the capability surface a
caller is shown, and report auth + transport posture — from the unauthenticated position an external attacker
occupies. Observations map to the **OWASP Top 10 for Agentic Applications** (ASI01–ASI10, 2026;
<https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>).

## Prime directive — READ, NEVER INVOKE
Enumerate the exposed surface; **never** exercise it. Allowed: discovery requests, a protocol handshake, and
read-only listing calls (`tools/list`, `resources/list`, `prompts/list`). FORBIDDEN here: `tools/call`,
fetching a resource body, rendering/triggering a prompt, or any state-changing request — those belong to the
gated `excessive-agency` executor under approval. Enumerating that a tool named `exec_shell` exists is recon;
calling it is exploitation.

## Protocols in scope
| Protocol | What it is | Discovery signal |
|---|---|---|
| MCP (Model Context Protocol) | JSON-RPC 2.0 agent/tool server | `initialize` handshake succeeds; `/mcp`, an SSE stream, or WS |
| A2A (Agent-to-Agent) | agent capability card | `/.well-known/agent.json` (agent-card JSON) |
| OpenAPI / REST tool surface | tool/plugin API | `/openapi.json`, `/.well-known/ai-plugin.json`, swagger UI |

## 1. Endpoint discovery
Seed from `host-discovery/host_discovery.json` (live HTTP(S) services). Probe well-known paths, read-only:
```
# MCP / SSE / agent-card / OpenAPI probes (GET/HEAD; nothing acted on)
for p in /mcp /sse /messages /rpc /.well-known/agent.json /.well-known/ai-plugin.json /openapi.json /v1; do
  curl -sk -o /dev/null -w "%{http_code} %{content_type}  $p\n" "https://TARGET$p"
done
```
A plain web server returns `200`/HTML on every path — that is NOT an agent. Confirmation comes from a real
protocol handshake (below), not a status code.

## 2. Protocol + transport identification (confidence-scored)
### MCP handshake — the confirmation gate
MCP speaks JSON-RPC 2.0. Negotiate a supported version (`2025-06-18`, `2025-03-26`, `2024-11-05`), send the
spec-required `notifications/initialized`, and carry `MCP-Protocol-Version` on post-handshake requests:
```
curl -sk https://TARGET/mcp -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
       "protocolVersion":"2025-06-18","capabilities":{},
       "clientInfo":{"name":"recon","version":"0"}}}'
# A valid result (serverInfo, capabilities, protocolVersion) = CONFIRMED MCP. Note any Mcp-Session-Id header.
```
Transports to recognise (all behind the same read-only boundary): **streamable-HTTP** (one endpoint), legacy
**HTTP+SSE** (pre-2025-03-26: a `GET` SSE stream + a POST message channel), and **WebSocket** (non-standard,
seen on some community gateways).
### A2A / OpenAPI
`/.well-known/agent.json` returning an agent card (name, skills, endpoints) = A2A. `/openapi.json` or a plugin
manifest = an OpenAPI tool surface. Both get identification + transport posture here; deep skill/operation
enumeration is out of scope — hand the mapped operations to `api-context` / `bola-bfla`.
### Confidence rule
Tag each target `confirmed` / `probable` / `tentative` / `unconfirmed`. **An endpoint that never completes a
real handshake is `unconfirmed` — cap every observation at info/low and say so.** Never present a target the
scan could not reach as "clean".

## 3. Capability-surface enumeration (MCP, read-only)
```
# tools/list — the agency surface (paginate with the returned cursor). NEVER tools/call.
curl -sk https://TARGET/mcp -H 'Mcp-Session-Id: <id>' -H 'MCP-Protocol-Version: 2025-06-18' \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
# resources/list and prompts/list likewise.
```
| Signal | What it means | Route / ASI |
|---|---|---|
| `tools/list` answers unauthenticated | full tool inventory to a stranger | ASI02 + ASI03 → `excessive-agency` |
| `resources/list` / `prompts/list` open | widens the enumerable surface | ASI02 |
| a `dispatch`/`search`/`invoke_*` meta-tool | real callable surface > what `tools/list` admits | ASI09 (inventory incomplete) |
| handshake `instructions` field populated | operator-prompt material pre-auth | ASI09 → `prompt-injection` / `sensitive-disclosure` |
Record each tool's `name`, declared params, and a risk note (names implying shell / filesystem / network =
high-value targets for `excessive-agency`). Do not invoke anything.

## 4. Auth + session posture
| Check | How (read-only) | ASI |
|---|---|---|
| enumeration open vs auth-gated | does `tools/list` need a credential? | — (fact) |
| OAuth metadata + PKCE | `GET /.well-known/oauth-authorization-server` → `code_challenge_methods_supported` includes `S256`? | ASI03 |
| bearer challenge present | an unauthenticated call returns `401` **with** `WWW-Authenticate: Bearer`? | ASI03 |
| redirect-URI laxity | registered redirect URIs wildcard / overly broad | ASI03 |
| session-ID entropy | sample a few `Mcp-Session-Id` values — predictable / short? **record entropy, never the value** | ASI03 |
| Host-header validation | repeat `initialize` with a foreign `Host:` — accepted? (DNS rebinding; HIGH only for loopback targets, else MEDIUM) | ASI03 |

## 5. Transport posture (protocol-neutral — runs against any identified endpoint)
```
openssl s_client -connect TARGET:443 -servername TARGET </dev/null 2>/dev/null | openssl x509 -noout -dates -subject
curl -sk -X OPTIONS https://TARGET/mcp -H 'Origin: https://evil.example' \
  -H 'Access-Control-Request-Method: POST' -D -        # a real CORS preflight
```
| Check | ASI | De-dupe to |
|---|---|---|
| plaintext HTTP (tokens / tool args on the wire) | ASI07 | — |
| cleartext downgrade (same host also answers in the clear) | ASI07 | — |
| TLS cert / cipher health | ASI09 | `tls-attacks` |
| CORS wildcard / reflected (and wildcard + credentials) | ASI03 | `cors` |
| missing rate-limit headers (unbounded call volume) | ASI08 | `security-headers` |

## 6. ASI mapping (cite only what's defensible)
Map each observation to the OWASP Agentic Top 10 category it actually evidences — do not cite one to look
thorough. Severity reflects **exposure**, not confirmed impact (this feeder never exploits). Key anchors:
ASI02 Tool Misuse & Exploitation (open tool inventory), ASI03 Agent Identity & Privilege Abuse (unauth
surface; weak OAuth / session / CORS / Host validation), ASI07 Insecure Communication (plaintext / downgrade),
ASI08 (unbounded call volume / cascading failure), ASI09 (incomplete inventory, pre-auth disclosure, transport
assurance). A pure fact ("enumeration is auth-gated") is left uncited.

## 7. Coverage accounting (silence must mean something)
Every check records one of: **matched** (ran, found it) · **clean** (ran, applicable, passed) · **skipped**
(didn't apply / excluded) · **could-not-run** (errored / timed-out / decode-failed). If any check is
could-not-run, the scan `status` is `incomplete` — lead the summary with that; an absent observation is NOT a
clean result.

## 8. Emit + route
Consolidate into `agent_context.json` (schema `_contract/agent_context.schema.json`):
- `tool_targets[]` → `excessive-agency` (enumerated tools to probe for over-permissioned actions)
- `injection_points[]` + `variant_hint` → `prompt-injection` / `sensitive-disclosure` / `llm-output-handling`
  (instructions-field leak, resource / prompt channels)
- generic transport exposures → `tls-attacks` / `cors` / `security-headers` / `exposed-surface` (don't re-report)
- relate to `llm-context` — the agent-protocol surface augments the LLM-app surface
Each exposure carries a redacted, read-only reproduction (a one-line `curl`, or a two-step re-handshake →
replay for a session-bound call) so it can be verified by hand.
