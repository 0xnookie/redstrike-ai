# Proxy Spine — route HTTP through an interception proxy (imported by every web-touching skill)

When an interception proxy is connected, **every HTTP request the engagement makes goes through it.** The
proxy is the engagement's HTTP **spine** and shared evidence store — *not* a fallback for a blocked fetch
(that is rung 3 of `anti-automation-ladder.md`; the spine sits **under** rungs 1–5 as the transport). Routing
through it makes every request **logged, searchable, scoped, reproducible, and reviewable by a human**,
instead of ephemeral traffic that vanishes when the turn ends.

**Optional but preferred.** With no proxy connected the framework runs exactly as before (the ladder's lower
rungs + `interactsh` for OOB). With one connected, the rules below apply. This is a layer *on top of*
`roe-gate.md`, never a replacement for it.

## 1. The discipline it buys
- **Observability** — a human can open the proxy's History/Replay and *watch what the agent did*; the work is
  not trapped in a chat transcript.
- **Reproducibility** — a confirmation request is stored as a replayable entry, re-run byte-for-byte, instead
  of being regenerated from a prompt.
- **Scope at the transport** — the proxy won't forward an out-of-scope host even if the agent errs
  (defense-in-depth with the scope gate).
- **Shared source of truth** — the human and the agent see the same History, Sitemap, and Findings.
- **Reviewable evidence** — a finding points at a logged request/response pair, not a pasted `curl`.

## 2. Capabilities, not vendors (tool-first)
Target the **capability**; the operator picks the backend; **degrade gracefully** to the floor so nothing is
mandatory. (Name the capability in a skill step, e.g. "obtain an OAST payload" — not a product.)

| Capability | What it gives the engagement | Backends (any one) | Floor if none |
|---|---|---|---|
| **history** | searchable record of every request/response | Caido History · Burp proxy history · mitmproxy flows · ZAP | `logs/fetch.log` |
| **replay**  | re-send / tamper a stored request | Caido Replay · Burp Repeater / send-request | `curl` from the logged request |
| **oast**    | attributable out-of-band callback, auto-correlated to its request | Caido QuickSSRF · Burp Collaborator (Pro) | `interactsh-client` |
| **findings**| a shared place to file + export evidence | Caido Findings · Burp Scanner issues (read) | `findings.json` |
| **scope**   | transport-level allow/deny | Caido Scopes · (Burp scope) | `scope.yaml` + the scope gate |

Backends differ — design to the lowest common capability: Burp's send-to-Intruder only *opens a tab* (no
attack-start) and it has no scope/sitemap-list tool; Collaborator/Scanner are Pro-only. Caido exposes a
broader surface (Sitemap, Replay collections, Automate, Scopes). Never assume a backend-specific tool exists.

## 3. Route all traffic through it
When a proxy is connected, make the whole toolchain egress through it so one History holds everything:
- Export `HTTP_PROXY`/`HTTPS_PROXY` (and `NO_PROXY` for out-of-scope) and **trust the proxy CA**.
- `curl -x`, `httpx -http-proxy`, `ffuf -x`, `nuclei -proxy`, `sqlmap --proxy`, `katana -proxy` all honor it.
- Record in the audit log which requests went through the proxy (chain of custody).

## 4. Human-in-the-loop sends
A **state-changing or authentication** request is *proposed and staged*, and a human fires it — the proxy's
send-approval is an extra gate above `roe-gate.md` §2, not a replacement. Read-only sends (GETs, idempotent
probes) flow normally. **Redact** secrets (tokens, cookies, PII) to `‹redacted›` in anything exported or filed.

## 5. Export → the engagement
The **`proxy-context`** feeder exports the connected proxy's captured history to
`<engagement>/proxy-context/http_history.json` (shape in `skills/proxy-context/SKILL.md`). That export:
- **enriches the content map / Site Map** — real method·status·type·params·headers·body per URL (feeds
  `content-discovery`'s `content.json routes[]` and the console Site Map's request/response view);
- becomes **replay-backed evidence** — an executor's confirmation request is referenced by its history id so
  the independent reviewer verifies against the logged exchange.

Secrets are redacted on export; the raw proxy project stays local (never committed).

## 6. Scope + audit convergence
Generate the proxy's scope from `scope.yaml` so the transport layer and the scope gate **agree** (one scope,
two enforcement points). Every exchange is appended to the immutable engagement audit log §`roe-gate.md`.
