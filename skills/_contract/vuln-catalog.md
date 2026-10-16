# Vuln Category Catalog — every category gets its own agent

The rule: **every vulnerability category has its own agent.** No monolithic "web scanner."
An agent owns one coherent way of *confirming* a bug, so its `verify.md` gauntlet stays sharp
and its false-positive checks are specific. Generalize the XSS pattern across the catalog.

## The split rule (family vs. single agent)

A category is built one of two ways:

- **Compound → a family:** a shared `<class>-context` feeder + one agent per variant, when the
  variants need **different confirmation methods** but **share recon/attack surface**. XSS is the
  archetype (`xss-context` → reflected / stored / dom / blind — four different confirmations, one
  injection-surface analysis). Build the feeder first; each variant chains FROM it.
- **Atomic → a single agent:** one quad/quint, no feeder, when **one confirmation method** covers
  the category (e.g. CSRF, open redirect, clickjacking).

Decision test: *do the variants confirm differently but recon the same?* → family. Otherwise single.

## Two-tier recon

```
GLOBAL surface recon            PER-CLASS context feeders         VARIANT / CATEGORY agents
host-discovery ─┐
content-discovery ├─▶  <class>-context  ─▶  <class>-<variant>  (findings: review.md + verify.md)
js-analysis ─────┘      (recon: review.md only)
```

Global recon runs once per engagement. Each `<class>-context` feeder specializes that surface for
its class (injectable params, URL-fetching sinks, object references, XML endpoints, …). Variant
agents consume the feeder and produce findings. The **orchestrator** routes targets to the
relevant class feeders based on global-recon signals (a `url=` param → `ssrf-context`; a login
form → `auth-context`; a GraphQL endpoint → `api-context`; a DOM sink → `xss-context`).

## Contract

Every agent — feeder or variant, every category — is built on `_contract/README.md`:
interview header, `checklist.md` (load-bearing), `review.md` (+ manifest, `verify_completion.py`),
and `verify.md` **iff** it emits `findings.json`. Active categories import `_contract/roe-gate.md`.
Findings use `_contract/finding.schema.json`; feeders define a `<class>_context.schema.json`.

## Catalog (OWASP-aligned)

Legend: Pattern = family (feeder+variants) or single. Status: ✅ built · ◻ planned.

| Category | OWASP | Pattern | Feeder | Agents | Status |
|---|---|---|---|---|---|
| **XSS** | A03 Injection | family | `xss-context` ✅ | `xss-reflected` ✅ · `xss-stored` ✅ · `xss-dom` ✅ · `xss-blind` ✅ | ✅ complete |
| **SQL/NoSQL injection** | A03 | family | `sqli-context` ✅ (injectable params, DBMS fingerprint, query context) | `sqli-inband` ✅ (error+union) · `sqli-blind` ✅ (boolean+time+oob) | ✅ |
| **Command / code / template injection** | A03 | family | `injection-context` ✅ (reflective sinks + tech fingerprint) | `ssti` ✅ · `command-injection` ✅ · `deserialization` ✅ (code-injection via ssti/cmdi) | ✅ |
| **SSRF** | A10 | family | `ssrf-context` ✅ (URL-fetching sinks, parser/allowlist behavior) | `ssrf-inband` ✅ · `ssrf-blind` ✅ · `ssrf-cloud` ✅ (protocol-smuggling in refs) | ✅ |
| **Access control / IDOR** | A01 | family | `authz-context` ✅ (object refs + role matrix + endpoint inventory) | `idor` ✅ (+ mass-assignment) · `privesc` ✅ (vertical + horizontal + forced-browsing) | ✅ |
| **XXE** | A05 | family | `xxe-context` ◻ (XML parsers/endpoints) | `inband` · `blind-oast` · `ssrf-via-xxe` | ◻ |
| **File / path** | A01/A05 | family | `file-context` ◻ (path/file/upload params + upload endpoints) | `path-traversal` · `lfi` · `rfi` · `upload-to-rce` | ◻ |
| **Auth & session** | A07 | family | `auth-context` ◻ (login/session/token flows) | `authn-bypass` · `session-mgmt` · `jwt` · `oauth` · `mfa-bypass` · `password-reset` | ◻ |
| **API** | — (WSTG/API Top 10) | family | `api-context` ◻ (REST/GraphQL schema + authz) | reuses `authz-*` + `injection-*`; adds `bola` · `bofla` · `excessive-data` · `graphql` | ◻ |
| **CSRF** | — | single | — | `csrf` ✅ | ✅ |
| **CORS misconfig** | A05 | single | — | `cors` ✅ | ✅ |
| **Open redirect** | — | single | — | `open-redirect` ✅ | ✅ |
| **Clickjacking** | — | single | — | `clickjacking` ✅ | ✅ |
| **Host header injection** | — | single | — | `host-header` ✅ | ✅ |
| **HTTP request smuggling** | — | single | — | `request-smuggling` ✅ | ✅ |
| **Web cache poisoning/deception** | — | single | — | `cache-poisoning` ✅ | ✅ |
| **Subdomain takeover** | — | single | — | `subdomain-takeover` ✅ | ✅ |
| **Security misconfig / headers** | A05 | single (recon-ish) | — | `security-headers` ✅ | ✅ |
| **Secrets / sensitive data** | A02 | single | — | `secrets` ✅ (consumes `js-analysis/secrets.json`) | ✅ |
| **Business logic** | — | single (bespoke) | — | `business-logic` ✅ | ✅ |

## Notes
- Families are built **feeder-first**; a variant is worthless without its context artifact.
- A category that starts atomic can grow into a family later — split when a second confirmation
  method appears (that is exactly how XSS earned four agents).
- These agents are invoked inside the `vuln-analysis` + `exploitation` phases of the PTES spine
  (`skills/README.md` roadmap). The orchestrator owns routing and phase gating.
