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
GLOBAL surface recon (once/engagement, IN ORDER)          PER-CLASS context feeders    VARIANT / CATEGORY agents
osint ─▶ host-discovery ─▶ content-discovery ─▶ js-analysis*  ─▶  <class>-context  ─▶  <class>-<variant>
                                                                      (recon: review.md only) (findings: review.md + verify.md)
```

\* **`js-analysis` is CONDITIONAL and DOWNSTREAM, not parallel.** Run it only when the target serves
client-side JS; for a pure API / JS-less target, skip it with an explicit N/A note (as recon still covers
the surface via host + content discovery). It consumes host-discovery (live hosts) and content-discovery
(crawled JS URLs). Its extracted endpoints/params MAY re-enrich content-discovery's `custom_wordlist.txt`
on an OPTIONAL second pass — an enrichment, **not** a precedence, so recon stays acyclic.

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
| **SQL injection** | A03 | family | `sqli-context` ✅ (injectable params, DBMS fingerprint, query context) | `sqli-inband` ✅ (error+union) · `sqli-blind` ✅ (boolean+time+oob) | ✅ |
| **Command / code / template injection** | A03 | family | `injection-context` ✅ (reflective sinks + tech fingerprint) | `ssti` ✅ · `command-injection` ✅ · `deserialization` ✅ (code-injection via ssti/cmdi) | ✅ |
| **SSRF** | A10 | family | `ssrf-context` ✅ (URL-fetching sinks, parser/allowlist behavior) | `ssrf-inband` ✅ · `ssrf-blind` ✅ · `ssrf-cloud` ✅ (protocol-smuggling in refs) | ✅ |
| **Access control / IDOR** | A01 | family | `authz-context` ✅ (object refs + role matrix + endpoint inventory) | `idor` ✅ (+ mass-assignment) · `privesc` ✅ (vertical + horizontal + forced-browsing) | ✅ |
| **XXE** | A05 | family | `xxe-context` ✅ (XML parsers/endpoints) | `xxe-inband` ✅ · `xxe-blind` ✅ (ssrf-via-xxe → ssrf-cloud) | ✅ |
| **File / path** | A01/A05 | family | `file-context` ✅ (path/file/upload params + upload endpoints) | `path-traversal-lfi` ✅ (+rfi/wrappers in refs) · `upload-rce` ✅ | ✅ |
| **Auth & session** | A07 | family | `auth-context` ✅ (login/session/token flows) | `auth-bypass` ✅ (+ session/mfa/reset) · `jwt` ✅ · `oauth` ✅ | ✅ |
| **API** | — (WSTG/API Top 10) | family | `api-context` ✅ (REST/GraphQL schema + authz) | `bola-bfla` ✅ (BOLA+BFLA+excessive-data+mass-assign) · `graphql` ✅ ; reuses `authz-*`/`injection-*` | ✅ |
| **AI / LLM** | OWASP LLM Top 10 (2025) | family | `llm-context` ✅ (model/API/guardrails/tools/data/output-sinks) | `prompt-injection` ✅ (LLM01) · `sensitive-disclosure` ✅ (LLM02/07/08) · `excessive-agency` ✅ (LLM06) · `llm-output-handling` ✅ (LLM05) | ✅ |
| **Active Directory** *(internal / assumed-breach)* | MITRE ATT&CK | family | `ad-context` ✅ (BloodHound + principals/ACL/ADCS/paths) | `ad-kerberos` ✅ · `ad-acl-abuse` ✅ · `ad-adcs` ✅ (ESC1-8) · `ad-lateral-movement` ✅ | ✅ |
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
| **NoSQL injection** | A03 Injection | single | — | `nosql-injection` ✅ (operator `$ne`/`$gt`/`$regex`/`$where` + syntax; auth bypass + query manipulation) | ✅ |
| **LDAP injection** | A03 Injection | single | — | `ldap-injection` ✅ (filter breakout `*)(uid=*))(|(uid=*`; auth bypass + directory enum) | ✅ |
| **Prototype pollution** | A03/A08 | single | — | `prototype-pollution` ✅ (client + server `__proto__`/`constructor.prototype` via merge sinks; gadget → XSS/RCE/DoS) | ✅ |
| **Race condition** | WSTG-BUSL | single | — | `race-condition` ✅ (TOCTOU + limit-overrun; single-packet attack; state-break proof) | ✅ |
| **HTTP parameter pollution** | A03/A05 | single | — | `parameter-pollution` ✅ (dup/polluted params across URL/body/JSON/cookie/header; gateway-vs-backend precedence flip) | ✅ |
| **WAF / filter bypass** | — | single (capability) | — | `waf-bypass` ✅ (fingerprint + tuned evasion ladder; feeds the vuln agents; review-only, no findings) | ✅ |
| **Exposed surface / sensitive files** | A05/A01 | single | — | `exposed-surface` ✅ (active dir/file/param fuzzing → signature-confirmed exposures: VCS `/.git`, backups, `.env`/config, data dumps, directory listing, debug/actuator panels, nuclei info-leaks; de-duped vs `secrets`/`security-headers`/`privesc`) | ✅ |

## Notes
- Families are built **feeder-first**; a variant is worthless without its context artifact.
- A category that starts atomic can grow into a family later — split when a second confirmation
  method appears (that is exactly how XSS earned four agents).
- These agents are invoked inside the `vuln-analysis` + `exploitation` phases of the PTES spine
  (`skills/README.md` roadmap). The orchestrator owns routing and phase gating.
- **Post-exploitation / privesc:** `linux-privesc` + `windows-privesc` (on a landed host), plus the
  **Active Directory** family (internal / assumed-breach), run in the exploitation / post-exploitation
  phases — approval-gated, benign-proof + cleanup, not web vuln categories.
