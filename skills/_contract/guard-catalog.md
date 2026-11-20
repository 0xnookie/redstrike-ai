# guard-catalog — the framework DEFENSES that legitimately clear a class (and the escape-hatch that defeats each)

The inverse of [`counterevidence.md`](counterevidence.md): that file stops you dismissing a real candidate for an invalid reason; this one names the SMALL set of real, framework-level guards that genuinely rule a class out, and — for each — the exact condition that re-opens it.
Consulted by every **executor** before refuting a surface with "a framework control handles it", by `source-audit` when it calibrates lead confidence, and by `code-audit` when it confirms or refutes a source lead.

A refutation is only valid when you have (a) confirmed the guard is actually **in the path** of THIS sink/route (not a safe sibling — see `counterevidence.md`), and (b) checked its **escape-hatch** and found it absent.
Skip (b) and you have a shallow clear, not a rule-out.

## Why the escape-hatches ARE the attack surface

On a hardened codebase the generic guards hold almost everywhere, so recon over-flags whole classes that the framework already defeats, and "sanitized=false" from a taint pass is routinely a false-negative (the dominant guard is invisible to grep).
The real findings do not come from a class the framework forgot — they come from the **one call site that slipped the guard**: the serializer that skips the shared sanitizer, the raw-SQL path around the ORM, the finalizer that trusts the staged value, the plain repo used where a scoped one was required.
Every confirmed finding in a hardened audit lived in an escape-hatch.
So treat each entry's escape-hatch as a hunt target, not a footnote: enumerate the sibling paths and prove the guard is present on EACH, because one miss is the finding.

## Closure mapping (ties to `counterevidence.md`)

- Guard present + in-path + escape-hatch absent → **ruled out** (a verified in-path control, the only valid empty-surface close).
- Guard present but an escape-hatch is open → **confirmed** candidate (the escape-hatch is the finding; rate it to the sink it reaches).
- Guard present but you could not reach the escape-hatch to test it → **open proof-gap**, never a silent clean.

## Reading an entry

Each guard carries: **id · the guard · the class it clears · in-path signal (confirm before refuting) · escape-hatch (the condition that defeats it)**.
Entries are generic-first; a `stack:` tag names the framework family where the pattern is concrete.

---

### G-01 · Framework/ORM column allowlist

- **Guard:** the ORM / query builder assembles SQL from a fixed table+column registry and binds every value, so request data becomes a parameter, never SQL syntax or an identifier.
- **Clears:** identifier-concat (and value-concat) SQLi on any sink routed through the ORM / data-abstraction layer.
- **In-path signal:** the sink is the ORM/DAL builder (not a raw driver handle); column and table names resolve through a field registry / enum; values are bound placeholders.
- **Escape-hatch:** a raw-SQL path that bypasses the ORM — a direct `executeStatement`/`query`/`raw()` with a concatenated identifier, or an ORM `orderBy`/field/sort argument taken from the request without the allowlist. *(stack: PHP data-abstraction layer / Doctrine, Django ORM, ActiveRecord, Sequelize)*

### G-02 · Library-version secure-default (XML parser)

- **Guard:** on a modern XML library the external-entity and external-DTD resolution is OFF by default, so `loadXML`/`simplexml_load_*` called with option flags `0` does not expand external entities.
- **Clears:** XXE on a parse of attacker-influenced bytes, for the library floor the codebase actually ships.
- **In-path signal:** the parse uses option flags `0` (or no entity-loader toggle) AND the pinned library floor is at or above the version where secure defaults landed.
- **Escape-hatch:** an entity-substitution / external-load flag is set (e.g. `NOENT` / `DTDLOAD` / `DTDVALID`), or the library floor is an old pin below the secure-default version. **This guard is INVISIBLE to taint** — the parse reads attacker bytes, so a taint pass reports `sanitized=false`; that is a FALSE-NEGATIVE here, not a reason to raise confidence. Note the asymmetry with a hardened sibling parser that sets `NONET` + rejects DOCTYPEs: the lax call is only defence-in-depth-short, not exploitable, until the floor drops or a flag flips. *(stack: libxml / PHP DOMDocument + SimpleXML)*

### G-03 · Type-keyed input-sanitization backbone

- **Guard:** a shared write-time sanitizer (strip-tags / HTML purify) is applied by the scalar-text field serializers (string / long-text), so stored scalar text is neutralised before it is ever persisted.
- **Clears:** stored XSS on scalar text fields that go through the shared backbone.
- **In-path signal:** the field's serializer is one that invokes the shared sanitizer on write, and the value is a scalar string/text type.
- **Escape-hatch:** a List / JSON / array serializer that persists the value verbatim (JSON-encode with no strip/sanitize) and so SKIPS the shared backbone — a list-typed or structured field that later meets a raw/unescaped sink. **This is exactly where the real HIGH lived** (a list-field value stored unsanitised, then concatenated into a template and emitted `|raw`). *(stack: entity/field serializer layers — PHP DAL, Rails serializers, any type-dispatched write pipeline)*

### G-04 · Output auto-escape + purifier-on-AllowHtml

- **Guard:** the template engine HTML-auto-escapes every variable by default, and the few fields explicitly flagged as HTML-bearing are run through an HTML purifier/sanitizer, so output is safe in both the common and the rich-text case.
- **Clears:** reflected/stored XSS at a template sink where auto-escape is in force.
- **In-path signal:** the variable is emitted through the auto-escaping engine with no raw filter, OR the field is an AllowHtml field that the purifier processed; a `|raw` that only re-emits an already-escaped capture is still safe.
- **Escape-hatch:** a raw/unescaped sink (`|raw`, `safe`, `v-html`, `dangerouslySetInnerHTML`, string-concatenated HTML) fed by a field that is NOT AllowHtml and was NOT purified — the auto-escape is bypassed and the purifier never ran. *(stack: Twig / Jinja / Blade / ERB autoescape + HTML-purifier)*

### G-05 · Lax setter / strict finalizer (server-side recompute)

- **Guard:** an intermediate setter is deliberately permissive (it stores a staged/requested value without full validation), but the finalizer that acts on it RE-VALIDATES or RE-COMPUTES server-side before the state change commits.
- **Clears:** value-tampering / eligibility-bypass via the lax setter, when a strict finalizer governs the committed outcome.
- **In-path signal:** trace from the setter to the commit and confirm the finalizer independently re-checks (active / eligibility / availability-rule / ownership) and BLOCKS on failure — not merely reads the staged value back.
- **Escape-hatch:** the finalizer TRUSTS the staged value — it reads back what the setter stored without recomputing or re-validating it, so the lax setter's value flows straight into the committed state. *(stack: checkout/cart pipelines, multi-step wizards, draft→publish flows)*

### G-06 · Authoritative-record-over-request derivation

- **Guard:** a security-relevant value is derived from an authoritative stored entity (the account's own address / role / tenant), and a request/context-supplied value is used only as a fallback when no authoritative record exists.
- **Clears:** tampering with the request/context copy of a value that an entity governs (tax country, pricing tier, ownership, role).
- **In-path signal:** the resolution reads the entity FIRST (`entity.value ?? context.value`) and the operation that matters requires the entity to be present.
- **Escape-hatch:** a path where the request/context value GOVERNS because there is no authoritative entity to override it — a guest/anonymous flow, a pre-registration step, or an operation reachable before the entity is attached — so the fallback becomes the primary. *(stack: session/context factories, multi-tenant resolvers)*

### G-07 · Deny-by-default field ACL / expose-flag allowlist

- **Guard:** fields and associations are hidden from the API unless explicitly flagged exposable, and reads go through a SCOPE-AWARE repository that applies the tenant/visibility filter, so cross-principal data is filtered by default.
- **Clears:** over-exposure / excessive-data / nested-read leaks where the field ACL and the scoped repository are both in the path.
- **In-path signal:** the read uses the scoped/sales-channel repository (the one whose criteria pipeline injects the visibility filter) AND the leaked field is NOT on the expose allowlist.
- **Escape-hatch:** a PLAIN repository used where the scoped one was required — the plain type never runs the visibility-filter pipeline, so a nested association (e.g. `order → lineItems → product → reviews`) returns other principals' unfiltered rows. Also: a sensitive field mistakenly flagged exposable. *(stack: entity-repository layers with a scoped subclass — PHP DAL SalesChannelRepository, scoped query scopes)*

### G-08 · Scope-partitioned write mapper

- **Guard:** writes from a low-trust scope pass through a mapper/allowlist that DROPS every key not marked writable in that scope, and privileged fields carry a write-protection flag that only a higher scope can set.
- **Clears:** mass-assignment / over-posting on an endpoint fronted by the mapper.
- **In-path signal:** the write path runs the scope mapper (non-allowlisted keys discarded) and the sensitive field is write-protected to a higher scope.
- **Escape-hatch:** a write path that SKIPS the mapper, or a sensitive field that is NOT write-protected — e.g. a privilege/role list stored as a plain list field with no write-protection flag, upserted verbatim in user scope with no subset check, letting a caller grant itself more than it holds. *(stack: request→entity mappers, mass-assignment guards, strong-params allowlists)*

### G-09 · CSPRNG + single-use + bound + short-TTL token

- **Guard:** a security token is a high-entropy CSPRNG value, single-use (consumed on first use), bound to its subject, and short-lived, and sensitive changes additionally re-authenticate.
- **Clears:** token brute-force / guessing / reuse for recovery, confirmation, and similar one-shot flows.
- **In-path signal:** confirm EVERY leg — entropy (CSPRNG, wide), single-use consumption, subject binding, short TTL, and (for account-changing flows) a re-auth step.
- **Escape-hatch:** a MISSING leg. The token is stored in plaintext/verbatim at rest (a plain string field, not a hash of the token) → a DB-read turns into account takeover; or no effective rate-limit on issuance → mail-flooding / throttle-evasion; or not actually single-use → replay. A strong token with one weak leg is still a finding (rate it to the leg). *(stack: password-reset / email-confirm / invite tokens)*

### G-10 · Signed token with claims inside the signature

- **Guard:** an issued token is signed (HMAC / asymmetric) over a payload that CONTAINS the authorization claims (subject, scope, channel), so the claims cannot be altered without breaking the signature.
- **Clears:** token forgery / claim-tampering for impersonation / imitation tokens.
- **In-path signal:** the security-deciding claims are INSIDE the signed payload and the verifier checks the signature before trusting them.
- **Escape-hatch:** a security claim carried OUTSIDE the signature (a separate header/param the verifier trusts), or no `jti`/single-use → the valid token is REPLAYABLE within its TTL. A correctly-signed, claim-bound token with no `jti` is still a replay finding (usually low, rate to window + blast radius). *(stack: HMAC-signed app/imitation tokens, JWT — JWT crypto specifics route to the jwt executor)*

### G-11 · SameSite=Lax explicit + POST-only + password re-auth

- **Guard:** the session cookie sets `SameSite=Lax` EXPLICITLY (so the browser's Lax-by-default POST grace window does not apply), every sensitive state change is POST-only (cross-site POST is Lax-blocked), and credential changes additionally require the current password.
- **Clears:** CSRF / cross-origin forced state change and CSRF-driven account takeover.
- **In-path signal:** confirm the cookie flag is set explicitly, the sensitive action is POST, and (for credential changes) the current-password check is in the path.
- **Escape-hatch:** a state-changing GET (Lax permits top-level-navigation GET → forgeable via a link/`<img>`), or a password-less sensitive POST that relies on Lax ALONE (a legacy/SameSite-ignoring client re-exposes it). Rate the forgeable action's real impact — a GET logout is nuisance; a password-less account-delete POST is not. *(stack: session-cookie SameSite + method routing)*

### G-12 · SSRF-hardened HTTP client (IP-pin / no-redirect)

- **Guard:** outbound fetches of attacker-influenceable URLs go through a hardened client that resolves+pins the IP, blocks private/link-local ranges, and refuses redirects, so a supplied URL cannot reach internal services or metadata.
- **Clears:** SSRF on the fetch paths that use the hardened client.
- **In-path signal:** the specific fetcher in question instantiates the hardened client (not a bare HTTP client), and the egress filter runs before the request.
- **Escape-hatch:** a SIBLING fetch path that uses the PLAIN client (a renderer, a PDF/image library with remote-fetch enabled, an app/webhook sub-request), or an app/customer-supplied URL fed into an internal sub-request with no egress filter on that leg. The hardened client on one path says nothing about the others. *(stack: guzzle/curl wrappers, document/image renderers with remote-asset fetch)*

### G-13 · Template sandbox (SecurityPolicy / empty function allowlist / neutered `_self`)

- **Guard:** server-rendered user/admin-authored templates run in a sandbox with a SecurityPolicy — an empty allowed-callable list, an in-memory array loader (no filesystem includes), and the self-reference/code-access objects removed from context — so an evaluated expression cannot reach code execution.
- **Clears:** SSTI→RCE (the injection may still EVALUATE, but the RCE gadgets are blocked).
- **In-path signal:** the render env has the sandbox/SecurityPolicy attached, the callable allowlist is empty, the loader is in-memory, and no exec-capable object sits in the render context.
- **Escape-hatch:** the callable allowlist is POPULATED (any dangerous function re-enabled), or a plugin/caller injects an exec-capable object into the render context, or the sandbox is simply not attached on this particular string-render path. **Split the rating:** template-expression injection is confirmable on its own (medium); the RCE is LOW until the sandbox is shown absent/defeated. *(stack: Twig SecurityExtension / Jinja SandboxedEnvironment)*

### G-14 · Archive-extraction neutralization

- **Guard:** archive extraction validates entry paths (reject absolute paths and `..` traversal) and the extraction primitive normalises/confines the output directory, so a crafted entry cannot write outside the target.
- **Clears:** zip-slip / path-traversal-on-extract for the write confinement itself.
- **In-path signal:** confirm a non-empty confinement prefix is enforced AND the extraction primitive neutralises absolute/traversal paths on the target OS.
- **Escape-hatch:** a validator that checks ONLY the path-prefix and `..` traversal (CONTENT-BLIND — no file-type/extension allowlist), followed by an UNCONDITIONAL, content-blind copy of the extracted files into a WEB-SERVED directory. A benign-pathed `.php`/`.htaccess`/handler entry passes the path check and lands as an executable under a public URL → webshell. **This was the CRITICAL** — the path-traversal guard was intact, but nothing filtered WHAT was extracted before copying it web-reachable. *(stack: app/plugin/theme installers, upload-then-extract flows)*
