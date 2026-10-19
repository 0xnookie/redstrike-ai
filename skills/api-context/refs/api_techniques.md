# API attack techniques (shared by bola-bfla / graphql) — OWASP API Security Top 10
# Use TEST accounts. No DoS (no deep-nesting / batching bombs). Overlaps access-control (idor/privesc).

## Enumeration
- OpenAPI/Swagger (`/swagger.json`, `/openapi.json`, `/api-docs`), GraphQL introspection, `apis.jsonl`
  from js-analysis, old API versions (`/v1`,`/v2`), hidden methods (OPTIONS, PATCH).

## BOLA (API1 — object-level, = IDOR for APIs)
- Swap an object id in path/body to another identity's object; sequential/uuid/predictable ids.
- Cross-tenant object access; nested object refs in the body.

## BFLA (API5 — function-level)
- As a low-priv identity, call admin/privileged operations (HTTP method + path the matrix reserves).
- Method override (`X-HTTP-Method-Override`), accessing admin endpoints directly.

## Excessive data exposure (API3)
- Endpoint returns more fields than the UI uses (PII, internal flags, other users' data) — client-side
  filtered only. Compare `returns_fields` vs what's displayed.

## Mass assignment (API6)
- Send extra fields (`role`, `isAdmin`, `verified`, `balance`) to create/update endpoints.

## GraphQL-specific
- **Introspection** enabled → full schema (`__schema`, `__type`).
- Field-level authz: a query returning a field a role shouldn't see.
- IDOR via `node(id:)` / global ids; alias-based data harvest.
- Injection via arguments (SQLi/NoSQLi through resolver args).
- **DoS (DO NOT run):** deeply nested queries, alias/batching amplification — REPORT the possibility,
  don't execute a resource-exhausting query.

## Rate limiting (API4)
- Missing limits on sensitive ops (login, OTP) — a FEW attempts only (never a real brute-force).

---

## Extended arsenal — GraphQL transport & endpoint surface
# Find the endpoint, enumerate how it accepts input, then confirm liveness with a benign __typename probe.
- Common mounts: `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphql/console`, `/graphiql`, `/playground`,
  `/query`, `/gql`, `/index.php?graphql`, `/.netlify/functions/graphql`, `/subscriptions` (WebSocket).
- Transports/methods: POST `application/json`, POST `application/graphql`, POST form-urlencoded,
  GET `?query=` (CSRF-relevant), WebSocket (`graphql-ws` / `graphql-transport-ws`).
- Request shape: `query` + `variables` + `operationName`; a multi-operation document selects by `operationName`.
- Fingerprint the engine (apollo / graphene / hasura / graphql-php / ...) with `graphw00f` — the engine dictates
  introspection defaults, error verbosity, batching support, and field-suggestion behaviour.

```graphql
# minimal liveness probe — safe on any endpoint
query { __typename }
```

---

## Extended arsenal — GraphQL introspection & schema extraction
# Introspection ON → the whole schema: types, fields, args, enums, interfaces, directives, deprecations.
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name } subscriptionType { name }
    types { ...FullType }
    directives { name description locations args { ...InputValue } }
  }
}
fragment FullType on __Type {
  kind name description
  fields(includeDeprecated: true) {
    name description args { ...InputValue } type { ...TypeRef }
    isDeprecated deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
  possibleTypes { ...TypeRef }
}
fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
fragment TypeRef on __Type {
  kind name ofType { kind name ofType { kind name ofType { kind name } } }
}
```
```bash
# inventory only — list type + field NAMES, never row data
curl -s TARGET/graphql -H 'content-type: application/json' \
  --data '{"query":"query{__schema{types{name fields{name}}}}"}' | jq '.data.__schema.types[].name'
```
- Partial introspection: some engines block `__schema` but still answer `__type(name:"User")` — enumerate type-by-type.
- Evidence = type/field inventory (counts + a few names), not a data dump.

---

## Extended arsenal — GraphQL introspection-disabled recovery
# Introspection OFF does not keep the schema secret — rebuild it from the resolver's own feedback.
- `__typename` is almost always allowed → confirms GraphQL and root-type names.
- Field suggestions: a mistyped field often returns `Did you mean "<real field>"?` — walk the schema blind.
```graphql
query { user { emial } }     # typo -> server suggests "email", "emailVerified", ...
```
- Automated inference: `clairvoyance` brute-forces fields/args against that suggestion oracle to reconstruct a schema.
- Validation errors leak types: a wrong arg type returns `Expected type "UserFilter"`; required-arg errors name inputs.
- `graphw00f` fingerprint tells you which recovery oracle (suggestions vs error shape) the engine exposes.

---

## Extended arsenal — GraphQL batching & aliasing (authz / rate-limit bypass)
# Two batch forms. Use a HANDFUL (<=~10) to PROVE a control gap — never thousands (that is the DoS catalogue: report only).
```json
[{"query":"query{__typename}"},{"query":"query{__typename}"}]
```
```graphql
# alias batch — N operations in ONE HTTP request (2 identities under test)
query {
  a: me { id }
  b: node(id: "VXNlcjoy") { ... on User { id email } }
}
```
- Rate-limit relevance: if the limiter keys on HTTP requests, a few aliased attempts in one request slip past the
  per-request counter — proving the limiter counts the wrong unit. Keep attempts minimal.
- Authz relevance: alias the same object query as A for several of B's ids to probe missing per-object checks (few, targeted).
- Batched mutations (`a: redeemCoupon(...) b: redeemCoupon(...)`) are a concurrency/limit-overrun test → hand off to the
  race-condition skill; do not hammer here.

---

## Extended arsenal — GraphQL CSRF
# JSON POST usually forces a CORS preflight (not CSRF-able). The gaps are GET and simple-request bodies.
- Does the endpoint run **mutations over GET** (`?query=mutation...`)? → classic CSRF via image/link.
- Does it accept `Content-Type: application/x-www-form-urlencoded` (a CORS "simple request", no preflight)? →
  an auto-submitting cross-origin form works.
```html
<form action="https://TARGET/graphql" method="POST" enctype="application/x-www-form-urlencoded">
  <input name="query" value="mutation{ setEmail(email:&quot;attacker@TOKEN.oob.example&quot;){ ok } }">
</form><script>document.forms[0].submit()</script>
```
- Checks: SameSite on the session cookie, a CSRF token, and whether `application/json` is REQUIRED (mitigates).
- Confirm with 2 identities + a benign state change on the TEST account; hand cross-origin delivery nuance to the csrf skill.

---

## Extended arsenal — GraphQL field-level authorization testing
# An object can be authorized while a FIELD on it is not. Test per field, with 2 identities.

| Step | Low-priv identity A | High-priv identity B |
|---|---|---|
| Same query, sensitive fields | `user(id:A){ email role auditLog }` | same query |
| Compare | field returns data, or `null` + error? | baseline (should return) |

- Target fields: `email`, `phone`, `passwordHash`, `ssn`, `role`, `permissions`, `internalNotes`, `auditLog`, `apiKey`.
- A field that returns data to A which only B should see = field-authz bypass (this skill's finding, not plain IDOR).
- `null` + an `errors` entry scoped to that path = authz enforced (the baseline you compare against).

---

## Extended arsenal — GraphQL node(id:) / global-id & Relay IDOR
# Relay exposes a generic node(id:) that often skips per-type ownership checks. Global ids are usually base64("Type:pk").
```bash
echo -n 'VXNlcjox' | base64 -d        # -> User:1
printf 'User:2' | base64              # -> VXNlcjoy   (B's TEST object)
```
```graphql
query { node(id: "VXNlcjoy") { ... on User { id email } } }   # as identity A, fetch B's node
```
- Also test typed root fields (`user(id:)`, `order(id:)`) with the other identity's id.
- Non-base64 global ids: raw ints, UUIDs, hashids, composite `type:tenant:pk` — decode, rotate the pk/tenant, re-encode.
- Finding = A reads/edits B's node; baseline = A reads A's node. 2 identities mandatory; redact PII; a couple of swaps, no sweep.

---

## Extended arsenal — GraphQL argument-injection probes (hand-off)
# Resolver args feed SQL / NoSQL / OS / template / directory sinks. Here: DETECTION markers only — the matching
# injection skill confirms and exploits (sqli-*, nosql-injection, command-injection, ssti, ldap-injection).

| Sink | Benign marker in an arg | Hand off to |
|---|---|---|
| SQL | `'` , `")` , `1 AND 1=1` vs `1 AND 1=2` (differential) | sqli-inband / sqli-blind |
| NoSQL | variables `{"user":{"$gt":""}}` , `{"$ne":null}` | nosql-injection |
| OS cmd | `;id` , `$(id)` , `` `id` `` (no OOB fired here) | command-injection |
| Template | `${7*7}` , `{{7*7}}` , `#{7*7}` | ssti |
| LDAP | `*)(uid=*` | ldap-injection |

- Observe the error/behaviour differential as a SIGNAL only; record the exact `type.field(arg:)` + the differential.
- The injection agent fires the confirmed OOB/timing proof; the OOB canary host placeholder `TOKEN.oob.example` is set there, not here.

---

## Extended arsenal — GraphQL mutation abuse & privilege fields
# Mutations are the write surface — BFLA + mass-assignment live here. Use your OWN test objects; re-read to confirm.
- Enumerate from the schema: `create*`, `update*`, `delete*`, `set*Role`, `grant*`, `impersonate*`, `invite*`, `*Admin*`.
- BFLA: as low-priv A, call a mutation the matrix reserves for a higher role — did it execute?
- Mass-assignment in input objects: input types often accept more than the UI sets. Set a privileged input field on your
  own object and re-query to confirm the server honoured it:
```graphql
mutation { updateUser(input:{ id:"<A>", role: ADMIN, isVerified: true }) { id role isVerified } }
```
- Nested inputs: `input:{ profile:{ ownerId:"<B>" } }`. Confirm by read-back; never flip another identity's live object.

---

## Extended arsenal — GraphQL verbose-error information disclosure
# Error bodies leak internals even with introspection off.
- Trigger: type mismatch, missing required arg, bad enum value, malformed document.
- Harvest from `errors[].message` + `errors[].extensions` (`code`, `exception.stacktrace`, `path`): framework + version,
  DB driver errors, file paths, internal hostnames, resolver names.
- Report the disclosure class + a redacted excerpt; a leaked secret/token routes to the secrets skill.

---

## Extended arsenal — GraphQL persisted queries & APQ
# Automatic Persisted Queries (APQ): the client sends a sha256 hash; on a miss it registers the full query. If APQ is
# (mis)used as an allow-list, test whether it is actually enforced.
```json
{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"<64-hex>"}}}
```
- `PersistedQueryNotFound` on a random hash → the endpoint lets you REGISTER arbitrary ops (allow-list not enforced):
  resend with the full `query` + its matching hash.
- Also test: does the endpoint still accept plain non-persisted queries? If yes, the "allow-list" is cosmetic.
- GET + an APQ hash is another CSRF/caching surface — note it; keep probes benign.

---

## Extended arsenal — GraphQL DoS feasibility (ASSESS & REPORT — do not run)
# NEVER fire an amplifying query at a live target. Assess the defenses with safe, shallow probes and REPORT the gap.

| Vector | What makes it possible | Safe signal (do NOT amplify) |
|---|---|---|
| Deep nesting | cyclic type refs (`posts{author{posts{...}}}`) | is a depth limit documented/enforced? |
| Alias amplification | many aliases of a costly field in one op | is there an alias-count cap? |
| Array batching | N operations per HTTP request | is there a batch-size cap? |
| Field duplication | the same field repeated K times | normalization / cost cap? |
| Directive overload | `@include`/`@skip` stacked | directive-count cap? |
| Wide pagination | `first: <huge>` on a list | max page-size enforced? |

- Benign assessment: send ONE shallow legitimate query; note the absence of a depth/cost/complexity limit; REPORT feasibility.
- A missing complexity/cost analysis IS the finding — proven by configuration/behaviour, never by exhausting the server.

---

## Extended arsenal — GraphQL benign confirmation recipe
# Minimal, repeatable, benign proof per flaw class — the evidence the graphql-verify reviewer expects.
- Introspection: type/field COUNTS + a few names (not a schema dump).
- Field-authz / node-IDOR: paired requests — A reads B's field/node (redacted) + the B-as-B baseline; 2 identities.
- Mutation BFLA / mass-assign: the mutation response + a read-back showing the changed field on the TEST object.
- Arg-injection: the differential/marker + the hand-off to the injection agent (no exploitation here).
- DoS: the config/behaviour note that a limit is absent — never an amplified request.
- Rate-limit: a few aliased/batched attempts showing the counter unit is wrong; stop at the proof.

---

## Extended arsenal — REST method-override & verb tampering
# The router, the framework override layer, and the authz middleware can disagree on the effective method.

| Vector | Example | Use |
|---|---|---|
| Override header | `X-HTTP-Method-Override: DELETE` | reach a verb the ACL blocks on the real method |
| Alt headers | `X-HTTP-Method`, `X-Method-Override` | framework-specific overrides |
| Body/query field | `?_method=PUT` , `_method=DELETE` | form-based override |
| Direct verb | `PUT`/`PATCH`/`DELETE` on a GET/POST-only UI route | missing method-level authz |
| `OPTIONS` | read the `Allow:` header | enumerate hidden verbs |
| `HEAD` | GET-filtered route that ignores HEAD | bypass a body/response filter |

- Many WAF/ACL rules are verb-specific; a tampered method can skip the rule while the backend still acts.
- Confirm with 2 identities where authz is the question; de-dupe vs the privesc / parameter-pollution skills.

---

## Extended arsenal — REST content-type & parser confusion
# The gateway and the backend can parse the SAME body differently — or honour an unexpected type.
- Send JSON with `Content-Type: application/x-www-form-urlencoded` (and the reverse) — does the backend still parse it?
- `text/plain` / missing content-type to dodge a JSON-only WAF body inspector or a CSRF content-type guard.
- Charset/suffix tricks: `application/json; charset=utf-7`, `application/json;x=1`, trailing junk after the type.
- XML where JSON is expected → may activate an XML parser (XXE) → hand off to the xxe skill (marker only here).
- Gateway-vs-backend field precedence (overlapping fields across types) overlaps the parameter-pollution skill — hand off.

---

## Extended arsenal — REST API versioning & shadow endpoints
# Old and undocumented versions often predate the current authz checks.
- Path versions: `/v1 /v2 /v3 /v0`, `/api/v1` vs `/api/v2` — retest the SAME object across versions with one identity.
- Header versions: `X-API-Version: 0`, `Accept: application/vnd.<app>+json;version=1`.
- Shadow mounts: `/internal`, `/admin`, `/debug`, `/private`, `/beta`, `/test`, `/legacy`, `/actuator`, `/_`.
- Representation suffixes: `.json`, `.xml`, trailing `;` or `/` — can route to a different handler.
- Discover with `ffuf` over a version/endpoint wordlist (rate-limited, scope-gated); confirm the authz drift per version.

---

## Extended arsenal — REST mass-assignment field discovery (deep)
# The write surface is usually wider than the UI. Source candidate fields, then prove persistence on your OWN object.
- Field sources: the object's own GET response, OpenAPI/JSON-schema, JS bundles, sibling endpoints, validation errors.
- Privileged candidates: `role roles isAdmin is_staff verified email_verified status approved balance credits price
  discount owner_id org_id tenant_id permissions scopes feature_flags`.
```http
PATCH /api/users/<A> HTTP/1.1
Content-Type: application/json

{"isAdmin": true}
```
- Technique: GET object → PATCH/PUT with one candidate added → GET again; persisted + honoured = mass-assignment.
- Nested/array wrappers: `{"user":{"role":"admin"}}`, `{"roles":["admin"]}`. Re-read to confirm; your object only.
- De-dupe with the idor / privesc skills; this skill owns the API mass-assignment angle.

---

## Extended arsenal — REST BOLA/BFLA deep (id formats, nested refs, tenant scoping)
# Object-level (BOLA) and function-level (BFLA) authz in depth. 2 identities always: A acts on B's thing = finding.

| ID format | Example | Note |
|---|---|---|
| Sequential int | `1002` | trivially enumerable (few targeted swaps — no mass pull) |
| UUIDv1 | time+MAC | guessable (timestamp-ordered), unlike v4 |
| UUIDv4 | random | not guessable, but still leaks via lists/refs |
| base64 / hashids | `VXNlcjox` | decode/rotate (see node(id:)) |
| Composite | `org-12/user-45` | swap each segment independently |
| MongoID | 12-byte, time-prefixed | partially predictable |

- ID locations: path, query, JSON body (incl. nested), headers (`X-Account-Id`, `X-Tenant`), cookies.
- Nested refs: `/orders/{o}/items/{i}` — test `{i}` authz independent of `{o}`.
- Tenant scoping: keep A's session, swap `tenant_id`/`org_id`/`X-Tenant`; try `0`, `null`, `*`.
- BFLA: enumerate role-reserved functions from the matrix; low-priv A invokes them (direct route or tampered method).
- Benign: a couple of targeted swaps to B's TEST object; never iterate the whole id space.

---

## Extended arsenal — REST excessive-data detection
# The endpoint returns more than the UI renders — filtered client-side only.
- Diff response JSON fields vs the rendered view; flag `password hash token secret apiKey ssn dob salary` + internal flags.
- List endpoints returning OTHER users' records; `_embedded`/`_links` exposing admin relations.
- `?fields=` / `?include=` / `?expand=` / `?with=` pulling related sensitive objects.
- Compare the verbose single-object read (all scalars) against the summarized list form.
- Report field names + the over-exposure; redact values, no bulk capture.

---

## Extended arsenal — REST rate-limit & anti-automation probing (few attempts)
# Prove the CONTROL is missing/weak with a SMALL burst — never a real brute-force.
- Small burst (~5-10) at login/OTP/reset/coupon → expect `429` + `Retry-After` / lockout; note if none appears.
- Limiter key test (a few tries): rotate `X-Forwarded-For`/`X-Real-IP`/`X-Originating-IP`, swap account vs token —
  does the counter reset? → spoofable key.
- Response-timing or sequential-token side channels aid enumeration; note them, do not harvest.
- GraphQL alias/array-batch (few) to show the counter unit is per-request not per-operation.
- Stop at the proof of the gap; the finding is the missing control, not harvested data.

---

## Extended arsenal — REST parameter pollution (hand-off)
# Duplicated/overlapping params resolved differently by gateway vs backend (first-wins / last-wins / array-concat).
- Security-relevant dups: `role=user&role=admin`, `id=`, `amount=`, `account=`, filter/scope params.
- Spread the duplicate across URL + body + JSON + cookie + header to find the precedence seam.
- This is the parameter-pollution skill's core — record the candidate + observed precedence and HAND OFF; don't fully exploit here.

---

## Extended arsenal — REST JSON/XML/multipart body tricks
# Body-parser quirks flip validation, authz, and field selection.
- JSON duplicate keys: `{"role":"user","role":"admin"}` — which wins is parser-dependent → authz flip.
- Type juggling: `"1"` vs `1`, `true`/`1`/`"true"`, scalar-as-array `{"id":[1,2]}`, `null` vs omitted (skip a validator).
- Unknown/extra fields = mass-assignment (above); unicode escapes `\u0000`/overlong to slip filters.
- XML bodies: entity/DTD markers = XXE → hand off to the xxe skill; a `billion laughs` body is DoS → DO NOT run.
- Multipart: duplicate parts, per-part `Content-Type`, filename/extension tricks, boundary confusion → upload-rce hand-off.

---

## Extended arsenal — REST pagination & filter abuse
# Pagination and filter params are an access-control and injection surface — keep probes benign.
- `limit`/`per_page`/`page_size`: request a MODESTLY larger page to show no server cap (prove the gap, redact, no bulk dump).
- Offset/cursor tampering to step onto another tenant's records (2 identities; targeted, not a sweep).
- `filter`/`q`/`sort`/`order` into SQL/NoSQL/search sinks → injection markers only → hand off to the injection skills.
- `sort=<hidden_field>` / `fields=<hidden_field>` can confirm a hidden field's existence (pairs with excessive-data).
- GraphQL `first/last/after`: assess large-page feasibility (see the DoS catalogue) — report, don't pull.
