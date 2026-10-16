# API attack techniques (shared by bola-bfla / graphql) — OWASP API Security Top 10
# Use TEST accounts. No DoS (no deep-nesting / batching bombs). Overlaps access-control (idor/privesc).

## Enumeration
- OpenAPI/Swagger (`/swagger.json`, `/openapi.json`, `/api-docs`), GraphQL introspection, `apis.json`
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
