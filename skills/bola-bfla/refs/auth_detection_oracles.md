# Framework auth-detection oracles — "is authorization ENFORCED, or ABSENT?" by error-type divergence
# Authorized, in-scope API only. TEST accounts; benign reads. No DoS (no deep nesting / batching bombs).
# These oracles decide WHERE to spend a BOLA/BFLA test: they separate an endpoint whose auth middleware
# caught you (401/403) from one where auth was NEVER CHECKED and your request fell through to the backend.

## The core signal
A missing-authz endpoint does not answer with a clean `401`/`403` — it answers with whatever the *business
logic* produces when it runs un-gated: a `404`, a null-dereference stack trace, a queryset error, a
"could not resolve", or an actual `success:true`. The framework's error *shape* is the oracle:

> **A `401`/`403` = the auth layer caught the request. A backend / business / lookup error = auth was never
> checked and the call reached the handler.** The second case is the one to attack.

Send every candidate operation **twice** — once **with no auth header**, once with a **syntactically fake**
token (`Authorization: Bearer invalidtoken123`). If both return the *same backend error* (not `401`/`403`),
no auth middleware sits in front of that operation. Then tabulate per operation.

## Apollo / GraphQL — per-resolver auth is opt-in
Auth in many GraphQL servers is enforced *inside each resolver*, not at a service-wide middleware. A resolver
that forgot the check runs its body unauthenticated.

```bash
# No auth:
curl -s -X POST https://TARGET/graphql -H "Content-Type: application/json" \
  -d '{"query":"mutation { targetMutation(input:{field:\"x\"}) { success } }"}'
# Fake auth:
curl -s -X POST https://TARGET/graphql -H "Content-Type: application/json" \
  -H "Authorization: Bearer invalidtoken123" \
  -d '{"query":"mutation { targetMutation(input:{field:\"x\"}) { success } }"}'
```

| Response (both calls) | Verdict |
|---|---|
| `401` / `403` / `{"errors":[{"extensions":{"code":"UNAUTHENTICATED"}}]}` | auth enforced on this resolver |
| `500` / `NullReferenceException` / `404` / a *business* error / `success:true` | **auth never checked — resolver unprotected** |

Test **every** mutation, prioritising state-changers: SSO/identity mappings, password reset, user update,
session/logout, permission grants. Build the table (below) — a column of backend errors is a column of BFLA.

## Django REST Framework (DRF) — auth runs BEFORE queryset access
DRF checks permission classes before the view touches the ORM, so the error *level* is diagnostic on an
object-lookup URL:

```bash
curl -s "https://api.TARGET/accounts/"                      # protected list
curl -s "https://api.TARGET/resource/nonexistent-id/"       # object lookup, no auth
```

| Response | Verdict |
|---|---|
| `401 {"detail":"Authentication credentials were not provided."}` | auth **enforced** |
| `403 {"detail":"You do not have permission to perform this action."}` | authN ok, authZ enforced |
| `404 {"detail":"Not found."}` or a queryset/ORM error on the lookup | **`AllowAny` bypass** — the view reached the DB without an auth gate |

Rule: in DRF, a `404`/queryset-level message on an object lookup proves authentication was never checked
(the handler got far enough to miss-lookup the object). White-box corroboration: `permission_classes =
[AllowAny]` on the viewset; DRF APIs commonly mount at `/api/v1/`, `/api/v2/`, viewset-style routes.

## ASP.NET / .NET Core — null-deref proves the handler ran un-gated
When a .NET handler runs without the identity an `[Authorize]` filter would have populated, it dereferences a
null principal/claim and throws:

| Response signature | Verdict |
|---|---|
| `System.NullReferenceException` / `System.ArgumentNullException` in the body or stack trace | **code reached without auth** (the filter never ran) |
| `401` / `403` (`AccessDenied`) | auth enforced |

Controller class names in the trace reveal internal architecture; error bodies may leak internal URLs
(`service.internal/Controller/Method`) — note them for recon, do not pivot destructively.

## Envoy / gRPC-Web proxy — routing gaps bypass RBAC
A gRPC-Web front proxy can gate one path shape but not another, and leaks method names in errors:

| Probe | Signal | Verdict |
|---|---|---|
| `GET /v1/accounts/` with a bad token | `{"code":7,...,"method = /svc.v1.Service/AccountList"}` | RBAC enforced on `/v1/` + method name leaked (enumerate siblings) |
| same resource on a **non-`/v1/`** path (`/accounts/`) | `200` / backend data | **RBAC bypass** — the proxy only guards `/v1/` |
| `PUT` / `PATCH` / `DELETE` to the gRPC path | `"Could not resolve"` | proxy routes only `GET`+`POST` to gRPC (the verb never reaches RBAC) |

Enumerate methods from the leaked `method = /…` strings, then retest each on the un-gated path shape.

## Tabulate (the deliverable)
Record one row per operation; a backend-error column is a BFLA/BOLA candidate to confirm with two identities.

| Operation | No auth | Fake auth | Verdict |
|---|---|---|---|
| `login` | works | works | public (intentional) |
| `logout` | backend error | same error | **MISSING AUTH** |
| `updateUser` | `NullRef` | same | **MISSING AUTH** |
| `GET /resource/{id}/` (DRF) | `404 Not found` | same | **AllowAny bypass** |
| `addPermission` | `403` | `403` | protected |

## Hand-back
An oracle hit is a *lead*, not a finding: it says auth is absent, not that you accessed another tenant's
object. Confirm the real BOLA/BFLA with **two TEST identities** (identity A reaches B's object / low-priv A
runs the privileged op) per the BOLA/BFLA steps in `SKILL.md`, rate it, and de-dupe against `idor`/`privesc`
at reporting. BFLA privileged actions stay benign/reversible and approval-gated.
