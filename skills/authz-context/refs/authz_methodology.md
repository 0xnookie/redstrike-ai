# Access-control mapping methodology (shared by idor / privesc)
# Access control is tested by COMPARING identities. You need ≥2 accounts. The feeder maps; the
# variants violate the map. Record everything so the reviewer can see the intended vs actual access.

## Identities (auth.env)
- `A` — low-priv attacker account
- `B` — victim account (different owner, same role) → horizontal / IDOR
- `admin` — higher-priv account (if authorized) → vertical / function-level
Capture each identity's session (cookie/token) separately.

## Object references (→ idor)
Find every request where an `id` selects a resource: `/api/users/123`, `?order_id=`, `{ "account": 55 }`,
UUIDs, hashids, filenames, base64 ids. Note `id_type` (sequential ids are trivially enumerable; uuids
need a leak) and whether the server SHOULD enforce ownership (`owner_scoped`).

## Role → endpoint matrix (→ privesc)
Crawl each sensitive endpoint as EACH identity; record who the app LETS reach it (status 200 vs 403).
The matrix reveals function-level gaps (a low-priv account reaching an admin function) and the intended
role for each endpoint.

## Mass-assignment candidates
For object-create/update endpoints, list fields the client sends vs fields the server manages
(`role`, `is_admin`, `verified`, `balance`, `owner_id`). A server-managed field the client can set =
mass-assignment candidate (→ idor/privesc depending on effect).

## The test (variants)
IDOR: as `A`, request `B`'s object id → do you get B's data? (owner check missing)
Vertical: as `A`, call an admin-only function → does it work? (function-level check missing)
Always compare to the intended access in `authz_context.json`. Use TEST accounts; don't read real users.
