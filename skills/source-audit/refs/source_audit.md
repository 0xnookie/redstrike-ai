# Source audit — dangerous-sink grep arsenal + routing

White-box static review. Each hit is a **candidate** routed to the executor that proves it against the running
target. Read-only — never execute the source. Redact secret values; hand deps to `cve-intelligence`.

## Cross-language first pass
```bash
semgrep --config auto --json -o logs/semgrep.json .     # security + language rulesets
rg -n --no-heading -S "(api[_-]?key|secret|token|password|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY)" .   # secret candidates → secrets
# dependency manifests → cve-intelligence
rg --files -g '{package.json,package-lock.json,yarn.lock,requirements*.txt,Pipfile.lock,composer.lock,go.mod,Gemfile.lock,pom.xml,Cargo.toml}'
```

## JavaScript / TypeScript
```bash
rg -n "eval\(|new Function\(|setTimeout\(\s*['\"]|document\.write|\.innerHTML\s*=|insertAdjacentHTML|dangerouslySetInnerHTML" .   # → xss-dom / xss-reflected
rg -n "child_process|\.exec\(|execSync|spawn\(" .                      # → command-injection
rg -n "__proto__|constructor\s*\[|Object\.assign\(|_\.merge\(|\bmerge\(|setValue\(" .   # → prototype-pollution
rg -n "addEventListener\(\s*['\"]message|\.postMessage\(" .           # → xss-dom (postMessage)
rg -n "require\(\s*[^'\"]|import\(\s*[^'\"]" .                        # dynamic require → command/path
```
CWE-79 / CWE-94 / CWE-1321 (proto-pollution).

## Python
```bash
rg -n "pickle\.loads?|cPickle|yaml\.load\((?!.*SafeLoader)|jsonpickle" .   # → deserialization
rg -n "\beval\(|\bexec\(|__import__\(" .                               # → command-injection / ssti
rg -n "subprocess\.(call|run|Popen|check_output)\(.*shell\s*=\s*True|os\.(system|popen)\(" .   # → command-injection
rg -n "render_template_string|Template\(|Environment\(" .             # → ssti (Jinja)
rg -n "\.execute\(\s*[f\"'].*%|\+\s*request\.|cursor\.execute\(.*%" . # → sqli-*
rg -n "open\(\s*.*request\.|send_file\(|os\.path\.join\(.*request" . # → path-traversal-lfi
```
CWE-502 / CWE-94 / CWE-78 / CWE-89.

## PHP
```bash
rg -n "unserialize\(|__wakeup|__destruct|phar://" .                  # → deserialization
rg -n "\binclude(_once)?\s*\(|\brequire(_once)?\s*\(|fopen\(|file_get_contents\(" .   # → path-traversal-lfi / rfi
rg -n "\beval\(|assert\(|system\(|exec\(|passthru\(|shell_exec\(|popen\(|`" .   # → command-injection
rg -n "==[^=]|!=[^=]" .                                               # type juggling (triage) → auth-bypass/logic
rg -n "extract\(|\\\$\\\$|\bmysql_query\(|->query\(\s*[\"'].*\\\$" .  # mass-var / sqli → sqli-*
```
CWE-502 / CWE-98 / CWE-78 / CWE-697 (type juggling).

## Go
```bash
rg -n "template\.HTML\(|text/template" .                             # → xss (unescaped)
rg -n "exec\.Command\(|os/exec" .                                    # → command-injection
rg -n "fmt\.Sprintf\(.*(SELECT|INSERT|UPDATE|DELETE)|db\.(Query|Exec)\(\s*[\"'].*\+" .   # → sqli-*
rg -n "http\.Get\(|http\.NewRequest\(.*\+" .                         # → ssrf-*
```
CWE-79 / CWE-78 / CWE-89.

## Ruby
```bash
rg -n "YAML\.load\((?!.*safe)|Marshal\.load|Oj\.load" .              # → deserialization
rg -n "\.send\(|\.public_send\(|eval\(|system\(|%x\(|`|Open3" .      # → command-injection / logic
rg -n "render\s+inline:|ERB\.new\(" .                                # → ssti
rg -n "permit!|params\.require.*permit\s*\(\s*\)" .                  # mass assignment → idor/privesc
```
CWE-502 / CWE-78 / CWE-915 (mass assignment).

## Rust
```bash
rg -n "\.unwrap\(\)|\.expect\(|panic!\(" .                           # DoS on attacker input (triage)
rg -n "unsafe\s*\{|transmute|from_raw" .                             # memory-safety → exploit-dev/fuzzing
rg -n "Command::new\(|process::Command" .                            # → command-injection
```
CWE-248 / CWE-787.

## Java
```bash
rg -n "ObjectInputStream|readObject\(|XMLDecoder|readUnshared\(" .   # → deserialization
rg -n "Runtime\.getRuntime\(\)\.exec|ProcessBuilder\(" .            # → command-injection
rg -n "createQuery\(\s*[\"'].*\+|Statement.*executeQuery\(\s*[\"'].*\+" .   # → sqli-*
rg -n "DocumentBuilderFactory|SAXParserFactory|XMLReader" .         # → xxe-* (check FEATURE flags)
```
CWE-502 / CWE-78 / CWE-89 / CWE-611.

## C / C++
```bash
rg -n "\b(strcpy|strcat|sprintf|gets|scanf|memcpy|alloca)\(" .       # memory-safety → fuzzing / exploit-dev
rg -n "\bsystem\(|popen\(|execl?p?\(" .                              # → command-injection
rg -n "format.*%n|printf\(\s*[a-z]" .                                # format string → exploit-dev
```
CWE-120 / CWE-134 / CWE-78.

## Routing table (candidate → executor)
| Sink pattern class | Route to |
|---|---|
| HTML/DOM write, template unescaped | `xss-dom` / `xss-reflected` / `xss-stored` |
| native deserializer (pickle/unserialize/ObjectInputStream/Marshal/YAML) | `deserialization` |
| shell/exec/command builder | `command-injection` |
| template engine eval | `ssti` |
| string-built SQL | `sqli-inband` / `sqli-blind` |
| include/open on user path | `path-traversal-lfi` |
| proto-pollution merge/assign | `prototype-pollution` |
| XML parser w/o hardening | `xxe-inband` / `xxe-blind` |
| server-side fetch on user URL | `ssrf-inband` / `ssrf-blind` |
| mass assignment / permit! | `idor` / `privesc` |
| memory-unsafe / format string | `fuzzing` / `exploit-dev` |
| hardcoded secret | `secrets` (value redacted) |
| pinned dependency version | `cve-intelligence` / `supply-chain` |

Emit each candidate into `source_findings.jsonl` (`file`, `line`, `language`, `pattern`, `category`, `route`,
redacted `snippet`) and consolidate the routed map + `routing[]` into `source_context.json`. The executor then
PROVES it against the running target — a grep hit alone is never a finding.
