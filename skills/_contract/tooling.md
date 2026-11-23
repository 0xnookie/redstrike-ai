# Tooling — the tool-first rule + the standard roster (imported by every skill)

Redstrike runs on **Linux** (Kali / Debian / Parrot). Every tool below is `apt`- or `pipx`-installable
there. Author steps for bash; assume a host that already ships these.

## The rule: real tools, not hand-rolled scripts
**Use the established, battle-tested tool for a job. Do NOT re-implement one in a script.** A skill that
needs a port scan calls `nmap`/`naabu`/`rustscan`; content brute-force calls `ffuf`/`feroxbuster`/
`gobuster`; SQLi confirmation drives `sqlmap`; cracking is `hashcat`/`john`. Rolling your own socket
scanner, request-fuzzer, or hash-cracker is slower, noisier, less correct, and unreviewable — it is a bug,
not initiative.

Scripting is **glue only**: orchestrate tools, parse their output (`jq`, `ripgrep`, `awk`), de-dupe, pipe
one into the next, shape artifacts. The moment a script starts *re-implementing a tool's core job*, stop
and call the tool.

**Legitimate exceptions** (a tool genuinely can't express the logic): bespoke `business-logic` abuse, the
`race-condition` single-packet attack, `exploit-dev` / `fuzzing` harnesses and PoCs, a one-off `curl` to
confirm a signature. Even then prefer a library/tool primitive (`turbo-intruder`, `pwntools`) over raw code.

## Standard roster (modern-first; each SKILL.md §Tools names the per-step primary)

### Network & reconnaissance
`nmap` · `masscan` · `rustscan` · `naabu` · `amass` · `subfinder` · `dnsx` · `nuclei` · `fierce` ·
`dnsenum` · `autorecon` · `theharvester` · `responder` · `netexec` (nxc) · `enum4linux-ng`

### Web application
`httpx` · `katana` · `gobuster` · `feroxbuster` · `dirsearch` · `ffuf` · `dirb` · `nikto` · `sqlmap` ·
`wpscan` · `arjun` · `paramspider` · `dalfox` · `wafw00f` · `hakrawler` · `gau` · `waymore`

### Password & authentication
`hydra` · `john` · `hashcat` · `medusa` · `patator` · `netexec`/`crackmapexec` · `evil-winrm` ·
`hash-identifier` · `ophcrack`

### Binary analysis & reverse engineering
`gdb` (+ `pwndbg`/`gef`) · `radare2` · `binwalk` · `ghidra` · `checksec` · `strings` · `objdump` ·
`volatility3` · `foremost` · `steghide` · `exiftool`

### Glue (allowed — parsing/orchestration, not re-implementation)
`jq` · `ripgrep` (rg) · `yq` · `curl` · `awk`/`sed` · `python` (orchestration + the bespoke-logic exceptions)

## Install

The complete roster (168 tools / 19 categories — the lists above plus every domain tool the skills call)
lives in **`scripts/tools.manifest`** and is installed by script. Full guide: **`INSTALL.md`**.

```bash
scripts/doctor.sh          # read-only: what's present / missing / manual
scripts/install.sh         # core set (glue + recon + web + password + intercept)
scripts/install.sh --all   # everything (AD, cloud, container, mobile, iot, wireless, binary, fuzzing, llm…)
scripts/install.sh ad cloud --dry-run   # scope by category; preview without changing anything
```

Manual fallback (Kali ships most; Debian/Parrot as needed):
```bash
sudo apt update && sudo apt install -y nmap masscan amass nikto sqlmap hydra john hashcat gobuster \
  dirb ffuf feroxbuster whatweb wafw00f binwalk radare2 gdb exiftool steghide foremost
pdtm -ia                                    # httpx katana naabu dnsx subfinder nuclei interactsh-client
pipx install arjun paramspider git-dumper   # + the rest — see scripts/tools.manifest
```

The anti-automation ladder (`anti-automation-ladder.md`) stays orthogonal: it decides **how** to fetch when
blocked; this file decides **which** tool does the job. The proxy spine (`proxy.md`) is orthogonal too: when an
interception proxy (the `intercept` category — Caido / Burp / `mitmproxy` / ZAP) is connected it becomes the
HTTP **transport** for the whole toolchain, and `proxy-context` exports its History into the engagement.

## Preflight — detect, don't assume
The roster above *assumes a Linux host that ships these*. Do not confuse that assumption with the shell a
command happens to run in. **A tool missing from one shell's `PATH` is not absent** — the toolkit may live in
a WSL distro, a container, a `pipx`/`go/bin` dir, or a different user. Before concluding a capability is
unavailable, probe the **real execution environment** (e.g. `wsl.exe -e bash -lc 'command -v ffuf nmap sqlmap'`,
`docker run … which …`, `pipx list`), and run tools from wherever they actually are. **Never report a tool
"missing" — or a surface "untestable / exhausted" — off a single shell's `PATH`.** (Field lesson: "no ffuf"
was read from the wrong shell while the whole toolkit sat in WSL, and nearly closed a host that had an
unenumerated app on it.)

At engagement start the launcher **runs the toolchain producer** — it probes the **real execution
environment** (on Windows via `wsl.exe -e bash -lc 'command -v …'` — the `-e` is required, or wsl.exe
mangles the script and every capability falsely reads as degraded) for each recon/web **capability** (a JOB:
subdomain-enum / dns-resolve / http-probe / port-scan / content-discovery), records the per-capability
result (`primary` present? which `fallback`? `ok`|`degraded`) to **`runtime/tooling.json`**, and surfaces a
`degraded` capability in the run's outcome diagnostics (`degraded-empty`) instead of letting a missing primary
fall back silently. Reproduce it anytime with `redstrike doctor --json` (or `scripts/doctor.sh --json`). So:
**when a capability's primary is missing and you fall back** (e.g. `httpx`→`nmap`, `dnsx`→`dig`,
`subfinder`→`amass`, `naabu`→`nmap`), **write a one-line degradation note into the feeder's `summary.md`** —
"http-probe DEGRADED: httpx unavailable, used curl" — so empty/thin results are never read as a clean target.

Still **detect and record the rest of what the engagement actually has**, because it decides what is testable:
- **toolkit location** — which shell/distro/container runs the roster; route tool calls there (`runtime/tooling.json` records which shell was probed).
- **interception proxy** — is one connected? If so it is the transport + a discovery source (`proxy.md`).
- **browser automation** — `chrome-devtools-mcp` / `claude-in-chrome` / `playwright`. **Required** for
  client-rendered surface: SPA/DOM-XSS confirmation, WebSocket/chatbot flows, anything behind JS. For browser-gated tests,
  **invoke `browser-exploit` (`_contract/browser-session.md`) to drive it autonomously; when no browser driver
  is available, say so and flag for the human** — do not hand-roll a CLI substitute,
  and never spoof a browser fingerprint to slip a scripted client past a WAF (that is evasion, barred by
  `roe-gate.md` and any WAF-safe rule; a WebSocket upgrade that resets with no HTTP status is that signal —
  stop and flag, don't bypass).
