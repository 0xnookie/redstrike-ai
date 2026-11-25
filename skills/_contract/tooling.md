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
and call the tool. And glue is **reused, not duplicated** — see *Reuse before you write* below.

**Legitimate exceptions** (a tool genuinely can't express the logic): bespoke `business-logic` abuse, the
`race-condition` single-packet attack, `exploit-dev` / `fuzzing` harnesses and PoCs, a one-off `curl` to
confirm a signature. Even then prefer a library/tool primitive (`turbo-intruder`, `pwntools`) over raw code.

### Reuse before you write — one job, one tool, never twice
If a tool already exists for the job, **use it**. If a *bespoke* primitive is genuinely needed (one of the
legitimate exceptions above — business-logic abuse, an authed multi-step probe, the race single-packet
attack), write it **ONCE** as a reusable, parameterized helper in **`scripts/`** — do **not** re-write the
same login/proxy/request boilerplate per probe. **Before writing a probe script, check `scripts/` for an
existing helper** (`rg -l 'def ' scripts/` / read the `scripts/*.py` headers); a second hand-rolled copy of
logic that already lives there is the bug, not the first one.

For bespoke **authed / proxied HTTP probes** this helper already exists: **`scripts/rs_http.py`**. Point your
probe at it (`from rs_http import request`, or `python scripts/rs_http.py --engagement <dir> GET <url> …`)
instead of re-rolling `urllib`. It is engagement-aware, so a bespoke probe inherits the guardrails for free:
it **refuses out-of-scope URLs** (hard stop), **throttles to the scope's `rate_limit_rps`** (a real
client-side sleep, not prose), **routes through `RS_PROXY`/`HTTP(S)_PROXY`** (so every request lands in the
operator's Burp/Caido history), **persists a cookie jar** (`--cookies`, the login-once case), and **appends a
redacted JSONL log** to `runtime/http_log.jsonl` (Authorization / Cookie / token values redacted).

> Field lesson (city-of-vienna): a session re-rolled the same `urllib`+proxy+login boilerplate in ~6 separate
> ad-hoc scripts — each one re-implementing an HTTP client (the anti-pattern this file bars) — and every one
> of them **ignored the scope rate cap** (`rate_limit_rps: 5`), while `nuclei` was separately launched at
> `-rl 18/30/35` against government production. One reused, scope-aware primitive (`scripts/rs_http.py`) is
> exactly what stops both the duplication and the cap-busting.

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

## Execution environment — on non-Linux, the container IS the toolchain
The roster above assumes a **Linux** host. On **Windows or macOS** the host shell ships almost none of it, so
the operator runs a redstrike **docker container** (image `redstrike-ai:latest`) that carries the roster, and
**every tool call MUST go through that container** — `docker exec <container> bash -lc '…'`, never the bare
host shell. Run `ffuf`/`nuclei`/`curl`/a python probe on the Windows host and you find "no tools"; the same
call inside the container runs the roster and egresses through the operator's proxy.

Order of preference for *where a tool runs* (first that applies wins):
1. a **native Linux / Kali** host (or you are already inside one) → run the tool directly;
2. else the **redstrike docker container** (`redstrike-ai:latest`) → `docker exec <container> bash -lc '…'`;
3. else a **WSL distro** (`wsl.exe -e bash -lc '…'` — the Preflight note below already covers its detection).

At preflight, **detect the container** (`docker ps`, find the running `redstrike-ai` container) alongside the
other environment probes, **record which container/shell runs the roster in `runtime/tooling.json`**, and then
**route every tool invocation there**. This is the MANDATE the "Preflight — detect, don't assume" section below
only *detects*: on non-Linux, "the container is present" means "the container is now the target for all
tooling", not an option to weigh. (Field lesson: the city-of-vienna engagement ran on Windows — every
`ffuf`/`nuclei`/`curl`/python probe executed inside the container and egressed through the operator's proxy;
running them on the Windows host would have reported a toolless, falsely-"clean" target.)

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
