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
blocked; this file decides **which** tool does the job.
