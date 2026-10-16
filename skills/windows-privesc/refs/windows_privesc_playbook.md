# Windows privilege-escalation playbook
# In-scope host, approval-gated, benign proof (whoami=SYSTEM), always clean up. Lowest-risk vector first.

## Enumerate
```
whoami /all                                   # groups + PRIVILEGES (SeImpersonate/SeBackup/SeDebug)
.\winPEASx64.exe                              # or PowerUp: Invoke-AllChecks ; SharpUp ; Seatbelt -group=all
systeminfo                                    # patch level -> windows-exploit-suggester
accesschk.exe -uwcqv "Users" *                # writable services / dirs
```

## Vectors → exploitation (benign SYSTEM proof)
| Vector | Check | Exploit (benign) |
|---|---|---|
| **SeImpersonate/SeAssignPrimaryToken** | `whoami /priv` | `PrintSpoofer`/`GodPotato`/`JuicyPotato` → run a benign command as SYSTEM |
| **Unquoted service path** | space in path + writable dir | drop a benign exe in the gap, restart service, confirm, REMOVE |
| **Weak service permissions** | `accesschk -uwcqv user *` (SERVICE_CHANGE_CONFIG) | `sc config bin= <benign>` → restart → confirm → RESTORE |
| **Writable service binary** | writable .exe in service dir | replace with a benign marker (BACK UP original), confirm, RESTORE |
| **AlwaysInstallElevated** | HKLM+HKCU reg = 1 | `msiexec` a benign MSI that runs as SYSTEM, confirm, uninstall |
| **DLL hijack** | missing DLL in a writable PATH dir | drop a benign proxy DLL, trigger, confirm, REMOVE |
| **Autoruns / scheduled task** | writable autorun/task | point at a benign marker (BACK UP), confirm, RESTORE |
| **Saved creds** | `cmdkey /list`, registry, unattend.xml, web.config | `runas /savecred` or reuse the cred |
| **Token / SeBackup / SeDebug** | `whoami /priv` | SeBackup → read SAM; SeDebug → open lsass (feasibility; avoid dumping) |
| **Kernel/patch** | `systeminfo` + suggester | HIGH RISK (crash) — report feasibility, run ONLY with approval in a safe window |

## Proof + cleanup
Prove with `whoami` = `nt authority\system` (or new admin) + a benign command. Record EVERYTHING created
or changed (services, binaries, registry, tasks, MSIs, DLLs) in `cleanup.md` and RESTORE originals / remove.
No persistence, no destruction, no bulk credential dumping. Back up any file you replace.
