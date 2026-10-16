# IoT / embedded attack reference (firmware + hardware)
# Approval-gated. AUTHORIZED device/image only. Benign proof. No bricking / no flashing modified firmware.
# REDACT all recovered credentials/keys/certs in artifacts. In-scope device models/images only.

## Firmware acquisition
- Vendor download / support portal / OTA capture (sniff the update fetch).
- Flash dump from the device (see hardware section) when no image is published.
- Identify the container: `file firmware.bin` ; `binwalk firmware.bin` (signatures, offsets, entropy).

## Extraction
```
binwalk -e firmware.bin                            # carve + extract known filesystems/blobs
unblob firmware.bin -o out/                        # recursive, format-aware extraction
# firmware-mod-kit for older/rebuildable images (extract-firmware.sh)
```
If extraction yields a filesystem (squashfs/jffs2/ubifs/cramfs/ext), mount/inspect it read-only. If a blob
is high-entropy and won't carve, it is likely encrypted/compressed → note it and pivot to a flash dump.

## Filesystem + entropy analysis
```
binwalk -E firmware.bin                            # entropy map: flat high entropy -> encrypted/packed
```
Walk the rootfs: `/etc` (passwd/shadow, configs), `/etc/init.d` + rc scripts (what starts at boot),
`/www` / `/web` (web UI, CGI), `/usr/sbin` + `/bin` (service binaries), startup + OTA scripts.

## Hardcoded / default + stored credentials  (the most common finding)
```
firmwalker rootfs/                                 # triage: creds, keys, URLs, interesting files
# Then targeted:
grep -R -nE "password|passwd|secret|api[_-]?key|BEGIN .*PRIVATE KEY|token" rootfs/
# Cracked logins:
# /etc/shadow or /etc/passwd hashes -> offline crack (hashcat/john). Default creds in configs/web UI.
```
Benign proof: recover ONE default/hardcoded credential or key; redact it. Note if it is shared across the
model/fleet (remote impact) vs per-device.

## Insecure update mechanism
- Is the update image **signed** and is the signature **verified** on-device? Unsigned/unverified → forge.
- Transport: fetched over plaintext http → MITM-swappable. No anti-rollback → downgrade to a vulnerable build.
- Recover the OTA signing/verification key from the filesystem/binary → assess whether updates are forgeable.
Benign proof: show the verification step is absent/weak (do NOT flash a forged image onto a device).

## Hardware interfaces
```
# UART console (TX/RX/GND on a header): find baud, get a shell/bootloader prompt.
baudrate                                           # auto-detect the serial baud rate
# attach a USB-TTL adapter; a root/bootloader console or password prompt is the finding.
# JTAG/SWD: debug access to halt the CPU / read memory (ARM SWD, boundary scan).
# SPI flash dump (read the chip directly):
flashrom -p ch341a_spi -r dump.bin                 # CH341A programmer; also linux_spi / FT2232
```
Benign proof: reach a console banner/prompt or dump the flash to recover the image. Read-only; don't write.

## Embedded-binary analysis
Load service/auth/update binaries into Ghidra (or a disassembler): find hardcoded secrets, command-exec
sinks (`system()`/`popen()` on attacker input → command injection), weak crypto, backdoor/debug accounts,
and auth logic flaws. Correlate with exposed services below.

## Exposed network services
Map listening services + their configs: telnet/SSH with default creds, an unauthenticated web/CGI admin,
UPnP, a debug port, MQTT/CoAP without auth, a legacy busybox service. Cross-reference recovered default
creds and the binary analysis for a remote pre-auth path.

## Reporting
Each finding: device/image, the weakness, the vector, the benign proof (redacted secret / console banner /
missing signature check), attacker preconditions (physical access, fleet-wide secret, network reach), and
remediation (unique per-device creds, signed+verified updates with anti-rollback, disable debug interfaces
in production, authenticate services).

---

## Extended arsenal — encrypted-firmware triage + vendor-key recovery feasibility
```
binwalk -E firmware.bin                            # entropy: flat ~0.95+ across the whole image -> encrypted
binwalk -Y firmware.bin                            # opcode/arch heuristics: is there ANY plaintext code?
ent firmware.bin ; xxd firmware.bin | head         # byte histogram + header magic sanity
```
Triage ladder (stop at first win):

| Observation | Likely state | Next step |
|---|---|---|
| Carves to a filesystem | not encrypted | extract + analyse (base ref) |
| Flat high entropy, no magic | block-cipher encrypted | hunt the key, don't brute the blob |
| High entropy + known magic (gzip/lzma/uImage) | compressed only | decompress, re-run file/binwalk |
| Plaintext header, high-entropy body | enveloped payload | key/IV may sit in header or bootloader |

Where the vendor key lives (assess feasibility; do NOT exfiltrate/publish fleet secrets):
- An earlier / un-encrypted firmware revision of the same model (decrypt routine + key often shipped in the clear once).
- The bootloader / SoC-ROM stage that decrypts the next stage (dump via flash/JTAG; recover AES key + IV/mode).
- A companion mobile/desktop app or update client (key embedded for client-side decrypt).

Benign proof: show the OTA payload is encrypted with a key recoverable from an in-scope artifact (fingerprint only); no fleet-wide decrypt.

---

## Extended arsenal — U-Boot / bootloader environment inspection
Read-only first. Interrupting autoboot and *printing* env is safe; `setenv`/`saveenv`/flash writes can brick -> catalogued-not-fired.
```
# On the UART console, interrupt autoboot (press a key at the countdown), then at the prompt:
printenv                                           # dump bootargs, bootcmd, serverip, ethaddr, secure flags
help ; version                                     # applet list + U-Boot build (match to known weaknesses)
md 0x<addr> <n>                                    # read memory (inspect loaded image / keys) -- READ only
# Derive the same facts offline from the dumped flash (no brick risk):
strings -n 8 mtd_uboot_env.bin | grep -E "bootcmd|bootargs|baudrate|verify|secure"
fw_printenv                                        # if the env userspace tool + config exist on the rootfs
```
Interesting findings: `bootdelay` (autoboot interrupt window open), `bootargs` reachable `init=/bin/sh`, `verify=`/secure-boot toggled off, a `serverip`/TFTP recovery path, console left enabled in production.
Caution: `setenv`, `saveenv`, `mw`, `erase`, `sf write`, `nand write` MODIFY NVRAM/flash -> APPROVAL-GATED, catalogued-not-fired on a production unit. Prefer deriving facts from the dumped flash offline.
Benign proof: `printenv` shows secure-boot disabled or a single-user-shell bootarg reachable (log the banner); no writes.

---

## Extended arsenal — NVRAM / config-store secret extraction
```
# Router/embedded NVRAM blob carved from flash:
strings -n 6 nvram.bin | grep -iE "passwd|psk|wpa|key|secret|admin|http_passwd|ppp|token"
nvram show 2>/dev/null                             # live device userspace (read-only) if the tool is present
# Config stores on disk:
find rootfs/ -regextype posix-extended -regex '.*\.(conf|cfg|ini|xml|json|db|dat)$'
sqlite3 config.db '.tables' ; sqlite3 config.db 'select * from <t>;'   # inspect embedded config DBs (read)
grep -RniE "wifi_key|wpa_psk|admin_pass|cloud_token|device_secret" rootfs/
```
Look for: Wi-Fi PSK stored plaintext/base64, cloud/pairing tokens, TR-069/ACS creds, VPN/PPP secrets, per-device provisioning keys. Note default-vs-provisioned and fleet-shared-vs-unique.
Benign proof: recover ONE config secret (redacted fingerprint); flag reversible/trivial obfuscation (base64, static-XOR, hardcoded-key) as "stored plaintext-equivalent".

---

## Extended arsenal — filesystem triage checklist (deep)

| Location | Grep / action | What it proves |
|---|---|---|
| `/etc/init.d`, `/etc/rc*.d`, `/etc/inittab` | boot-start list, `respawn` shells | auto-started services + debug consoles |
| `/www` `/web` `/cgi-bin` `/htdocs` | `grep -RniE "system\(|popen\(|exec"` | CGI command-exec sinks (pre-auth?) |
| `/etc` `/etc/ssl` `/etc/certs`, `*.pem *.key *.crt *.p12` | `find -name '*.key' -o -name '*.pem'` | shipped private keys / device certs |
| `/usr/bin` `/bin` (busybox) | applet symlinks / `busybox` list | enabled applets (telnetd, tftp, nc, ftpd) |
| `/etc/passwd`, `/etc/shadow` | inline hash fields, extra uid-0 | backdoor / second-root accounts |
| `*.sh`, OTA/update scripts | `grep -RniE "wget|curl|tftp|http://"` | plaintext update fetch / hardcoded hosts |
| `/etc/hosts`, dropbear/ssh keys | hardcoded IPs, `authorized_keys` | baked-in cloud/C2 endpoints, planted keys |
| `/lib` `/usr/lib` | `strings` on vendored SO libs | lib version -> CVE match |

```
find rootfs/ \( -name '*.key' -o -name '*.pem' -o -name '*.crt' -o -name '*.p12' \) -print
grep -RniE "BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY" rootfs/     # shipped private key material
awk -F: '($2!="x" && $2!="*" && $2!="!"){print $1}' rootfs/etc/passwd   # accounts with inline hashes
rootfs/bin/busybox 2>/dev/null | sed -n '/Currently defined functions/,$p'  # compiled-in applets
```
Benign proof: identify ONE shipped private key / extra uid-0 account / pre-auth CGI exec sink (redact key to fingerprint).

---

## Extended arsenal — flash dump tooling matrix (SPI / NAND / eMMC) + chip-ID
Identify the chip first (package + part number -> datasheet pinout/voltage), then pick the method. Read-only dumps; verify with a second read.

| Memory | Typical package | Read tool / rig | Notes |
|---|---|---|---|
| SPI NOR | SOIC-8 / WSON-8 | `flashrom -p ch341a_spi` ; `-p ft2232_spi` ; `-p linux_spi:dev=/dev/spidev0.0` | SOIC8 test-clip in-circuit or desolder; power-isolate the SoC |
| SPI NOR (verify) | - | `flashrom -p buspirate_spi:dev=/dev/ttyUSB0` | slow; good for cross-check read |
| Parallel/SPI NAND | TSOP-48 | dedicated NAND programmer; dump raw incl. OOB/spare | bad-block + ECC: dump with OOB, de-ECC offline |
| eMMC | BGA-153/169 | in-system via test pads (CMD/CLK/DAT0/VCC/VCCQ/GND) as an SD device, or BGA reball | `dd if=/dev/mmcblkX of=emmc.img bs=4M` read-only |
| UFS | BGA | vendor/JTAG tooling | rarely needed; rate feasibility |

```
flashrom -p ch341a_spi                             # probe only (no -r): print detected chip ID + size
flashrom -p ch341a_spi -r d1.bin && flashrom -p ch341a_spi -r d2.bin && cmp d1.bin d2.bin  # two reads must match
# NAND: dump raw with OOB then strip ECC/spare offline. eMMC: image partitions read-only as a block device.
```
Chip-ID: read the part number off the package; match VCC (1.8V vs 3.3V -- wrong voltage damages the chip). Benign proof: a verified read-only image (two reads identical); no writes/erases.

---

## Extended arsenal — UART/JTAG workflow + glitch/fault-injection (AWARENESS)
```
# UART: locate pads (TX idles high ~3.3V, RX, GND; VCC NOT needed) -- confirm with a logic analyzer/scope.
screen /dev/ttyUSB0 115200                         # or: picocom -b 115200 /dev/ttyUSB0
# common bauds 115200/57600/38400/9600; garbage = wrong baud/level or TX<->RX swapped.
# JTAG/SWD: discover pinout (scan unknown pads for TCK/TMS/TDI/TDO), then halt + inspect READ-only:
openocd -f interface/<adapter>.cfg -f target/<soc>.cfg   # then: halt ; mdw <addr> <n>  (no flash write)
```
Console outcomes (the finding): a root shell with no password, a `login:` with recoverable default creds, or a U-Boot prompt (see bootloader section).
Fault-injection / glitching -- AWARENESS + feasibility only, catalogued-not-fired:
- Voltage/clock glitching to skip a secure-boot signature check or a password compare, or to bypass a JTAG lock -> enables reading an otherwise-protected image (crowbar-VCC or EM-pulse rigs exist).
- High skill + physical access + risk of permanent damage -> rate feasibility against the target's protections (locked JTAG? secure boot? flash readout protection/RDP?); do NOT perform on a production/only unit.
Benign proof: a console banner/shell, or an openocd `halt`+register read; glitching stays catalogued-not-fired.

---

## Extended arsenal — firmware emulation for dynamic testing (rehosting)
Run the extracted firmware off-device to exercise services dynamically without risking the unit.
```
# Single-binary (user-mode) emulation (arch per `file ./bin/httpd`):
qemu-mipsel-static ./bin/httpd                     # run one binary under qemu-user
cp $(which qemu-mipsel-static) rootfs/ ; sudo chroot rootfs ./usr/sbin/<svc>   # chroot for its lib deps
# Full-system emulation (kernel + rootfs) for router/Linux targets:
#   system-mode qemu boots the squashfs rootfs; a libnvram preload shim fakes NVRAM reads;
#   a tap interface brings the web UI / CGI up at a local IP for live testing.
```
Common hurdles: missing NVRAM entries (libnvram shim with faked values), watchdog reboots (stub it), hardware/GPIO ioctls (nop them), wrong endianness/arch (match `file` output). Benign proof: reach the emulated web UI / telnet banner and drive an auth or CGI sink dynamically (OOB/benign marker) -- no physical device touched.

---

## Extended arsenal — update-forgery ASSESSMENT checklist (no flashing)
Assess forgeability on the bench; NEVER flash a modified image onto a device (catalogued-not-fired).

| Check | How | Weak if |
|---|---|---|
| Image signed? | find a sig block/cert/`.sig`; strings for `verify` `RSA` `sha256` | no signature at all |
| Signature verified on-device? | find the verify call in the updater (Ghidra) | verify absent / return value ignored |
| Which key verifies? | locate pubkey/cert in rootfs | key present but privkey also shipped |
| Integrity vs authenticity | CRC/MD5 only, or a real signature? | checksum-only (forgeable) |
| Transport | updater uses `http://` vs TLS+pinning | plaintext -> MITM swap |
| Anti-rollback | version/monotonic counter enforced? | downgrade to a vulnerable build allowed |
| Encryption != authentication | encrypted-but-unsigned | decrypt+modify+re-encrypt if key known |

```
grep -RniE "sign|verify|rsa|sha256|pubkey|\.pem" rootfs/ update/   # updater logic + key material
# In Ghidra: trace updater -> does it call verify() AND branch on the result BEFORE writing flash?
```
Benign proof: demonstrate the verify step is absent/ignored or integrity-only (code path / missing call) -- do NOT build or flash a forged image.

---

## Extended arsenal — binary-analysis sink checklist
In Ghidra/disassembler, triage service/auth/update binaries for these sinks and correlate each to a reachable (ideally pre-auth) input.

| Sink class | Patterns to find | Impact |
|---|---|---|
| Command exec | `system` `popen` `exec*` `do_system`, shell `%s` format | command injection |
| Hardcoded secret | embedded key/cert/PSK, basic-auth string, API token | fleet secret / auth bypass |
| Backdoor/debug | magic-value compare `strcmp(x,"<magic>")`, debug CGI, undocumented acct | hidden access |
| Weak PRNG / keygen | `rand()`/`srand(time())` seeding a session/token/key, static seed | predictable creds/sessions |
| Memory-unsafe | `strcpy`/`sprintf`/`memcpy` on network input, no bounds | overflow -> exploit-dev |
| Auth logic | password compare, token check, "is admin" branch | bypassable check |
| Info in logs | secrets written to syslog/console | secondary disclosure |

```
strings -n 6 svc | grep -iE "system|popen|/bin/sh|password|token|BEGIN .*KEY|rand"   # pre-Ghidra triage
grep -aoE "/bin/(sh|busybox) -c" svc
# Then in Ghidra: xref each sink back to a request/param parser; mark sinks with no auth gate.
```
Benign proof: one sink with a traced path from external input (e.g. a CGI param reaching `system()`), or one hardcoded credential / magic-value backdoor (redacted).

---

## Extended arsenal — read-only protocol-service checks
Benign, read-only enumeration of exposed IoT services on an in-scope device. No writes to actuators/config/safety state.
```
# MQTT -- open/unauthenticated broker? (subscribe is read-only; do NOT publish to control topics)
mosquitto_sub -h <dev> -t '#' -v -C 5              # anon subscribe, 5 msgs then stop; '#' = all topics
nmap -p1883,8883 --script mqtt-subscribe <dev>
# CoAP -- discover resources (read-only GET of /.well-known/core)
coap-client -m get coap://<dev>/.well-known/core
nmap -sU -p5683 --script coap-resources <dev>
# UPnP/SSDP -- device/service description + exposed control actions
upnpc -l                                           # list IGD + port mappings (do NOT add/remove)
nmap -sU -p1900 --script upnp-info <dev>
# ONVIF (IP cameras) -- GetDeviceInformation / capabilities (no PTZ/config writes)
nmap -p80,8000,8899 <dev>
# Telnet / RTSP -- banner + auth presence (no brute of prod)
nmap -p23 --script telnet-ntlm-info,banner <dev>
nmap -p554 --script rtsp-url-brute <dev>           # discover stream paths (read-only); view only an authorized feed
```
Benign proof: an unauthenticated broker you can subscribe to, a CoAP resource list, an open UPnP control action, or an unauthenticated RTSP/Telnet banner -- read-only; never publish/actuate/alter config. Cross-reference recovered default creds for a remote pre-auth path.
