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
